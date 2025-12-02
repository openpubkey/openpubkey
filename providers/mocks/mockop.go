// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/util"
)

type MockOp struct {
	Issuer              string
	MockProviderBackend *MockProviderBackend
	Subjects            []Subject
	KeyBinding          bool

	authCodes     map[string]AuthSession
	refreshTokens map[string]AuthSession
	httpClient    *http.Client
}

type AuthSession struct {
	AuthCode    string
	Nonce       string
	Jkt         string // Only used for key binding (JWK thumbprint of the user's bound key)
	Cnf         []byte // JWK of user's bound key as JSON []byte
	SubjectAuth Subject
}

type Subject struct {
	SubjectID string
	Claims    map[string]any
	Protected map[string]any
}

func NewMockOp(issuer string, subjects []Subject) (*MockOp, error) {
	opBackend, err := NewMockProviderBackend(issuer, "RS256", 2)
	if err != nil {
		return nil, err
	}
	return &MockOp{
		httpClient:          nil,
		Issuer:              issuer,
		MockProviderBackend: opBackend,
		Subjects:            subjects,
		KeyBinding:          false,
		authCodes:           map[string]AuthSession{},
		refreshTokens:       map[string]AuthSession{},
	}, nil
}

func NewMockKeyBindingOp(issuer string, subjects []Subject) (*MockOp, error) {
	opBackend, err := NewMockProviderBackend(issuer, "RS256", 2)
	if err != nil {
		return nil, err
	}
	return &MockOp{
		httpClient:          nil,
		Issuer:              issuer,
		MockProviderBackend: opBackend,
		Subjects:            subjects,
		KeyBinding:          true,
		authCodes:           map[string]AuthSession{},
		refreshTokens:       map[string]AuthSession{},
	}, nil
}

func (m *MockOp) GetHTTPClient() *http.Client {
	if m.httpClient == nil {
		m.httpClient = &http.Client{
			Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				url := req.URL.String()
				switch url {
				case m.GetWellKnownURI():
					if req.Method != http.MethodGet {
						return nil, fmt.Errorf("unexpected HTTP method %s for URL %s, expected GET", req.Method, url)
					}
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Type": {"application/json"}},
						Body:       io.NopCloser(strings.NewReader(m.GetWellKnownResponse())),
					}, nil
				case m.GetJwksURI():
					if req.Method != http.MethodGet {
						return nil, fmt.Errorf("unexpected HTTP method %s for URL %s, expected GET", req.Method, url)
					}
					jwks, err := m.MockProviderBackend.GetJwks()
					if err != nil {
						return nil, err
					}
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Type": {"application/json"}},
						Body:       io.NopCloser(strings.NewReader(string(jwks))),
					}, nil
				case m.GetTokenURI():
					if req.Method != http.MethodPost {
						return nil, fmt.Errorf("unexpected HTTP method %s for URL %s, expected POST", req.Method, url)
					}
					tokensJSON, err := m.IssueTokens(req)
					if err != nil {
						return nil, err
					}
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Type": {"application/json"}},
						Body:       io.NopCloser(strings.NewReader(string(tokensJSON))),
					}, nil
				default:
					return nil, fmt.Errorf("unexpected HTTP call to %s %s", req.Method, req.URL)
				}
			}),
		}
	}
	return m.httpClient
}

// Run simulates the user interaction with the OP to complete the auth code flow.
func (m *MockOp) Run(userAuth *UserBrowserInteractionMock) error {
	// Checks if the subject specified exists
	var subject *Subject
	for _, s := range m.Subjects {
		if s.SubjectID == userAuth.SubjectId {
			subject = &s
			break
		}
	}
	if subject == nil {
		// In the real world the opk client doesn't get an error message if the user fails to auth to the OP.
		// We panic here to help catch bugs in test quickly.
		panic(fmt.Sprintf("subject not found: %s in Subjects %v", userAuth.SubjectId, m.Subjects))
	}

	fmt.Println("MockOp received consent auth done signal for subject:", userAuth.SubjectId)
	browserOpenUri := userAuth.browserOpenUri

	// Make request to the URL to simulate browser opening to that URL
	jar, err := cookiejar.New(nil) // Cookie jar is needed for state cookies used by OpenID Connect to prevent CSRF attacks
	if err != nil {
		return err
	}
	cookieClient := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// This traps the redirect, allowing us to inspect it
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest(http.MethodGet, browserOpenUri, nil)
	if err != nil {
		return err
	}
	resp, err := cookieClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected redirect, got %s: %s", resp.Status, string(b))
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("redirect missing Location header")
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		return fmt.Errorf("bad redirect Location: %w", err)
	}

	// Redirect is to OP Auth endpoint
	state := locURL.Query().Get("state")
	if state == "" {
		return fmt.Errorf("auth endpoint params (URI=%s) missing state", loc)
	}
	nonce := locURL.Query().Get("nonce")
	if nonce == "" {
		return fmt.Errorf("auth endpoint params (URI=%s) missing nonce", loc)
	}
	ruri := locURL.Query().Get("redirect_uri")
	if ruri == "" {
		return fmt.Errorf("auth endpoint params (URI=%s) missing redirect_uri", loc)
	}

	dPopJkt := ""
	if m.KeyBinding {
		dPopJkt = locURL.Query().Get("dpop_jkt")
	}

	cb, err := url.Parse(ruri)
	if err != nil {
		return err
	}

	// Respond with auth code by making request to the client's redirect_uri listener
	q := cb.Query()
	authcode := m.CreateAuthCode(nonce, subject, dPopJkt)
	q.Set("code", authcode)
	q.Set("state", state)
	cb.RawQuery = q.Encode()

	callbackReq, err := http.NewRequest(http.MethodGet, cb.String(), nil)
	if err != nil {
		return err
	}
	callbackResp, err := cookieClient.Do(callbackReq)
	if err != nil {
		return err
	}
	defer callbackResp.Body.Close()
	_, err = io.ReadAll(callbackResp.Body)
	return err
}

func (m *MockOp) GetTokenURI() string {
	return m.Issuer + "/token"
}

func (m *MockOp) CreateAuthCode(nonce string, subject *Subject, jkt string) string {
	authcode := fmt.Sprintf("fake-auth-code-%d", len(m.authCodes)+1)
	authSession := AuthSession{
		AuthCode:    authcode,
		Nonce:       nonce,
		SubjectAuth: *subject,
		Jkt:         jkt,
	}
	m.authCodes[authcode] = authSession
	return authcode
}

func (m *MockOp) GetJwksURI() string {
	return m.Issuer + "/oauth2/v3/certs"
}

func (m *MockOp) GetWellKnownURI() string {
	return m.Issuer + "/.well-known/openid-configuration"
}

func (m *MockOp) GetWellKnownResponse() string {
	return fmt.Sprintf(`{
	"issuer": "%s",
	"authorization_endpoint": "%s",
	"device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
	"token_endpoint": "%s",
	"userinfo_endpoint": "%s",
	"revocation_endpoint": "https://oauth2.googleapis.com/revoke",
	"jwks_uri": "%s",
	"response_types_supported": [
		"code",
		"token",
		"id_token",
		"code token",
		"code id_token",
		"token id_token",
		"code token id_token",
		"none"
	],
	"subject_types_supported": [
		"public"
	],
	"id_token_signing_alg_values_supported": [
		"RS256"
	],
	"scopes_supported": [
		"openid",
		"email",
		"profile"
	],
	"token_endpoint_auth_methods_supported": [
		"client_secret_post",
		"client_secret_basic"
	],
	"claims_supported": [
		"aud",
		"email",
		"email_verified",
		"exp",
		"family_name",
		"given_name",
		"iat",
		"iss",
		"name",
		"picture",
		"sub"
	],
	"code_challenge_methods_supported": [
		"plain",
		"S256"
	],
	"grant_types_supported": [
		"authorization_code",
		"refresh_token",
		"urn:ietf:params:oauth:grant-type:device_code",
		"urn:ietf:params:oauth:grant-type:jwt-bearer"
	]
}`, m.Issuer, m.GetAuthzEndpointURI(), m.GetTokenURI(), m.GetUserInfoURI(), m.GetJwksURI())
}

func (m *MockOp) GetAuthzEndpointURI() string {
	return m.Issuer + "/o/oauth2/v2/auth"
}

func (m *MockOp) GetUserInfoURI() string {
	return m.Issuer + "/oauth2/v3/userinfo"
}

func (m *MockOp) GetUserInfo() (string, error) {
	panic("not implemented")
}

func (m *MockOp) IssueTokens(req *http.Request) ([]byte, error) {
	err := req.ParseForm()
	if err != nil {
		return nil, err
	}
	var authSession AuthSession
	grantType := req.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		authCode := req.FormValue("code")
		if !strings.HasPrefix(authCode, "fake-auth-code-") {
			return nil, fmt.Errorf("incorrect auth code, got %s, expected fake-auth-code- prefix", authCode)
		}
		authSession := m.authCodes[authCode]
		if authSession.Nonce == "" {
			return nil, fmt.Errorf("unknown auth code: %s", authCode)
		}
		if m.KeyBinding {
			dpop := req.Header.Get("DPoP")
			if dpop == "" {
				return nil, fmt.Errorf("missing DPoP header for key binding token request")
			}

			jktExpected := authSession.Jkt
			if jktExpected == "" {
				return nil, fmt.Errorf("no JKT registered for auth code: %s", authCode)
			}

			cHash := sha256.Sum256([]byte(authSession.AuthCode))
			cHashB64 := base64.RawURLEncoding.EncodeToString(cHash[:])
			claimsRequired := map[string]any{
				"c_hash": cHashB64,
				"htm":    "POST",
				"htu":    m.GetTokenURI(),
			}

			jwkMap, err := validateDPoPReturnJwk(dpop, jktExpected, claimsRequired)
			if err != nil {
				return nil, fmt.Errorf("failed to validate DPoP JWT: %w", err)
			}

			m.MockProviderBackend.IDTokenTemplate.ExtraClaims = map[string]any{
				"cnf": map[string]any{
					"jwk": jwkMap,
				},
			}
			m.MockProviderBackend.IDTokenTemplate.ExtraProtectedClaims = map[string]any{
				"typ": "id_token+cnf",
			}
		}
		cicHash := authSession.Nonce
		m.MockProviderBackend.IDTokenTemplate.AddCommit(cicHash)

	case "refresh_token":
		refreshToken := req.FormValue("refresh_token")
		var ok bool
		authSession, ok = m.refreshTokens[refreshToken]
		if !ok {
			return nil, fmt.Errorf("unknown refresh token: %s", refreshToken)
		}
		m.MockProviderBackend.IDTokenTemplate.NoNonce = true

		if m.KeyBinding {
			// TODO: require DPoP proof here, when we add refresh token DPoP support
		}
	default:
		return nil, fmt.Errorf("unsupported grant_type: %s", grantType)
	}

	tokens, err := m.MockProviderBackend.IDTokenTemplate.IssueTokens()
	if err != nil {
		return nil, err
	}
	tokens.RefreshToken = []byte(fmt.Sprintf("mock-refresh-token-%d", len(m.refreshTokens)+1))
	m.refreshTokens[string(tokens.RefreshToken)] = authSession

	type tokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token,omitempty"`
	}

	resp := tokenResponse{
		AccessToken:  string(tokens.AccessToken),
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		IDToken:      string(tokens.IDToken),
		RefreshToken: string(tokens.RefreshToken),
	}

	return json.Marshal(resp)
}

func (m *MockOp) RandomSigningKey() (crypto.Signer, string, discover.PublicKeyRecord) {
	return m.MockProviderBackend.RandomSigningKey()
}

type UserBrowserInteractionMock struct {
	SubjectId string
	// browserOpenUri captures the URL that would be opened in a browser
	browserOpenUri string
}

func (u *UserBrowserInteractionMock) BrowserOpenOverrideFunc(op *MockOp) func(string) error {
	return func(url string) error {
		u.browserOpenUri = url
		return op.Run(u)
	}
}

func validateDPoPReturnJwk(dpop string, jktExpected string, claimsRequired map[string]any) (map[string]string, error) {
	dpopJwt, err := oidc.NewDpopJwt([]byte(dpop))
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP JWT: %w", err)
	}

	jwkJson, err := dpopJwt.GetJWKIfClaimsMatch(claimsRequired)
	if err != nil {
		return nil, fmt.Errorf("DPoP claims validation failed: %w", err)
	}

	key, err := jwk.ParseKey(jwkJson)
	if err != nil {
		return nil, err
	}

	// Check that the JWK thumbprint of public key in the DPoP header matches the JKT specified by the user
	jktGot, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	jktGotb64 := util.Base64EncodeForJWT(jktGot)
	if string(jktGotb64) != jktExpected {
		return nil, fmt.Errorf("JWK thumbprint mismatch, expected %s, got %s", jktExpected, string(jktGotb64))
	}

	// Ensure that the alg match (DPoPheader.sig.ph.alg == DPoPheader.sig.ph.jwk.alg)
	algInPh := dpopJwt.GetSignature().GetProtectedClaims().Alg
	if algInPh == "" {
		return nil, fmt.Errorf("no alg in protected header of DPoP header")
	}
	if algInPh != key.Algorithm().String() {
		return nil, fmt.Errorf("in DPoP header the alg (%s) in JWK doesn't match alg (%s) in protected header", key.Algorithm(), algInPh)
	}

	// Check that the DPoP header is correctly signed by the JWK in the DPoP header
	if _, err := jws.Verify([]byte(dpopJwt.GetRaw()), jws.WithKey(jwa.KeyAlgorithmFrom(algInPh), key)); err != nil {
		return nil, fmt.Errorf("failed to verify DPoP header signature: %w", err)
	}

	var jwkKey map[string]string
	if err := json.Unmarshal(jwkJson, &jwkKey); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWK into DPoP header: %w", err)
	}
	return jwkKey, nil
}
