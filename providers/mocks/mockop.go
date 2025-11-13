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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/openpubkey/openpubkey/discover"
)

type MockOp struct {
	Issuer              string
	MockProviderBackend *MockProviderBackend
	Subjects            []Subject

	authCodes map[string]string
	// refreshTokens         map[string]string // TODO: Implement refresh tokens
	httpClient *http.Client
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
		authCodes:           map[string]string{},
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

	// How this mocking flow works:
	//                                        OPK Client                 MockOp.Run()
	//                                           |                           |
	//                                           | Client starts HTTP server |
	//                                           |                           |
	// 1. Client calls OpenBrowser function      |-OpenBrowser(URI)--------->|
	// 2. Sim. browser opening the URI           |<------HTTP Request to URI-|
	// 3. Client redirects to Web chooser        |-Redirect to Web Chooser-->|
	//  ...Run() chooses which OP to use         |<-------------------Choice-|
	// 4. Client redirects to OP Auth endpoint   |-Redirect to OP Auth EP--->|
	// 5. Run learns state, nonce, redirect_uri  |                           |
	//  ...responds with auth code               |<--------------(Auth Code)-|
	//                                           |                              MockOp.RounderTripper
	// 6. Client calls token endpoint            |-POST (Auth Code)------------------->|
	//    ... RounderTripper resps. with tokens  |<----------------HTTP Resp. (Tokens)-|
	//
	// 1. Opk_client calls OpenBrowser function which is overridden to to call MockOp.Run()
	// 2. Simulate browser opening the browserOpenUri so opk client redirect
	// us to either OP Auth screen or Web Chooser
	// 3. Trap redirect from the client to see where client tried to send us:
	//   IF: redirect was to the web chooser, fire a request to select the OP
	//   and get redirected to OP Auth endpoint.
	// 4. The client redirect is to OP Auth endpoint.
	// 5. Extract state, nonce, redirect_uri values from the URI params,
	// send auth code to opk client by redirecting to redirect_uri.
	// 6. opk client will then request tokens via the token endpoint which we
	// mock in our httpClient round tripper.

	fmt.Println("MockOp received consent auth done signal for subject:", userAuth.SubjectId)
	browserOpenUri := userAuth.browserOpenUri

	// 2. Make request to the URL to simulate browser opening to that URL
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

	// Is redirect to Web Chooser or Auth endpoint?
	loc := resp.Header.Get("Location")
	if loc == "" {
		return fmt.Errorf("redirect missing Location header")
	}
	locURL, err := url.Parse(loc)
	if err != nil {
		return fmt.Errorf("bad redirect Location: %w", err)
	}
	// Redirect is to Web Chooser
	// TODO: handle web chooser

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

	cb, err := url.Parse(ruri)
	if err != nil {
		return err
	}

	// Respond with auth code by making request to the client's redirect_uri listener
	q := cb.Query()
	authcode := m.CreateAuthCode(nonce)
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

func (m *MockOp) CreateAuthCode(nonce string) string {
	authcode := fmt.Sprintf("fake-auth-code-%d", len(m.authCodes))
	m.authCodes[authcode] = nonce
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
	var nonce string
	grantType := req.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		authCode := req.FormValue("code")
		if !strings.HasPrefix(authCode, "fake-auth-code-") {
			return nil, fmt.Errorf("incorrect auth code, got %s, expected fake-auth-code- prefix", authCode)
		}

		nonce = m.authCodes[authCode]
		if nonce == "" {
			return nil, fmt.Errorf("unknown auth code: %s", authCode)
		}
	case "refresh_token":
		// TODO: We need to get a token here without a nonce
		nonce = ""
	default:
		return nil, fmt.Errorf("unsupported grant_type: %s", grantType)
	}

	cicHash := nonce
	m.MockProviderBackend.IDTokenTemplate.AddCommit(cicHash)
	tokens, err := m.MockProviderBackend.IDTokenTemplate.IssueTokens()
	if err != nil {
		return nil, err
	}

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
	// WebChooserChoice specifies which choice to make at the web chooser screen.
	// If web chooser is not used and this field is not empty, we return an error.
	// If web chooser is used and this field is empty, we return an error.
	WebChooserChoice string
	// browserOpenUri captures the URL that would be opened in a browser
	browserOpenUri string
}

func (u *UserBrowserInteractionMock) BrowserOpenOverrideFunc(op *MockOp) func(string) error {
	return func(url string) error {
		u.browserOpenUri = url
		return op.Run(u)
	}
}

type Subject struct {
	SubjectID string
	Claims    map[string]string
	Protected map[string]string
}
