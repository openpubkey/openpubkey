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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type MockOp struct {
	Issuer              string
	MockProviderBackend *MockProviderBackend

	authCodes map[string]string
	// refreshTokens         map[string]string // TODO: Implement refresh tokens
	signalConsentAuthDone chan string
	httpClient            *http.Client
}

func NewMockOp(issuer string, idtTemplate *IDTokenTemplate, opBackend *MockProviderBackend) (*MockOp, error) {
	opBackend.SetIDTokenTemplate(idtTemplate)
	return &MockOp{
		httpClient:          nil,
		Issuer:              issuer,
		MockProviderBackend: opBackend,
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
					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Type": {"application/json"}},
						Body:       io.NopCloser(strings.NewReader(m.GetWellKnownResponse())),
					}, nil
				case m.GetJwksURI():
					jwks, err := m.GetJwks()
					if err != nil {
						return nil, err
					}

					return &http.Response{
						StatusCode: 200,
						Header:     http.Header{"Content-Type": {"application/json"}},
						Body:       io.NopCloser(strings.NewReader(jwks)),
					}, nil
				case m.GetTokenURI():
					err := req.ParseForm()
					if err != nil {
						return nil, err
					}

					var nonce string
					grantType := req.FormValue("grant_type")
					if grantType == "authorization_code" {
						authCode := req.FormValue("code")
						if !strings.HasPrefix(authCode, "fake-auth-code-") {
							return nil, fmt.Errorf("incorrect auth code, got %s, expected fake-auth-code- prefix", authCode)
						}

						nonce = m.authCodes[authCode]
						if nonce == "" {
							return nil, fmt.Errorf("unknown auth code: %s", authCode)
						}
					} else if grantType == "refresh_token" {
						// TODO: We need to get a token here without a nonce
						nonce = ""
					} else {
						return nil, fmt.Errorf("unsupported grant_type: %s", grantType)
					}

					tokens, err := m.MockProviderBackend.RequestTokensOverrideFunc(nonce)
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

					tokensJSON, err := json.Marshal(resp)
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

func (m *MockOp) GetUserAuthCompleteSignal() chan string {
	if m.signalConsentAuthDone == nil {
		m.signalConsentAuthDone = make(chan string, 1)
	}
	return m.signalConsentAuthDone
}

func (m *MockOp) Run(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case redirect_uri := <-m.GetUserAuthCompleteSignal():
		fmt.Println("MockOp received consent auth done signal for redirect URI:", redirect_uri)

		jar, err := cookiejar.New(nil)
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

		req, err := http.NewRequest(http.MethodGet, redirect_uri, nil)
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

func (m *MockOp) GetJwks() (string, error) {
	keysByKid := m.MockProviderBackend.GetProviderPublicKeySet()

	keySet := jwk.NewSet()
	for kid, v := range keysByKid {
		fmt.Printf("KID %s: %+v\n", kid, v)
		jwkKey, err := jwk.PublicKeyOf(v.PublicKey)
		if err != nil {
			return "", err
		}
		if err := jwkKey.Set(jwk.AlgorithmKey, v.Alg); err != nil {
			return "", err
		}
		if err := jwkKey.Set(jwk.KeyIDKey, kid); err != nil {
			return "", err
		}

		if err := keySet.AddKey(jwkKey); err != nil {
			return "", err
		}
	}

	jwksJson, err := json.Marshal(keySet)
	if err != nil {
		return "", err
	}
	return string(jwksJson), nil
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
