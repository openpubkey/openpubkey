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
	"fmt"
	"io"
	"net/http"
	"strings"
)

const googleWellknownResponse = `{
	"issuer": "https://accounts.google.com",
	"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
	"device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
	"token_endpoint": "https://oauth2.googleapis.com/token",
	"userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
	"revocation_endpoint": "https://oauth2.googleapis.com/revoke",
	"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
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
}`

func NewMockGoogleUserInfoHTTPClient(userInfoResponse, requiredToken string) *http.Client {
	return NewMockUserInfoClient(
		"https://accounts.google.com/.well-known/openid-configuration",
		"https://openidconnect.googleapis.com/v1/userinfo",
		googleWellknownResponse,
		userInfoResponse,
		requiredToken,
	)
}

func NewMockUserInfoClient(wellKnownUri string, userInfoUri string, wellknownResponse string, userInfoResponse string, requiredToken string) *http.Client {
	return &http.Client{
		Transport: RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet && strings.HasPrefix(req.URL.String(), wellKnownUri) {
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(wellknownResponse)),
				}, nil
			}

			if req.Method == http.MethodGet && req.URL.String() == userInfoUri {
				if req.Header.Get("Authorization") != "Bearer "+requiredToken {
					return nil, fmt.Errorf("invalid access token")
				}
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{"Content-Type": {"application/json"}},
					Body:       io.NopCloser(strings.NewReader(userInfoResponse)),
				}, nil
			}
			return nil, fmt.Errorf("unexpected HTTP call to %s %s", req.Method, req.URL)
		}),
	}
}

type RoundTripFunc func(req *http.Request) (*http.Response, error)

func (f RoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
