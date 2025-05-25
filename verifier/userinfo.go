// Copyright 2025 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package verifier

import (
	"context"
	"net/http"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)


// UserInfoRequester enables the retrieval of user info from an OpenID Provider
// using the access token obtained during authentication. It uses the PK Token
// look up the issuer URI for the OpenID Provider and ensure that the subject
// (sub claim) in the ID token matches the subject in the access token.
type UserInfoRequester struct {
	Issuer      string
	Subject     string
	AccessToken string
	HttpClient  *http.Client
}

func NewUserInfoRequester(pkt *pktoken.PKToken, accessToken string) (*UserInfoRequester, error) {
	issuer, err := pkt.Issuer()
	if err != nil {
		return nil, err
	}
	sub, err := pkt.Subject()
	if err != nil {
		return nil, err
	}
	return &UserInfoRequester{
		Issuer:      issuer,
		Subject:     sub,
		AccessToken: accessToken,
	}, nil
}


// Request calls an OpenID Provider's user info endpoint using the provided access token.
// The access token must match subject (sub claim) in the ID token issued alongside that
// access token. This function returns the user info JSON as a string.
func (ui *UserInfoRequester) Request(ctx context.Context) (string, error) {

	httpClient := http.DefaultClient
	if ui.HttpClient != nil {
		httpClient = ui.HttpClient
	}

	// We use zitadel/oidc to call the userinfo endpoint rather than calling
	// the endpoint directly to take advantage of the zitadel's ability to use
	// HTTP proxies in requests.
	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, ui.Issuer, "", "", "", nil, rp.WithHTTPClient(httpClient))
	if err != nil {
		return "", err
	}
	info, err := rp.Userinfo[*oidc.UserInfo](
		ctx,
		ui.AccessToken,
		"Bearer",
		ui.Subject,
		relyingParty,
	)
	if err != nil {
		return "", err
	}

	jsonInfo, err := info.MarshalJSON()
	if err != nil {
		// We should not reach this because rp.NewRelyingPartyOIDC already unmarshals the JSON to check the sub
		return "", err
	}

	return string(jsonInfo), nil
}
