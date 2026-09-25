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
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/zitadel/oidc/v4/pkg/client/rp"
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

	// We decode into rawUserInfo rather than oidc.UserInfo because we only
	// need the sub claim (so zitadel/oidc can check it against the ID token)
	// and the response body itself. Decoding into oidc.UserInfo would subject
	// the response to that type's strict per-field decoding, which rejects the
	// whole response when an OP sends a claim in a shape it does not expect.
	info, err := rp.Userinfo[*rawUserInfo](
		ctx,
		ui.AccessToken,
		"Bearer",
		ui.Subject,
		relyingParty,
	)
	if err != nil {
		return "", err
	}

	return info.JSON(), nil
}

// rawUserInfo captures an OpenID Provider's userinfo response verbatim while
// exposing the sub claim, which is the only field this package needs.
//
// Implementing rp.SubjectGetter this way keeps sub verification intact while
// avoiding the strict claim decoding of oidc.UserInfo. That strictness is a
// real compatibility hazard: as of zitadel/oidc v4 the oidc.Bool fields
// (email_verified, phone_number_verified) return an error for any value that
// is not a boolean or the strings "true"/"false", so a provider that sends
// "email_verified": null fails the entire userinfo request rather than
// returning the remaining claims. Passing the body through also means callers
// see exactly what the OP sent instead of a re-serialized approximation.
type rawUserInfo struct {
	subject string
	raw     []byte
}

// GetSubject implements rp.SubjectGetter.
func (u *rawUserInfo) GetSubject() string { return u.subject }

// JSON returns the userinfo response with insignificant whitespace removed.
func (u *rawUserInfo) JSON() string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, u.raw); err != nil {
		// UnmarshalJSON only ever stores well-formed JSON, so this is
		// unreachable; fall back to the unmodified body rather than losing it.
		return string(u.raw)
	}
	return buf.String()
}

func (u *rawUserInfo) UnmarshalJSON(data []byte) error {
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return err
	}
	u.subject = claims.Subject
	u.raw = append([]byte(nil), data...)
	return nil
}
