// Copyright 2024 OpenPubkey
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

package providers

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/openpubkey/openpubkey/discover"
	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

// Interface for interacting with the OP (OpenID Provider) that only returns
// an ID Token
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error)
	PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error)
	PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error)
	// Returns the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
	Issuer() string
	VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error
}

// Interface for an OpenIdProvider that uses the web browser
type BrowserOpenIdProvider interface {
	OpenIdProvider
	ClientID() string
	HookHTTPSession(h http.HandlerFunc)
	ReuseBrowserWindowHook(chan string)
}

// AuthorizationURLHandler handles an authorization URL produced during a
// browser-based authentication flow. Applications can use it to display the
// URL, open a browser, or integrate the URL into their own user interface.
type AuthorizationURLHandler func(url string) error

// ErrAuthorizationURLHandlerUnsupported is returned when a browser provider
// does not support configuring an AuthorizationURLHandler.
var ErrAuthorizationURLHandlerUnsupported = errors.New("authorization URL handler is not supported by this provider")

// SetAuthorizationURLHandler configures how an application handles the
// authorization URL produced by a browser provider. It is kept outside the
// BrowserOpenIdProvider interface so existing third-party implementations
// remain source compatible.
func SetAuthorizationURLHandler(provider BrowserOpenIdProvider, handler AuthorizationURLHandler) error {
	configurable, ok := provider.(interface {
		SetAuthorizationURLHandler(AuthorizationURLHandler)
	})
	if !ok {
		return ErrAuthorizationURLHandlerUnsupported
	}
	configurable.SetAuthorizationURLHandler(handler)
	return nil
}

// Interface for an OpenIdProvider that returns an ID Token, Refresh Token and Access Token
type RefreshableOpenIdProvider interface {
	OpenIdProvider
	RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error)
	VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error
}

// Interface for an OpenIdProvider that supports key binding of the ID Token
type KeyBindingOpenIdProvider interface {
	OpenIdProvider
	ConfigKeyBinding(kbSigner crypto.Signer, kbAlg string) error
}

const KEYBOUND_TYP = "dpop+id_token"

type CommitType struct {
	Claim        string
	GQCommitment bool
}

var CommitTypesEnum = struct {
	NONCE_CLAIM CommitType
	KEY_BOUND   CommitType
	AUD_CLAIM   CommitType
	GQ_BOUND    CommitType
}{
	NONCE_CLAIM: CommitType{Claim: "nonce", GQCommitment: false},
	KEY_BOUND:   CommitType{Claim: "cnf", GQCommitment: false}, //  Key_bound ID tokens are ID tokens where the user's public key in the "cnf" claim in the ID Token payload
	AUD_CLAIM:   CommitType{Claim: "aud", GQCommitment: false},
	GQ_BOUND:    CommitType{Claim: "", GQCommitment: true}, // The commitmentClaim is bound to the ID Token using only the GQ signature
}

func getEnvVar(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%q environment variable not set", name)
	}
	return value, nil
}
