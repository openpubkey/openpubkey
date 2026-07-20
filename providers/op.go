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
	"io"
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

// LoginURIHook receives the browser entry URI produced during a
// browser-based authentication flow. StandardOp supplies its local login URI,
// which redirects the browser into the OpenID Provider authorization flow.
//
// The hook is called before automatic browser opening is attempted. This
// ensures the application receives the URI even if the browser cannot be
// opened. When automatic browser opening is disabled, the application can use
// the hook to display the URI, open a browser, or integrate the URI into its
// own user interface. Returning an error aborts the authentication flow and
// returns that error to the caller. If automatic browser opening fails after a
// hook has received the URI, the opening error is not returned; the hook
// is expected to have made the URI available through an application-controlled
// mechanism.
type LoginURIHook func(uri string) error

// ErrLoginURIHookUnsupported is returned when a browser provider
// does not support configuring a LoginURIHook.
var ErrLoginURIHookUnsupported = errors.New("login URI hook is not supported by this provider")

// ErrOutWriterUnsupported is returned when a browser provider does not support
// configuring an output writer.
var ErrOutWriterUnsupported = errors.New("output writer is not supported by this provider")

// ErrErrorWriterUnsupported is returned when a browser provider does not support
// configuring an error writer.
var ErrErrorWriterUnsupported = errors.New("error writer is not supported by this provider")

// SetLoginURIHook configures how an application handles or observes
// the browser entry URI produced by a browser provider. It is kept outside the
// BrowserOpenIdProvider interface so existing third-party implementations
// remain source compatible. See LoginURIHook for invocation and
// error semantics.
func SetLoginURIHook(provider BrowserOpenIdProvider, hook LoginURIHook) error {
	configurable, ok := provider.(interface {
		SetLoginURIHook(LoginURIHook)
	})
	if !ok {
		return ErrLoginURIHookUnsupported
	}
	configurable.SetLoginURIHook(hook)
	return nil
}

// SetOutWriter configures where a browser provider writes non-fatal,
// user-facing messages. A nil writer retains the default of os.Stdout. It is
// kept outside BrowserOpenIdProvider so existing third-party implementations
// remain source compatible.
func SetOutWriter(provider BrowserOpenIdProvider, writer io.Writer) error {
	configurable, ok := provider.(interface {
		SetOutWriter(io.Writer)
	})
	if !ok {
		return ErrOutWriterUnsupported
	}
	configurable.SetOutWriter(writer)
	return nil
}

// SetErrWriter configures where a browser provider writes non-fatal error and
// diagnostic messages. A nil writer retains the default of os.Stderr. It is
// kept outside BrowserOpenIdProvider so existing third-party implementations
// remain source compatible.
func SetErrWriter(provider BrowserOpenIdProvider, writer io.Writer) error {
	configurable, ok := provider.(interface {
		SetErrWriter(io.Writer)
	})
	if !ok {
		return ErrErrorWriterUnsupported
	}
	configurable.SetErrWriter(writer)
	return nil
}

// SetDefaultWriters supplies inherited output writers without replacing
// writers explicitly configured on the provider. Providers that do not support
// configurable writers are left unchanged.
func SetDefaultWriters(provider BrowserOpenIdProvider, outWriter, errWriter io.Writer) {
	configurable, ok := provider.(interface {
		SetDefaultWriters(io.Writer, io.Writer)
	})
	if ok {
		configurable.SetDefaultWriters(outWriter, errWriter)
	}
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
