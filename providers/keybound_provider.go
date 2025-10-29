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

package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

// KeyBindingOp configures standardOp the OIDC key binding protocol as described in the
// draft standard "OpenID Connect Key Binding" at https://openid.github.io/connect-key-binding/main.html
type KeyBindingOp struct {
	StandardOp
}

// ConfigKeyBinding sets up the KeyBindingOp to use the provided signer and algorithm.
// This is required to successfully use this type of OP.
func (s *KeyBindingOp) ConfigKeyBinding(kbSigner crypto.Signer, kbAlg string) {
	s.keyBindingSigner = kbSigner
	s.keyBindingSignerAlg = kbAlg

	base := http.DefaultTransport
	if s.HttpClient != nil {
		base = s.HttpClient.Transport
	}

	if s.keyBindingSigner != nil {
		s.Scopes = append(s.Scopes, "bound_key")
	}

	// Override the StandardOp's HTTP client so we can read the authcode and set the DPoP header
	s.StandardOp.HttpClient = &http.Client{
		Transport: &dPoPRoundTripper{
			Base:   base,
			Signer: kbSigner,
			Alg:    kbAlg,
		},
	}
}

func (s *KeyBindingOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(
		s.issuer,
		ProviderVerifierOpts{
			CommitType:             CommitTypesEnum.NONCE_CLAIM, // TODO: Key bound ID Tokens should have their own commit type
			ClientID:               s.clientID,
			DiscoverPublicKey:      &s.publicKeyFinder,
			RequireKeyBoundIDToken: true,
		})
	return vp.VerifyIDToken(ctx, idt, cic)
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type dPoPRoundTripper struct {
	Base   http.RoundTripper
	Signer crypto.Signer
	Alg    string
}

func (t *dPoPRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/oauth/token" {
		u := *req.URL
		u.Fragment = ""
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		htu := u.String()
		htm := strings.ToUpper(req.Method)

		// Use GetBody to read the body of the request non-destructively
		r, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer r.Close()

		bodyBytes, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(bodyBytes))
		authCode := form.Get("code")

		token, err := createDPoPToken(htm, htu, authCode, t.Signer, t.Alg)
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", string(token))

		return t.Base.RoundTrip(req)
	}
	return t.Base.RoundTrip(req)
}

func createDPoPToken(htm, htu, authcode string, signer crypto.Signer, alg string) ([]byte, error) {
	jwkKey, err := jwk.PublicKeyOf(signer.Public())
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}

	ph := jws.NewHeaders()
	ph.Set("typ", "dpop+jwt")
	ph.Set("alg", alg)
	ph.Set("jwk", jwkKey)

	cHash := sha256.Sum256([]byte(authcode))
	payload := map[string]any{
		"htm":    htm,
		"htu":    htu,
		"jti":    randomB64(16),
		"iat":    time.Now().Add(-30 * time.Second).Unix(),
		"c_hash": base64.RawURLEncoding.EncodeToString(cHash[:]),
	}

	payloadStr, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return jws.Sign(payloadStr,
		jws.WithKey(jwa.KeyAlgorithmFrom(alg), signer,
			jws.WithProtectedHeaders(ph),
		),
	)
}
