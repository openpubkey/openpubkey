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

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// KeyBindingOp configures standardOp to use the OIDC key binding protocol as described in the
// draft standard "OpenID Connect Key Binding" at https://openid.github.io/connect-key-binding/main.html
type KeyBindingOp struct {
	StandardOp
}

// ConfigKeyBinding sets up the KeyBindingOp to use the provided signer and algorithm.
// This is required to successfully use this type of OP.
func (s *KeyBindingOp) ConfigKeyBinding(kbSigner crypto.Signer, kbAlg string) error {
	s.keyBindingSigner = kbSigner
	s.keyBindingSignerAlg = kbAlg

	base := http.DefaultTransport
	if s.HttpClient != nil {
		base = s.HttpClient.Transport
	}

	s.Scopes = append(s.Scopes, "bound_key")

	jktb64, err := CreateJKT(kbSigner, kbAlg)
	if err != nil {
		return err
	}
	s.StandardOp.ExtraURLParamOpts = append(s.StandardOp.ExtraURLParamOpts, rp.WithURLParam("dpop_jkt", string(jktb64)))

	// Override the StandardOp's HTTP client so we can read the authcode and set the DPoP header
	if s.StandardOp.HttpClient == nil {
		s.StandardOp.HttpClient = &http.Client{}
	}
	s.StandardOp.HttpClient.Transport = &dPoPRoundTripper{
		Base:   base,
		Signer: kbSigner,
		Alg:    kbAlg,
	}
	return nil
}

func (s *KeyBindingOp) VerifyIDToken(ctx context.Context, idt []byte, cic *clientinstance.Claims) error {
	vp := NewProviderVerifier(
		s.issuer,
		ProviderVerifierOpts{
			CommitType:        CommitTypesEnum.KEY_BOUND,
			ClientID:          s.clientID,
			DiscoverPublicKey: &s.publicKeyFinder,
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
	if req.URL.Path == "/oauth/token" || req.URL.Path == "/token" { // TODO: We should infer this from the OP WellKnown URI config, but currently we haven't looked up those values at RoundTripper creation time
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
		if err != nil {
			return nil, err
		}
		authCode := form.Get("code")
		jti := randomB64(16)
		iat := time.Now().Add(-30 * time.Second).Unix()

		token, err := CreateDpopJwt(htm, htu, jti, authCode, iat, t.Signer, t.Alg)
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", string(token))

		return t.Base.RoundTrip(req)
	}
	return t.Base.RoundTrip(req)
}

// CreateDpopJwt creates a DPoP JWT for the given parameters and signs it with
// the provided signer and algorithm and returns it as a compact JWT.
func CreateDpopJwt(htm, htu, jti, authcode string, iat int64, signer crypto.Signer, alg string) ([]byte, error) {
	jwkKey, err := CreateJWK(signer, alg)
	if err != nil {
		return nil, err
	}

	ph := jws.NewHeaders()
	if err := ph.Set("typ", "dpop+jwt"); err != nil {
		return nil, err
	}
	if err := ph.Set("alg", alg); err != nil {
		return nil, err
	}
	if err := ph.Set("jwk", jwkKey); err != nil {
		return nil, err
	}

	cHash := sha256.Sum256([]byte(authcode))
	payload := oidc.DpopClaims{
		Htm:   htm,
		Htu:   htu,
		Jti:   jti,
		Iat:   iat,
		CHash: base64.RawURLEncoding.EncodeToString(cHash[:]),
	}

	payloadStr, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	keyAlg, err := jwa.KeyAlgorithmFrom(alg)
	if err != nil {
		return nil, err
	}

	return jws.Sign(payloadStr,
		jws.WithKey(keyAlg, signer,
			jws.WithProtectedHeaders(ph),
		),
	)
}

func CreateJKT(signer crypto.Signer, alg string) ([]byte, error) {
	jwkKey, err := CreateJWK(signer, alg)
	if err != nil {
		return nil, err
	}
	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return util.Base64EncodeForJWT(thumbprint), nil
}

func CreateJWK(signer crypto.Signer, alg string) (jwk.Key, error) {
	jwkKey, err := jwk.PublicKeyOf(signer.Public())
	if err != nil {
		return nil, err
	}
	err = jwkKey.Set(jwk.AlgorithmKey, alg)
	if err != nil {
		return nil, err
	}
	return jwkKey, nil
}
