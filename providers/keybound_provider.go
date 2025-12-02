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

	jktb64, err := createJKT(kbSigner, kbAlg)
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

// func (s *KeyBindingOp) RefreshTokens(ctx context.Context, refreshToken []byte) (*simpleoidc.Tokens, error) {
// 	return s.StandardOpRefreshable.RefreshTokens(ctx, refreshToken)
// 	cookieHandler, err := configCookieHandler()
// 	if err != nil {
// 		return nil, err
// 	}
// 	options := []rp.Option{
// 		rp.WithCookieHandler(cookieHandler),
// 		rp.WithVerifierOpts(
// 			rp.WithIssuedAtOffset(s.IssuedAtOffset),
// 			rp.WithNonce(nil), // disable nonce check
// 		),
// 	}
// 	if s.HttpClient != nil {
// 		options = append(options, rp.WithHTTPClient(s.HttpClient))
// 	}

// 	// The redirect URI is not sent in the refresh request so we set it to an empty string.
// 	// According to the OIDC spec the only values send on a refresh request are:
// 	// client_id, client_secret, grant_type, refresh_token, and scope.
// 	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
// 	redirectURI := ""
// 	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, s.issuer, s.clientID,
// 		s.ClientSecret, redirectURI, s.Scopes, options...)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create RP to verify token: %w", err)
// 	}
// 	retTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, string(refreshToken), "", "")
// 	if err != nil {
// 		return nil, err
// 	}

// 	if retTokens.RefreshToken == "" {
// 		// Google does not rotate refresh tokens, the one you get at the
// 		// beginning is the only one you'll ever get. This may not be true
// 		// of OPs.
// 		retTokens.RefreshToken = string(refreshToken)
// 	}

// 	return &simpleoidc.Tokens{
// 		IDToken:      []byte(retTokens.IDToken),
// 		RefreshToken: []byte(retTokens.RefreshToken),
// 		AccessToken:  []byte(retTokens.AccessToken)}, nil
// }

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

// func (s *KeyBindingOp) VerifyRefreshedIDToken(ctx context.Context, origIdt []byte, reIdt []byte) error {
// 	if err := simpleoidc.SameIdentity(origIdt, reIdt); err != nil {
// 		return fmt.Errorf("refreshed ID Token is for different subject than original ID Token: %w", err)
// 	}
// 	if err := simpleoidc.RequireOlder(origIdt, reIdt); err != nil {
// 		return fmt.Errorf("refreshed ID Token should not be issued before original ID Token: %w", err)
// 	}

// 	options := []rp.Option{}
// 	if s.HttpClient != nil {
// 		options = append(options, rp.WithHTTPClient(s.HttpClient))
// 	}
// 	redirectURI := ""
// 	relyingParty, err := rp.NewRelyingPartyOIDC(ctx, s.issuer, s.clientID,
// 		s.ClientSecret, redirectURI, s.Scopes, options...)
// 	if err != nil {
// 		return fmt.Errorf("failed to create RP to verify token: %w", err)
// 	}
// 	_, err = rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, string(reIdt), relyingParty.IDTokenVerifier())
// 	return err
// }

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

		token, err := createDPoPToken(htm, htu, jti, authCode, iat, t.Signer, t.Alg)
		if err != nil {
			return nil, err
		}
		req.Header.Set("DPoP", string(token))

		return t.Base.RoundTrip(req)
	}
	return t.Base.RoundTrip(req)
}

func createDPoPToken(htm, htu, jti, authcode string, iat int64, signer crypto.Signer, alg string) ([]byte, error) {
	jwkKey, err := createJWK(signer, alg)
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
	payload := map[string]any{
		"htm":    htm,
		"htu":    htu,
		"jti":    jti,
		"iat":    iat,
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

func createJKT(signer crypto.Signer, alg string) ([]byte, error) {
	jwkKey, err := createJWK(signer, alg)
	if err != nil {
		return nil, err
	}
	thumbprint, err := jwkKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return util.Base64EncodeForJWT(thumbprint), nil
}

func createJWK(signer crypto.Signer, alg string) (jwk.Key, error) {
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
