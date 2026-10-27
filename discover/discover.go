// Copyright 2024 OpenPubkey
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

package discover

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/openpubkey/openpubkey/jose"
	"github.com/openpubkey/openpubkey/util"

	oidcclient "github.com/zitadel/oidc/v3/pkg/client"
)

type PublicKeyRecord struct {
	PublicKey crypto.PublicKey
	Alg       string
	Issuer    string
	WasCached bool
}

func publicKeyRecordFromJWK(key jwk.Key, issuer string, wasCached bool) (*PublicKeyRecord, error) {
	// Let jwx handle the key extraction generically
	// NOTE: this will pass through private keys as well as public keys
	var pkr = &PublicKeyRecord{WasCached: wasCached}
	var pubKey any
	if err := jwk.Export(key, &pubKey); err != nil {
		return pkr, fmt.Errorf("failed to decode public key: %w", err)
	}

	// If we got a private key (crypto.Signer), extract its public key
	if signer, ok := pubKey.(crypto.Signer); ok {
		pubKey = signer.Public()
	}

	alg, ok := key.Algorithm()
	if !ok || alg.String() == "" {
		// OPs such as azure (microsoft) do not specify alg in their JWKS. To
		// handle this case, assume no alg in JWKS means RSA as OIDC requires
		// OPs use RSA.
		alg = jwa.RS256()
	}

	// Validate that key type matches the declared algorithm
	switch alg {
	case jwa.RS256(), jwa.PS256():
		if _, ok := pubKey.(*rsa.PublicKey); !ok {
			return pkr, fmt.Errorf("algorithm %s requires RSA key, got %T", alg, pubKey)
		}
	case jwa.ES256():
		if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
			return pkr, fmt.Errorf("algorithm %s requires ECDSA key, got %T", alg, pubKey)
		}
	case jwa.EdDSA(), jwa.EdDSAEd25519():
		if _, ok := pubKey.(ed25519.PublicKey); !ok {
			return pkr, fmt.Errorf("algorithm %s requires Ed25519 key, got %T", alg, pubKey)
		}
	default:
		return pkr, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	pkr.PublicKey = pubKey
	pkr.Alg = alg.String()
	pkr.Issuer = issuer
	return pkr, nil
}

// DefaultPubkeyFinder constructs a PublicKeyFinder that does no cacheing,
// simply looking up the JWKS from the provider on every call.
func DefaultPubkeyFinder() *PublicKeyFinder {
	return &PublicKeyFinder{
		JwksFunc: func(ctx context.Context, issuer string) ([]byte, error) {
			return GetJwksByIssuer(ctx, issuer, nil)
		},
	}
}

// NewPubkeyFinderWithCache constructs a PublicKeyFinder that uses the provided
// cache to obtain previously-resolved keys without necessarily needing to hit
// the provider's JWKS endpoint.  The maxAge parameter is the maximum age of
// a cache entry that will be returned in normal use; if there is no entry
// within this age available, but the provider cannot be reached to retrieve a
// new key set, then a previously cached key up to twice this age may still be
// returned as a fallback.
func NewPubkeyFinderWithCache(f JwksFetchFunc, cache DiscoveryCache, maxAge time.Duration) *PublicKeyFinder {
	return &PublicKeyFinder{
		JwksFunc: f,
		CacheConfig: DiscoveryCacheConfig{
			Cache:          cache,
			StandardMaxAge: maxAge,
			FallbackMaxAge: maxAge * 2,
		},
	}
}

type JwksFetchFunc func(ctx context.Context, issuer string) ([]byte, error)

type PublicKeyFinder struct {
	util.OutOrErrWriter
	JwksFunc    JwksFetchFunc
	CacheConfig DiscoveryCacheConfig
}

// GetJwksByIssuer fetches the JWKS from the issuer's JWKS endpoint found at the
// issuer's well-known configuration. It doesn't attempt to parse the response
// but instead returns the JSON bytes of the JWKS. If httpClient is nil, then
// http.DefaultClient is used when fetching.
func GetJwksByIssuer(ctx context.Context, issuer string, httpClient *http.Client) ([]byte, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	discConf, err := oidcclient.Discover(ctx, issuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, "GET", discConf.JwksURI, nil)
	if err != nil {
		return nil, err
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from JWKS URI: %s", http.StatusText(response.StatusCode))
	}
	return io.ReadAll(response.Body)
}

// parseJwks parses a JWKS document. Parsing is lenient in the RFC 7517 section 5
// sense: an entry that cannot be decoded (for example because it declares an alg
// this build does not understand) is retained in the set as a jwk.UnsupportedKey
// placeholder instead of failing the entire set, so the keys we do understand
// stay usable. Strict parsing drops the whole JWKS on the floor over a single
// unknown entry.
func parseJwks(b []byte) (jwk.Set, error) {
	return jwk.Parse(b, jwk.WithStrictKeySetParsing(false))
}

// readCache returns the cached JWKS for issuer if there is a usable entry no
// older than maxAge. A cache miss, a read error, or an unparseable entry all
// yield nil — the caller is expected to fall back to a fresh fetch.
func (f *PublicKeyFinder) readCache(ctx context.Context, issuer string, maxAge time.Duration) jwk.Set {
	if f.CacheConfig.Cache == nil {
		return nil
	}
	b, err := f.CacheConfig.Cache.Read(ctx, issuer, maxAge)
	if err != nil {
		return nil
	}
	jwks, err := parseJwks(b)
	if err != nil {
		_, _ = fmt.Fprintf(f.ErrWriter(), "Failed to unmarshal cached JWKS for %s: %v\n", issuer, err)
		return nil
	}
	return jwks
}

// fetchFresh retrieves the JWKS from the provider and, on success, caches it.
func (f *PublicKeyFinder) fetchFresh(ctx context.Context, issuer string) (jwk.Set, error) {
	jwksJson, err := f.JwksFunc(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch fresh JWKS: %w", err)
	}
	jwks, err := parseJwks(jwksJson)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal fresh JWKS: %w", err)
	}
	if f.CacheConfig.Cache != nil {
		if err := f.CacheConfig.Cache.Write(issuer, jwksJson); err != nil {
			_, _ = fmt.Fprintf(f.ErrWriter(), "Failed to write JWKS cache for %s: %v\n", issuer, err)
		}
	}
	return jwks, nil
}

func (f *PublicKeyFinder) fetchAndParseJwks(ctx context.Context, issuer string, mayUseCache bool) (jwk.Set, bool, error) {
	if mayUseCache {
		if jwks := f.readCache(ctx, issuer, f.CacheConfig.StandardMaxAge); jwks != nil {
			return jwks, true, nil
		}
	}

	jwks, err := f.fetchFresh(ctx, issuer)
	if err == nil {
		return jwks, false, nil
	}

	// Provider unreachable or serving garbage: fall back to a cached entry that
	// is too old for normal use but still within FallbackMaxAge, unless the
	// caller explicitly asked to bypass the cache.
	if mayUseCache {
		if fallbackJwks := f.readCache(ctx, issuer, f.CacheConfig.FallbackMaxAge); fallbackJwks != nil {
			_, _ = fmt.Fprintf(f.ErrWriter(), "Using fallback JWKS from cache for %s: %v\n", issuer, err)
			return fallbackJwks, true, nil
		}
	}
	return nil, false, err
}

// ByToken looks up an OP public key in the JWKS using the KeyID (kid) in the
// protected header from the supplied token.
func (f *PublicKeyFinder) ByToken(ctx context.Context, issuer string, token []byte, mayUseCache bool) (*PublicKeyRecord, error) {
	jwt, err := jws.Parse(token)
	emptyPkr := &PublicKeyRecord{WasCached: false}
	if err != nil {
		return emptyPkr, fmt.Errorf("error parsing JWK in JWKS: %w", err)
	}
	// a JWT is guaranteed to have exactly one signature
	headers := jwt.Signatures()[0].ProtectedHeaders()

	headersAlg, ok := headers.Algorithm()
	if !ok {
		return emptyPkr, fmt.Errorf("error getting algorithm from JWT headers")
	}
	keyID, _ := headers.KeyID()
	if headersAlg.String() == jose.GQ256 {
		origHeadersJson, err := util.Base64DecodeForJWT([]byte(keyID))
		if err != nil {
			return emptyPkr, fmt.Errorf("error base64 decoding GQ kid: %w", err)
		}

		// If GQ then replace the GQ headers with the original headers
		err = json.Unmarshal(origHeadersJson, &headers)
		if err != nil {
			return emptyPkr, fmt.Errorf("error unmarshalling GQ kid to original headers: %w", err)
		}
		// Extract the kid from the original headers after unmarshaling
		keyID, _ = headers.KeyID()
		headersAlg, _ = headers.Algorithm()
	}
	// Use the KeyID (kid) in the headers from the supplied token to look up the public key
	return f.byKeyIDForAlg(ctx, issuer, keyID, headersAlg.String(), mayUseCache)
}

// ByKeyID looks up an OP public key in the JWKS using the KeyID (kid) supplied.
// If no KeyID (kid) exists in the header and there is only one key in the JWKS,
// that key is returned. This  is useful for cases where an OP may not set a KeyID
// (kid) in the JWT header.
//
// The JWT RFC states that it is acceptable to not use a KeyID (kid) if there is
// only one key in the JWKS:
// "The "kid" (key ID) parameter is used to match a specific key.  This is used,
// for instance, to choose among a set of keys within a JWK Set
// during key rollover.  The structure of the "kid" value is
// unspecified.  When "kid" values are used within a JWK Set, different
// keys within the JWK Set SHOULD use distinct "kid" values.  (One
// example in which different keys might use the same "kid" value is if
// they have different "kty" (key type) values but are considered to be
// equivalent alternatives by the application using them.)  The "kid"
// value is a case-sensitive string.  Use of this member is OPTIONAL.
// When used with JWS or JWE, the "kid" value is used to match a JWS or
// JWE "kid" Header Parameter value." - RFC 7517
// https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
//
// Entries that cannot be used (for example ones jwx could not decode) are
// skipped with a warning on ErrWriter, as RFC 7517 section 5 recommends, so
// they never hide a usable key that shares their kid. When the kid is absent,
// only usable keys count towards the single-key rule.
func (f *PublicKeyFinder) ByKeyID(ctx context.Context, issuer string, keyID string, mayUseCache bool) (*PublicKeyRecord, error) {
	return f.byKeyIDForAlg(ctx, issuer, keyID, "", mayUseCache)
}

// byKeyIDForAlg is ByKeyID, preferring a key that fits tokenAlg when several
// keys share the kid. An empty tokenAlg expresses no preference.
func (f *PublicKeyFinder) byKeyIDForAlg(ctx context.Context, issuer string, keyID string, tokenAlg string, mayUseCache bool) (*PublicKeyRecord, error) {
	jwks, wasCached, err := f.fetchAndParseJwks(ctx, issuer, mayUseCache)
	emptyPkr := &PublicKeyRecord{WasCached: wasCached}
	if err != nil {
		return emptyPkr, fmt.Errorf(`failed to fetch JWK set: %w`, err)
	}

	candidates := keysWithKeyID(jwks, keyID)
	if len(candidates) == 0 && keyID == "" {
		candidates = f.soleKey(jwks, issuer)
	}
	if len(candidates) == 0 {
		return emptyPkr, fmt.Errorf("no matching public key found for kid %s", keyID)
	}
	if len(candidates) > 1 {
		_, _ = fmt.Fprintf(f.ErrWriter(), "Warning: JWK set for %s has %d keys with kid %q\n", issuer, len(candidates), keyID)
	}
	return f.bestKeyForAlg(candidates, issuer, keyID, tokenAlg, wasCached)
}

// bestKeyForAlg returns the first usable candidate whose alg equals tokenAlg,
// else the first whose key type can verify tokenAlg, else the first usable
// one. Unusable candidates are skipped with a warning when others remain.
func (f *PublicKeyFinder) bestKeyForAlg(candidates []jwk.Key, issuer string, keyID string, tokenAlg string, wasCached bool) (*PublicKeyRecord, error) {
	var best *PublicKeyRecord
	bestScore := -1
	var errs []error
	for _, key := range candidates {
		pkr, err := publicKeyRecordFromJWK(key, issuer, wasCached)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if score := algFitScore(pkr, tokenAlg); score > bestScore {
			best, bestScore = pkr, score
		}
	}
	if best == nil {
		return &PublicKeyRecord{WasCached: wasCached}, errors.Join(errs...)
	}
	for _, err := range errs {
		_, _ = fmt.Fprintf(f.ErrWriter(), "Warning: skipping unusable key with kid %q in JWK set for %s: %v\n", keyID, issuer, err)
	}
	return best, nil
}

// soleKey returns the JWK set's only usable key, or else its only key, for
// tokens without a kid. It returns nil when the set has several candidates.
func (f *PublicKeyFinder) soleKey(jwks jwk.Set, issuer string) []jwk.Key {
	keys := allKeys(jwks)
	if usable := usableKeys(keys); len(usable) == 1 {
		if skipped := len(keys) - 1; skipped > 0 {
			_, _ = fmt.Fprintf(f.ErrWriter(), "Warning: token has no kid; skipping %d unusable keys in JWK set for %s\n", skipped, issuer)
		}
		return usable
	}
	if len(keys) == 1 {
		return keys
	}
	return nil
}

func algFitScore(pkr *PublicKeyRecord, tokenAlg string) int {
	switch {
	case tokenAlg == "":
		return 0
	case pkr.Alg == tokenAlg:
		return 2
	case keyTypeFitsAlg(pkr.PublicKey, tokenAlg):
		return 1
	default:
		return 0
	}
}

func keyTypeFitsAlg(pubKey crypto.PublicKey, alg string) bool {
	switch pubKey.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		return strings.HasPrefix(alg, "ES")
	case ed25519.PublicKey:
		return alg == jwa.EdDSA().String() || alg == jwa.EdDSAEd25519().String()
	default:
		return false
	}
}

func keysWithKeyID(jwks jwk.Set, keyID string) []jwk.Key {
	var keys []jwk.Key
	for _, key := range allKeys(jwks) {
		if kid, ok := key.KeyID(); ok && kid == keyID {
			keys = append(keys, key)
		}
	}
	return keys
}

func usableKeys(keys []jwk.Key) []jwk.Key {
	var usable []jwk.Key
	for _, key := range keys {
		if !jwk.IsUnsupportedKey(key) {
			usable = append(usable, key)
		}
	}
	return usable
}

func allKeys(jwks jwk.Set) []jwk.Key {
	keys := make([]jwk.Key, 0, jwks.Len())
	for i := range jwks.Len() {
		if key, ok := jwks.Key(i); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func (f *PublicKeyFinder) ByJKT(ctx context.Context, issuer string, jkt string, mayUseCache bool) (*PublicKeyRecord, error) {
	jwks, wasCached, err := f.fetchAndParseJwks(ctx, issuer, mayUseCache)
	emptyPkr := &PublicKeyRecord{WasCached: wasCached}
	if err != nil {
		return emptyPkr, err
	}

	for i := range jwks.Len() {
		key, ok := jwks.Key(i)
		if !ok {
			continue
		}
		if jwk.IsUnsupportedKey(key) {
			// Lenient JWKS parsing (see parseJwks) retains entries that could
			// not be decoded as placeholders. A placeholder cannot be
			// thumbprinted, but it must not abort the search for the keys we
			// can use.
			continue
		}
		jktOfKey, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return emptyPkr, fmt.Errorf("error computing Thumbprint of key in JWKS: %w", err)
		}
		jktOfKeyB64 := util.Base64EncodeForJWT(jktOfKey)
		if jkt == string(jktOfKeyB64) {
			pk, err := publicKeyRecordFromJWK(key, issuer, wasCached)
			return pk, err
		}
	}

	return emptyPkr, fmt.Errorf("no matching public key found for jkt %s", jkt)
}
