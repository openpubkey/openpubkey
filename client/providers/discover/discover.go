package discover

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"

	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

type PublicKeyRecord struct {
	PublicKey crypto.PublicKey
	Alg       string
	Issuer    string
}

func NewPublicKeyRecord(key jwk.Key, issuer string) (*PublicKeyRecord, error) {
	var pubKey interface{}
	if key.Algorithm() == jwa.RS256 {
		pubKey = new(rsa.PublicKey)
	}
	if key.Algorithm() == jwa.ES256 {
		pubKey = new(ecdsa.PublicKey)
	}
	err := key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return &PublicKeyRecord{
		PublicKey: pubKey,
		Alg:       key.Algorithm().String(),
		Issuer:    issuer,
	}, nil
}

func DefaultPubkeyFinder() *PublicKeyFinder {
	return &PublicKeyFinder{
		JwksFunc: GetJwksByIssuer,
	}
}

type JwksFetchFunc func(ctx context.Context, issuer string) ([]byte, error)

type PublicKeyFinder struct {
	JwksFunc JwksFetchFunc
}

// GetJwksByIssuer fetches the JWKS from the issuer's JWKS endpoint found at the issuer's well-known
// configuration. It doesn't attempt to parse the response but instead returns the JSON bytes of
// the JWKS.
func GetJwksByIssuer(ctx context.Context, issuer string) ([]byte, error) {
	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, "GET", discConf.JwksURI, nil)
	if err != nil {
		return nil, err
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	resp, err := http.DefaultClient.Get(discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received non-200 from JWKS URI: %s", http.StatusText(response.StatusCode))
	}
	return io.ReadAll(resp.Body)
}

func (f *PublicKeyFinder) fetchAndParseJwks(ctx context.Context, issuer string) (jwk.Set, error) {
	jwksJson, err := f.JwksFunc(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf(`failed to fetch JWKS: %w`, err)
	}
	jwks := jwk.NewSet()
	if err := json.Unmarshal(jwksJson, jwks); err != nil {
		return nil, fmt.Errorf(`failed to unmarshal JWKS: %w`, err)
	}
	return jwks, nil
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
func (f *PublicKeyFinder) ByKeyID(ctx context.Context, issuer string, keyID string) (*PublicKeyRecord, error) {
	jwks, err := f.fetchAndParseJwks(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf(`failed to fetch JWK set: %w`, err)
	}

	// If keyID is blank and there is only one key in the JWKS, return that key
	key, ok := jwks.LookupKeyID(keyID)
	if ok {
		return NewPublicKeyRecord(key, issuer)
	}

	return nil, fmt.Errorf("no matching public key found for kid %s", keyID)
}

// ByToken looks up an OP public key in the JWKS using the KeyID (kid) in the
// protected header from the supplied token.
func (f *PublicKeyFinder) ByToken(ctx context.Context, issuer string, token []byte) (*PublicKeyRecord, error) {
	jwt, err := jws.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("error parsing JWK in JWKS: %w", err)
	}
	// a JWT is guaranteed to have exactly one signature
	headers := jwt.Signatures()[0].ProtectedHeaders()

	if headers.Algorithm() == gq.GQ256 {
		origHeadersJson, err := util.Base64DecodeForJWT([]byte(headers.KeyID()))
		if err != nil {
			return nil, fmt.Errorf("error base64 decoding GQ kid: %w", err)
		}

		// If GQ then replace the GQ headers with the original headers
		err = json.Unmarshal(origHeadersJson, &headers)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling GQ kid to original headers: %w", err)
		}
	}
	// Use the KeyID (kid) in the headers from the supplied token to look up the public key
	return f.ByKeyID(ctx, issuer, headers.KeyID())
}

func (f *PublicKeyFinder) ByJTK(ctx context.Context, issuer string, jtk string) (*PublicKeyRecord, error) {
	jwks, err := f.fetchAndParseJwks(ctx, issuer)
	if err != nil {
		return nil, err
	}

	it := jwks.Keys(ctx)
	for it.Next(ctx) {
		key := it.Pair().Value.(jwk.Key)
		jktOfKey, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("error computing Thumbprint of key in JWKS: %w", err)
		}
		jtkOfKeyB64 := util.Base64EncodeForJWT(jktOfKey)
		if jtk == string(jtkOfKeyB64) {
			return NewPublicKeyRecord(key, issuer)
		}
	}

	return nil, fmt.Errorf("no matching public key found for jtk %s", jtk)
}
