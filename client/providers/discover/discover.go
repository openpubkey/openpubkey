package discover

import (
	"context"
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/util"

	oidcclient "github.com/zitadel/oidc/v2/pkg/client"
)

func ProviderPublicKey(ctx context.Context, headers jws.Headers, issuer string) (crypto.PublicKey, error) {
	// If GQ then pull the kid from the original headers
	if headers.Algorithm() == gq.GQ256 {
		origHeadersB64 := []byte(headers.KeyID())
		origHeadersJson, err := util.Base64DecodeForJWT(origHeadersB64)
		if err != nil {
			return nil, fmt.Errorf("error base64 decoding GQ kid: %w", err)
		}

		err = json.Unmarshal(origHeadersJson, &headers)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling GQ kid to original headers: %w", err)
		}
	}

	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}

	kid := headers.KeyID()
	key, ok := jwks.LookupKeyID(kid)
	if !ok {
		return nil, fmt.Errorf("key %s isn't in JWKS", kid)
	}

	if key.Algorithm() != jwa.RS256 {
		return nil, fmt.Errorf("expected alg to be RS256 in JWK with kid %q for OP %q, got %q", kid, issuer, key.Algorithm())
	}

	pubKey := new(rsa.PublicKey)
	err = key.Raw(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return pubKey, err
}

type PublicKeyRecord struct {
	PublicKey crypto.PublicKey
	Alg       string
	Issuer    string
	JwkJson   []byte
}

func getJwks(ctx context.Context, issuer string) (jwk.Set, error) {
	discConf, err := oidcclient.Discover(issuer, http.DefaultClient)
	if err != nil {
		return nil, fmt.Errorf("failed to call OIDC discovery endpoint: %w", err)
	}

	jwks, err := jwk.Fetch(ctx, discConf.JwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch to JWKS: %w", err)
	}
	return jwks, nil
}

func publicKeyByKeyId(jwks jwk.Set, keyID string) (*PublicKeyRecord, error) {
	key, ok := jwks.LookupKeyID(keyID)
	if ok {
		record := &PublicKeyRecord{PublicKey: key}
		return record, nil
	}
	return nil, fmt.Errorf("no matching public key found for kid %s", keyID)
}

type PublicKeyFinder struct{}

func PublicKeyByKeyId(ctx context.Context, issuer string, keyID string) (*PublicKeyRecord, error) {
	jwks, err := getJwks(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return publicKeyByKeyId(jwks, keyID)
}

func PublicKeyByToken(ctx context.Context, issuer string, token []byte) (*PublicKeyRecord, error) {
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
	return PublicKeyByKeyId(ctx, issuer, headers.KeyID())
}

func PublicKeyByJTK(ctx context.Context, issuer string, jtk string) (*PublicKeyRecord, error) {
	jwks, err := getJwks(ctx, issuer)
	if err != nil {
		return nil, err
	}

	it := jwks.Keys(ctx)
	for it.Next(ctx) {
		key := it.Pair().Value.(jwk.Key)
		jtkOfKey, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("error computing Thumbprint of key in JWKS: %w", err)
		}
		jtkOfKeyB64 := util.Base64EncodeForJWT(jtkOfKey)
		if jtk == string(jtkOfKeyB64) {
			record := &PublicKeyRecord{PublicKey: key}
			return record, nil
		}
	}

	return nil, fmt.Errorf("no matching public key found: %w", err)
}
