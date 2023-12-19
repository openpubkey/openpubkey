package clientinstance

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/util"
)

// Client Instance Claims, referred also as "cic" in the OpenPubKey paper
type Claims struct {
	publicKey jwk.Key

	// Claims are stored in the protected header portion of JWS signature
	protected map[string]any
}

// Client instance claims must relate to a single key pair
func NewClaims(publicKey jwk.Key, claims map[string]any) (*Claims, error) {
	// Make sure our JWK has the algorithm header set
	if publicKey.Algorithm().String() == "" {
		return nil, fmt.Errorf("user JWK requires algorithm to be set")
	}

	// Make sure no claims are using our reserved values
	for _, reserved := range []string{"alg", "upk", "rz", "typ"} {
		if _, ok := claims[reserved]; ok {
			return nil, fmt.Errorf("use of reserved header name, %s, in additional headers", reserved)
		}
	}

	rand, err := generateRand()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %w", err)
	}

	// Assign required values
	claims["typ"] = "CIC"
	claims["alg"] = publicKey.Algorithm().String()
	claims["upk"] = publicKey
	claims["rz"] = rand

	return &Claims{
		publicKey: publicKey,
		protected: claims,
	}, nil
}

func ParseClaims(protected map[string]any) (*Claims, error) {
	// Get our standard headers and make sure they match up
	if _, ok := protected["rz"]; !ok {
		return nil, fmt.Errorf(`missing required "rz" claim`)
	}
	upk, ok := protected["upk"]
	if !ok {
		return nil, fmt.Errorf(`missing required "upk" claim`)
	}
	upkBytes, err := json.Marshal(upk)
	if err != nil {
		return nil, err
	}
	upkjwk, err := jwk.ParseKey(upkBytes)
	if err != nil {
		return nil, err
	}
	alg, ok := protected["alg"]
	if !ok {
		return nil, fmt.Errorf(`missing required "alg" claim`)
	} else if alg != upkjwk.Algorithm() {
		return nil, fmt.Errorf(`provided "alg" value different from algorithm provided in "upk" jwk`)
	}
	return &Claims{
		publicKey: upkjwk,
		protected: protected,
	}, nil
}

func (c *Claims) PublicKey() jwk.Key {
	return c.publicKey
}

func (c *Claims) KeyAlgorithm() jwa.KeyAlgorithm {
	return c.publicKey.Algorithm()
}

// Returns a hash of all client instance claims which includes a random value
func (c *Claims) Hash() ([]byte, error) {
	buf, err := json.Marshal(c.protected)
	if err != nil {
		return nil, err
	}

	return util.B64SHA3_256(buf), nil
}

// This function signs the payload of the provided token with the protected headers
// as defined by the client instance claims and returns a jwt in compact form.
func (c *Claims) Sign(signer crypto.Signer, algorithm jwa.KeyAlgorithm, token []byte) ([]byte, error) {
	_, payload, _, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}

	// We need to make sure we're signing the decoded bytes
	payloadDecoded, err := util.Base64DecodeForJWT(payload)
	if err != nil {
		return nil, err
	}

	headers := jws.NewHeaders()
	for key, val := range c.protected {
		if err := headers.Set(key, val); err != nil {
			return nil, err
		}
	}

	cicToken, err := jws.Sign(
		payloadDecoded,
		jws.WithKey(
			algorithm,
			signer,
			jws.WithProtectedHeaders(headers),
		),
	)
	if err != nil {
		return nil, err
	}

	return cicToken, nil
}

func generateRand() (string, error) {
	bits := 256
	rBytes := make([]byte, bits/8)
	_, err := rand.Read(rBytes)
	if err != nil {
		return "", err
	}

	rz := hex.EncodeToString(rBytes)
	return rz, nil
}
