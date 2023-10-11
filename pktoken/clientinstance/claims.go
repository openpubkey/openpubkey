package clientinstance

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/signer"
)

// Client Instance Claims, referred also as "cic" in the OpenPubKey paper
type Claims struct {
	// Claims are stored in the protected header portion of JWS signature
	protected map[string]any
}

// Client instance claims must relate to a single key pair
func NewClaims(publicKey jwk.Key, claims map[string]any) (*Claims, error) {
	// Make sure no claims are using our reserved values
	for _, reserved := range []string{"alg", "upk", "rz"} {
		if _, ok := claims[reserved]; ok {
			return nil, fmt.Errorf("use of reserved header name, %s, in additional headers", reserved)
		}
	}

	rand, err := generateRand()
	if err != nil {
		return nil, fmt.Errorf("failed to generate random value: %w", err)
	}

	// Assign required values
	claims["alg"] = publicKey.Algorithm().String()
	claims["upk"] = publicKey
	claims["rz"] = rand

	return &Claims{
		protected: claims,
	}, nil
}

func Parse(raw []byte) (*Claims, error) {
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, err
	}

	return &Claims{
		protected: claims,
	}, nil
}

func (c *Claims) UserPublicKey() (jwk.Key, error) {
	return nil, nil
}

func (c *Claims) AlgorithmKey() (jwa.KeyAlgorithm, error) {
	return nil, nil
}

// Returns a hash of all client instance claims which includes a random value
func (c *Claims) Commitment() (string, error) {
	// LUCIE: Do we need to sort to maintain ordering???
	buf, err := json.Marshal(c.protected)
	if err != nil {
		return "", err
	}

	return sha3_256(buf), nil
}

// This function signs the payload of the provided token with the protected headers
// as defined by the client instance claims and returns a jwt in compact form.
func (c *Claims) Sign(signer *signer.Signer, token []byte) ([]byte, error) {
	_, payload, _, err := jws.SplitCompact(token)
	if err != nil {
		return nil, err
	}

	// We need to make sure we're signing the decoded bytes
	payloadDecoded, err := base64.RawURLEncoding.DecodeString(string(payload))
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
			signer.JWKKey().Algorithm(),
			signer.SigningKey(),
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

func sha3_256(msg []byte) string {
	h := crypto.SHA3_256.New()
	h.Write(msg)
	image := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(image)
}
