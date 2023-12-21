package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"golang.org/x/crypto/sha3"
)

type JwksServer struct {
	uri       string
	jwksBytes []byte
}

// A very simple JWKS server for our MFA Cosigner example code.
func NewJwksServer(signer crypto.Signer, alg jwa.SignatureAlgorithm) (*JwksServer, string, error) {
	// Compute the kid (Key ID) as the SHA-3 of the public key
	pubkey := signer.Public().(*ecdsa.PublicKey) // TODO: handle non-ecdsa signers
	pubkeyBytes := elliptic.Marshal(pubkey, pubkey.X, pubkey.Y)
	pubkeyHash := sha3.Sum256(pubkeyBytes)
	kid := hex.EncodeToString(pubkeyHash[:])

	// Generate our JWKS using our signing key
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, "", err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyIDKey, kid)

	// Put our jwk into a set
	keySet := jwk.NewSet()
	keySet.AddKey(jwkKey)

	// Now convert our key set into the raw bytes for printing later
	keySetBytes, _ := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return nil, "", err
	}

	// Find an empty port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", fmt.Errorf("failed to bind to an available port: %w", err)
	}

	server := &JwksServer{
		uri:       fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port),
		jwksBytes: keySetBytes,
	}

	// Host our JWKS at a localhost url
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", server.printJWKS)
	go func() {
		http.Serve(listener, mux)
	}()
	return server, kid, nil
}

func (s *JwksServer) URI() string {
	return s.uri
}

func (s *JwksServer) printJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.jwksBytes)
}
