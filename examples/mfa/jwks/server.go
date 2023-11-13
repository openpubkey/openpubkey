package jwks

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type Server struct {
	uri       string
	jwksBytes []byte
}

func NewServer(signer crypto.Signer, alg jwa.SignatureAlgorithm, kid string) (*Server, error) {
	// Generate our JWKS using our signing key
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyIDKey, kid)

	// Put our jwk into a set
	keySet := jwk.NewSet()
	keySet.AddKey(jwkKey)

	// Now convert our key set into the raw bytes for printing later
	keySetBytes, _ := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return nil, err
	}

	// Find an empty port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}

	server := &Server{
		uri:       fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port),
		jwksBytes: keySetBytes,
	}

	// Host our JWKS at a localhost url
	http.HandleFunc("/.well-known/jwks.json", server.printJWKS)
	go func() {
		http.Serve(listener, nil)
	}()

	return server, nil
}

func (s *Server) URI() string {
	return s.uri
}

func (s *Server) printJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.jwksBytes)
}
