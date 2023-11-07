package webauthn

import (
	"crypto"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type WebAuthnCosigner struct {
	csid   string
	signer crypto.Signer
	jwkKey jwk.Key

	ACL []string
}

func New() (*WebAuthnCosigner, error) {
	// Generate our key pair
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	// Use that key pair to generate our jwk
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)
	jwkKey.Set(jwk.KeyIDKey, "my-key-id")

	// Find an empty port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}

	cosigner := &WebAuthnCosigner{
		signer: signer,
		jwkKey: jwkKey,
		csid:   listener.Addr().String(),
	}

	// Host our JWKS at a localhost url
	http.HandleFunc("/.well-known/jwks.json", cosigner.jwksHandler)
	go func() {
		http.Serve(listener, nil)
	}()

	fmt.Printf("check out %s/.well-known/jwks.json\n", listener.Addr().String())

	return cosigner, nil
}

func (c *WebAuthnCosigner) Cosign(pkt *pktoken.PKToken) ([]byte, error) {
	// extract our user information from the id token
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, err
	}

	// Now we'll register our user
	server, err := NewServer()
	if err != nil {
		return nil, err
	}

	err = server.RegisterOrLogin(&webAuthnUser{
		id:          []byte(claims.Subject),
		username:    "lucie",
		displayName: "lucie",
	})
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func (c *WebAuthnCosigner) jwksHandler(w http.ResponseWriter, r *http.Request) {
	keySet := jwk.NewSet()
	keySet.AddKey(c.jwkKey)

	data, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		http.Error(w, "Failed to marshal JWKS", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
