package mfacosigner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/examples/mfa/mfacosigner/jwks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Server struct {
	uri      string
	doneChan chan error
	cosigner *MfaCosigner
}

func New(serverUri, rpID, rpOrigin, RPDisplayName string) (*Server, error) {
	server := &Server{
		doneChan: make(chan error),
	}
	server.uri = serverUri

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: RPDisplayName,
		RPID:          rpID,
		RPOrigin:      rpOrigin,
	}

	cosigner, err := initCosigner(cfg)
	if err != nil {
		fmt.Println("failed to initialize cosigner: ", err)
		return nil, err
	}
	server.cosigner = cosigner

	http.Handle("/", http.FileServer(http.Dir("mfacosigner/static")))

	http.HandleFunc("/mfa-auth-init", server.initAuth)

	http.HandleFunc("/check-registration", server.checkIfRegistered)

	http.HandleFunc("/register/begin", server.beginRegistration)
	http.HandleFunc("/register/finish", server.finishRegistration)

	http.HandleFunc("/login/begin", server.beginLogin)
	http.HandleFunc("/login/finish", server.finishLogin)

	http.HandleFunc("/sign", server.signPkt)

	http.HandleFunc("/done", server.done)

	err = http.ListenAndServe(":3003", nil)
	return nil, err
}

func (s *Server) URI() string {
	return s.uri
}

func (s *Server) initAuth(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		return
	}
	pktB64 := []byte(r.URL.Query().Get("pkt"))
	pktJson, err := util.Base64DecodeForJWT(pktB64)
	if err != nil {
		return
	}
	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		return
	}
	sig := []byte(r.URL.Query().Get("sig1"))

	authID, err := s.cosigner.InitAuth(pkt, sig)
	if err != nil {
		http.Error(w, "Error initiating authentication", http.StatusInternalServerError)
		return
	}
	mfapage := fmt.Sprintf("/?authid=%s", authID)

	http.Redirect(w, r, mfapage, http.StatusFound)
}

func (s *Server) done(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		// Read the body of the request
		body, err := io.ReadAll(r.Body)
		defer r.Body.Close()
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}

		// Convert the body to a string
		bodyStr := string(body)

		// Create an error from the body string
		requestError := errors.New(bodyStr)

		s.doneChan <- requestError
	} else {
		s.doneChan <- nil
	}
}

func (s *Server) checkIfRegistered(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}
	registered := s.cosigner.CheckIsRegistered(authID)

	response, _ := json.Marshal(map[string]bool{
		"isRegistered": registered,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func GetAuthID(r *http.Request) (string, error) {
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	return string([]byte(r.URL.Query().Get("authid"))), nil
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	options, err := s.cosigner.BeginRegistration(authID)

	optionsJson, err := json.Marshal(options)
	if err != nil {
		fmt.Printf("Failed to marshal options: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
}

func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponse(r)
	if err != nil {
		http.Error(w, "Error in parsing credential", http.StatusInternalServerError)
		return
	}

	err = s.cosigner.FinishRegistration(authID, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(201)
	w.Write([]byte("MFA registration Successful! You may now close this window"))
	fmt.Println("MFA registration complete")
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}
	options, err := s.cosigner.BeginLogin(authID)
	if err != nil {
		fmt.Println("Failed to begin webauthn login:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	optionsJson, err := json.Marshal(options)
	if err != nil {
		fmt.Println("Failed to marshal options:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) {
	authID, err := GetAuthID(r)
	if err != nil {
		http.Error(w, "Error in authID", http.StatusInternalServerError)
		return
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponse(r)
	if err != nil {
		http.Error(w, "Error in parsing credential", http.StatusInternalServerError)
		return
	}

	authcode, ruri, err := s.cosigner.FinishLogin(authID, parsedResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mfaURI := string(ruri) + "?authcode=" + string(authcode)

	response, _ := json.Marshal(map[string]string{
		"redirect_uri": mfaURI,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func (s *Server) signPkt(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("error parsing authcode and sig:", err)
		return
	}

	authcode := []byte(r.URL.Query().Get("authcode"))
	sig := []byte(r.URL.Query().Get("sig2"))

	if pkt, err := s.cosigner.RedeemAuthcode(authcode, sig); err != nil {
		fmt.Println("Signature Grant Failed:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else {
		pktJson, err := json.Marshal(pkt)
		if err != nil {
			fmt.Println("error unmarshal:", err)
			return
		}

		pktB64 := util.Base64EncodeForJWT(pktJson)
		response, _ := json.Marshal(map[string]string{
			"pkt": string(pktB64),
		})

		w.WriteHeader(201)
		w.Write(response)
	}
}

func initCosigner(cfg *webauthn.Config) (*MfaCosigner, error) {
	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return nil, err
	}

	kid := "test-kid"
	server, err := jwks.NewServer(signer, alg, kid)
	if err != nil {
		return nil, err
	}

	fmt.Println("JWKS hosted at", server.URI()+"/.well-known/jwks.json")
	return NewCosigner(signer, alg, server.URI(), kid, cfg)
}
