package webauthn

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/openpubkey/openpubkey/client/cosigner/mfa"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Server struct {
	uri      string
	doneChan chan error
	user     User
	auth     *webauthn.WebAuthn
	session  *webauthn.SessionData
}

type User interface {
	webauthn.User
	AddCredential(cred webauthn.Credential)
}

var _ mfa.Authenticator = (*Server)(nil)

func New() (*Server, error) {
	server := &Server{
		doneChan: make(chan error),
	}

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}
	server.uri = fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: "OpenPubkey",
		RPID:          "localhost",
		RPOrigin:      server.uri,
	}

	server.auth, err = webauthn.New(cfg)
	if err != nil {
		return nil, err
	}

	http.Handle("/", http.FileServer(http.Dir("webauthn/static")))

	http.HandleFunc("/check-registration", server.checkIfRegistered)

	http.HandleFunc("/register/begin", server.beginRegistration)
	http.HandleFunc("/register/finish", server.finishRegistration)

	http.HandleFunc("/login/begin", server.beginLogin)
	http.HandleFunc("/login/finish", server.finishLogin)

	http.HandleFunc("/done", server.done)

	go func() {
		http.Serve(listener, nil)
	}()

	return server, nil
}

func (s *Server) Authenticate(pkt *pktoken.PKToken) error {
	// extract our user information from the id token
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return err
	}

	s.user = &user{
		id:          []byte(claims.Subject),
		username:    claims.Email,
		displayName: strings.Split(claims.Email, "@")[0],
	}

	util.OpenUrl(s.uri)
	return <-s.doneChan
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
	registered := false
	if len(s.user.WebAuthnCredentials()) > 0 {
		registered = true
	}

	response, _ := json.Marshal(map[string]bool{
		"isRegistered": registered,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	options, session, err := s.auth.BeginRegistration(s.user)
	if err != nil {
		fmt.Println("Failed to begin webauthn registration:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.session = session

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
	credential, err := s.auth.FinishRegistration(s.user, *s.session, r)
	if err != nil {
		fmt.Println("Failed to finish registration:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.user.AddCredential(*credential)

	w.WriteHeader(201)
	w.Write([]byte("MFA registration Successful! You may now close this window"))
	fmt.Println("MFA registration complete")
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {
	options, session, err := s.auth.BeginLogin(s.user)
	if err != nil {
		fmt.Println("Failed to begin webauthn login:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.session = session

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
	credential, err := s.auth.FinishLogin(s.user, *s.session, r)
	if err != nil {
		fmt.Println("Failed to finish login:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.user.AddCredential(*credential)

	w.WriteHeader(201)
	w.Write([]byte("MFA login successful! You may now close this window"))
	fmt.Println("MFA login complete")
}
