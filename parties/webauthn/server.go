package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Server struct {
	user    User
	mfa     *webauthn.WebAuthn
	session *webauthn.SessionData
}

type User interface {
	webauthn.User
	AddCredential(cred webauthn.Credential)
}

func NewServer() (*Server, error) {
	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: "OPK Webauthn",          // Display Name for your site
		RPID:          "localhost",             // Generally the FQDN for your site
		RPOrigin:      "http://localhost:8080", // The origin URLs allowed for WebAuthn requests
	}

	webAuthn, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}

	return &Server{
		mfa: webAuthn,
	}, nil
}

func (s *Server) RegisterOrLogin(user User) error {
	s.user = user

	http.HandleFunc("/login/begin", s.beginLogin)
	http.HandleFunc("/login/finish", s.finishLogin)
	http.HandleFunc("/register/begin", s.beginRegistration)
	http.HandleFunc("/register/finish", s.finishRegistration)
	http.Handle("/", http.FileServer(http.Dir("../../parties/webauthn/static")))

	fmt.Println("Please open http://localhost:8080")

	// Start the HTTP server
	return http.ListenAndServe(":8080", nil)
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	options, session, err := s.mfa.BeginRegistration(s.user)
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
	credential, err := s.mfa.FinishRegistration(s.user, *s.session, r)
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
	options, session, err := s.mfa.BeginLogin(s.user)
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
	credential, err := s.mfa.FinishLogin(s.user, *s.session, r)
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
