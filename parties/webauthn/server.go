package webauthn

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/webauthn"
)

type Server struct {
	user    webauthn.User
	mfa     *webauthn.WebAuthn
	session *webauthn.SessionData
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

func (s *Server) Start() error {
	// Register a new user account
	http.HandleFunc("/mfa/register-begin", s.beginRegistration)
	http.HandleFunc("/mfa/register-finish", s.finishRegistration)

	http.HandleFunc("/mfa/login-begin", s.beginLogin)
	http.HandleFunc("/mfa/login-finish", s.finishLogin)
	return http.ListenAndServe(":8181", nil)
}

func (s *Server) Register(user webauthn.User) error {
	s.user = user
	// s.server = &http.Server{Addr: ":8080"}

	http.HandleFunc("/beginRegistration", s.beginRegistration)
	http.HandleFunc("/finishRegistration", s.finishRegistration)
	http.Handle("/", http.FileServer(http.Dir("../../parties/webauthn/static")))

	fmt.Println("Please open http://localhost:8080")

	// Start the HTTP server
	return http.ListenAndServe(":8080", nil)
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	options, session, err := s.mfa.BeginRegistration(s.user)
	if err != nil {
		fmt.Println("Failed to being webauthn registration:", err.Error())
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

	fmt.Printf("%s", string(optionsJson))

	w.Header().Set("Content-Type", "application/json")
	w.Write(optionsJson)
	fmt.Println("Beginregistration complete")
}

func (s *Server) finishRegistration(w http.ResponseWriter, r *http.Request) {
	fmt.Println("starting finishRegistration")

	// // Read the body of the request
	// body, err := io.ReadAll(r.Body)
	// if err != nil {
	// 	// If there is an error reading the body, write an HTTP error response
	// 	http.Error(w, "Error reading request body", http.StatusInternalServerError)
	// 	return
	// }
	// defer r.Body.Close()

	// // Convert the body to a string and print it
	// bodyString := string(body)
	// fmt.Println("Request Body:", bodyString)

	// var ccr protocol.CredentialCreationResponse

	// if err := json.NewDecoder(r.Body).Decode(&ccr); err != nil {
	// 	fmt.Println("WE FUKCED UP HERE:", err)
	// }

	// _, err := ccr.Parse()
	// fmt.Println("ccr ERROR", err)

	credential, err := s.mfa.FinishRegistration(s.user, *s.session, r)
	if err != nil {
		fmt.Printf("Failed to finish registration: %+v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If creation was successful, store the credential object
	// Pseudocode to add the user credential.
	// s.user.AddCredential(credential)
	// datastore.SaveUser(user)
	fmt.Printf("%+v", credential)

	w.WriteHeader(201)
	w.Write([]byte("MFA registration Successful! You may now close this window"))
	fmt.Println("MFA registration compelte")
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request) {}
