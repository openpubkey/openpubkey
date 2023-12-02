package webauthn

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"encoding/hex"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/cosigner/mfa"
	"github.com/openpubkey/openpubkey/examples/mfa/jwks"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type Server struct {
	uri         string
	doneChan    chan error
	user        User
	users       map[string]User
	auth        *webauthn.WebAuthn
	session     *webauthn.SessionData
	authCodeMap map[string]*pktoken.PKToken
	cosigner    *MfaCosigner
}

type User interface {
	webauthn.User
	AddCredential(cred webauthn.Credential)
}

type InitMFAAuth struct {
	RedirectUri string `json:"ruri"`
	TimeSigned  int64  `json:"time"`
}

var _ mfa.Authenticator = (*Server)(nil)

func New() (*Server, error) {
	server := &Server{
		doneChan: make(chan error),
	}

	cosigner, err := initCosigner()
	if err != nil {
		fmt.Println("failed to initialize cosigner: ", err)
		return nil, err
	}

	server.cosigner = cosigner

	// listener, err := net.Listen("tcp", ":0")
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	// }
	// server.uri = fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)
	server.uri = fmt.Sprintf("http://localhost:3003")

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: "OpenPubkey",
		RPID:          "localhost",
		RPOrigin:      server.uri,
	}

	wauth, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}
	server.auth = wauth

	server.users = make(map[string]User)
	server.authCodeMap = make(map[string]*pktoken.PKToken)

	http.Handle("/", http.FileServer(http.Dir("../mfa/webauthn/static")))

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
	var claims struct {
		Issuer   string   `json:"iss"`
		Audience []string `json:"aud"`
		Subject  string   `json:"sub"`
		Email    string   `json:"email"`
	}
	err = json.Unmarshal(pkt.Payload, &claims)
	if err != nil {
		http.Error(w, "Error deserializing PK Token payload", http.StatusInternalServerError) // TODO: Decide what these errors should be
		return
	}

	sig := []byte(r.URL.Query().Get("sig"))

	authID, err := s.cosigner.InitAuth(pkt, sig)

	if err != nil {
		http.Error(w, "Error initiating authentication", http.StatusInternalServerError)
		return
	}

	userKey := UserKey{Issuer: claims.Issuer, Aud: strings.Join(claims.Audience, ","), Sub: claims.Subject}
	if s.cosigner.IsRegistered(userKey) {
		regURI := fmt.Sprintf("/register/%s", authID)

		response, _ := json.Marshal(map[string]string{
			"redirect_uri": regURI,
		})

		w.WriteHeader(201)
		w.Write(response)
	} else {
		loginUri := fmt.Sprintf("/login/%s", authID)

		response, _ := json.Marshal(map[string]string{
			"redirect_uri": loginUri,
		})

		w.WriteHeader(201)
		w.Write(response)
	}
}

// TODO: This function trusts that the requesting party is allowed to request MFA
// authentication. According to the paper, this should be doing the POP Auth flow
// to verify that the requesting party has the corresponding signing key. Details
// in https://github.com/openpubkey/openpubkey/issues/58
// func (s *Server) Authenticate(pkt *pktoken.PKToken) error {
// 	// extract our user information from the id token
// 	var claims struct {
// 		Subject string `json:"sub"`
// 		Email   string `json:"email"`
// 	}
// 	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
// 		return err
// 	}

// 	s.user = &user{
// 		id:          []byte(claims.Subject),
// 		username:    claims.Email,
// 		displayName: strings.Split(claims.Email, "@")[0],
// 	}

// 	util.OpenUrl(s.uri)
// 	return <-s.doneChan
// }

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
	email, _, pkt, err := ClaimsFromPktInURL(r)
	if err != nil {
		http.Error(w, "Error reading pkt in URI", http.StatusInternalServerError)
		return
	}

	err = r.ParseForm()
	if err != nil {
		http.Error(w, "Error reading sig in URI", http.StatusInternalServerError)
		return
	}

	sigB64 := []byte(r.URL.Query().Get("sig"))
	sig, err := util.Base64DecodeForJWT(sigB64)
	if err != nil {
		http.Error(w, "Error reading sig in URI", http.StatusInternalServerError)
		return
	}

	//TODO: deserialize
	fmt.Printf("%s \n", sig)

	_, err = pkt.VerifySignedMessage(sig)
	if err != nil {
		fmt.Println("error verifying sig:", err)
		return
	}

	var initMFAAuth struct {
		redirectUri string `json:"ruri"`
		currentTime int64  `json:"time"`
	}

	if err := json.Unmarshal(pkt.Payload, &initMFAAuth); err != nil {
		fmt.Println("error unmarshaling osmMsg:", err)
		return
	}

	// TODO: Save redirect URI
	// TODO: check time is expired

	_, ok := s.users[string(email)]
	registered := ok

	response, _ := json.Marshal(map[string]bool{
		"isRegistered": registered,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func ClaimsFromPktInURL(r *http.Request) (string, string, *pktoken.PKToken, error) {
	err := r.ParseForm()
	if err != nil {
		return "", "", nil, err
	}

	pktB64 := []byte(r.URL.Query().Get("pkt"))
	pktJson, err := util.Base64DecodeForJWT(pktB64)
	if err != nil {
		return "", "", nil, err
	}

	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		return "", "", nil, err
	}

	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return "", "", nil, err
	}

	return claims.Email, claims.Subject, pkt, nil
}

func (s *Server) beginRegistration(w http.ResponseWriter, r *http.Request) {
	email, subject, _, err := ClaimsFromPktInURL(r)

	if err != nil {
		fmt.Printf("Error attempting to unmarshal pkt: %v", err)
		http.Error(w, "Error attempting to unmarshal pkt:", http.StatusBadRequest)
		return
	}
	cred := &user{
		id:          []byte(subject),
		username:    email,
		displayName: strings.Split(email, "@")[0],
	}

	options, session, err := s.auth.BeginRegistration(cred)
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
	email, subject, _, err := ClaimsFromPktInURL(r)

	cred := &user{
		id:          []byte(subject),
		username:    email,
		displayName: strings.Split(email, "@")[0],
	}

	credential, err := s.auth.FinishRegistration(cred, *s.session, r)
	if err != nil {
		fmt.Println("Failed to finish registration:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cred.AddCredential(*credential)

	// TODO: Check if user already has a cred and reject so that an attacker can't just overwrite an existing cred
	s.users[email] = cred

	w.WriteHeader(201)
	w.Write([]byte("MFA registration Successful! You may now close this window"))
	fmt.Println("MFA registration complete")
}

func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request) {
	email, _, _, err := ClaimsFromPktInURL(r)

	options, session, err := s.auth.BeginLogin(s.users[email])
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
	email, _, pkt, err := ClaimsFromPktInURL(r)

	credential, err := s.auth.FinishLogin(s.users[email], *s.session, r)
	if err != nil {
		fmt.Println("Failed to finish login:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.users[email].AddCredential(*credential)
	// w.Write([]byte("MFA login successful!"))

	authCode, err := s.GenAuthCode(pkt)
	if err != nil {
		fmt.Println("Failed to generate authcode:", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	mfaURI := fmt.Sprintf("http://localhost:3000/mfacallback?authcode=%s", authCode)

	response, _ := json.Marshal(map[string]string{
		"redirect_uri": mfaURI,
	})

	w.WriteHeader(201)
	w.Write(response)
}

func (s *Server) signPkt(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		fmt.Println("error parsing authcode:", err)
		return
	}

	authcode := []byte(r.URL.Query().Get("authcode"))
	sig := []byte(r.URL.Query().Get("sig"))

	if pkt, err := s.cosigner.CheckAuthcode(authcode, sig); err != nil {
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

	// if pkt, ok := s.authCodeMap[string(authcode)]; ok {

	// 	msg, err := pkt.VerifySignedMessage(sig)
	// 	if err != nil {
	// 		fmt.Println("error verifying sig:", err)
	// 		return
	// 	}
	// 	if !bytes.Equal(msg, authcode) {
	// 		fmt.Println("error message doesn't make authcode:", err)
	// 		return
	// 	}

	// 	if err := s.cosigner.Cosign(pkt); err != nil {
	// 		fmt.Println("error cosigning:", err)
	// 		return
	// 	}
	// }

}

func (s *Server) GenAuthCode(pkt *pktoken.PKToken) (string, error) {

	authCodeBytes := make([]byte, 32)

	if _, err := rand.Read(authCodeBytes); err != nil {
		return "", err
	}

	authCode := hex.EncodeToString(authCodeBytes)
	s.authCodeMap[authCode] = pkt
	return authCode, nil
}

func initCosigner() (*MfaCosigner, error) {
	// authenticator, err := webauthn.New()
	// if err != nil {
	// 	return nil, err
	// }

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

	return NewCosigner(signer, alg, server.URI(), kid, "http://localhost")
}
