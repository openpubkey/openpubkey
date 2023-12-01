package webauthn

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type AuthState struct {
	Pkt         *pktoken.PKToken
	RedirectUri string
	Session     *webauthn.SessionData
}

type MfaCosigner struct {
	issuer       string
	keyID        string
	alg          jwa.KeyAlgorithm
	signer       crypto.Signer
	authIdIter   atomic.Uint64
	hmacKey      []byte
	auth         *webauthn.WebAuthn
	authIdMap    map[string]*AuthState
	authCodeMap  map[string]string
	subDeviceMap map[string]webauthn.User
}

func NewCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string) (*MfaCosigner, error) {
	hmacKey := make([]byte, 64)

	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	// WebAuthn configuration
	cfg := &webauthn.Config{
		RPDisplayName: "OpenPubkey",
		RPID:          "localhost",
		RPOrigin:      "RP origin",
	}

	wauth, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}

	return &MfaCosigner{
		issuer:       issuer,
		keyID:        keyID,
		alg:          alg,
		signer:       signer,
		authIdIter:   atomic.Uint64{},
		hmacKey:      hmacKey,
		auth:         wauth,
		authIdMap:    make(map[string]*AuthState),
		authCodeMap:  make(map[string]string),
		subDeviceMap: make(map[string]webauthn.User),
	}, nil
}

func (c *MfaCosigner) InitAuth(pkt *pktoken.PKToken, sig []byte) (string, error) {

	msg, err := pkt.VerifySignedMessage(sig)
	if err != nil {
		return "", err
	}

	var initMFAAuth *InitMFAAuth
	if err := json.Unmarshal(msg, &initMFAAuth); err != nil {
		fmt.Printf("error creating init auth message: %s", err)
	}
	authId := c.CreateAuthID(pkt, initMFAAuth.RedirectUri)

	return authId, err
}

func (c *MfaCosigner) CreateAuthID(pkt *pktoken.PKToken, ruri string) string {
	authIdInt := c.authIdIter.Add(1)
	timeNow := time.Now().Unix()

	iterAndTime := []byte{}
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(authIdInt))
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(timeNow))

	mac := hmac.New(crypto.SHA3_256.New, c.hmacKey)
	mac.Write(iterAndTime)
	authId := hex.EncodeToString(mac.Sum(nil))

	c.authIdMap[authId] = &AuthState{
		Pkt:         pkt,
		RedirectUri: ruri,
	}
	return authId
}

func (c *MfaCosigner) NewAuthcode(authId string) ([]byte, error) {
	authCodeBytes := make([]byte, 32)

	if _, err := rand.Read(authCodeBytes); err != nil {
		return nil, err
	}

	authCode := hex.EncodeToString(authCodeBytes)
	c.authCodeMap[authCode] = authId

	return []byte(authCode), nil
}

func (c *MfaCosigner) CheckAuthcode(authcode []byte, sig []byte) ([]byte, error) {

	authId := c.authCodeMap[string(authcode)]
	authState := c.authIdMap[authId]
	pkt := authState.Pkt

	msg, err := authState.Pkt.VerifySignedMessage(sig)
	if err != nil {
		fmt.Println("error verifying sig:", err)
		return nil, err
	}
	if !bytes.Equal(msg, authcode) {
		fmt.Println("error message doesn't make authcode:", err)
		return nil, err
	}

	if err := c.Cosign(pkt, authId); err != nil {
		fmt.Println("error cosigning:", err)
		return nil, err

	}

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		fmt.Println("error unmarshal:", err)
		return nil, err
	}

	pktB64 := util.Base64EncodeForJWT(pktJson)

	return pktB64, nil
}

func (c *MfaCosigner) IsRegistered(sub string) bool {
	_, ok := c.subDeviceMap[sub]
	return ok
}

func (c *MfaCosigner) Cosign(pkt *pktoken.PKToken, authID string) error {
	authState := c.authIdMap[authID]

	protected := pktoken.CosignerClaims{
		ID:          c.issuer,
		KeyID:       c.keyID,
		Algorithm:   c.alg.String(),
		AuthID:      authID,
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: authState.RedirectUri,
	}

	jsonBytes, err := json.Marshal(protected)
	if err != nil {
		return err
	}

	var headers map[string]any
	if err := json.Unmarshal(jsonBytes, &headers); err != nil {
		return err
	}

	// Now that our mfa has authenticated the user, we can add our signature
	return pkt.Sign(pktoken.Cos, c.signer, c.alg, headers)
}

func PktFromURL(v url.Values) (string, *pktoken.PKToken, error) {

	pktB64 := []byte(v.Get("pkt"))
	pktJson, err := util.Base64DecodeForJWT(pktB64)
	if err != nil {
		return "", nil, err
	}

	var pkt *pktoken.PKToken
	if err := json.Unmarshal(pktJson, &pkt); err != nil {
		return "", nil, err
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return "", nil, err
	}

	return claims.Subject, pkt, nil
}

func (c *MfaCosigner) BeginRegistration(authID string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {

	authState := c.authIdMap[authID]
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	err := json.Unmarshal(authState.Pkt.Payload, &claims)
	if err != nil {
		return nil, nil, err
	}

	cred := &user{
		id:          []byte(claims.Subject),
		username:    claims.Email,
		displayName: strings.Split(claims.Email, "@")[0],
	}

	creation, session, err := c.auth.BeginRegistration(cred)

	authState.Session = session

	return creation, session, err
}

func (c *MfaCosigner) FinishRegistration(authID string) error {

	authState := c.authIdMap[authID]
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	err := json.Unmarshal(authState.Pkt.Payload, &claims)
	if err != nil {
		return err
	}

	cred := &user{
		id:          []byte(claims.Subject),
		username:    claims.Email,
		displayName: strings.Split(claims.Email, "@")[0],
	}

	// credential, err := c.auth.FinishRegistration(cred, *authState.Session, r)
	var parsedResponse *protocol.ParsedCredentialCreationData
	credential, err := c.auth.CreateCredential(cred, *authState.Session, parsedResponse)
	cred.AddCredential(*credential)

	// TODO: Check if user already has a cred and reject so that an attacker can't just overwrite an existing cred
	if _, ok := c.subDeviceMap[claims.Subject]; ok != false {
		return fmt.Errorf("Already has a webauthn device registered for this user")
	} else {
		c.subDeviceMap[claims.Subject] = cred
		return nil
	}
}

func (c *MfaCosigner) BeginLogin(authID string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {

	authState := c.authIdMap[authID]
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	err := json.Unmarshal(authState.Pkt.Payload, &claims)
	if err != nil {
		return nil, nil, err
	}

	creation, session, err := c.auth.BeginLogin(c.subDeviceMap[claims.Subject])
	if err != nil {
		return nil, nil, err
	}
	authState.Session = session
	return creation, session, err
}

func (c *MfaCosigner) FinishLogin(authID string) ([]byte, error) {

	authState := c.authIdMap[authID]
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email"`
	}
	err := json.Unmarshal(authState.Pkt.Payload, &claims)
	if err != nil {
		return nil, err
	}

	cred := c.subDeviceMap[claims.Subject]

	var parsedResponse *protocol.ParsedCredentialAssertionData
	_, err = c.auth.ValidateLogin(cred, *authState.Session, parsedResponse)
	// credential, err := c.auth.FinishLogin(c.subDeviceMap[claims.Subject], *authState.Session, r)
	if err != nil {
		return nil, err
	}

	// TODO: Why do we need to do this?
	// cred.AddCredential(*credential)

	// w.Write([]byte("MFA login successful!"))

	authCode, err := c.NewAuthcode(authID)
	if err != nil {
		return nil, err
	}

	// TODO:
	// mfaURI := fmt.Sprintf("http://localhost:3000/mfacallback?authcode=%s", authCode)

	return authCode, nil
}
