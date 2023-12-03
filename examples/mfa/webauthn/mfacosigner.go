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
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/pktoken"
)

type UserKey struct {
	Issuer string // ID Token issuer (iss)
	Aud    string // ID Token audience (aud)
	Sub    string // ID Token subject ID (sub)
}

type AuthState struct {
	Pkt         *pktoken.PKToken
	Issuer      string // ID Token issuer (iss)
	Aud         string // ID Token audience (aud)
	Sub         string // ID Token subject ID (sub)
	Username    string // ID Token email or username
	DisplayName string // ID Token display name (or username if none given)
	RedirectURI string // Redirect URI
	Session     *webauthn.SessionData
}

func NewAuthState(pkt *pktoken.PKToken, ruri string) (*AuthState, error) {
	var claims struct {
		Issuer string `json:"iss"`
		Aud    any    `json:"aud"` //TODO: This is a broken pattern as typically audience is not a JSON list, but as an artifact of our mock ID Token it is.
		Sub    string `json:"sub"`
		Email  string `json:"email"`
	}
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, err
	}
	// An audience can be a string or an array of strings.
	//
	// RFC-7519 JSON Web Token (JWT) says:
	// "In the general case, the "aud" value is an array of case-
	// sensitive strings, each containing a StringOrURI value.  In the
	// special case when the JWT has one audience, the "aud" value MAY be a
	// single case-sensitive string containing a StringOrURI value."
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	var audience string
	switch t := claims.Aud.(type) {
	case string:
		audience = t
	case []any:
		audList := []string{}
		for _, v := range t {
			audList = append(audList, v.(string))
		}
		audience = strings.Join(audList, ",")
	default:
		return nil, fmt.Errorf("failed to deserialize aud (audience) claim in ID Token: %d", t)
	}

	return &AuthState{
		Pkt:         pkt,
		Issuer:      claims.Issuer,
		Aud:         audience,
		Sub:         claims.Sub,
		Username:    claims.Email,
		DisplayName: strings.Split(claims.Email, "@")[0], //TODO: Use full name from ID Token
		RedirectURI: ruri,
	}, nil

}

func (as AuthState) UserKey() UserKey {
	return UserKey{Issuer: as.Issuer, Aud: as.Aud, Sub: as.Sub}
}

func (as *AuthState) NewUser() *user {
	return &user{
		id:          []byte(as.Sub),
		username:    as.Username,
		displayName: as.DisplayName,
	}
}

type MfaCosigner struct {
	Iss         string
	keyID       string
	alg         jwa.KeyAlgorithm
	signer      crypto.Signer
	authIdIter  atomic.Uint64
	hmacKey     []byte
	webAuthn    *webauthn.WebAuthn
	authIdMap   map[string]*AuthState
	authCodeMap map[string]string
	users       map[UserKey]*user
}

func NewCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string, cfg *webauthn.Config) (*MfaCosigner, error) {
	hmacKey := make([]byte, 64)

	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	wauth, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}

	return &MfaCosigner{
		Iss:         issuer,
		keyID:       keyID,
		alg:         alg,
		signer:      signer,
		authIdIter:  atomic.Uint64{},
		hmacKey:     hmacKey,
		webAuthn:    wauth,
		authIdMap:   make(map[string]*AuthState),
		authCodeMap: make(map[string]string),
		users:       make(map[UserKey]*user),
	}, nil
}

func (c *MfaCosigner) InitAuth(pkt *pktoken.PKToken, sig []byte) (string, error) {
	msg, err := pkt.VerifySignedMessage(sig)
	if err != nil {
		return "", err
	}
	var initMFAAuth cosigner.InitMFAAuth
	if err := json.Unmarshal(msg, &initMFAAuth); err != nil {
		fmt.Printf("error creating init auth message: %s", err)
		return "", err
	} else if authState, err := NewAuthState(pkt, initMFAAuth.RedirectUri); err != nil {
		fmt.Printf("error creating init auth state: %s", err)
		return "", err
	} else {
		authID := c.CreateAuthID(pkt, initMFAAuth.RedirectUri)
		c.authIdMap[authID] = authState
		return authID, nil
	}
}

func (c *MfaCosigner) CreateAuthID(pkt *pktoken.PKToken, ruri string) string {
	authIdInt := c.authIdIter.Add(1)
	timeNow := time.Now().Unix()

	iterAndTime := []byte{}
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(authIdInt))
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(timeNow))
	mac := hmac.New(crypto.SHA3_256.New, c.hmacKey)

	return hex.EncodeToString(mac.Sum(nil))
}

func (c *MfaCosigner) NewAuthcode(authID string) ([]byte, error) {
	authCodeBytes := make([]byte, 32)
	if _, err := rand.Read(authCodeBytes); err != nil {
		return nil, err
	}
	authCode := hex.EncodeToString(authCodeBytes)
	c.authCodeMap[authCode] = authID
	return []byte(authCode), nil
}

func (c *MfaCosigner) RedeemAuthcode(authcode []byte, sig []byte) (*pktoken.PKToken, error) {
	if authID, ok := c.authCodeMap[string(authcode)]; !ok {
		return nil, fmt.Errorf("Invalid authcode")
	} else {
		authState := c.authIdMap[authID]
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
		if err := c.Cosign(pkt, authID); err != nil {
			fmt.Println("error cosigning:", err)
			return nil, err
		}
		return pkt, nil
	}
}

func (c *MfaCosigner) CheckIsRegistered(authID string) bool {
	authState := c.authIdMap[authID]
	userKey := authState.UserKey()
	return c.IsRegistered(userKey)
}

func (c *MfaCosigner) IsRegistered(userKey UserKey) bool {
	_, ok := c.users[userKey]
	return ok
}

func (c *MfaCosigner) Cosign(pkt *pktoken.PKToken, authID string) error {
	authState := c.authIdMap[authID]

	protected := pktoken.CosignerClaims{
		Iss:         c.Iss,
		KeyID:       c.keyID,
		Algorithm:   c.alg.String(),
		AuthID:      authID,
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: authState.RedirectURI,
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

func (c *MfaCosigner) BeginRegistration(authID string) (*protocol.CredentialCreation, error) {
	authState := c.authIdMap[authID]
	userKey := authState.UserKey()

	if c.IsRegistered(userKey) {
		return nil, fmt.Errorf("Already has a webauthn device registered for this user")
	}
	user := authState.NewUser()
	credCreation, session, err := c.webAuthn.BeginRegistration(user)
	authState.Session = session
	return credCreation, err
}

func (c *MfaCosigner) FinishRegistration(authID string, parsedResponse *protocol.ParsedCredentialCreationData) error {
	authState := c.authIdMap[authID]
	userKey := authState.UserKey()
	if c.IsRegistered(userKey) {
		return fmt.Errorf("Already has a webauthn device registered for this user")
	}
	user := authState.NewUser()
	credential, err := c.webAuthn.CreateCredential(user, *authState.Session, parsedResponse)
	if err != nil {
		return err
	}
	user.AddCredential(*credential)
	// TODO: Should use some mechanism to ensure that a registration session can't overwrite the result of another registration session for the same user if the user interleaved their registration sessions. It is a very unlikely possibility but it would be good to rule it out.
	c.users[userKey] = user
	return nil
}

func (c *MfaCosigner) BeginLogin(authID string) (*protocol.CredentialAssertion, error) {
	authState := c.authIdMap[authID]
	userKey := authState.UserKey()

	if credAssertion, session, err := c.webAuthn.BeginLogin(c.users[userKey]); err != nil {
		return nil, err
	} else {
		authState.Session = session
		return credAssertion, err
	}

}

func (c *MfaCosigner) FinishLogin(authID string, parsedResponse *protocol.ParsedCredentialAssertionData) ([]byte, []byte, error) {
	authState := c.authIdMap[authID]
	userKey := authState.UserKey()

	_, err := c.webAuthn.ValidateLogin(c.users[userKey], *authState.Session, parsedResponse)
	// credential, err := c.auth.FinishLogin(c.subDeviceMap[claims.Subject], *authState.Session, r)
	if err != nil {
		return nil, nil, err
	}

	if authcode, err := c.NewAuthcode(authID); err != nil {
		return nil, nil, err
	} else {
		// authcodeRuri := authState.RedirectURI + "#" + string(authcode)
		return authcode, []byte(authState.RedirectURI), nil
	}
}
