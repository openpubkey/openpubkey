package mfacosigner

import (
	"crypto"
	"crypto/rand"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/cosigner"
)

type UserKey struct {
	Issuer string // ID Token issuer (iss)
	Aud    string // ID Token audience (aud)
	Sub    string // ID Token subject ID (sub)
}

func NewUser(as *cosigner.AuthState) *user {
	return &user{
		id:          []byte(as.Sub),
		username:    as.Username,
		displayName: as.DisplayName,
	}
}

type MfaCosigner struct {
	*cosigner.AuthCosigner
	webAuthn   *webauthn.WebAuthn
	sessionMap map[string]*webauthn.SessionData
	users      map[cosigner.UserKey]*user
}

func New(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string, cfg *webauthn.Config) (*MfaCosigner, error) {
	hmacKey := make([]byte, 64)

	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	wauth, err := webauthn.New(cfg)
	if err != nil {
		return nil, err
	}

	authCos, err := cosigner.New(signer, alg, issuer, keyID)
	if err != nil {
		return nil, err
	}

	return &MfaCosigner{
		AuthCosigner: authCos,
		webAuthn:     wauth,
		sessionMap:   make(map[string]*webauthn.SessionData),
		users:        make(map[cosigner.UserKey]*user),
	}, nil
}

func (c *MfaCosigner) CheckIsRegistered(authID string) bool {
	authState, _ := c.AuthStateStore.LookupAuthState(authID)
	userKey := authState.UserKey()
	return c.IsRegistered(userKey)
}

func (c *MfaCosigner) IsRegistered(userKey cosigner.UserKey) bool {
	_, ok := c.users[userKey]
	return ok
}

func (c *MfaCosigner) BeginRegistration(authID string) (*protocol.CredentialCreation, error) {
	authState, _ := c.AuthStateStore.LookupAuthState(authID)
	userKey := authState.UserKey()

	if c.IsRegistered(userKey) {
		return nil, fmt.Errorf("already has a webauthn device registered for this user")
	}
	user := NewUser(&authState)
	credCreation, session, err := c.webAuthn.BeginRegistration(user)
	if err != nil {
		return nil, err
	}
	c.sessionMap[authID] = session
	return credCreation, err
}

func (c *MfaCosigner) FinishRegistration(authID string, parsedResponse *protocol.ParsedCredentialCreationData) error {
	authState, _ := c.AuthStateStore.LookupAuthState(authID)
	session := c.sessionMap[authID]

	userKey := authState.UserKey()
	if c.IsRegistered(userKey) {
		return fmt.Errorf("already has a webauthn device registered for this user")
	}
	user := NewUser(&authState)
	credential, err := c.webAuthn.CreateCredential(user, *session, parsedResponse)
	if err != nil {
		return err
	}
	user.AddCredential(*credential)

	// TODO: Should use some mechanism to ensure that a registration session
	// can't overwrite the result of another registration session for the same
	// user if the user interleaved their registration sessions. It is a very
	// unlikely possibility but it would be good to rule it out.
	c.users[userKey] = user
	return nil
}

func (c *MfaCosigner) BeginLogin(authID string) (*protocol.CredentialAssertion, error) {
	authState, _ := c.AuthStateStore.LookupAuthState(authID)
	userKey := authState.UserKey()

	if user, ok := c.users[userKey]; !ok {
		return nil, fmt.Errorf("user does not exist for userkey given %s", userKey)
	} else if credAssertion, session, err := c.webAuthn.BeginLogin(user); err != nil {
		return nil, err
	} else {
		c.sessionMap[authID] = session
		return credAssertion, err
	}

}

func (c *MfaCosigner) FinishLogin(authID string, parsedResponse *protocol.ParsedCredentialAssertionData) (string, string, error) {
	authState, _ := c.AuthStateStore.LookupAuthState(authID)
	session := c.sessionMap[authID]
	userKey := authState.UserKey()

	_, err := c.webAuthn.ValidateLogin(c.users[userKey], *session, parsedResponse)
	if err != nil {
		return "", "", err
	}

	if authcode, err := c.NewAuthcode(authID); err != nil {
		return "", "", err
	} else {
		return authcode, authState.RedirectURI, nil
	}
}
