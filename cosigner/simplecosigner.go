package cosigner

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

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
)

type SimpleCosigner struct {
	alg    jwa.KeyAlgorithm
	signer crypto.Signer
}

type Authenticator interface {
	// Authenticate(pkt *pktoken.PKToken) error
	URI() string
}

func NewSimpleCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm) *SimpleCosigner {
	return &SimpleCosigner{
		alg:    alg,
		signer: signer,
	}
}

func (c *SimpleCosigner) Cosign(pkt *pktoken.PKToken, cosClaims pktoken.CosignerClaims) error { //TODO: Maybe change to type Any to provide flexibility
	jsonBytes, err := json.Marshal(cosClaims)
	if err != nil {
		return err
	}

	var headers map[string]any
	if err := json.Unmarshal(jsonBytes, &headers); err != nil {
		return err
	}
	return pkt.Sign(pktoken.Cos, c.signer, c.alg, headers)
}

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
	} else {
		var audience string

		// An audience can be a string or an array of strings.
		//
		// RFC-7519 JSON Web Token (JWT) says:
		// "In the general case, the "aud" value is an array of case-
		// sensitive strings, each containing a StringOrURI value.  In the
		// special case when the JWT has one audience, the "aud" value MAY be a
		// single case-sensitive string containing a StringOrURI value."
		// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
		switch t := claims.Aud.(type) {
		case string:
			audience = t
		case []string:
			audience = strings.Join(t, ",")
		default:
			return nil, fmt.Errorf("failed to deserialize aud (audience) claim in ID Token")
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
}

type InitMFAAuth struct {
	RedirectUri string `json:"ruri"`
	TimeSigned  int64  `json:"time"`
	Nonce       string `json:"nonce"`
}

type AuthCosigner struct {
	SimpleCosigner
	Iss         string
	keyID       string
	authIdIter  atomic.Uint64
	hmacKey     []byte
	webAuthn    *webauthn.WebAuthn
	authIdMap   map[string]*AuthState
	authCodeMap map[string]string
}

func NewCosigner(signer crypto.Signer, alg jwa.SignatureAlgorithm, issuer, keyID string, cfg *webauthn.Config) (*AuthCosigner, error) {
	hmacKey := make([]byte, 64)

	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	return &AuthCosigner{
		SimpleCosigner: SimpleCosigner{
			alg:    alg,
			signer: signer},
		Iss:         issuer,
		keyID:       keyID,
		authIdIter:  atomic.Uint64{},
		hmacKey:     hmacKey,
		authIdMap:   make(map[string]*AuthState),
		authCodeMap: make(map[string]string),
	}, nil
}

func (c *AuthCosigner) InitAuth(pkt *pktoken.PKToken, sig []byte) (string, error) {
	msg, err := pkt.VerifySignedMessage(sig)
	if err != nil {
		return "", err
	}
	var initMFAAuth *InitMFAAuth
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

func (c *AuthCosigner) CreateAuthID(pkt *pktoken.PKToken, ruri string) string {
	authIdInt := c.authIdIter.Add(1)
	timeNow := time.Now().Unix()

	iterAndTime := []byte{}
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(authIdInt))
	iterAndTime = binary.LittleEndian.AppendUint64(iterAndTime, uint64(timeNow))
	mac := hmac.New(crypto.SHA3_256.New, c.hmacKey)

	return hex.EncodeToString(mac.Sum(nil))
}

func (c *AuthCosigner) NewAuthcode(authID string) ([]byte, error) {
	authCodeBytes := make([]byte, 32)
	if _, err := rand.Read(authCodeBytes); err != nil {
		return nil, err
	}
	authCode := hex.EncodeToString(authCodeBytes)
	c.authCodeMap[authCode] = authID
	return []byte(authCode), nil
}

func (c *AuthCosigner) RedeemAuthcode(authcode []byte, sig []byte) (*pktoken.PKToken, error) {
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
		if err := c.IssueSignature(pkt, authID); err != nil {
			fmt.Println("error cosigning:", err)
			return nil, err
		}
		return pkt, nil
	}
}

func (c *AuthCosigner) IssueSignature(pkt *pktoken.PKToken, authID string) error {
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

	// Now that our mfa has authenticated the user, we can add our signature
	return c.Cosign(pkt, protected)
}

func ComputeNonce() (string, error) {
	bits := 256
	rBytes := make([]byte, bits/8)
	_, err := rand.Read(rBytes)
	if err != nil {
		return "", err
	}

	rz := hex.EncodeToString(rBytes)
	return rz, nil
}

func CreateInitAuthSig(ruri string, pkt *pktoken.PKToken, signer crypto.Signer) ([]byte, error) {
	nonce, err := ComputeNonce()
	if err != nil {
		return nil, err
	}

	msg := InitMFAAuth{
		RedirectUri: ruri,
		TimeSigned:  time.Now().Unix(),
		Nonce:       nonce,
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	return pkt.NewSignedMessage(msgJson, signer)
}
