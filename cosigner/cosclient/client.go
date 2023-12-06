package cosclient

import (
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

// TODO: Add message construction, message validation and deserialization helpers here. Break out POP auth into it's own thing.
type AuthCosignerClient struct {
	Issuer      string
	RedirectURI string
}

func (c *AuthCosignerClient) Auth(signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
	ch := make(chan []byte)
	errCh := make(chan error)

	// This is where we get the authcode from the Cosigner
	http.Handle("/mfacallback",
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Get authcode from Cosigner via Cosigner redirecting user's browser window
			params := r.URL.Query()
			if _, ok := params["authcode"]; !ok {
				errCh <- fmt.Errorf("Cosigner did not return an authcode in the URI")
				return
			}
			authcode := params["authcode"][0] // This is the authcode issued by the cosigner not the OP

			// Sign authcode from cosigner under PK Token and send signed authcode to Cosigner
			sig2, err := pkt.NewSignedMessage([]byte(authcode), signer)
			if err != nil {
				errCh <- err
				return
			}
			res, err := http.Get(fmt.Sprintf("%s/sign?sig2=%s", c.Issuer, sig2))
			if err != nil {
				errCh <- fmt.Errorf("error requesting MFA cosigner signature: %w", err)
				return
			}

			// Receive response from Cosigner that has cosigner signature on PK Token
			resBody, err := io.ReadAll(res.Body)
			if err != nil {
				errCh <- fmt.Errorf("error reading MFA cosigner signature response: %w", err)
				return
			}
			cosSig, err := util.Base64DecodeForJWT(resBody)
			if err != nil {
				errCh <- fmt.Errorf("error reading MFA cosigner signature response: %w", err)
				return
			}
			// Success
			w.Write([]byte("You may now close this window"))
			ch <- cosSig
		}),
	)
	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error serializing PK Token: %w\n", err)
	}
	pktB63 := util.Base64EncodeForJWT(pktJson)
	initAuthMsgJson, nonce, err := c.CreateInitAuthSig()
	sig1, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error init auth signed message: %w\n", err)
	}

	// Trigger redirect of user's browser window to a URI controlled by the Cosigner sending the PK Token in the URI
	redirCh <- fmt.Sprintf("%s/mfa-auth-init?pkt=%s&sig1=%s", c.Issuer, string(pktB63), string(sig1))

	select {
	case cosSig := <-ch:
		// To be safe we perform these checks before adding the cosSig to the pktoken
		if err := c.ValidateCosPHeader(cosSig, nonce); err != nil {
			return nil, err
		}
		pkt.AddSignature(cosSig, pktoken.Cos)
		if err != nil {
			return nil, fmt.Errorf("error in adding cosigner signature to PK Token: %w\n", err)
		}
		return pkt, nil
	case err := <-errCh:
		return nil, err
	}
}

func (c *AuthCosignerClient) ValidateCosPHeader(cosSig []byte, nonce string) error {
	if cosSigParsed, err := jws.Parse(cosSig); err != nil {
		return fmt.Errorf("failed to parse Cosigner signature: %w", err)
	} else if len(cosSigParsed.Signatures()) != 1 {
		return fmt.Errorf("the Cosigner signature does not have the correct number of signatures: %w", err)
	} else {
		ph := cosSigParsed.Signatures()[0].ProtectedHeaders()
		if nonceRet, ok := ph.Get("nonce"); !ok {
			return fmt.Errorf("nonce not set in Cosigner signature protected header")
		} else if nonce != nonceRet {
			return fmt.Errorf("incorrect nonce set in Cosigner signature")
		}
		if ruriRet, ok := ph.Get("ruri"); !ok {
			return fmt.Errorf("ruri (redirect URI) not set in Cosigner signature protected header")
		} else if c.RedirectURI != ruriRet {
			return fmt.Errorf("unexpected ruri (redirect URI) set in Cosigner signature, expected %s", c.RedirectURI)
		}
		if issRet, ok := ph.Get("iss"); !ok {
			return fmt.Errorf("iss (Cosigner Issuer) not set in Cosigner signature protected header")
		} else if c.Issuer != issRet {
			return fmt.Errorf("unexpected iss (Cosigner Issuer) set in Cosigner signature, expected %s", c.Issuer)
		}
		return nil
	}
}

func (c *AuthCosignerClient) CreateInitAuthSig() ([]byte, string, error) {
	bits := 256
	rBytes := make([]byte, bits/8)
	_, err := rand.Read(rBytes)
	if err != nil {
		return nil, "", err
	}

	nonce := hex.EncodeToString(rBytes)
	if err != nil {
		return nil, "", err
	}

	msg := msgs.InitMFAAuth{
		RedirectUri: c.RedirectURI,
		TimeSigned:  time.Now().Unix(),
		Nonce:       nonce,
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		return nil, "", err
	}
	return msgJson, nonce, nil
}
