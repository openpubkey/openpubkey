package cosclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

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
	// Trigger redirect of user's browser window to cosigner so that user can authenticate to cosigner
	redirCh <- fmt.Sprintf("%s/mfa-auth-init?pkt=%s&sig1=%s", c.Issuer, string(pktB63), string(sig1))

	select {
	case cosSig := <-ch:
		pkt.AddSignature(cosSig, pktoken.Cos)
		if err != nil {
			return nil, fmt.Errorf("error in adding cosigner signature to PK Token: %w\n", err)
		}
		if err := c.ValidateCos(pkt, nonce); err != nil {
			return nil, err
		}
		return pkt, nil
	case err := <-errCh:
		return nil, err
	}
}

func (c *AuthCosignerClient) ValidateCos(pkt *pktoken.PKToken, nonce string) error {
	if pheaders, err := pkt.Cos.ProtectedHeaders().AsMap(context.TODO()); err != nil {
		return err
	} else {
		if nonceRet, ok := pheaders["nonce"]; !ok {
			return fmt.Errorf("Nonce not set in Cosigner signature")
		} else {
			//TODO: Check that nonce is what we set originally
			if nonce != nonceRet {
				return fmt.Errorf("Incorrect nonce set in Cosigner signature")
			}
			return nil
		}
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
