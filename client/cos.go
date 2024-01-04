package client

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/openpubkey/openpubkey/cosigner/msgs"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
	"github.com/sirupsen/logrus"
)

type CosignerProvider struct {
	Issuer       string
	CallbackPath string
}

func (p *CosignerProvider) GetIssuer() string {
	return p.Issuer
}

func (c *CosignerProvider) RequestToken(ctx context.Context, signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
	// Find an unused port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("failed to bind to an available port: %w", err)
	}

	port := listener.Addr().(*net.TCPAddr).Port
	host := fmt.Sprintf("localhost:%d", port)
	redirectURI := fmt.Sprintf("http://%s%s", host, c.CallbackPath)

	ch := make(chan []byte)
	errCh := make(chan error)

	// This is where we get the authcode from the Cosigner
	mux := http.NewServeMux()
	mux.Handle(c.CallbackPath,
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
			authcodeSigUri, err := c.AuthcodeURI(sig2)
			if err != nil {
				errCh <- fmt.Errorf("cosigner client hit error when building authcode URI: %w", err)
				return
			}
			res, err := http.Get(authcodeSigUri)
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

	server := &http.Server{
		Addr:    host,
		Handler: mux,
	}
	logrus.Infof("listening on http://%s/", host)
	logrus.Info("press ctrl+c to stop")
	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			logrus.Error(err)
		}
	}()
	defer server.Shutdown(ctx)

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error serializing PK Token: %w", err)
	}

	initAuthMsgJson, nonce, err := c.CreateInitAuthSig(redirectURI)
	sig1, err := pkt.NewSignedMessage(initAuthMsgJson, signer)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error init auth signed message: %w", err)
	}

	redirUri, err := c.InitAuthURI(pktJson, sig1)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error when building init auth URI: %w", err)
	}

	select {
	// Trigger redirect of user's browser window to a URI controlled by the Cosigner sending the PK Token in the URI
	// case redirCh <- fmt.Sprintf("%s/mfa-auth-init?pkt=%s&sig1=%s", c.Issuer, string(pktB63), string(sig1)):
	case redirCh <- redirUri:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	select {
	case cosSig := <-ch: // Received cosigner signature
		// To be safe we perform these checks before adding the cosSig to the pktoken
		if err := c.ValidateCos(cosSig, nonce, redirectURI); err != nil {
			return nil, err
		}
		if err := pkt.AddSignature(cosSig, pktoken.Cos); err != nil {
			return nil, fmt.Errorf("error in adding cosigner signature to PK Token: %w", err)
		}
		return pkt, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *CosignerProvider) InitAuthURI(pktJson []byte, sig1 []byte) (string, error) {
	pktB63 := util.Base64EncodeForJWT(pktJson)
	if uri, err := url.Parse(c.Issuer); err != nil {
		return "", err
	} else {
		uri := uri.JoinPath("mfa-auth-init")
		v := uri.Query()
		v.Add("pkt", string(pktB63))
		v.Add("sig1", string(sig1))
		uri.RawQuery = v.Encode()

		// URI Should be: https://<issuer>/mfa-auth-init?pkt=<pktJsonB64>&sig1=<sig1>
		return uri.String(), nil
	}
}

func (c *CosignerProvider) AuthcodeURI(sig2 []byte) (string, error) {
	if uri, err := url.Parse(c.Issuer); err != nil {
		return "", err
	} else {
		uri := uri.JoinPath("sign")
		v := uri.Query()
		v.Add("sig2", string(sig2))
		uri.RawQuery = v.Encode()

		// URI Should be: https://<issuer>/sign?&sig2=<sig2>
		return uri.String(), nil
	}

}

func (c *CosignerProvider) ValidateCos(cosSig []byte, expectedNonce string, expectedRedirectURI string) error {
	if cosSigParsed, err := jws.Parse(cosSig); err != nil {
		return fmt.Errorf("failed to parse Cosigner signature: %w", err)
	} else if len(cosSigParsed.Signatures()) != 1 {
		return fmt.Errorf("the Cosigner signature does not have the correct number of signatures: %w", err)
	} else {
		ph := cosSigParsed.Signatures()[0].ProtectedHeaders()
		if nonceRet, ok := ph.Get("nonce"); !ok {
			return fmt.Errorf("nonce not set in Cosigner signature protected header")
		} else if expectedNonce != nonceRet {
			return fmt.Errorf("incorrect nonce set in Cosigner signature")
		}
		if ruriRet, ok := ph.Get("ruri"); !ok {
			return fmt.Errorf("ruri (redirect URI) not set in Cosigner signature protected header")
		} else if expectedRedirectURI != ruriRet {
			return fmt.Errorf("unexpected ruri (redirect URI) set in Cosigner signature, got %s expected %s", ruriRet, expectedRedirectURI)
		}
		if issRet, ok := ph.Get("iss"); !ok {
			return fmt.Errorf("iss (Cosigner Issuer) not set in Cosigner signature protected header")
		} else if c.Issuer != issRet {
			return fmt.Errorf("unexpected iss (Cosigner Issuer) set in Cosigner signature, expected %s", c.Issuer)
		}
		return nil
	}
}

func (c *CosignerProvider) CreateInitAuthSig(redirectURI string) ([]byte, string, error) {
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
		RedirectUri: redirectURI,
		TimeSigned:  time.Now().Unix(),
		Nonce:       nonce,
	}
	msgJson, err := json.Marshal(msg)
	if err != nil {
		return nil, "", err
	}
	return msgJson, nonce, nil
}
