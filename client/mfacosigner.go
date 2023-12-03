package client

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openpubkey/openpubkey/cosigner"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/util"
)

type MFACosignerClient struct {
	Issuer       string
	RedirectURI  string
	CallbackPath string
}

func (mfa *MFACosignerClient) Auth(signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
	ch2 := make(chan []byte)
	errCh := make(chan error)
	// This is where we get the mfa authcode
	mfaAuthCodeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		mfaAuthCode := params["authcode"][0]

		fmt.Printf("Successfully Received Auth Code: %v\n", mfaAuthCode)

		sig, err := pkt.NewSignedMessage([]byte(mfaAuthCode), signer)
		if err != nil {
			errCh <- fmt.Errorf("error signing MFA authcode: %w", err)
			return
		}

		requestURL := fmt.Sprintf("%s/sign?authcode=%s&sig2=%s", mfa.Issuer, mfaAuthCode, sig)
		res, err := http.Get(requestURL)
		if err != nil {
			errCh <- fmt.Errorf("error requesting MFA cosigner signature: %w", err)
			return
		}

		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			errCh <- fmt.Errorf("error reading MFA cosigner signature response: %w", err)
			return
		}
		fmt.Printf("resBody: %s\n", resBody)

		var jsonResp struct {
			PktB64 string `json:"pkt"`
		}
		if err := json.Unmarshal(resBody, &jsonResp); err != nil {
			errCh <- fmt.Errorf("returned MFA cosigner signature not valid: %w", err)
			return
		}
		pktCosB64 := []byte(jsonResp.PktB64)

		pktCosJson, err := util.Base64DecodeForJWT(pktCosB64)
		w.Write([]byte("You may now close this window"))

		ch2 <- pktCosJson
	})
	http.Handle("/mfacallback", mfaAuthCodeHandler)

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error serializing PK Token: %w\n", err)

	}
	pktB63 := util.Base64EncodeForJWT(pktJson)

	sig1, err := cosigner.CreateInitAuthSig(mfa.RedirectURI, pkt, signer)
	if err != nil {
		return nil, fmt.Errorf("cosigner client hit error init auth signed message: %w\n", err)
	}

	redirCh <- fmt.Sprintf("%s/mfa-auth-init?pkt=%s&sig1=%s", mfa.Issuer, string(pktB63), string(sig1))

	select {
	case pktCosJson := <-ch2:
		fmt.Println(string(pktCosJson))
		var pkt *pktoken.PKToken
		if err := json.Unmarshal(pktCosJson, &pkt); err != nil {
			return nil, fmt.Errorf("cosigner client could not read response body: %w\n", err)
		}
		return pkt, nil
	case err := <-errCh:
		return nil, err
	}
}
