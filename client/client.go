package client

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

type OpkClient struct {
	Op OpenIdProvider
}

func (o *OpkClient) OidcAuth(
	ctx context.Context,
	signer crypto.Signer,
	alg jwa.KeyAlgorithm,
	extraClaims map[string]any,
	signGQ bool,
) (*pktoken.PKToken, error) {
	// Use our signing key to generate a JWK key with the alg header set
	jwkKey, err := jwk.PublicKeyOf(signer)
	if err != nil {
		return nil, err
	}
	jwkKey.Set(jwk.AlgorithmKey, alg)

	// Use provided public key to generate client instance claims
	cic, err := clientinstance.NewClaims(jwkKey, extraClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate client instance claims: %w", err)
	}

	// Define our OIDC nonce as a commitment to the client instance claims
	nonce, err := cic.Hash()
	if err != nil {
		return nil, fmt.Errorf("error getting nonce: %w", err)
	}

	redirCh := make(chan string)
	oidcEnder := func(w http.ResponseWriter, r *http.Request) {
		redirectUri := <-redirCh
		http.Redirect(w, r, redirectUri, http.StatusFound)
	}
	oidcDone, err := o.Op.RequestTokensCos(ctx, string(nonce), oidcEnder)
	if err != nil {
		return nil, err
	}
	idToken := oidcDone.Token

	// Sign over the payload from the ID token and client instance claims
	cicToken, err := cic.Sign(signer, alg, idToken.Bytes())
	if err != nil {
		fmt.Errorf("error creating cic token: %w", err)
		return nil, err
	}

	// Combine our ID token and signature over the cic to create our PK Token
	pkt, err := pktoken.New(idToken.Bytes(), cicToken)
	if err != nil {
		fmt.Printf("error creating PK Token: %w", err)
		return nil, err
	}

	err = VerifyPKToken(ctx, pkt, o.Op)
	if err != nil {
		fmt.Printf("error verifying PK Token: %w", err)
		return nil, err
	}

	return o.CosAuth(signer, pkt, redirCh)

}

func (o *OpkClient) CosAuth(signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
	ch2 := make(chan []byte)
	// This is where we get the mfa authcode
	mfaAuthCodeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		fmt.Printf("params: %s\n", params)
		mfaAuthCode := params["authcode"][0]

		fmt.Printf("Successfully Received Auth Code: %v\n", mfaAuthCode)

		sig, err := pkt.NewSignedMessage([]byte(mfaAuthCode), signer)
		if err != nil {
			fmt.Printf("error signing mfaauthcode  %s\n", err)
			os.Exit(1)
		}

		requestURL := fmt.Sprintf("http://localhost:3003/sign?authcode=%s&sig=%s", mfaAuthCode, sig)

		res, err := http.Get(requestURL)
		if err != nil {
			fmt.Printf("error making http request: %s\n", err)
			os.Exit(1)
		}

		resBody, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Printf("client: could not read response body: %s\n", err)
			os.Exit(1)
		}
		fmt.Printf("resBody: %s\n", resBody)

		var jsonResp struct {
			PktB64 string `json:"pkt"`
		}
		if err := json.Unmarshal(resBody, &jsonResp); err != nil {
			fmt.Printf("client: could not read response body: %s\n", err)
			os.Exit(1)
		}
		pktCosB64 := []byte(jsonResp.PktB64)

		pktCosJson, err := util.Base64DecodeForJWT(pktCosB64)

		w.Write([]byte("You may now close this window"))

		ch2 <- pktCosJson
	})
	http.Handle("/mfacallback", mfaAuthCodeHandler)

	pktJson, err := json.Marshal(pkt)
	if err != nil {
		fmt.Printf("error serializing PK Token: %w", err)
	}

	pktB63 := util.Base64EncodeForJWT(pktJson)

	redirCh <- fmt.Sprintf("http://localhost:3003/?pkt=%s", string(pktB63))

	fmt.Printf("Redirecting: \n")

	select {
	case pktCosJson := <-ch2:
		var pkt *pktoken.PKToken
		if err := json.Unmarshal(pktCosJson, &pkt); err != nil {
			fmt.Printf("client: could not read response body: %s\n", err)
			return nil, err
		}
		return pkt, nil
	}
}
