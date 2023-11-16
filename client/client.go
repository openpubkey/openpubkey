package client

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/awnumar/memguard"
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

	callback := func(w http.ResponseWriter, r *http.Request, idt []byte, state string) []byte {
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}
		idToken := memguard.NewBufferFromBytes(idt)

		// Sign over the payload from the ID token and client instance claims
		cicToken, err := cic.Sign(signer, alg, idToken.Bytes())
		if err != nil {
			fmt.Errorf("error creating cic token: %w", err)
			return nil
		}

		// Combine our ID token and signature over the cic to create our PK Token
		pkt, err := pktoken.New(idToken.Bytes(), cicToken)
		if err != nil {
			fmt.Printf("error creating PK Token: %w", err)
			return nil
		}

		err = VerifyPKToken(ctx, pkt, o.Op)
		if err != nil {
			fmt.Printf("error verifying PK Token: %w", err)
		}

		// w.Write([]byte("You may now close this window"))
		pktJson, err := json.Marshal(pkt)
		if err != nil {
			fmt.Printf("error serializing PK Token: %w", err)
		}

		ch2 := make(chan []byte)
		// This is where we get the mfa authcode
		mfaAuthCodeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			params := r.URL.Query()
			fmt.Printf("params: %s\n", params)
			mfaAuthCode := params["authcode"][0]

			fmt.Printf("Successfully Received Auth Code: %v\n", mfaAuthCode)

			w.Write([]byte("You may now close this window"))

			requestURL := fmt.Sprintf("http://localhost:3003/sign?authcode=%s", mfaAuthCode)
			res, err := http.Get(requestURL)
			if err != nil {
				fmt.Printf("error making http request: %s\n", err)
				os.Exit(1)
			}

			fmt.Printf("client: got response!\n")
			fmt.Printf("client: status code: %d\n", res.StatusCode)
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

			ch2 <- pktCosJson
		})
		http.Handle("/mfacallback", mfaAuthCodeHandler)

		pktB63 := util.Base64EncodeForJWT(pktJson)

		mfaURI := fmt.Sprintf("http://localhost:3003/?pkt=%s", string(pktB63))
		http.Redirect(w, r, mfaURI, http.StatusFound)
		fmt.Printf("Redirecting: \n")

		select {
		case pktCosJson := <-ch2:
			return pktCosJson
		}

	}

	pktCosJson, err := o.Op.RequestTokensCos(ctx, string(nonce), callback)
	if err != nil {
		return nil, err
	}
	var pkt *pktoken.PKToken

	if err := json.Unmarshal(pktCosJson.Bytes(), &pkt); err != nil {
		fmt.Printf("client: could not unmarshal pktCos: %s\n", err)
		return nil, err
	} else {
		return pkt, nil
	}
}
