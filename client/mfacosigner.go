package client

// type MFACosignerClient struct {
// 	Issuer       string
// 	RedirectURI  string
// 	CallbackPath string
// }

// func (mfa *MFACosignerClient) Auth(signer crypto.Signer, pkt *pktoken.PKToken, redirCh chan string) (*pktoken.PKToken, error) {
// 	cosClient := &cosclient.AuthCosignerClient{
// 		Issuer:      mfa.Issuer,
// 		RedirectURI: mfa.RedirectURI,
// 	}

// 	ch2 := make(chan []byte)
// 	errCh := make(chan error)
// 	// This is where we get the mfa authcode
// 	mfaAuthCodeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		params := r.URL.Query()
// 		mfaAuthCode := params["authcode"][0]

// 		fmt.Printf("Successfully Received Auth Code: %v\n", mfaAuthCode)

// 		requestURL, err := cosClient.CreateRedeemAuthcodeUri(mfaAuthCode)
// 		if err != nil {
// 			errCh <- err
// 			return
// 		}
// 		res, err := http.Get(requestURL)
// 		if err != nil {
// 			errCh <- fmt.Errorf("error requesting MFA cosigner signature: %w", err)
// 			return
// 		}

// 		resBody, err := io.ReadAll(res.Body)
// 		if err != nil {
// 			errCh <- fmt.Errorf("error reading MFA cosigner signature response: %w", err)
// 			return
// 		}
// 		var jsonResp struct {
// 			PktB64 string `json:"pkt"`
// 		}
// 		if err := json.Unmarshal(resBody, &jsonResp); err != nil {
// 			errCh <- fmt.Errorf("returned MFA cosigner signature not valid: %w", err)
// 			return
// 		}
// 		pktCosB64 := []byte(jsonResp.PktB64)

// 		pktCosJson, err := util.Base64DecodeForJWT(pktCosB64)
// 		w.Write([]byte("You may now close this window"))

// 		ch2 <- pktCosJson
// 	})
// 	http.Handle("/mfacallback", mfaAuthCodeHandler)

// 	initAuthUri, err := cosClient.CreateInitAuthUri()
// 	if err != nil {
// 		return nil, err
// 	}

// 	redirCh <- initAuthUri

// 	select {
// 	case pktCosJson := <-ch2:
// 		fmt.Println(string(pktCosJson))
// 		var pkt *pktoken.PKToken
// 		if err := json.Unmarshal(pktCosJson, &pkt); err != nil {
// 			return nil, fmt.Errorf("cosigner client could not read response body: %w\n", err)
// 		}
// 		return pkt, nil
// 	case err := <-errCh:
// 		return nil, err
// 	}
// }
