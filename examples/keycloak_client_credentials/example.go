// Copyright 2026 OpenPubkey
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/goccy/go-json"
	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

func SignClientCredentials(op client.OpenIdProvider) ([]byte, []byte, error) {
	opkClient, err := client.New(op)
	if err != nil {
		return nil, nil, err
	}

	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return nil, nil, err
	}

	msg := []byte("All is discovered - flee at once")
	signedMsg, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return nil, nil, err
	}

	pktJSON, err := json.Marshal(pkt)
	if err != nil {
		return nil, nil, err
	}

	return pktJSON, signedMsg, nil
}

func VerifyClientCredentials(op client.OpenIdProvider, pktJSON []byte, signedMsg []byte) error {
	pkt := new(pktoken.PKToken)
	if err := json.Unmarshal(pktJSON, &pkt); err != nil {
		return err
	}

	pktVerifier, err := verifier.New(op)
	if err != nil {
		return err
	}
	if err := pktVerifier.VerifyPKToken(context.Background(), pkt); err != nil {
		return err
	}

	msg, err := pkt.VerifySignedMessage(signedMsg)
	if err != nil {
		return err
	}

	claims := new(oidc.OidcClaims)
	if err := json.Unmarshal(pkt.Payload, claims); err != nil {
		return err
	}

	fmt.Printf("Verification successful: sub=%s iss=%s signed the message '%s'\n", claims.Subject, claims.Issuer, string(msg))
	return nil
}

func keycloakOpFromEnv() (providers.BrowserOpenIdProvider, error) {
	issuer := os.Getenv("OPENPUBKEY_KEYCLOAK_ISSUER")
	if issuer == "" {
		return nil, fmt.Errorf("OPENPUBKEY_KEYCLOAK_ISSUER is required, for example https://keycloak.example.com/realms/myrealm")
	}

	clientID := os.Getenv("OPENPUBKEY_KEYCLOAK_CLIENT_ID")
	if clientID == "" {
		return nil, fmt.Errorf("OPENPUBKEY_KEYCLOAK_CLIENT_ID is required")
	}

	opts := providers.GetDefaultStandardOpOptions(issuer, clientID)
	opts.ClientSecret = os.Getenv("OPENPUBKEY_KEYCLOAK_CLIENT_SECRET")

	if redirectURI := os.Getenv("OPENPUBKEY_KEYCLOAK_REDIRECT_URI"); redirectURI != "" {
		opts.RemoteRedirectURI = redirectURI
	}

	return providers.NewStandardOpWithOptions(opts), nil
}

func keycloakClientCredentialsOpFromEnv() (providers.OpenIdProvider, error) {
	op, err := keycloakOpFromEnv()
	if err != nil {
		return nil, err
	}

	stdOp, ok := op.(*providers.StandardOp)
	if !ok {
		return nil, fmt.Errorf("configured keycloak provider is not a standard provider")
	}

	stdOp.ClientCredentialsFlow = true
	stdOp.GQSign = true
	if len(stdOp.Scopes) == 0 {
		stdOp.Scopes = []string{"openid"}
	}

	return stdOp, nil
}

// It uses the same environment variables as example.go:
// OPENPUBKEY_KEYCLOAK_ISSUER
// OPENPUBKEY_KEYCLOAK_CLIENT_ID
// OPENPUBKEY_KEYCLOAK_CLIENT_SECRET
// OPENPUBKEY_KEYCLOAK_REDIRECT_URI
func main() {
	op, err := keycloakClientCredentialsOpFromEnv()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	pktJSON, signedMsg, err := SignClientCredentials(op)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if err := VerifyClientCredentials(op, pktJSON, signedMsg); err != nil {
		fmt.Println("Error:", err)
		return
	}
}
