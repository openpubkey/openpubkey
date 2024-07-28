// Copyright 2024 OpenPubkey
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

package gitlab_example

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

type Opts struct {
	altOp providers.OpenIdProvider
}

func SignWithGitlab(opts ...Opts) error {
	var op providers.OpenIdProvider

	// If an alternative OP is provided, use that instead of the default.
	// Currently only used for testing where a mockOP is provided.
	if len(opts) > 0 && opts[0].altOp != nil {
		op = opts[0].altOp
	} else {
		// Creates OpenID Provider (OP) configuration, this will be used to request the ID Token from Gitlab
		op = providers.NewGitlabOpFromEnvironment("OPENPUBKEY_JWT")
	}

	// Creates a new OpenPubkey client
	opkClient, err := client.New(op)
	if err != nil {
		return err
	}

	// Generates a PK Token by authorizing to the OpenID Provider
	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return err
	}

	// Serialize the PK Token to JSON so we can print it. Typically this
	// serialization of the PK Token would be sent with the signed message
	pktJson, err := pkt.MarshalJSON()
	if err != nil {
		return err
	}
	fmt.Println("pkt:", string(pktJson))

	pktCom, _ := pkt.Compact()
	b64pktCom := base64.StdEncoding.EncodeToString(pktCom)
	fmt.Println("pkt compact:", string(b64pktCom))

	// Create a verifier to check that the PK Token is well formed
	// The OPK client does this as well, but for the purposes of the
	// example we show how a relying party might verify a PK Token
	verifier, err := verifier.New(op)
	if err != nil {
		return err
	}

	// Verify the PK Token. We supply the OP (gitlab) we wish to verify against
	err = verifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		return err
	}

	// Sign a message over the user's public key in the PK Token
	msg := []byte("All is discovered - flee at once")
	signedMsg, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return err
	}
	fmt.Println("signedMsg:", string(signedMsg))

	// Verify the signed message
	_, err = pkt.VerifySignedMessage(signedMsg)
	if err != nil {
		return err
	}

	fmt.Println("Success!")
	return nil
}
