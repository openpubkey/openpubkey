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
	"fmt"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/client/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

func SignWithGitlab() error {

	op, err := providers.NewGitlabOpFromEnvironment("OPENPUBKEY_JWT")
	if err != nil {
		return err
	}
	opkClient, err := client.New(op)
	if err != nil {
		return err
	}

	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		return err
	}

	pktJson, err := pkt.MarshalJSON()
	if err != nil {
		return err
	}
	fmt.Println("pkt:", pktJson)

	verifier, err := verifier.New(op.Verifier())
	if err != nil {
		return err
	}

	err = verifier.VerifyPKToken(context.Background(), pkt)
	if err != nil {
		return err
	}

	msg := []byte("All is discovered - flee at once")
	signedMsg, err := pkt.NewSignedMessage(msg, opkClient.GetSigner())
	if err != nil {
		return err
	}
	fmt.Println("signedMsg:", string(signedMsg))

	fmt.Println("Success!")
	return nil
}
