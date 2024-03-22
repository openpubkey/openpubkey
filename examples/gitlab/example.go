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
