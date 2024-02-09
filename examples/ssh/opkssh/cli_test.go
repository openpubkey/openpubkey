package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/client"
	clientmocks "github.com/openpubkey/openpubkey/client/mocks"
	"github.com/openpubkey/openpubkey/examples/ssh/sshcert"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/stretchr/testify/require"

	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
)

func AllowAllPolicyEnforcer(userDesired string, pkt *pktoken.PKToken) error {
	return nil
}

func TestAuthorizedKeysCommand(t *testing.T) {
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}

	// extra ID token payload claims
	mockEmail := "arthur.aardvark@example.com"
	extraClaims := map[string]any{
		"email": mockEmail,
	}

	op, err := clientmocks.NewMockOpenIdProvider(t, extraClaims)
	if err != nil {
		t.Fatal(err)
	}

	client, err := client.New(op, client.WithSigner(signer, alg))
	require.NoError(t, err)

	pkt, err := client.Auth(context.Background())
	require.NoError(t, err)

	principals := []string{"guest", "dev"}
	cert, err := sshcert.New(pkt, principals)
	if err != nil {
		t.Error(err)
	}

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		t.Error(err)
	}

	signerMas, err := ssh.NewSignerWithAlgorithms(sshSigner.(ssh.AlgorithmSigner),
		[]string{ssh.KeyAlgoECDSA256})
	if err != nil {
		t.Error(err)
	}

	sshCert, err := cert.SignCert(signerMas)
	if err != nil {
		t.Error(err)
	}
	certTypeAndCertB64 := ssh.MarshalAuthorizedKey(sshCert)
	typeArg := strings.Split(string(certTypeAndCertB64), " ")[0]
	certB64Arg := strings.Split(string(certTypeAndCertB64), " ")[1]

	userArg := "user"
	pubkeyList, err := authorizedKeysCommand(userArg, typeArg, certB64Arg, AllowAllPolicyEnforcer, op)
	if err != nil {
		t.Error(err)
	}
	expectedPubkeyList := "cert-authority ecdsa-sha2-nistp256"
	if !strings.Contains(pubkeyList, expectedPubkeyList) {
		t.Error(err)
	}
}
