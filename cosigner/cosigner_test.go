package cosigner

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/mocks"
	"github.com/openpubkey/openpubkey/util"
	"github.com/stretchr/testify/require"
)

func TestSimpleCosigner(t *testing.T) {
	// Generate the key pair for our cosigner
	alg := jwa.ES256
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		t.Error(err)
	}

	cos := &Cosigner{
		Alg:    alg,
		Signer: signer,
	}

	email := "arthur.aardvark@example.com"
	pkt, err := mocks.GenerateMockPKTokenWithEmail(signer, alg, email)
	require.NoError(t, err, "failed to generate key pair")

	cosignerClaims := pktoken.CosignerClaims{
		Iss:         "example.com",
		KeyID:       "none",
		Algorithm:   cos.Alg.String(),
		AuthID:      "none",
		AuthTime:    time.Now().Unix(),
		IssuedAt:    time.Now().Unix(),
		Expiration:  time.Now().Add(time.Hour).Unix(),
		RedirectURI: "none",
		Nonce:       "test-nonce",
	}

	cosToken, err := cos.Cosign(pkt, cosignerClaims)
	require.NoError(t, err, "failed cosign PK Token")
	require.NotNil(t, cosToken, "cosign signature is nil")
}
