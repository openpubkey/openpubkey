package providers

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/openpubkey/openpubkey/discover"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
)

// Interface for interacting with the OP (OpenID Provider)
type OpenIdProvider interface {
	RequestTokens(ctx context.Context, cic *clientinstance.Claims) ([]byte, error)
	PublicKeyByKeyId(ctx context.Context, keyID string) (*discover.PublicKeyRecord, error)
	PublicKeyByJTK(ctx context.Context, jtk string) (*discover.PublicKeyRecord, error)
	PublicKeyByToken(ctx context.Context, token []byte) (*discover.PublicKeyRecord, error)
	// Returns the OpenID provider issuer as seen in ID token e.g. "https://accounts.google.com"
	Issuer() string
	VerifyProvider(ctx context.Context, pkt *pktoken.PKToken) error
}

type BrowserOpenIdProvider interface {
	OpenIdProvider
	HookHTTPSession(h http.HandlerFunc)
}

type CommitType struct {
	Claim        string
	GQCommitment bool
}

var CommitTypesEnum = struct {
	NONCE_CLAIM CommitType
	AUD_CLAIM   CommitType
	GQ_BOUND    CommitType
}{
	NONCE_CLAIM: CommitType{Claim: "nonce", GQCommitment: false},
	AUD_CLAIM:   CommitType{Claim: "aud", GQCommitment: false},
	GQ_BOUND:    CommitType{Claim: "", GQCommitment: true}, // The commitmentClaim is bound to the ID Token using only the GQ signature
}

func getEnvVar(name string) (string, error) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%q environment variable not set", name)
	}
	return value, nil
}
