package parties_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openpubkey/openpubkey/parties"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/signer"
)

var (
	// key              = []byte("NotASecureKey123")
	clientID = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	// requiredAudience = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"

	// The clientSecret was intentionally checked in for the purposes of this example. It holds no power. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	issuer       = "https://accounts.google.com"
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)

func TestOpkClient(t *testing.T) {
	signer, err := signer.NewECDSASigner()
	if err != nil {
		t.Fatal(err)
	}

	cic, err := clientinstance.NewClaims(signer.JWKKey(), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	client := &parties.OpkClient{
		Op: &parties.GoogleOp{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Issuer:       issuer,
			Scopes:       scopes,
			RedirURIPort: redirURIPort,
			CallbackPath: callbackPath,
			RedirectURI:  redirectURI,
		},
		Signer: signer,
		Cic:    cic,
		Gq:     false,
	}

	pktJson, err := client.OidcAuth()
	if err != nil {
		t.Fatal(err)
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, pktJson, "", "    "); err != nil {
		t.Fatalf("Our PK Token doesn't want to be pretty: %s", err)
	}
}
