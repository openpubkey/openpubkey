package internal

import (
	"github.com/openpubkey/openpubkey/client/providers"
)

// Redirect ports and URI are set dynamically after this is retrieved
var GoogleOp = providers.GoogleOp{
	ClientID: "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com",
	// Google requires a ClientSecret even if this a public OIDC App
	ClientSecret: "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",
	Issuer:       "https://accounts.google.com",
	Scopes:       []string{"openid profile email"},
	CallbackPath: "/login-callback",
}
