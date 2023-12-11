package internal

import (
	"github.com/openpubkey/openpubkey/client/providers"
)

// Redirect ports and URI are set dynamically after this is retrieved
var GoogleOp = providers.GoogleOp{
	ClientID: "878305696756-dd5ns57fccufrruii19fd7ed6jpd155r.apps.googleusercontent.com",
	// Google requires a ClientSecret even if this a public OIDC App
	ClientSecret: "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",
	Issuer:       "https://accounts.google.com",
	Scopes:       []string{"openid profile email"},
	CallbackPath: "/login-callback",
}
