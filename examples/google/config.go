package main

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"
)

const (
	gq           = true
	keyAlgorithm = jwa.ES256

	// Directories for saving data
	fpClientCfg = "configs/clcfg"
	fpCaCfg     = "configs/cacfg"
	fpMfaCfg    = "configs/mfacfg"
)

var (
	key              = []byte("NotASecureKey123")
	clientID         = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	requiredAudience = "184968138938-g1fddl5tglo7mnlbdak8hbsqhhf79f32.apps.googleusercontent.com"
	// The clientSecret was intentionally checked in for the purposes of this example,. It holds no power. Do not report as a security issue
	clientSecret = "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" // Google requires a ClientSecret even if this a public OIDC App
	issuer       = "https://accounts.google.com"
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)
)
