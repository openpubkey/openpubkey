package main

import "fmt"

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

	fpClientCfg = "configs/clcfg"
	fpMfaCfg    = "configs/mfacfg"
	fpCaCfg     = "configs/cacfg"
)
