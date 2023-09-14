package main

import "fmt"

var (
	key          = []byte("NotASecureKey123")
	clientID     = "YOUR GOOGLE CLIENT ID"
	clientSecret = "YOUR GOOGLE CLIENT SECRET" // Google requires a ClientSecret even if this a public OIDC App
	issuer       = "https://accounts.google.com"
	scopes       = []string{"openid profile email"}
	redirURIPort = "3000"
	callbackPath = "/login-callback"
	redirectURI  = fmt.Sprintf("http://localhost:%v%v", redirURIPort, callbackPath)

	fpClientCfg = "configs/clcfg"
	fpMfaCfg    = "configs/mfacfg"
	fpCaCfg     = "configs/cacfg"
)
