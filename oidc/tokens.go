package oidc

type Tokens struct {
	IDToken      []byte
	RefreshToken []byte
	AccessToken  []byte
}
