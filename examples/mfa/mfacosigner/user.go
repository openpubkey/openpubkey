package mfacosigner

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

type user struct {
	id          []byte
	username    string
	displayName string
	credentials []webauthn.Credential
}

var _ webauthn.User = (*user)(nil)

func (u *user) WebAuthnID() []byte {
	return u.id
}

func (u *user) WebAuthnName() string {
	return u.username
}

func (u *user) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *user) WebAuthnIcon() string {
	return ""
}

func (u *user) AddCredential(cred webauthn.Credential) {
	u.credentials = append(u.credentials, cred)
}

func (u *user) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
