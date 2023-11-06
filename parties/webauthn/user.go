package webauthn

import (
	"github.com/go-webauthn/webauthn/webauthn"
)

// TODO: move this to a _test.go file.
type webAuthnUser struct {
	id          []byte
	username    string
	displayName string
}

var _ webauthn.User = (*webAuthnUser)(nil)

func (u *webAuthnUser) WebAuthnID() []byte {
	return u.id
}

func (u *webAuthnUser) WebAuthnName() string {
	return u.username
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	return u.displayName
}

func (u *webAuthnUser) WebAuthnIcon() string {
	return ""
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return []webauthn.Credential{}
}
