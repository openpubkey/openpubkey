package providers

// Config declares the minimal interface for an OP (OpenID provider) config. It
// provides methods to get configuration values for a specific OIDC client
// implementation.
type Config interface {
	// ClientID returns the registered client identifier that is valid at the OP
	// issuer
	ClientID() string
	// Issuer returns the OP's issuer URL identifier
	Issuer() string
}
