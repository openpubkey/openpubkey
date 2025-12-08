// TODO: I had this as 'crypto' first, but this caused a lot of
// collisions with the go stdlib crypto package. Any recommendations
// on a better name are welcome!
package jose

type KeyAlgorithm string

// This list is taken from the built-in values of
// jwx/v3/jwa/signature_gen.go
// TODO: Do we want to support all algorithms?
const (
	ES256  = KeyAlgorithm("ES256")
	ES256K = KeyAlgorithm("ES256K")
	ES384  = KeyAlgorithm("ES384")
	ES512  = KeyAlgorithm("ES512")
	EdDSA  = KeyAlgorithm("EdDSA")
	HS256  = KeyAlgorithm("HS256")
	HS384  = KeyAlgorithm("HS384")
	HS512  = KeyAlgorithm("HS512")
	None   = KeyAlgorithm("none")
	PS256  = KeyAlgorithm("PS256")
	PS384  = KeyAlgorithm("PS384")
	PS512  = KeyAlgorithm("PS512")
	RS256  = KeyAlgorithm("RS256")
	RS384  = KeyAlgorithm("RS384")
	RS512  = KeyAlgorithm("RS512")
)
