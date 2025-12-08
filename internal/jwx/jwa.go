package jwx

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/openpubkey/openpubkey/jose"
)

func FromJoseAlgorithm(alg jose.KeyAlgorithm) (jwa.KeyAlgorithm, bool) {
	return jwa.LookupSignatureAlgorithm(string(alg))
}

func ToJoseAlgorithm(alg jwa.KeyAlgorithm) jose.KeyAlgorithm {
	return jose.KeyAlgorithm(alg.String())
}
