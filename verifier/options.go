package verifier

import (
	"fmt"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
)

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")

func GQOnly() Check {
	return func(pkt *pktoken.PKToken) error {
		alg, ok := pkt.ProviderAlgorithm()
		if !ok {
			return fmt.Errorf("missing provider algorithm header")
		}

		if alg != gq.GQ256 {
			return ErrNonGQUnsupported
		}
		return nil
	}
}

// Option that allows specification of a single cosigner, if strict then an error is thrown if the cosigner is not found
func WithCosigner(issuer string, strict bool) Check {
	return func(pkt *pktoken.PKToken) error {
		if pkt.Cos == nil {
			if strict {
				return fmt.Errorf("missing required cosigner")
			}
			return nil
		}

		claims, err := pkt.ParseCosignerClaims()
		if err != nil {
			return err
		}

		if claims.Issuer != issuer {
			return fmt.Errorf("expected cosigner: %s, expected %s", claims.Issuer, issuer)
		}

		return nil
	}
}
