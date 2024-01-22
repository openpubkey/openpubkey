package verifier

import (
	"fmt"

	"github.com/openpubkey/openpubkey/gq"
	"github.com/openpubkey/openpubkey/pktoken"
)

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")
var _ Option = GQOnly

type Option func(*pktoken.PKToken) error

func GQOnly(pkt *pktoken.PKToken) error {
	alg, ok := pkt.ProviderAlgorithm()
	if !ok {
		return fmt.Errorf("missing provider algorithm header")
	}

	if alg != gq.GQ256 {
		return ErrNonGQUnsupported
	}
	return nil
}
