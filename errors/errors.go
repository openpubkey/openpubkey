package errors

import "fmt"

var ErrNonGQUnsupported = fmt.Errorf("non-GQ signatures are not supported")
