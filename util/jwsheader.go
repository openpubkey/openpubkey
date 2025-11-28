package util

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jws"
)

func HeadersAsMap(headers jws.Headers) (map[string]any, error) {
	headersMap := make(map[string]any)
	for _, key := range headers.Keys() {
		var value any
		if err := headers.Get(key, &value); err != nil {
			return nil, fmt.Errorf("get value for %s: %w", key, err)
		}
		headersMap[key] = value
	}

	return headersMap, nil
}
