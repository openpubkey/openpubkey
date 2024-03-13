package util

import (
	"bytes"
	"encoding/json"
	"fmt"
)

func JoinJWTSegments(segments ...[]byte) []byte {
	return JoinBytes('.', segments...)
}

func JoinBytes(sep byte, things ...[]byte) []byte {
	return bytes.Join(things, []byte{sep})
}

func ParseJWTSegment(segment []byte, v any) error {
	segmentJSON, err := Base64DecodeForJWT(segment)
	if err != nil {
		return fmt.Errorf("error decoding segment: %w", err)
	}

	err = json.Unmarshal(segmentJSON, v)
	if err != nil {
		return fmt.Errorf("error parsing segment: %w", err)
	}

	return nil
}
