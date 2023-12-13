package util

import "bytes"

func JoinJWTSegments(segments ...[]byte) []byte {
	return JoinBytes('.', segments...)
}

func JoinBytes(sep byte, things ...[]byte) []byte {
	return bytes.Join(things, []byte{sep})
}
