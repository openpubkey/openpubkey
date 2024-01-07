package cosigner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthIDs(t *testing.T) {
	hmacKey := []byte{0x1, 0x2, 0x3}

	aid := NewAuthIDIssuer(hmacKey)

	// Test if we get the same value if we supply exact the same time
	unixTime := uint64(5)
	authID1, err := aid.CreateAuthID(unixTime)
	require.NoError(t, err, "failed to create auth ID")

	authID2, err := aid.CreateAuthID(unixTime)
	require.NoError(t, err, "failed to create auth ID")
	require.NotEqualValues(t, authID1, authID2)

	require.Equal(t, "644117927902f52d3949804c7ce417509d9437eb1240a9bf75725c9f61d5b424", authID1)
	require.Equal(t, "f7d16adcef9f7d0e72139f0edae98db64c2db1f0cb8b59468d4766e91126f4eb", authID2)
}
