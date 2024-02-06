package reader

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReader(t *testing.T) {
	err := read()
	require.NoError(t, err)
}
