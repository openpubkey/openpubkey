package providers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetEnvVar(t *testing.T) {
	originalEnv := os.Getenv("TEST_ENV_VAR")
	os.Setenv("TEST_ENV_VAR", "test value")
	defer os.Setenv("TEST_ENV_VAR", originalEnv)

	_, err := getEnvVar("TEST_ENV_VAR")
	require.NoError(t, err)

	_, err = getEnvVar("NON_EXISTENT_ENV_VAR")
	require.Error(t, err)
}
