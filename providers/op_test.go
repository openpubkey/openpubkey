package providers

import (
	"os"
	"testing"
)

func TestGetEnvVar(t *testing.T) {
	originalEnv := os.Getenv("TEST_ENV_VAR")
	os.Setenv("TEST_ENV_VAR", "test value")
	defer os.Setenv("TEST_ENV_VAR", originalEnv)

	value, err := getEnvVar("TEST_ENV_VAR")
	if err != nil {
		t.Errorf("getEnvVar returned an error: %v", err)
	}
	if value != "test value" {
		t.Errorf("getEnvVar returned unexpected value: %s", value)
	}

	_, err = getEnvVar("NON_EXISTENT_ENV_VAR")
	if err == nil {
		t.Error("getEnvVar did not return an error for non-existent environment variable")
	}
}
