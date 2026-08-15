package ui

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/memory"
)

// mockStdin is a robust helper that replaces os.Stdin with a pipe containing the desired input.
// It writes asynchronously to prevent Windows OS pipe buffer deadlocks (Windows limits pipes to 4096 bytes).
func mockStdin(t *testing.T, input string) func() {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	// We MUST write in a goroutine. If the input exceeds 4096 bytes (like in TestReadUnbufferedLine_TooLong),
	// a synchronous w.WriteString would block forever on Windows waiting for a reader to free up buffer space.
	go func() {
		defer w.Close() //nolint:errcheck // ALWAYS trigger EOF for the reader, even if write fails
		_, _ = w.WriteString(input)
	}()

	origStdin := os.Stdin
	os.Stdin = r

	return func() {
		os.Stdin = origStdin
		_ = r.Close()
	}
}

func TestPromptString(t *testing.T) {
	defer mockStdin(t, "test input\n")()

	result, err := PromptString("Enter something: ")
	require.NoError(t, err)
	defer memory.SecureZero(result)
	assert.Equal(t, []byte("test input"), result)
}

func TestPromptConfirm(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"Yes", "y\n", true},
		{"Yes full", "yes\n", true},
		{"No", "n\n", false},
		{"No full", "no\n", false},
		{"Other", "other\n", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer mockStdin(t, tt.input)()

			result, err := PromptConfirm("Confirm?")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPromptPassword_Fallback(t *testing.T) {
	defer mockStdin(t, "secret password\n")()

	result, err := PromptPassword("Password: ")
	require.NoError(t, err)

	// SECURITY: Tests must clean up sensitive byte slices too!
	defer memory.SecureZero(result)

	assert.Equal(t, []byte("secret password"), result)
}

func TestPromptChoice(t *testing.T) {
	defer mockStdin(t, "2\n")()

	choices := []string{"Option 1", "Option 2", "Option 3"}
	choice, err := PromptChoice("Select:", choices)
	require.NoError(t, err)
	assert.Equal(t, 1, choice) // 0-indexed
}

func TestReadUnbufferedLine_TooLong(t *testing.T) {
	// Generate a 4097 bytes input (1 byte over the 4096 limit)
	longInput := bytes.Repeat([]byte("a"), 4097)
	defer mockStdin(t, string(longInput))()

	_, err := readUnbufferedLine()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "input too long")
}

func TestPromptSecurePassword(t *testing.T) {
	defer mockStdin(t, "super_secure_vault_key\n")()

	securePass, err := PromptSecurePassword("Master Password: ")
	require.NoError(t, err)
	require.NotNil(t, securePass)

	// SECURITY: Always destroy enclaves in tests to prevent OS mlock crashes in CI.
	defer func() {
		_ = securePass.Destroy()
	}()

	// Verify the enclave contains the correct data without leaking it to a string.
	err = securePass.Access(func(b []byte) error {
		assert.Equal(t, []byte("super_secure_vault_key"), b)
		return nil
	})
	require.NoError(t, err)
}

func TestPromptSecurePasswordWithConfirmation_Match(t *testing.T) {
	// Two inputs separated by newline for the two prompts
	defer mockStdin(t, "match_pass_123\nmatch_pass_123\n")()

	securePass, err := PromptSecurePasswordWithConfirmation("Pass: ", "Confirm: ")
	require.NoError(t, err)
	require.NotNil(t, securePass)

	defer func() {
		_ = securePass.Destroy()
	}()

	err = securePass.Access(func(b []byte) error {
		assert.Equal(t, []byte("match_pass_123"), b)
		return nil
	})
	require.NoError(t, err)
}

func TestPromptSecurePasswordWithConfirmation_Mismatch(t *testing.T) {
	// Deliberately mismatched inputs
	defer mockStdin(t, "match_pass_123\nWRONG_pass_456\n")()

	securePass, err := PromptSecurePasswordWithConfirmation("Pass: ", "Confirm: ")

	// Ensure an error is returned and NO secure password enclave is leaked
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "passwords do not match")
	assert.Nil(t, securePass)
}

func TestPrintfFunctions(_ *testing.T) {
	// Just verify they don't panic
	PrintfSuccessf("Success %s", "msg")
	PrintfInfof("Info %s", "msg")
	PrintfWarningf("Warning %s", "msg")
	PrintfErrorf("Error %s", "msg")
}
