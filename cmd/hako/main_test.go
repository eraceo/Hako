package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRun_Success verifies that a valid command execution returns exit code 0.
func TestRun_Success(t *testing.T) {
	// Backup global OS arguments and restore them automatically after the test
	oldArgs := os.Args
	t.Cleanup(func() {
		os.Args = oldArgs
	})

	// Inject safe arguments that will trigger a successful execution
	// The root command without arguments or with --help usually returns 0.
	os.Args = []string{"hako", "--help"}

	// Execute
	exitCode := run()

	// Assert
	assert.Equal(t, 0, exitCode, "Expected exit code 0 for a successful command execution")
}

// TestRun_Failure verifies that an invalid command execution returns exit code 1
// and correctly writes the error message to standard error (os.Stderr).
func TestRun_Failure(t *testing.T) {
	// Backup global OS state
	oldArgs := os.Args
	oldStderr := os.Stderr
	t.Cleanup(func() {
		os.Args = oldArgs
		os.Stderr = oldStderr
	})

	// Inject invalid arguments to force a Cobra routing error
	os.Args = []string{"hako", "this_command_absolutely_does_not_exist"}

	// Mock Stderr using an OS pipe to capture the output securely
	r, w, err := os.Pipe()
	require.NoError(t, err, "Failed to create OS pipe for Stderr")
	os.Stderr = w

	// Concurrently read from the pipe to prevent buffer deadlocks
	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	// Execute
	exitCode := run()

	// Close the writer to signal EOF to the concurrent reader
	err = w.Close()
	require.NoError(t, err)

	// Wait for the reader to finish and capture the output
	stderrOutput := <-outC
	_ = r.Close()

	// Assertions
	assert.Equal(t, 1, exitCode, "Expected exit code 1 for a failed command execution")

	// Verify our custom error formatting from main.go: fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	assert.True(t, strings.HasPrefix(stderrOutput, "Error: "),
		"Stderr output should start with the standard 'Error: ' prefix. Got: %q", stderrOutput)

	// Verify Cobra's underlying error is present
	assert.Contains(t, stderrOutput, "unknown command",
		"Stderr should contain the specific Cobra routing error")
}
