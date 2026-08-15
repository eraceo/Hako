package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
)

const osWindows = "windows"

// TestCase represents a standardized test case for CLI commands.
type TestCase struct {
	Name             string
	Args             []string
	SimulatedInput   string
	ExpectedContains []string
	ExpectedError    string
	MissingVault     bool
	// SetupVault allows custom vault initialization per test case
	SetupVault func(t *testing.T, testVaultPath string)
}

// RunCLICommandTest executes a standard TestCase, enforcing global test state
// resets, isolated environments, and mock strictness.
func RunCLICommandTest(t *testing.T, tt TestCase) {
	t.Run(tt.Name, func(t *testing.T) {
		// Clean Environment
		viper.Reset()

		// Fast crypto parameters to speed up tests significantly and avoid CI timeouts
		viper.Set("argon2_iterations", 1)
		viper.Set("argon2_memory", 1024)
		viper.Set("argon2_parallelism", 1)

		// Setup Vault State in an isolated temporary directory

		// file locking (flock) often hangs or fails in some containerized envs.
		if runtime.GOOS == "linux" && os.Getenv("WSL_DISTRO_NAME") != "" {
			t.Setenv("TMPDIR", "/tmp")
		}

		tempDir := t.TempDir()
		if runtime.GOOS != osWindows {
			// #nosec G302 -- Tests specifically demand 0700 to pass internal security audits
			require.NoError(t, os.Chmod(tempDir, 0700), "Failed to secure test directory permissions to 0700")
		}

		// Normalize Vault Path
		safeName := strings.ReplaceAll(tt.Name, " ", "_")
		safeName = strings.ReplaceAll(safeName, "/", "_") // Avoid path injection in test names
		vaultName := "vault_" + safeName + ".hako"
		testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

		if tt.MissingVault {
			// Point to a non-existent file
			testVaultPath = filepath.Join(tempDir, "this_does_not_exist.vault")
		} else if tt.SetupVault != nil {
			// Run custom setup logic
			tt.SetupVault(t, testVaultPath)
		}

		// Prepare strict arguments
		// We inject the vault path and disable keyfile to ensure isolation from host env
		cmdArgs := append([]string{}, tt.Args...)
		cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

		// Execute target command with strictly mocked I/O
		actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.SimulatedInput)

		// Assertions
		if tt.ExpectedError != "" {
			require.Error(t, err, "Expected an error but got nil")
			assert.Contains(t, err.Error(), tt.ExpectedError, "Error message mismatch")
			return // Expected an error, stop further assertions
		}

		// If no error expected, ensure we got none
		require.NoError(t, err, "Unexpected command failure: %v", err)

		// Verify multiple expected outputs dynamically
		for _, expectedStr := range tt.ExpectedContains {
			assert.Contains(t, actualOutput, expectedStr, "Output missing expected substring")
		}
	})
}

// executeCommandWithMocks executes the root command with mocked stdin and captured stdout AND stderr.
// It creates a FRESH command tree for every execution to prevent flag pollution.
func executeCommandWithMocks(t *testing.T, args []string, stdinInput string) (string, error) {
	t.Helper()

	// Instantiate a fresh RootCmd for this specific execution.
	rootCmd := NewRootCmd()

	// Silence help menu spam in tests to keep logs clean
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	// Mock Stdin synchronously
	rIn, wIn, err := os.Pipe()
	require.NoError(t, err, "Failed to create stdin pipe")

	if stdinInput != "" {
		_, err = wIn.WriteString(stdinInput)
		require.NoError(t, err, "Failed to write to stdin mock")
	}
	_ = wIn.Close()

	oldStdin := os.Stdin
	os.Stdin = rIn
	defer func() {
		os.Stdin = oldStdin
		_ = rIn.Close()
	}()

	// Mock Stdout
	rOut, wOut, err := os.Pipe()
	require.NoError(t, err, "Failed to create stdout pipe")
	oldStdout := os.Stdout
	os.Stdout = wOut

	rErr, wErr, err := os.Pipe()
	require.NoError(t, err, "Failed to create stderr pipe")
	oldStderr := os.Stderr
	os.Stderr = wErr

	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	// Read Stdout and Stderr concurrently to prevent deadlock
	outC := make(chan string)
	errC := make(chan string)

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rOut)
		outC <- buf.String()
	}()

	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, rErr)
		errC <- buf.String()
	}()

	// Execute Command with safe context
	cmdArgs := make([]string, len(args))
	copy(cmdArgs, args)
	rootCmd.SetArgs(cmdArgs)

	err = rootCmd.ExecuteContext(context.Background())

	// Close writers to release the readers
	_ = wOut.Close()
	_ = wErr.Close()

	// Collect output
	stdoutOutput := <-outC
	stderrOutput := <-errC

	_ = rOut.Close()
	_ = rErr.Close()

	// Return combined output so assertions find text regardless of stream
	return stdoutOutput + "\n" + stderrOutput, err
}

// setupTestVault creates a temporary vault file for testing and optionally populates it with empty entries.
func setupTestVault(t *testing.T, path, masterPass string, entryNames []string) {
	t.Helper()

	dir := filepath.Dir(path)
	if runtime.GOOS != osWindows {
		// #nosec G302 -- Tests specifically demand 0700 to pass internal security audits
		require.NoError(t, os.Chmod(dir, 0700), "Failed to secure test directory permissions to 0700")
	}

	vaultFile := storage.NewVaultFile(path)
	masterBytes := []byte(masterPass)
	defer memory.SecureZero(masterBytes)

	// Initialize with fast crypto to prevent test timeout in CI pipelines
	fastParams := crypto.Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    16,
		KeySize:     32,
	}
	err := vaultFile.Initialize(context.Background(), masterBytes, nil, fastParams)
	require.NoError(t, err, "Failed to initialize test vault")

	if len(entryNames) > 0 {
		// Load back to populate
		vault, err := vaultFile.Load(context.Background(), masterBytes, nil)
		require.NoError(t, err)

		defer func() {
			for _, e := range vault.Entries {
				e.Zero()
			}
		}()

		for _, name := range entryNames {
			passBytes := []byte("password123")
			entry, entryErr := secrets.NewEntry(
				name,
				[]byte("testuser"),
				passBytes,
				[]byte("http://example.com"),
				[]byte("notes"),
				[]string{"tag1"},
			)
			require.NoError(t, entryErr)
			vault.AddEntry(entry)
		}

		err = vaultFile.Save(context.Background(), vault, masterBytes, nil)
		require.NoError(t, err, "Failed to save populated test vault")
	}
}

// setupTestVaultWithEntry creates a vault and populates it with a specific full entry.
func setupTestVaultWithEntry(t *testing.T, path, masterPass string, entryName string) {
	t.Helper()

	dir := filepath.Dir(path)
	if runtime.GOOS != osWindows {
		// #nosec G302 -- Tests specifically demand 0700 to pass internal security audits
		require.NoError(t, os.Chmod(dir, 0700))
	}

	vf := storage.NewVaultFile(path)
	masterBytes := []byte(masterPass)
	defer memory.SecureZero(masterBytes)

	fastParams := crypto.Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    16,
		KeySize:     32,
	}
	err := vf.Initialize(context.Background(), masterBytes, nil, fastParams)
	require.NoError(t, err)

	vault, err := vf.Load(context.Background(), masterBytes, nil)
	require.NoError(t, err)

	oldPass := []byte("OldPassword123!")
	entry, err := secrets.NewEntry(
		entryName,
		[]byte("oldUser"),
		oldPass,
		[]byte("https://old.com"),
		[]byte("old notes"),
		[]string{"oldTag"},
	)
	require.NoError(t, err)

	vault.AddEntry(entry)
	err = vf.Save(context.Background(), vault, masterBytes, nil)
	require.NoError(t, err)
}

// captureOutput captures stdout from a function execution.
func captureOutput(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)

	origStdout := os.Stdout
	os.Stdout = w

	outC := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		outC <- buf.String()
	}()

	f()

	_ = w.Close()
	os.Stdout = origStdout
	return <-outC
}
