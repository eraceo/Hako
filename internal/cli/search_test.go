package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSearchCmd(t *testing.T) {
	// Isolate tests in a temporary directory
	tempDir := t.TempDir()

	tests := []struct {
		name           string
		args           []string
		stdinInput     string   // Simulated Stdin (Master Password)
		setupEntries   []string // Entries to create before running search
		expectedOutput string
		expectedErr    string
	}{
		{
			name:           "Search finds exact existing entry",
			args:           []string{"search", "Github"},
			stdinInput:     "masterpass123\n",
			setupEntries:   []string{"Github", "Twitter"},
			expectedOutput: "Found 1 entries:",
			expectedErr:    "",
		},
		{
			name:           "Search finds multiple partial matches",
			args:           []string{"search", "Git"},
			stdinInput:     "masterpass123\n",
			setupEntries:   []string{"Github", "Gitlab", "Twitter"},
			expectedOutput: "Found 2 entries:",
			expectedErr:    "",
		},
		{
			name:           "Search is case-insensitive",
			args:           []string{"search", "tWiTtEr"},
			stdinInput:     "masterpass123\n",
			setupEntries:   []string{"Twitter", "Facebook"},
			expectedOutput: "Found 1 entries:",
			expectedErr:    "",
		},
		{
			name:         "Search yields no results (prevents pattern leak)",
			args:         []string{"search", "NonExistent"},
			stdinInput:   "masterpass123\n",
			setupEntries: []string{"Github"},
			// Security validation: ensure the user's input (which could be an accidental paste of a password)
			// is NOT reflected/echoed back onto the terminal.
			expectedOutput: "No entries found matching the provided pattern.",
			expectedErr:    "",
		},
		{
			name:           "Fail on missing arguments",
			args:           []string{"search"},
			stdinInput:     "",
			setupEntries:   []string{},
			expectedOutput: "",
			expectedErr:    "accepts 1 arg(s), received 0",
		},
		{
			name:           "Fail when vault is missing",
			args:           []string{"search", "Github"},
			stdinInput:     "",         // Will fail before asking for password
			setupEntries:   []string{}, // Do not create a vault
			expectedOutput: "",
			expectedErr:    "vault file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			// Global flags are now handled by NewRootCmd(), so no manual reset needed.
			viper.Reset()

			// Set absolute cross-platform isolated vault path
			vaultName := "vault_" + strings.ReplaceAll(tt.name, " ", "_") + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			// Inject isolated Viper configuration with "Fast Crypto" settings
			// to avoid argon2 iteration panics and ensure tests complete in milliseconds.
			viper.Set("argon2_iterations", 1)
			viper.Set("argon2_memory", 1024)
			viper.Set("argon2_parallelism", 1)

			// Black-box setup: Pre-populate the vault
			// Uses the extremely fast internal API helper from test_helpers.go
			if len(tt.setupEntries) > 0 {
				setupTestVault(t, testVaultPath, "masterpass123", tt.setupEntries)
			}

			// Prepare strict arguments
			// Explicitly inject the isolated vault and disable keyfile AND config file to bypass host env
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none", "--config=")

			// Execute target command with strictly mocked I/O
			// executeCommandWithMocks instantiates NewRootCmd(), guaranteeing isolation.
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.stdinInput)

			// Assertions
			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Contains(t, actualOutput, tt.expectedOutput)

				// Strict Security Assertion: If no entries are found, ensure the pattern is NOT echoed.
				// This prevents accidental leakage if a user pastes a password into the search field.
				if strings.Contains(actualOutput, "No entries found matching") && len(tt.args) > 1 {
					// We check tt.args[1] which contains the pattern (e.g., "NonExistent")
					assert.NotContains(t, actualOutput, tt.args[1], "CRITICAL: The search pattern must not be echoed to the console")
				}
			}
		})
	}
}
