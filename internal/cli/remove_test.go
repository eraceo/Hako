package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type removeTestCase struct {
	name           string
	args           []string
	stdinInput     string
	setupEntries   []string
	expectedOutput string
	expectedErr    string
}

func getRemoveCmdTestCases() []removeTestCase {
	return []removeTestCase{
		{
			name:           "Force remove entry by name successfully",
			args:           []string{"rm", "Github", "-f"},
			stdinInput:     "masterpass123\n",
			setupEntries:   []string{"Github", "Twitter"},
			expectedOutput: "Entry 'Github' removed successfully",
			expectedErr:    "",
		},
		{
			name:           "Remove entry with confirmation (Yes)",
			args:           []string{"rm", "Twitter"},
			stdinInput:     "masterpass123\ny\n",
			setupEntries:   []string{"Twitter"},
			expectedOutput: "Entry 'Twitter' removed successfully",
			expectedErr:    "",
		},
		{
			name:           "Cancel remove entry with confirmation (No)",
			args:           []string{"rm", "Twitter"},
			stdinInput:     "masterpass123\nn\n",
			setupEntries:   []string{"Twitter"},
			expectedOutput: "Deletion canceled.",
			expectedErr:    "",
		},
		{
			name:           "Fail when entry is not found",
			args:           []string{"rm", "NonExistent", "-f"},
			stdinInput:     "masterpass123\n",
			setupEntries:   []string{"Github"},
			expectedOutput: "",
			// Corrected expectation to match actual error format
			expectedErr: "not found: 'NonExistent'",
		},
		{
			name:           "Fail on missing arguments",
			args:           []string{"rm"},
			stdinInput:     "",
			setupEntries:   []string{},
			expectedOutput: "",
			expectedErr:    "accepts 1 arg(s), received 0",
		},
	}
}

func TestRemoveCmd(t *testing.T) {
	tempDir := t.TempDir()
	tests := getRemoveCmdTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			vaultName := "vault_" + strings.ReplaceAll(tt.name, " ", "_") + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			// Use fast crypto parameters for tests to prevent timeouts
			viper.Set("argon2_iterations", 1)
			viper.Set("argon2_memory", 1024)
			viper.Set("argon2_parallelism", 1)

			if len(tt.setupEntries) > 0 {
				setupTestVault(t, testVaultPath, "masterpass123", tt.setupEntries)
			}

			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

			// executeCommandWithMocks handles stdout capture and stdin pipe
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.stdinInput)

			if tt.expectedErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				require.NoError(t, err)
				assert.Contains(t, actualOutput, tt.expectedOutput)
			}
		})
	}
}
