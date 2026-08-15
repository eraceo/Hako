package cli

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompletionCmd(t *testing.T) {
	tests := []struct {
		name             string
		args             []string
		expectedContains string
		expectedError    string
	}{
		{
			name:             "Generate Bash completion",
			args:             []string{"completion", "bash"},
			expectedContains: "# bash completion", // Standard bash header
		},
		{
			name:             "Generate Zsh completion",
			args:             []string{"completion", "zsh"},
			expectedContains: "#compdef",
		},
		{
			name:             "Generate Fish completion",
			args:             []string{"completion", "fish"},
			expectedContains: "complete -c", // Standard Fish completion command
		},
		{
			name:             "Generate PowerShell completion",
			args:             []string{"completion", "powershell"},
			expectedContains: "Register-ArgumentCompleter", // Standard PowerShell completion command
		},
		{
			name:          "Fails on missing shell argument",
			args:          []string{"completion"},
			expectedError: "accepts 1 arg(s), received 0",
		},
		{
			name:          "Fails on too many arguments",
			args:          []string{"completion", "bash", "zsh"},
			expectedError: "accepts 1 arg(s), received 2",
		},
		{
			name:          "Fails on unsupported shell",
			args:          []string{"completion", "cmd"},
			expectedError: "invalid argument \"cmd\" for \"hako completion\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			viper.Reset()
			// Global rootCmd references removed. Silencing is handled in helper.

			// Prepare strict arguments
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--keyfile=none") // Always bypass local config just in case

			// Execute target command with strictly mocked I/O
			// No Stdin ("") needed since generation is non-interactive
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, "")

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				// Use ToLower to handle slight variations in Cobra error messages across versions
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.expectedError))
				return
			}
			require.NoError(t, err)

			// We don't check the exact script content (as it changes with Cobra versions),
			// we just verify that it contains the shell-specific syntax markers.
			assert.Contains(t, actualOutput, tt.expectedContains)
		})
	}
}
