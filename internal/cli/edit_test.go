package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
)

type editTestCase struct {
	name           string
	args           []string
	simulatedInput string
	expectedOutput string
	expectedError  string
	// verifyFunc is a closure that runs AFTER the command execution to inspect the vault state.
	verifyFunc func(t *testing.T, v *secrets.Vault)
}

func getEditCmdTestCases(testMasterPass string) []editTestCase {
	return []editTestCase{
		{
			name: "Interactive edit of all fields",
			args: []string{"edit", "targetEntry"},
			// Inputs mapped to prompts: MasterPass -> Username -> Password -> URL -> Notes -> Tags
			simulatedInput: testMasterPass + "\n" +
				"newUser\n" +
				"NewSuperPass2024!\n" +
				"https://new.com\n" +
				"new notes\n" +
				"tag1,tag2\n",
			expectedOutput: "Entry 'targetEntry' updated successfully",
			verifyFunc: func(t *testing.T, v *secrets.Vault) {
				entry := v.GetEntryByName("targetEntry")
				require.NotNil(t, entry)

				_ = entry.Username.Access(func(b []byte) error {
					assert.Equal(t, []byte("newUser"), b)
					return nil
				})
				_ = entry.Password.Access(func(b []byte) error {
					assert.Equal(t, []byte("NewSuperPass2024!"), b)
					return nil
				})
				_ = entry.URL.Access(func(b []byte) error {
					assert.Equal(t, []byte("https://new.com"), b)
					return nil
				})
				assert.ElementsMatch(t, []string{"tag1", "tag2"}, entry.Tags)
			},
		},
		{
			name: "Keep existing fields when prompts are left blank",
			args: []string{"edit", "targetEntry"},
			// MasterPass + 5 empty Enter keys (\n) to skip updating any field
			simulatedInput: testMasterPass + "\n\n\n\n\n\n",
			expectedOutput: "Entry 'targetEntry' updated successfully",
			verifyFunc: func(t *testing.T, v *secrets.Vault) {
				entry := v.GetEntryByName("targetEntry")
				require.NotNil(t, entry)

				// Assert the old data (created by setupTestVaultWithEntry) is still intact
				_ = entry.Username.Access(func(b []byte) error {
					assert.Equal(t, []byte("oldUser"), b)
					return nil
				})
				_ = entry.URL.Access(func(b []byte) error {
					assert.Equal(t, []byte("https://old.com"), b)
					return nil
				})
				assert.ElementsMatch(t, []string{"oldTag"}, entry.Tags)
			},
		},
		{
			name:           "Fails on non-existent entry",
			args:           []string{"edit", "missingEntry"},
			simulatedInput: testMasterPass + "\n",
			expectedError:  "not found: 'missingEntry'",
		},
		{
			name: "Succeeds with short password",
			args: []string{"edit", "targetEntry"},
			// Inputs: MasterPass -> Username (blank) -> Password (short) -> URL -> Notes -> Tags
			simulatedInput: testMasterPass + "\n\n123\n\n\n\n",
			expectedOutput: "updated successfully",
			verifyFunc: func(t *testing.T, v *secrets.Vault) {
				entry := v.GetEntryByName("targetEntry")
				require.NotNil(t, entry)
				accessErr := entry.Password.Access(func(b []byte) error {
					assert.Equal(t, []byte("123"), b)
					return nil
				})
				require.NoError(t, accessErr)
			},
		},
	}
}

func TestEditCmd(t *testing.T) {
	const testMasterPass = "masterpass123"
	tempDir := t.TempDir()
	tests := getEditCmdTestCases(testMasterPass)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			viper.Reset()

			vaultName := "edit_vault_" + strings.ReplaceAll(tt.name, " ", "_") + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			viper.Set("argon2_iterations", 1)
			viper.Set("argon2_memory", 1024)
			viper.Set("argon2_parallelism", 1)

			// Setup Vault State using the shared helper (Fixes DUPL)
			// This creates "targetEntry" with "oldUser", "OldPassword123!", etc.
			if tt.name == "Fails on non-existent entry" {
				setupTestVault(t, testVaultPath, testMasterPass, nil)
			} else {
				setupTestVaultWithEntry(t, testVaultPath, testMasterPass, "targetEntry")
			}

			// Prepare strict arguments
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

			// Execute target command
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.simulatedInput)

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Contains(t, actualOutput, tt.expectedOutput)

			// Post-Execution Verification
			if tt.verifyFunc != nil {
				vf := storage.NewVaultFile(testVaultPath)
				masterBytes := []byte(testMasterPass)
				defer memory.SecureZero(masterBytes)

				vault, err := vf.Load(context.Background(), masterBytes, nil)
				require.NoError(t, err, "Failed to reload vault for verification")

				tt.verifyFunc(t, vault)
			}
		})
	}
}
