package cli

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/storage"
)

func TestPasswdCmd(t *testing.T) {
	const currentMasterPass = "old_master_pass123!"
	const newMasterPass = "New_Sup3r_M@ster_Pass!"

	tempDir := t.TempDir()

	tests := []struct {
		name             string
		args             []string
		simulatedInput   string // Input sequence: Current Pass -> New Pass -> Confirm New Pass
		expectedContains []string
		expectedError    string
		setupVault       bool // If true, creates a fresh vault before running the test
	}{
		{
			name: "Change password successfully",
			args: []string{"passwd"},
			// Input sequence: Current Pass -> New Pass -> Confirm New Pass
			simulatedInput: currentMasterPass + "\n" + newMasterPass + "\n" + newMasterPass + "\n",
			expectedContains: []string{
				"Master password changed successfully",
			},
			setupVault: true,
		},
		{
			name: "Fails if current password is wrong",
			args: []string{"passwd"},
			// Wrong Current -> (New Pass/Confirm irrelevant as it fails early)
			simulatedInput: "wrong_password123!\n" + newMasterPass + "\n" + newMasterPass + "\n",
			expectedError:  "message authentication failed",
			setupVault:     true,
		},
		{
			name: "Fails if new password confirmation mismatches",
			args: []string{"passwd"},
			// Current -> New -> Mismatch
			simulatedInput: currentMasterPass + "\n" + newMasterPass + "\n" + "Typo_Pass123!\n",
			expectedError:  "passwords do not match",
			setupVault:     true,
		},
		{
			name: "Fails if new password is too weak",
			args: []string{"passwd"},
			// Validator rejects short passwords (< 8 chars)
			simulatedInput: currentMasterPass + "\n" + "1234\n" + "1234\n",
			expectedError:  "password too short (min 8 characters)",
			setupVault:     true,
		},
		{
			name:           "Fails when vault is missing",
			args:           []string{"passwd"},
			simulatedInput: currentMasterPass + "\n",
			expectedError:  "vault file not found",
			setupVault:     false, // Deliberately do not create a vault
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			viper.Reset()

			// removed global rootCmd silencing, handled in executeCommandWithMocks

			vaultName := "passwd_vault_" + tt.name + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			// Fast crypto for tests
			viper.Set("argon2_iterations", 1)
			viper.Set("argon2_memory", 1024)
			viper.Set("argon2_parallelism", 1)

			// Setup Vault State
			if tt.setupVault {
				// We reuse our universal fast helper from test_helpers.go
				setupTestVault(t, testVaultPath, currentMasterPass, []string{"targetEntry"})
			}

			// Prepare strict arguments
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

			// Execute target command with strictly mocked I/O
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.simulatedInput)

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				for _, expected := range tt.expectedContains {
					assert.Contains(t, actualOutput, expected)
				}
			}

			// Post-Success Cryptographic Verification (Only for successful changes)
			if tt.name == "Change password successfully" && err == nil {
				vf := storage.NewVaultFile(testVaultPath)

				// A. Trying to open with OLD password MUST FAIL
				oldBytes := []byte(currentMasterPass)
				// Defer zeroing is good practice even in tests
				defer memory.SecureZero(oldBytes)

				_, errOld := vf.Load(context.Background(), oldBytes, nil)
				require.Error(t, errOld, "Vault should NOT open with the old password anymore")

				// B. Trying to open with NEW password MUST SUCCEED
				newBytes := []byte(newMasterPass)
				defer memory.SecureZero(newBytes)

				vault, errNew := vf.Load(context.Background(), newBytes, nil)
				require.NoError(t, errNew, "Vault MUST open with the new password")

				// C. Data Integrity Check: The entries must survive the re-encryption
				// We must defer destroying the vault entries to avoid mlock leaks
				defer func() {
					for _, e := range vault.Entries {
						e.Zero()
					}
				}()

				entry := vault.GetEntryByName("targetEntry")
				require.NotNil(t, entry, "Data should be intact after password change")
			}
		})
	}
}
