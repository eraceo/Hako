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

// addTestCase defines the structure for testing the 'add' command variations.
type addTestCase struct {
	name           string
	args           []string
	simulatedInput string
	expectedOutput string
	expectedError  string
	missingVault   bool
	verifyFunc     func(t *testing.T, entry *secrets.Entry)
}

func getAddCmdTestCases(testMasterPass string) []addTestCase {
	// Standard inputs for entry details to reuse in error cases
	// Flow: Username -> Password -> Confirm -> URL -> Notes -> Tags
	dummyEntryInputs := "dummyUser\ndummyPass123\ndummyPass123\n\n\n\n"

	return []addTestCase{
		{
			name: "Add interactive entry successfully",
			args: []string{"add", "newInteractiveEntry"},
			// Inputs Flow (Security-First Order):
			// Username
			// Password
			// Confirm Password
			// URL
			// Notes
			// Tags
			// Master Password (Late Unlock)
			simulatedInput: "myuser\n" +
				"mypassword123\n" +
				"mypassword123\n" +
				"https://hako.local\n" +
				"Test notes\n" +
				"tag1,tag2\n" +
				testMasterPass + "\n",
			expectedOutput: "Entry 'newInteractiveEntry' added successfully",
			verifyFunc: func(t *testing.T, entry *secrets.Entry) {
				accessErr := entry.Username.Access(func(b []byte) error {
					assert.Equal(t, []byte("myuser"), b)
					return nil
				})
				require.NoError(t, accessErr)

				accessErr = entry.Password.Access(func(b []byte) error {
					assert.Equal(t, []byte("mypassword123"), b)
					return nil
				})
				require.NoError(t, accessErr)
			},
		},
		{
			name: "Add entry via flags with generated password",
			args: []string{
				"add",
				"generatedEntry",
				"--user", "sysadmin",
				"--generate",
				"--length", "24",
				"--url", "https://prod.hako.local",
			},
			// Inputs Flow:
			// Master Password (optional prompts bypassed because flags are specified)
			simulatedInput: testMasterPass + "\n",
			expectedOutput: "Generated password:",
			verifyFunc: func(t *testing.T, entry *secrets.Entry) {
				accessErr := entry.Username.Access(func(b []byte) error {
					assert.Equal(t, []byte("sysadmin"), b)
					return nil
				})
				require.NoError(t, accessErr)

				accessErr = entry.URL.Access(func(b []byte) error {
					assert.Equal(t, []byte("https://prod.hako.local"), b)
					return nil
				})
				require.NoError(t, accessErr)
			},
		},
		{
			name: "Fails on duplicate entry name",
			args: []string{"add", "existingEntry"},
			// Inputs Flow:
			// Must provide entry details first to reach the duplicate check (post-vault-load)
			simulatedInput: dummyEntryInputs + testMasterPass + "\n",
			expectedError:  "already exists",
		},
		{
			name:         "Fails when vault is missing",
			args:         []string{"add", "someEntry"},
			missingVault: true,
			// Inputs Flow:
			// Must provide entry details first to reach vault loading
			simulatedInput: dummyEntryInputs + testMasterPass + "\n",
			expectedError:  "vault file not found",
		},
	}
}

func TestAddCmd(t *testing.T) {
	// #nosec G101 -- Mock credential strictly used for unit testing
	const testMasterPass = "super_secure_test_password"
	tempDir := t.TempDir()
	tests := getAddCmdTestCases(testMasterPass)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			viper.Reset()

			// Ensure absolute isolated path
			vaultName := "add_vault_" + strings.ReplaceAll(tt.name, " ", "_") + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			// Fast crypto parameters
			viper.Set("argon2_iterations", 1)
			viper.Set("argon2_memory", 1024)
			viper.Set("argon2_parallelism", 1)

			// Setup Vault State
			if tt.missingVault {
				testVaultPath = filepath.Join(tempDir, "this_does_not_exist.vault")
			} else {
				setupTestVault(t, testVaultPath, testMasterPass, []string{"existingEntry"})
			}

			// Prepare strict arguments
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

			// Execute target command with strictly mocked I/O
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.simulatedInput)

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.expectedError))
				return
			}

			require.NoError(t, err)
			assert.Contains(t, actualOutput, tt.expectedOutput)

			// Post-Execution Verification
			if tt.verifyFunc != nil {
				masterBytes := []byte(testMasterPass)
				defer memory.SecureZero(masterBytes)

				vf := storage.NewVaultFile(testVaultPath)
				v, loadErr := vf.Load(context.Background(), masterBytes, nil)
				require.NoError(t, loadErr, "Failed to reload vault after add")

				entryName := tt.args[1]
				addedEntry := v.GetEntryByName(entryName)
				require.NotNil(t, addedEntry, "The newly added entry should exist in the vault")

				tt.verifyFunc(t, addedEntry)
			}
		})
	}
}
