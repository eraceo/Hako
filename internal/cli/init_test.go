package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type initTestCase struct {
	name             string
	args             []string // Additional args beyond "init" (e.g. --gen-keyfile, --argon-memory)
	simulatedInput   string
	vaultPath        string
	keyfilePath      string
	expectedContains []string
	expectedError    string
	createDummyVault bool // If true, creates a fake file to simulate vault already exists
	createDummyKey   bool // If true, creates a fake file to simulate keyfile already exists
}

func getInitCmdTestCases() []initTestCase {
	return []initTestCase{
		{
			name:      "Initialize standard vault successfully",
			args:      []string{"--argon-memory=1024", "--argon-iter=1"}, // Fast crypto for tests
			vaultPath: "std_init.vault",
			// Input: Strong password + confirmation
			simulatedInput: "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n",
			expectedContains: []string{
				"Vault initialized successfully at:",
			},
		},
		{
			name:        "Initialize vault with keyfile",
			args:        []string{"--gen-keyfile", "--argon-memory=1024", "--argon-iter=1"},
			vaultPath:   "kf_init.vault",
			keyfilePath: "kf_init.key",
			// Input: Strong password + confirmation
			simulatedInput: "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n",
			expectedContains: []string{
				"Keyfile generated at:",
				"Vault initialized successfully at:",
			},
		},
		{
			name:           "Fails on password mismatch",
			args:           []string{},
			vaultPath:      "mismatch.vault",
			simulatedInput: "VeryStrongMasterPass123!\nOopsTypoPassword123!\n",
			expectedError:  "passwords do not match",
		},
		{
			name:           "Fails on weak master password",
			args:           []string{},
			vaultPath:      "weak.vault",
			simulatedInput: "1234\n1234\n",
			expectedError:  "invalid master password",
		},
		{
			name:             "Fails if vault already exists",
			args:             []string{},
			vaultPath:        "existing.vault",
			simulatedInput:   "", // No input needed, it should fail before prompting
			expectedError:    "vault already exists",
			createDummyVault: true,
		},
		{
			name:           "Fails if keyfile already exists (prevents overwrite)",
			args:           []string{"--gen-keyfile"},
			vaultPath:      "kf_exists.vault",
			keyfilePath:    "existing.key",
			simulatedInput: "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n",
			expectedError:  "keyfile already exists",
			createDummyKey: true,
		},
		{
			name:           "Fails on too low Argon2 memory",
			args:           []string{"--argon-memory=512"}, // Less than 1024
			vaultPath:      "low_mem.vault",
			simulatedInput: "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n",
			expectedError:  "argon2 memory must be at least 1024 KiB",
		},
		{
			name:           "Fails on too low Argon2 iterations",
			args:           []string{"--argon-iter=0"}, // Less than 1
			vaultPath:      "low_iter.vault",
			simulatedInput: "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n",
			expectedError:  "argon2 iterations must be at least 1",
		},
	}
}

func TestInitCmd(t *testing.T) {
	tempDir := t.TempDir()
	tests := getInitCmdTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			viper.Reset()

			// Ensure absolute isolated paths to avoid cross-test contamination
			absVaultPath := filepath.Clean(filepath.Join(tempDir, tt.vaultPath))
			viper.Set("vault_path", absVaultPath)

			absKeyPath := "none"
			if tt.keyfilePath != "" {
				absKeyPath = filepath.Clean(filepath.Join(tempDir, tt.keyfilePath))
				viper.Set("keyfile_path", absKeyPath)
			} else {
				viper.Set("keyfile_path", "none")
			}

			// Setup Filesystem State (simulating existing files)
			if tt.createDummyVault {
				// #nosec G306 -- Test file dummy content
				_ = os.WriteFile(absVaultPath, []byte("dummy vault content"), 0600)
			}
			if tt.createDummyKey {
				// Only write if keypath is set
				if absKeyPath != "none" {
					// #nosec G306 -- Test file dummy content
					_ = os.WriteFile(absKeyPath, []byte("old key content"), 0600)
				}
			}

			// Prepare strict arguments
			cmdArgs := []string{"init"}
			cmdArgs = append(cmdArgs, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+absVaultPath, "--keyfile="+absKeyPath)

			// Execute target command with strictly mocked I/O
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.simulatedInput)

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				// Use ToLower to make matching case-insensitive for robustness
				assert.Contains(t, strings.ToLower(err.Error()), strings.ToLower(tt.expectedError))
				return
			}
			require.NoError(t, err)

			for _, expected := range tt.expectedContains {
				assert.Contains(t, actualOutput, expected)
			}

			// Post-Success Filesystem Verification
			if err == nil {
				// Verify the vault file was physically created
				assert.FileExists(t, absVaultPath)

				// Verify the keyfile if it was requested
				if tt.keyfilePath != "" && strings.Contains(strings.Join(cmdArgs, " "), "--gen-keyfile") {
					assert.FileExists(t, absKeyPath)

					// A secure keyfile should be exactly 256 bytes per secrets.GenerateKeyfile logic
					info, statErr := os.Stat(absKeyPath)
					require.NoError(t, statErr)
					assert.Equal(t, int64(256), info.Size())
				}
			}
		})
	}
}
