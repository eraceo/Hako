package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/storage"
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
			name:        "Initialize vault with generate-keyfile alias",
			args:        []string{"--generate-keyfile", "--argon-memory=1024", "--argon-iter=1"},
			vaultPath:   "gen_kf_init.vault",
			keyfilePath: "gen_kf_init.key",
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
			isolateCLIEnv(t, true)

			// Ensure absolute isolated paths to avoid cross-test contamination
			absVaultPath := filepath.Clean(filepath.Join(tempDir, tt.vaultPath))

			absKeyPath := "none"
			if tt.keyfilePath != "" {
				absKeyPath = filepath.Clean(filepath.Join(tempDir, tt.keyfilePath))
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
				if tt.keyfilePath != "" && (strings.Contains(strings.Join(cmdArgs, " "), "--gen-keyfile") || strings.Contains(strings.Join(cmdArgs, " "), "--generate-keyfile")) {
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

func TestInitCmd_ConfigAndValidation(t *testing.T) {
	t.Run("Rejects excessive Argon2 memory before creating directories or config", func(t *testing.T) {
		isolateCLIEnv(t, false)
		subDir := filepath.Join(t.TempDir(), "nested_should_not_exist")
		vaultPath := filepath.Join(subDir, "vault.hako")
		customCfg := filepath.Join(t.TempDir(), "custom_cfg.yaml")

		cmdArgs := []string{
			"init",
			"--argon-memory=1048576",
			"--vault=" + vaultPath,
			"--keyfile=none",
			"--config=" + customCfg,
		}
		_, err := executeCommandWithMocks(t, cmdArgs, "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "argon2 memory must be at most 524288 KiB")
		assert.NoDirExists(t, subDir)
		assert.NoFileExists(t, customCfg)
	})

	t.Run("Uses Argon2 defaults from config file when flags omitted", func(t *testing.T) {
		isolateCLIEnv(t, false)
		tmp := t.TempDir()
		if runtime.GOOS != osWindows {
			// #nosec G302 -- Tests require 0700 to pass vault directory security checks
			require.NoError(t, os.Chmod(tmp, 0700))
		}
		cfgPath := filepath.Join(tmp, "cfg.yaml")
		vaultPath := filepath.Join(tmp, "cfg_vault.hako")

		yamlCfg := []byte("vault_path: \"" + filepath.ToSlash(vaultPath) + "\"\n" +
			"keyfile_path: \"none\"\n" +
			"argon2:\n  memory_kib: 2048\n  iterations: 2\n  parallelism: 2\n")
		// #nosec G306 -- Test configuration file
		require.NoError(t, os.WriteFile(cfgPath, yamlCfg, 0600))

		cmdArgs := []string{"init", "--config=" + cfgPath, "--vault=" + vaultPath, "--keyfile=none"}
		_, err := executeCommandWithMocks(t, cmdArgs, "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n")
		require.NoError(t, err)

		vf := storage.NewVaultFile(vaultPath)
		v, loadErr := vf.Load(context.Background(), []byte("VeryStrongMasterPass123!"), nil)
		require.NoError(t, loadErr)
		defer v.Zero()

		hdr := vf.Header()
		assert.Equal(t, uint32(2048), hdr.Argon2Params.Memory)
		assert.Equal(t, uint32(2), hdr.Argon2Params.Iterations)
		assert.Equal(t, uint8(2), hdr.Argon2Params.Parallelism)
	})

	t.Run("Creates default config at custom --config path and honors --argon-parallelism", func(t *testing.T) {
		isolateCLIEnv(t, false)
		tmp := t.TempDir()
		if runtime.GOOS != osWindows {
			// #nosec G302 -- Tests require 0700 to pass vault directory security checks
			require.NoError(t, os.Chmod(tmp, 0700))
		}
		customCfg := filepath.Join(tmp, "custom_sub", "hako.yaml")
		vaultPath := filepath.Join(tmp, "p_vault.hako")

		cmdArgs := []string{
			"init",
			"--config=" + customCfg,
			"--vault=" + vaultPath,
			"--keyfile=none",
			"--argon-memory=1024",
			"--argon-iter=1",
			"--argon-parallelism=2",
		}
		_, err := executeCommandWithMocks(t, cmdArgs, "VeryStrongMasterPass123!\nVeryStrongMasterPass123!\n")
		require.NoError(t, err)
		assert.FileExists(t, customCfg)

		vf := storage.NewVaultFile(vaultPath)
		v, loadErr := vf.Load(context.Background(), []byte("VeryStrongMasterPass123!"), nil)
		require.NoError(t, loadErr)
		defer v.Zero()

		assert.Equal(t, uint8(2), vf.Header().Argon2Params.Parallelism)
	})
}
