package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/storage"
)

func TestRekeyCmd(t *testing.T) {
	const masterPass = "Master_Password_123!"

	tempDir := t.TempDir()

	tests := []struct {
		name             string
		args             []string
		simulatedInput   string
		expectedContains []string
		expectedError    string
		setupVault       bool
		checkNewParams   func(t *testing.T, vaultPath string)
	}{
		{
			name:           "Rekey successfully with custom parameters",
			args:           []string{"rekey", "--memory=2048", "--iterations=2", "--parallelism=2"},
			simulatedInput: masterPass + "\n",
			expectedContains: []string{
				"Vault rekeyed successfully",
				"Memory:",
				"Iterations:",
			},
			setupVault: true,
			checkNewParams: func(t *testing.T, vaultPath string) {
				vf := storage.NewVaultFile(vaultPath)
				vault, err := vf.Load(context.Background(), []byte(masterPass), nil)
				require.NoError(t, err)
				defer vault.Zero()

				header := vf.Header()
				assert.Equal(t, uint32(2048), header.Argon2Params.Memory)
				assert.Equal(t, uint32(2), header.Argon2Params.Iterations)
				assert.Equal(t, uint8(2), header.Argon2Params.Parallelism)
			},
		},
		{
			name:           "Rekey successfully with apply-config flag",
			args:           []string{"rekey", "--apply-config"},
			simulatedInput: masterPass + "\n",
			expectedContains: []string{
				"Vault rekeyed successfully",
			},
			setupVault: true,
			checkNewParams: func(t *testing.T, vaultPath string) {
				vf := storage.NewVaultFile(vaultPath)
				vault, err := vf.Load(context.Background(), []byte(masterPass), nil)
				require.NoError(t, err)
				defer vault.Zero()

				header := vf.Header()
				assert.Equal(t, uint32(1024), header.Argon2Params.Memory)
				assert.Equal(t, uint32(1), header.Argon2Params.Iterations)
				assert.Equal(t, uint8(1), header.Argon2Params.Parallelism)
			},
		},
		{
			name:           "Fails if password is wrong",
			args:           []string{"rekey", "--memory=2048"},
			simulatedInput: "wrong_password123!\n",
			expectedError:  "message authentication failed",
			setupVault:     true,
		},
		{
			name:           "Fails if memory parameter is below minimum",
			args:           []string{"rekey", "--memory=10"},
			simulatedInput: masterPass + "\n",
			expectedError:  "invalid memory setting",
			setupVault:     true,
		},
		{
			name:           "Fails if memory is explicitly set to 0",
			args:           []string{"rekey", "--memory=0"},
			simulatedInput: masterPass + "\n",
			expectedError:  "invalid memory setting",
			setupVault:     true,
		},
		{
			name:           "Fails if memory exceeds maximum",
			args:           []string{"rekey", "--memory=1048576"},
			simulatedInput: masterPass + "\n",
			expectedError:  "invalid memory setting",
			setupVault:     true,
		},
		{
			name:           "Fails when vault does not exist",
			args:           []string{"rekey"},
			simulatedInput: masterPass + "\n",
			expectedError:  "vault file not found",
			setupVault:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateCLIEnv(t, true)

			vaultName := "rekey_vault_" + strings.ReplaceAll(tt.name, " ", "_") + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			if tt.setupVault {
				setupTestVault(t, testVaultPath, masterPass, []string{"targetEntry"})
			}

			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.simulatedInput)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				for _, expectedStr := range tt.expectedContains {
					assert.Contains(t, actualOutput, expectedStr)
				}
				if tt.checkNewParams != nil {
					tt.checkNewParams(t, testVaultPath)
				}
			}
		})
	}

	t.Run("Apply-config updates vault parameters from custom config", func(t *testing.T) {
		isolateCLIEnv(t, false)
		vaultPath := filepath.Join(t.TempDir(), "custom_apply_cfg.hako")
		setupTestVault(t, vaultPath, masterPass, []string{"targetEntry"})

		cfgPath := filepath.Join(t.TempDir(), "rekey_cfg.yaml")
		yamlCfg := []byte("vault_path: \"" + filepath.ToSlash(vaultPath) + "\"\n" +
			"keyfile_path: \"none\"\n" +
			"argon2:\n  memory_kib: 2048\n  iterations: 2\n  parallelism: 2\n")
		// #nosec G306 -- Test configuration file
		require.NoError(t, os.WriteFile(cfgPath, yamlCfg, 0600))

		cmdArgs := []string{"rekey", "--apply-config", "--config=" + cfgPath, "--vault=" + vaultPath, "--keyfile=none"}
		output, err := executeCommandWithMocks(t, cmdArgs, masterPass+"\n")
		require.NoError(t, err)
		assert.Contains(t, output, "Vault rekeyed successfully")

		vf := storage.NewVaultFile(vaultPath)
		v, loadErr := vf.Load(context.Background(), []byte(masterPass), nil)
		require.NoError(t, loadErr)
		defer v.Zero()

		hdr := vf.Header()
		assert.Equal(t, uint32(2048), hdr.Argon2Params.Memory)
		assert.Equal(t, uint32(2), hdr.Argon2Params.Iterations)
		assert.Equal(t, uint8(2), hdr.Argon2Params.Parallelism)
	})
}
