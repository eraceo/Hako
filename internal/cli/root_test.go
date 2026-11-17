package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/audit"
)

func TestRootCmd_InitConfig(t *testing.T) {
	tempDir := t.TempDir()

	// Define absolute paths for tests to bypass OS-specific default generation
	customVault := filepath.Join(tempDir, "custom_vault.bin")
	customKeyfile := filepath.Join(tempDir, "custom_keyfile")

	yamlVault := filepath.Join(tempDir, "yaml_vault.bin")
	yamlKeyfile := filepath.Join(tempDir, "yaml_keyfile")

	tests := []struct {
		name              string
		cfgFile           string
		vaultPath         string
		keyfile           string
		verbose           bool
		setupViper        func()
		expectedVaultPath string
		expectedKeyfile   string
		expectedLogLevel  string
	}{
		{
			name:              "CLI Flags override defaults",
			vaultPath:         customVault,
			keyfile:           customKeyfile,
			verbose:           true,
			setupViper:        func() {}, // No setup, rely entirely on CLI flags
			expectedVaultPath: customVault,
			expectedKeyfile:   customKeyfile,
			expectedLogLevel:  "debug", // Overridden by --verbose
		},
		{
			name:              "Keyfile=none clears the keyfile path",
			keyfile:           "none",
			vaultPath:         customVault, // Force vault to avoid local user dir resolution
			setupViper:        func() {},
			expectedVaultPath: customVault,
			expectedKeyfile:   "", // Cleared by "none"
			expectedLogLevel:  "info",
		},
		{
			name:    "Viper config file sets defaults",
			cfgFile: filepath.Join(tempDir, "hako_test_config.yaml"),
			setupViper: func() {
				// Create a physical dummy config file
				configPath := filepath.Join(tempDir, "hako_test_config.yaml")
				// Write YAML with normalized paths (forward slashes work everywhere)
				configData := []byte("vault_path: \"" + filepath.ToSlash(yamlVault) + "\"\n" +
					"keyfile_path: \"" + filepath.ToSlash(yamlKeyfile) + "\"\n" +
					"log_level: \"error\"\n")
				// #nosec G306 -- Test file permissions
				_ = os.WriteFile(configPath, configData, 0600)
			},
			expectedVaultPath: filepath.ToSlash(yamlVault),
			expectedKeyfile:   filepath.ToSlash(yamlKeyfile),
			expectedLogLevel:  "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateCLIEnv(t, false)

			if tt.setupViper != nil {
				tt.setupViper()
			}

			// Call initConfig directly
			cfg, err := initConfig(tt.cfgFile, tt.vaultPath, tt.keyfile, tt.verbose)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedVaultPath, cfg.VaultPath)
			assert.Equal(t, tt.expectedKeyfile, cfg.KeyfilePath)
			assert.Equal(t, tt.expectedLogLevel, cfg.LogLevel)
		})
	}
}

func TestRootCmd_NoSpuriousAuditOnUtilityCommands(t *testing.T) {
	t.Run("version and completion do not initialize or write audit log", func(t *testing.T) {
		isolateCLIEnv(t, false)
		auditPath := filepath.Join(t.TempDir(), "no_write_audit.log")
		t.Setenv("HAKO_AUDIT_LOG_PATH", auditPath)

		_, err := executeCommandWithMocks(t, []string{"version"}, "")
		require.NoError(t, err)
		assert.NoFileExists(t, auditPath)

		_, err = executeCommandWithMocks(t, []string{"completion", "bash"}, "")
		require.NoError(t, err)
		assert.NoFileExists(t, auditPath)
	})

	t.Run("audit verify-logs verifies existing chain without appending vault_load", func(t *testing.T) {
		isolateCLIEnv(t, false)
		auditDir := filepath.Join(t.TempDir(), "logs")
		require.NoError(t, os.MkdirAll(auditDir, 0700))
		auditPath := filepath.Join(auditDir, "audit.log")
		t.Setenv("HAKO_AUDIT_LOG_PATH", auditPath)

		logger := audit.NewLogger(auditPath, true)
		logger.LogEvent(audit.EventVaultInit, true, "seed event", nil)

		beforeBytes, err := os.ReadFile(auditPath) // #nosec G304
		require.NoError(t, err)

		output, err := executeCommandWithMocks(t, []string{"audit", "verify-logs"}, "")
		require.NoError(t, err)
		assert.Contains(t, output, "VERIFIED. Checked 1 events")

		afterBytes, err := os.ReadFile(auditPath) // #nosec G304
		require.NoError(t, err)
		assert.Equal(t, string(beforeBytes), string(afterBytes))
		assert.NotContains(t, strings.ToLower(string(afterBytes)), "vault_load")
	})
}
