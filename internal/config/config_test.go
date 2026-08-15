package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_Defaults(t *testing.T) {
	// Set temp home/appdata to ensure no user config is read
	tmpDir := t.TempDir()
	t.Setenv("APPDATA", tmpDir)
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("XDG_DATA_HOME", tmpDir)

	cfg, err := Load("")
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.NotEmpty(t, cfg.VaultPath)
	assert.NotEmpty(t, cfg.KeyfilePath)
	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, uint32(65536), cfg.Argon2.MemoryKiB)
	assert.Equal(t, uint32(4), cfg.Argon2.Iterations)
	assert.Equal(t, uint8(4), cfg.Argon2.Parallelism)
	assert.NotEmpty(t, cfg.Clipboard.ToolPreference)
	assert.Equal(t, 15, cfg.Clipboard.Timeout)
}

func TestLoad_ConfigFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	configContent := `
vault_path: /tmp/vault.bin
keyfile_path: /tmp/keyfile
log_level: debug
argon2:
  memory_kib: 1024
  iterations: 1
  parallelism: 1
clipboard:
  tool_preference:
    - custom_clip
  timeout: 30
`
	err := os.WriteFile(configFile, []byte(configContent), 0600)
	require.NoError(t, err)

	cfg, err := Load(configFile)
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "/tmp/vault.bin", cfg.VaultPath)
	assert.Equal(t, "/tmp/keyfile", cfg.KeyfilePath)
	assert.Equal(t, "debug", cfg.LogLevel)
	assert.Equal(t, uint32(1024), cfg.Argon2.MemoryKiB)
	assert.Equal(t, uint32(1), cfg.Argon2.Iterations)
	assert.Equal(t, uint8(1), cfg.Argon2.Parallelism)
	assert.Equal(t, []string{"custom_clip"}, cfg.Clipboard.ToolPreference)
	assert.Equal(t, 30, cfg.Clipboard.Timeout)
}

func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name      string
		modConfig func(*Config)
		wantErr   string
	}{
		{
			name: "Empty Vault Path",
			modConfig: func(c *Config) {
				c.VaultPath = ""
			},
			wantErr: "vault_path cannot be empty",
		},
		{
			name: "Low Iterations",
			modConfig: func(c *Config) {
				c.Argon2.Iterations = 0
			},
			wantErr: "iterations must be at least 1",
		},
		{
			name: "Low Memory",
			modConfig: func(c *Config) {
				c.Argon2.MemoryKiB = 512
			},
			wantErr: "memory_kib must be at least 1024",
		},
		{
			name: "Negative Clipboard Timeout",
			modConfig: func(c *Config) {
				c.Clipboard.Timeout = -1
			},
			wantErr: "clipboard.timeout cannot be negative",
		},
		{
			name: "Negative Audit Max Size",
			modConfig: func(c *Config) {
				c.AuditMaxSizeMB = -1
			},
			wantErr: "audit_max_size_mb cannot be negative",
		},
		{
			name: "Negative Audit Max Backups",
			modConfig: func(c *Config) {
				c.AuditMaxBackups = -1
			},
			wantErr: "audit_max_backups cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _ := defaultConfig()
			tt.modConfig(cfg)

			err := cfg.Validate()
			require.Error(t, err)

			assert.True(t, errors.Is(err, ErrInvalidConfig), "Error should wrap ErrInvalidConfig")
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestExpandPath(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "Empty path",
			path:     "",
			expected: "",
		},
		{
			name:     "Absolute path",
			path:     "/absolute/path",
			expected: "/absolute/path",
		},
		{
			name:     "Home directory expansion",
			path:     "~/test",
			expected: filepath.Join(homeDir, "test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := expandPath(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnsureDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "subdir", "vault.bin")
	keyfilePath := filepath.Join(tmpDir, "subdir", "keyfile")
	auditPath := filepath.Join(tmpDir, "subdir", "audit.log")

	cfg := &Config{
		VaultPath:    vaultPath,
		KeyfilePath:  keyfilePath,
		AuditLogPath: auditPath,
	}

	err := EnsureDirectories(cfg)
	require.NoError(t, err)

	assert.DirExists(t, filepath.Dir(vaultPath))
	assert.DirExists(t, filepath.Dir(keyfilePath))
	assert.DirExists(t, filepath.Dir(auditPath))
}

func TestContext(t *testing.T) {
	cfg := &Config{
		VaultPath: "my-vault",
	}
	ctx := WithContext(context.Background(), cfg)
	require.NotNil(t, ctx)

	retrieved := FromContext(ctx)
	assert.Equal(t, cfg, retrieved)

	assert.Panics(t, func() {
		FromContext(context.Background())
	}, "Should panic if config is missing from context")
}

func TestCreateDefaultConfigFile(t *testing.T) {
	// Set temp env to redirect config directory
	tmpDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpDir)
	t.Setenv("HOME", tmpDir)

	// First time creation
	err := CreateDefaultConfigFile()
	require.NoError(t, err)

	configPath := filepath.Join(tmpDir, "hako", "config.yaml")
	assert.FileExists(t, configPath)

	// Second time creation (should not fail, returns nil without overwriting)
	err = CreateDefaultConfigFile()
	require.NoError(t, err)
}

func TestLoad_EnvOverrides(t *testing.T) {
	t.Setenv("HAKO_VAULT_PATH", "/env/vault.bin")
	t.Setenv("HAKO_KEYFILE_PATH", "/env/keyfile")
	t.Setenv("HAKO_AUDIT_LOG_PATH", "/env/audit.log")
	t.Setenv("HAKO_CLIPBOARD_TOOL", "wl-copy")

	cfg, err := Load("")
	require.NoError(t, err)

	assert.Equal(t, "/env/vault.bin", cfg.VaultPath)
	assert.Equal(t, "/env/keyfile", cfg.KeyfilePath)
	assert.Equal(t, "/env/audit.log", cfg.AuditLogPath)
	assert.Equal(t, []string{"wl-copy"}, cfg.Clipboard.ToolPreference)
}

func TestLoad_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid_config.yaml")
	// write malformed yaml
	err := os.WriteFile(invalidFile, []byte("invalid_yaml: : :"), 0600)
	require.NoError(t, err)

	_, err = Load(invalidFile)
	assert.Error(t, err)
}

func TestValidate_AdditionalErrors(t *testing.T) {
	cfg, err := defaultConfig()
	require.NoError(t, err)

	// low parallelism
	cfg.Argon2.Parallelism = 0
	err = cfg.Validate()
	assert.ErrorIs(t, err, ErrInvalidConfig)
	assert.Contains(t, err.Error(), "parallelism must be at least 1")
}

func TestExpandPath_HomeOnly(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := expandPath("~")
	require.NoError(t, err)
	assert.Equal(t, homeDir, result)
}

func TestEnsureDirectories_Empty(t *testing.T) {
	// Empty directory path shouldn't fail
	cfg := &Config{
		VaultPath:    "vault.bin",
		KeyfilePath:  "",
		AuditLogPath: ".",
	}
	err := EnsureDirectories(cfg)
	assert.NoError(t, err)
}

func TestCreateDefaultConfigFile_MkdirError(t *testing.T) {
	tmpDir := t.TempDir()
	// Create a file
	filePath := filepath.Join(tmpDir, "somefile")
	err := os.WriteFile(filePath, []byte("data"), 0600)
	require.NoError(t, err)

	// Set XDG_CONFIG_HOME to point to a subdirectory of the file
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(filePath, "subdir"))

	err = CreateDefaultConfigFile()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create config directory")
}

func TestWriteNewConfigFile_OpenError(t *testing.T) {
	err := writeNewConfigFile("/nonexistent-dir/config.yaml", "content")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create config file")
}

func TestGetConfigDir_Error(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("APPDATA", "")
	_, err := getConfigDir()
	assert.Error(t, err)
}
