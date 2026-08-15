// Package config handles application configuration loading and parsing.
package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

type configKey struct{}

// WithContext returns a new context with the given configuration.
func WithContext(ctx context.Context, cfg *Config) context.Context {
	return context.WithValue(ctx, configKey{}, cfg)
}

// FromContext returns the configuration from the context.
// It panics if the configuration is not found, as it is a required dependency.
func FromContext(ctx context.Context) *Config {
	cfg, ok := ctx.Value(configKey{}).(*Config)
	if !ok {
		panic("config not found in context")
	}
	return cfg
}

const (
	osWindows = "windows"
	osDarwin  = "darwin"
)

// Config represents the application configuration.
// WARNING: This struct must NOT contain any sensitive data (e.g., passwords, keys, tokens).
type Config struct {
	VaultPath            string          `mapstructure:"vault_path" yaml:"vault_path"`
	KeyfilePath          string          `mapstructure:"keyfile_path" yaml:"keyfile_path"`
	AuditLogPath         string          `mapstructure:"audit_log_path" yaml:"audit_log_path"`
	AuditMaxSizeMB       int             `mapstructure:"audit_max_size_mb" yaml:"audit_max_size_mb"`
	AuditMaxBackups      int             `mapstructure:"audit_max_backups" yaml:"audit_max_backups"`
	AuditCompress        bool            `mapstructure:"audit_compress" yaml:"audit_compress"`
	AuditEnableHashChain bool            `mapstructure:"audit_enable_hash_chain" yaml:"audit_enable_hash_chain"`
	LogLevel             string          `mapstructure:"log_level" yaml:"log_level"`
	Argon2               Argon2Config    `mapstructure:"argon2" yaml:"argon2"`
	Clipboard            ClipboardConfig `mapstructure:"clipboard" yaml:"clipboard"`
}

// Argon2Config contains Argon2id parameters
type Argon2Config struct {
	MemoryKiB   uint32 `mapstructure:"memory_kib" yaml:"memory_kib"`
	Iterations  uint32 `mapstructure:"iterations" yaml:"iterations"`
	Parallelism uint8  `mapstructure:"parallelism" yaml:"parallelism"`
}

// ClipboardConfig contains clipboard settings
type ClipboardConfig struct {
	ToolPreference []string `mapstructure:"tool_preference" yaml:"tool_preference"`
	Timeout        int      `mapstructure:"timeout" yaml:"timeout"`
}

var (

	// ErrInvalidConfig is returned when configuration validation fails.
	ErrInvalidConfig = errors.New("validation error")
)

// getConfigDir returns the configuration directory for the current OS
func getConfigDir() (string, error) {
	if xdgConfigHome := os.Getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		return filepath.Join(xdgConfigHome, "hako"), nil
	}

	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}

	return filepath.Join(configDir, "hako"), nil
}

// getDataDir returns the data directory for the current OS
func getDataDir() (string, error) {
	if xdgDataHome := os.Getenv("XDG_DATA_HOME"); xdgDataHome != "" {
		return filepath.Join(xdgDataHome, "hako"), nil
	}

	switch runtime.GOOS {
	case osWindows:
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			localAppData = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(localAppData, "hako"), nil

	case osDarwin:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "hako"), nil

	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".local", "share", "hako"), nil
	}
}

// defaultConfig returns the hardcoded safe defaults.
func defaultConfig() (*Config, error) {
	dataDir, err := getDataDir()
	if err != nil {
		return nil, err
	}

	var toolPreference []string
	switch runtime.GOOS {
	case osWindows:
		toolPreference = []string{"win32api", "clip"}
	case osDarwin:
		toolPreference = []string{"pbcopy"}
	default:
		toolPreference = []string{"wl-copy", "xclip", "xsel"}
	}

	return &Config{
		VaultPath:            filepath.Join(dataDir, "vault.bin"),
		KeyfilePath:          filepath.Join(dataDir, "keyfile"),
		AuditLogPath:         filepath.Join(dataDir, "audit.log"),
		AuditMaxSizeMB:       10,
		AuditMaxBackups:      5,
		AuditCompress:        true,
		AuditEnableHashChain: true,
		LogLevel:             "info",
		Argon2: Argon2Config{
			MemoryKiB:   65536, // 64 MiB
			Iterations:  4,
			Parallelism: 4,
		},
		Clipboard: ClipboardConfig{
			ToolPreference: toolPreference,
			Timeout:        15,
		},
	}, nil
}

// Load loads configuration from file, environment, and defaults.
func Load(configFile string) (*Config, error) {
	// Get hardcoded defaults
	defaults, err := defaultConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to generate default config: %w", err)
	}

	// Initialize Viper with these defaults
	v := viper.New()
	if err := setupViper(v, configFile, defaults); err != nil {
		return nil, err
	}

	// Unmarshal into a fresh struct.
	finalCfg := *defaults

	if err := v.Unmarshal(&finalCfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Post-process (Environment overrides, path expansion)
	if err := postProcessConfig(&finalCfg); err != nil {
		return nil, err
	}

	// Validation (Sanity Checks)
	if err := finalCfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &finalCfg, nil
}

// setupViper initializes a viper instance with paths, env vars, and defaults.
func setupViper(v *viper.Viper, configFile string, defaults *Config) error {
	if configFile != "" {
		v.SetConfigFile(configFile)
	} else {
		configDir, err := getConfigDir()
		if err != nil {
			return fmt.Errorf("failed to get config directory: %w", err)
		}
		v.AddConfigPath(configDir)
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	// Environment variable support
	v.SetEnvPrefix("HAKO")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults in Viper
	v.SetDefault("vault_path", defaults.VaultPath)
	v.SetDefault("keyfile_path", defaults.KeyfilePath)
	v.SetDefault("audit_log_path", defaults.AuditLogPath)
	v.SetDefault("audit_max_size_mb", defaults.AuditMaxSizeMB)
	v.SetDefault("audit_max_backups", defaults.AuditMaxBackups)
	v.SetDefault("audit_compress", defaults.AuditCompress)
	v.SetDefault("audit_enable_hash_chain", defaults.AuditEnableHashChain)
	v.SetDefault("log_level", defaults.LogLevel)
	v.SetDefault("argon2.memory_kib", defaults.Argon2.MemoryKiB)
	v.SetDefault("argon2.iterations", defaults.Argon2.Iterations)
	v.SetDefault("argon2.parallelism", defaults.Argon2.Parallelism)
	v.SetDefault("clipboard.tool_preference", defaults.Clipboard.ToolPreference)
	v.SetDefault("clipboard.timeout", defaults.Clipboard.Timeout)

	if err := v.ReadInConfig(); err != nil {
		var configFileNotFoundError viper.ConfigFileNotFoundError
		if !errors.As(err, &configFileNotFoundError) {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	return nil
}

// postProcessConfig handles explicit environment overrides and path expansions.
//
// The manual os.Getenv calls below are intentional workarounds for a known
// Viper bug where AutomaticEnv does not correctly override values set via SetDefault.
func postProcessConfig(cfg *Config) error {
	if envVault := os.Getenv("HAKO_VAULT_PATH"); envVault != "" {
		cfg.VaultPath = envVault
	}
	if envKeyfile := os.Getenv("HAKO_KEYFILE_PATH"); envKeyfile != "" {
		cfg.KeyfilePath = envKeyfile
	}
	if envAudit := os.Getenv("HAKO_AUDIT_LOG_PATH"); envAudit != "" {
		cfg.AuditLogPath = envAudit
	}

	// Special Override: HAKO_CLIPBOARD_TOOL (singular)
	// Allows user to override the entire preference list with a single tool via ENV.
	if envTool := os.Getenv("HAKO_CLIPBOARD_TOOL"); envTool != "" {
		cfg.Clipboard.ToolPreference = []string{envTool}
	}

	// Expand home directory (~) in paths
	pathsToExpand := []*string{
		&cfg.VaultPath,
		&cfg.KeyfilePath,
		&cfg.AuditLogPath,
	}

	for _, p := range pathsToExpand {
		if *p != "" {
			expanded, err := expandPath(*p)
			if err != nil {
				return fmt.Errorf("failed to expand path %s: %w", *p, err)
			}
			*p = expanded
		}
	}

	// Special case: "none" means no keyfile.
	if strings.EqualFold(cfg.KeyfilePath, "none") {
		cfg.KeyfilePath = ""
	}

	return nil
}

// Validate performs sanity checks on the configuration.
func (c *Config) Validate() error {
	if c.VaultPath == "" {
		return fmt.Errorf("%w: vault_path cannot be empty", ErrInvalidConfig)
	}

	// Argon2 Safety Checks (prevent accidental weak settings)
	if c.Argon2.Iterations < 1 {
		return fmt.Errorf("%w: argon2.iterations must be at least 1", ErrInvalidConfig)
	}
	if c.Argon2.MemoryKiB < 1024 {
		return fmt.Errorf("%w: argon2.memory_kib must be at least 1024 (1 MiB)", ErrInvalidConfig)
	}
	if c.Argon2.Parallelism < 1 {
		return fmt.Errorf("%w: argon2.parallelism must be at least 1", ErrInvalidConfig)
	}

	// Audit Safety Checks
	if c.AuditMaxSizeMB < 0 {
		return fmt.Errorf("%w: audit_max_size_mb cannot be negative", ErrInvalidConfig)
	}
	if c.AuditMaxBackups < 0 {
		return fmt.Errorf("%w: audit_max_backups cannot be negative", ErrInvalidConfig)
	}

	// Clipboard Safety Checks
	if c.Clipboard.Timeout < 0 {
		return fmt.Errorf("%w: clipboard.timeout cannot be negative", ErrInvalidConfig)
	}

	return nil
}

// expandPath expands ~ to home directory
func expandPath(path string) (string, error) {
	if path == "" {
		return path, nil
	}

	if strings.HasPrefix(path, "~/") || path == "~" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		if path == "~" {
			return homeDir, nil
		}
		return filepath.Join(homeDir, path[2:]), nil
	}

	return path, nil
}

// EnsureDirectories creates necessary directories with secure permissions.
func EnsureDirectories(cfg *Config) error {
	dirs := []string{
		filepath.Dir(cfg.VaultPath),
		filepath.Dir(cfg.AuditLogPath), // Ensure audit dir exists
	}

	if cfg.KeyfilePath != "" {
		dirs = append(dirs, filepath.Dir(cfg.KeyfilePath))
	}

	for _, dir := range dirs {
		if dir == "" || dir == "." {
			continue
		}
		// 0700: Only user can read/write/execute
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// CreateDefaultConfigFile creates a default configuration file if it doesn't exist
func CreateDefaultConfigFile() error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	configPath := filepath.Join(configDir, "config.yaml")

	if mkdirErr := os.MkdirAll(configDir, 0700); mkdirErr != nil {
		return fmt.Errorf("failed to create config directory: %w", mkdirErr)
	}

	content, err := generateDefaultConfigContent()
	if err != nil {
		return err
	}

	return writeNewConfigFile(configPath, content)
}

// generateDefaultConfigContent builds the template string for the initial configuration file.
func generateDefaultConfigContent() (string, error) {
	cfg, err := defaultConfig()
	if err != nil {
		return "", fmt.Errorf("failed to get default config: %w", err)
	}

	var tools []string
	for _, t := range cfg.Clipboard.ToolPreference {
		tools = append(tools, fmt.Sprintf("%q", t))
	}
	toolsStr := fmt.Sprintf("[%s]", strings.Join(tools, ", "))

	content := fmt.Sprintf(`vault_path: "%s"
keyfile_path: "%s"
audit_log_path: "%s"
audit_max_size_mb: %d
audit_max_backups: %d
audit_compress: %t
audit_enable_hash_chain: %t

argon2:
  memory_kib: %d    # 64 MiB
  iterations: %d
  parallelism: %d

clipboard:
  tool_preference: %s
  timeout: %d      # Seconds

log_level: "%s"
`,
		filepath.ToSlash(cfg.VaultPath),
		filepath.ToSlash(cfg.KeyfilePath),
		filepath.ToSlash(cfg.AuditLogPath),
		cfg.AuditMaxSizeMB,
		cfg.AuditMaxBackups,
		cfg.AuditCompress,
		cfg.AuditEnableHashChain,
		cfg.Argon2.MemoryKiB,
		cfg.Argon2.Iterations,
		cfg.Argon2.Parallelism,
		toolsStr,
		cfg.Clipboard.Timeout,
		cfg.LogLevel,
	)

	return content, nil
}

// writeNewConfigFile atomically creates and writes the default configuration file.
// O_EXCL guarantees atomic creation and prevents symlink attacks (CWE-377).
// If the file already exists, it returns nil without overwriting.
func writeNewConfigFile(configPath string, content string) error {
	// #nosec G304 -- Loading local user configuration file
	f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("failed to create config file: %w", err)
	}

	// Write content first, then close once.
	// Do NOT use defer + explicit Close together — double-close corrupts the fd on Windows.
	_, writeErr := f.WriteString(content)
	closeErr := f.Close()

	if writeErr != nil {
		return fmt.Errorf("failed to write config file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to close config file: %w", closeErr)
	}
	return nil
}
