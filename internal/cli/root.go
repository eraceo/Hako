package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
)

const keyfileNone = "none"

// NewRootCmd creates a new root command with isolated flags.
// This Factory pattern is crucial for parallel testing and isolation.
func NewRootCmd() *cobra.Command {
	// Local variables for persistent flags (isolated per command instance)
	var (
		cfgFile   string
		vaultPath string
		keyfile   string
		verbose   bool
	)

	cmd := &cobra.Command{
		Use:   "hako",
		Short: "Hako - Secure, minimalist, local-first CLI password manager",
		Long: `Hako is a secure password manager designed for terminal-based workflows.
It uses industry-standard encryption (Argon2id + AES-256-GCM), secure memory enclaves,
and local-first storage to protect your credentials.

It supports Linux, macOS, and Windows and follows standard XDG Base Directory conventions.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Injection of local values into the config loader
			allowMissingCfg := cmd != nil && cmd.Name() == "init"
			cfg, err := initConfigWithOptions(cfgFile, vaultPath, keyfile, verbose, !shouldSkipAuditInit(cmd), allowMissingCfg)
			if err != nil {
				return err
			}

			// Store config in context for subcommands
			ctx := config.WithContext(cmd.Context(), cfg)
			cmd.SetContext(ctx)
			return nil
		},
		// SilenceUsage avoids showing help when a business error occurs (keeps UI clean).
		SilenceUsage: true,
		// SilenceErrors allows main.go to handle error printing consistently (avoids double printing).
		SilenceErrors: true,
	}

	// Definition of global flags on this specific instance
	cmd.PersistentFlags().StringVar(
		&cfgFile,
		"config",
		"",
		"config file (default is $HOME/.config/hako/config.yaml)",
	)

	cmd.PersistentFlags().StringVar(
		&vaultPath,
		"vault",
		"",
		"vault file path (default is $HOME/.local/share/hako/vault.bin)",
	)

	cmd.PersistentFlags().StringVar(
		&keyfile,
		"keyfile",
		"",
		"keyfile path for additional authentication (use '"+keyfileNone+"' to disable default keyfile)",
	)

	cmd.PersistentFlags().BoolVarP(
		&verbose,
		"verbose",
		"v",
		false,
		"enable verbose debug output",
	)

	// Registration of sub-commands (also instantiated afresh)
	cmd.AddCommand(
		NewPasswdCmd(),
		NewRekeyCmd(),
		NewRemoveCmd(),
		NewListCmd(),
		NewAuditCmd(),
		NewAddCmd(),
		NewEditCmd(),
		NewExportCmd(),
		NewGenerateCmd(),
		NewGetCmd(),
		NewCompletionCmd(),
		NewImportCmd(),
		NewInitCmd(),
		NewSearchCmd(),
		NewVersionCmd(),
		NewClipDaemonCmd(),
	)

	return cmd
}

// Execute instantiates a new root and executes it.
func Execute(ctx context.Context) error {
	return NewRootCmd().ExecuteContext(ctx)
}

func shouldSkipAuditInit(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	name := cmd.Name()
	if name == "__clip-daemon" || name == "version" || name == "help" || name == "completion" {
		return true
	}
	parent := cmd.Parent()
	if parent != nil && parent.Name() == "completion" {
		return true
	}
	if name == "verify-logs" && parent != nil && parent.Name() == "audit" {
		return true
	}
	return false
}

// initConfig is a pure function taking values as arguments.
// It loads configuration AND initializes global infrastructure (Audit).
func initConfig(cfgFile, vaultPath, keyfile string, verbose bool) (*config.Config, error) {
	return initConfigWithOptions(cfgFile, vaultPath, keyfile, verbose, true, false)
}

func initConfigWithOptions(cfgFile, vaultPath, keyfile string, verbose, enableAudit, allowMissing bool) (*config.Config, error) {
	var cfg *config.Config
	var err error
	if allowMissing {
		cfg, err = config.LoadAllowMissing(cfgFile)
	} else {
		cfg, err = config.Load(cfgFile)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	// Override configuration with CLI flags if provided
	if vaultPath != "" {
		cfg.VaultPath = vaultPath
	}

	if keyfile != "" {
		if keyfile == keyfileNone {
			cfg.KeyfilePath = ""
		} else {
			cfg.KeyfilePath = keyfile
		}
	}

	if verbose {
		cfg.LogLevel = "debug"
	}

	if !enableAudit {
		audit.InitGlobalLogger("", false)
		return cfg, nil
	}

	// Initialize the Global Audit Logger with options from config.
	audit.InitGlobalLoggerFromConfig(cfg)

	// If verbose mode is on, print where audit logs are going.
	if verbose {
		// Using Fprintf(Stderr) to avoid interfering with stdout CLI output buffers.
		_, _ = fmt.Fprintf(os.Stderr, "Debug: Audit logging initialized at %s\n", cfg.AuditLogPath)
	}

	return cfg, nil
}
