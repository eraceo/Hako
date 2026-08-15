package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/storage"
	"github.com/eraceo/Hako/internal/ui"
)

type rekeyOptions struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	applyConfig bool
}

// NewRekeyCmd creates and returns the rekey command.
func NewRekeyCmd() *cobra.Command {
	opts := &rekeyOptions{}

	cmd := &cobra.Command{
		Use:     "rekey",
		Aliases: []string{"tune-kdf", "update-kdf"},
		Short:   "Re-encrypt vault with fresh salt/nonce and update Argon2id parameters",
		Long: `Re-encrypt the vault file with fresh cryptographic salt and AES nonce.
Optionally update Argon2id key derivation parameters (memory, iterations, parallelism)
from CLI flags or from active configuration file (~/.config/hako/config.yaml).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRekey(cmd, opts)
		},
	}

	cmd.Flags().Uint32VarP(&opts.memory, "memory", "m", 0, "Argon2id memory limit in KiB (e.g., 65536 for 64MB)")
	cmd.Flags().Uint32VarP(&opts.iterations, "iterations", "t", 0, "Argon2id iterations/time cost")
	cmd.Flags().Uint8VarP(&opts.parallelism, "parallelism", "p", 0, "Argon2id degree of parallelism/threads")
	cmd.Flags().BoolVar(&opts.applyConfig, "apply-config", false, "Apply KDF parameters configured in config.yaml")

	return cmd
}

func validateArgon2Params(params crypto.Argon2Params) error {
	if params.Memory < storage.MinMemory || params.Memory > storage.MaxMemory {
		return fmt.Errorf("invalid memory setting: %d KiB (must be between %d and %d KiB)", params.Memory, storage.MinMemory, storage.MaxMemory)
	}
	if params.Iterations < storage.MinIterations || params.Iterations > storage.MaxIterations {
		return fmt.Errorf("invalid iterations setting: %d (must be between %d and %d)", params.Iterations, storage.MinIterations, storage.MaxIterations)
	}
	if params.Parallelism < storage.MinParallelism || params.Parallelism > storage.MaxParallelism {
		return fmt.Errorf("invalid parallelism setting: %d (must be between %d and %d)", params.Parallelism, storage.MinParallelism, storage.MaxParallelism)
	}
	return nil
}

func formatChange(oldVal, newVal interface{}) string {
	if oldVal == newVal {
		return fmt.Sprintf("%v (unchanged)", oldVal)
	}
	return fmt.Sprintf("%v -> %v", oldVal, newVal)
}

func runRekey(cmd *cobra.Command, opts *rekeyOptions) error {
	cfg := config.FromContext(cmd.Context())

	// 1. Authenticate & load vault
	vault, vaultFile, password, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		audit.LogFailure(audit.EventAuthFailure, "Failed to authenticate for rekey", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if password != nil {
			_ = password.Destroy()
		}
	}()
	defer vault.Zero()

	oldParams := vaultFile.Header().Argon2Params

	// 2. Determine target parameters
	newParams := oldParams
	if opts.applyConfig {
		newParams = crypto.Argon2Params{
			Memory:      cfg.Argon2.MemoryKiB,
			Iterations:  cfg.Argon2.Iterations,
			Parallelism: cfg.Argon2.Parallelism,
			SaltSize:    crypto.SaltSize,
			KeySize:     crypto.KeySize,
		}
	}
	if opts.memory > 0 {
		newParams.Memory = opts.memory
	}
	if opts.iterations > 0 {
		newParams.Iterations = opts.iterations
	}
	if opts.parallelism > 0 {
		newParams.Parallelism = opts.parallelism
	}

	// 3. Validate new parameters against storage bounds
	if err := validateArgon2Params(newParams); err != nil {
		audit.LogFailure(audit.EventSecurityError, "Invalid Argon2 parameters specified for rekey", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	// 4. Perform rekey & save
	saveAction := func(keyfileBytes []byte) error {
		return password.WithPassword(func(passBytes []byte) error {
			return vaultFile.UpdateKDFParams(cmd.Context(), vault, passBytes, keyfileBytes, newParams)
		})
	}

	if cfg.KeyfilePath != "" {
		err = withKeyfile(cfg.KeyfilePath, saveAction)
	} else {
		err = saveAction(nil)
	}

	if err != nil {
		audit.LogFailure(audit.EventVaultSave, "Failed to rekey vault", map[string]interface{}{
			"keyfile_used": cfg.KeyfilePath != "",
			"error":        err.Error(),
		})
		return fmt.Errorf("failed to rekey vault: %w", err)
	}

	audit.LogSuccess(audit.EventKDFUpdate, "Vault rekeyed successfully", map[string]interface{}{
		"old_memory":      oldParams.Memory,
		"new_memory":      newParams.Memory,
		"old_iterations":  oldParams.Iterations,
		"new_iterations":  newParams.Iterations,
		"old_parallelism": oldParams.Parallelism,
		"new_parallelism": newParams.Parallelism,
	})

	ui.PrintfSuccessf("\nVault rekeyed successfully with fresh salt and AES-GCM nonce.\n")
	ui.PrintfInfof("Argon2id Parameters:\n")
	ui.PrintfInfof("  Memory:      %s\n", formatChange(fmt.Sprintf("%d KiB", oldParams.Memory), fmt.Sprintf("%d KiB", newParams.Memory)))
	ui.PrintfInfof("  Iterations:  %s\n", formatChange(oldParams.Iterations, newParams.Iterations))
	ui.PrintfInfof("  Parallelism: %s\n", formatChange(oldParams.Parallelism, newParams.Parallelism))

	return nil
}
