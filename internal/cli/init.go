package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
	"github.com/eraceo/Hako/internal/ui"
)

// Sentinel errors to prevent dynamic error generation (err113).
var (
	ErrVaultExists       = errors.New("vault already exists")
	ErrArgonMemoryTooLow = errors.New("argon2 memory must be at least 1024 KiB")
	ErrArgonIterTooLow   = errors.New("argon2 iterations must be at least 1")
	ErrKeyfileExists     = errors.New("keyfile already exists (aborting to prevent overwrite)")
)

type initOptions struct {
	GenerateKeyfile bool
	ArgonMemory     uint32
	ArgonIter       uint32
}

// NewInitCmd creates and returns the init command.
// This factory pattern prevents global state pollution.
func NewInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new password vault",
		Long: `Initialize a new encrypted password vault.
// This command creates a new vault file and prompts for a master password.
Optionally, it can generate a keyfile for additional security.`,
		RunE: runInit,
	}

	cmd.Flags().Bool("gen-keyfile", false, "generate a keyfile for additional security")
	cmd.Flags().Uint32("argon-memory", 65536, "Argon2 memory parameter in KiB (default: 64MB)")
	cmd.Flags().Uint32("argon-iter", 3, "Argon2 iterations parameter")

	return cmd
}

func runInit(cmd *cobra.Command, _ []string) error {
	genKeyfile, _ := cmd.Flags().GetBool("gen-keyfile")
	argonMem, _ := cmd.Flags().GetUint32("argon-memory")
	argonIter, _ := cmd.Flags().GetUint32("argon-iter")

	opts := initOptions{
		GenerateKeyfile: genKeyfile,
		ArgonMemory:     argonMem,
		ArgonIter:       argonIter,
	}

	cfg := config.FromContext(cmd.Context())

	// Prepare audit context
	auditDetails := map[string]interface{}{
		"vault_path":   cfg.VaultPath,
		"gen_keyfile":  opts.GenerateKeyfile,
		"argon_memory": opts.ArgonMemory,
		"argon_iter":   opts.ArgonIter,
	}

	vaultFile, err := checkInitialState(cfg)
	if err != nil {
		audit.LogFailure(audit.EventVaultInit, "Initialization pre-check failed", map[string]interface{}{
			"error":      err.Error(),
			"vault_path": cfg.VaultPath,
		})
		ui.PrintfErrorf("Initialization failed: %v", err)
		return err
	}

	securePassword, err := promptAndValidateMasterPassword()
	if err != nil {
		audit.LogFailure(audit.EventSecurityError, "Master password validation failed or canceled", map[string]interface{}{
			"error": err.Error(),
		})
		ui.PrintfErrorf("Validation failed: %v", err)
		return err
	}
	defer func() {
		_ = securePassword.Destroy()
	}()

	var keyfile []byte
	if opts.GenerateKeyfile {
		keyfile, err = handleKeyfileGeneration(cfg.KeyfilePath)
		if err != nil {
			audit.LogFailure(audit.EventVaultInit, "Keyfile generation failed", map[string]interface{}{
				"error":        err.Error(),
				"keyfile_path": cfg.KeyfilePath,
			})
			ui.PrintfErrorf("Keyfile error: %v", err)
			return err
		}
		defer memory.SecureZero(keyfile)
	}

	if err := initializeVaultCore(cmd.Context(), vaultFile, securePassword, keyfile, opts); err != nil {
		audit.LogFailure(audit.EventVaultInit, "Vault cryptographic initialization failed", map[string]interface{}{
			"error": err.Error(),
		})
		ui.PrintfErrorf("Vault creation failed: %v", err)
		return err
	}

	// Log successful initialization with full parameters context
	audit.LogSuccess(audit.EventVaultInit, "Vault initialized successfully", auditDetails)

	handlePostInitSuccess(cfg.VaultPath, opts.GenerateKeyfile)

	return nil
}

func checkInitialState(cfg *config.Config) (*storage.VaultFile, error) {
	vaultFile := storage.NewVaultFile(cfg.VaultPath)
	if vaultFile.Exists() {
		return nil, fmt.Errorf("%w: %s", ErrVaultExists, ui.SanitizeString(cfg.VaultPath))
	}

	if err := config.EnsureDirectories(cfg); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	if err := config.CreateDefaultConfigFile(); err != nil {
		return nil, fmt.Errorf("failed to create default config file: %w", err)
	}

	return vaultFile, nil
}

func promptAndValidateMasterPassword() (*memory.SecurePassword, error) {
	securePassword, err := ui.PromptSecurePasswordWithConfirmation(
		"Enter master password: ",
		"Confirm master password: ",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	validator := secrets.NewValidator()
	err = securePassword.WithPassword(func(passwordBytes []byte) error {
		return validator.ValidateMasterPassword(passwordBytes)
	})
	if err != nil {
		_ = securePassword.Destroy()
		return nil, fmt.Errorf("invalid master password: %w", err)
	}

	return securePassword, nil
}

func handleKeyfileGeneration(path string) ([]byte, error) {
	keyfile, err := secrets.GenerateKeyfile(256) // 2048 bits
	if err != nil {
		return nil, fmt.Errorf("failed to generate keyfile: %w", err)
	}

	if writeErr := writeKeyfileSafely(path, keyfile); writeErr != nil {
		memory.SecureZero(keyfile)
		return nil, fmt.Errorf("failed to write keyfile: %w", writeErr)
	}

	ui.PrintfSuccessf("Keyfile generated at: %s", ui.SanitizeString(path))
	ui.PrintfWarningf("Keep this keyfile secure and backed up! You will lose access to your vault if you lose it.")

	return keyfile, nil
}

func initializeVaultCore(
	ctx context.Context, // Explicitly pass context.Context to match standard library usage
	vaultFile *storage.VaultFile,
	securePassword *memory.SecurePassword,
	keyfile []byte,
	opts initOptions,
) error {
	if opts.ArgonMemory < 1024 {
		return ErrArgonMemoryTooLow
	}
	if opts.ArgonIter < 1 {
		return ErrArgonIterTooLow
	}

	params := crypto.Argon2Params{
		Memory:      opts.ArgonMemory,
		Iterations:  opts.ArgonIter,
		Parallelism: 2,
		SaltSize:    crypto.SaltSize,
		KeySize:     crypto.KeySize,
	}

	var initErr error
	err := securePassword.WithPassword(func(passwordBytes []byte) error {
		initErr = vaultFile.Initialize(ctx, passwordBytes, keyfile, params)
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to access password enclave: %w", err)
	}
	if initErr != nil {
		return fmt.Errorf("failed to initialize vault: %w", initErr)
	}

	return nil
}

// handlePostInitSuccess prints the success and warning messages after the vault is safely written.
func handlePostInitSuccess(vaultPath string, generatedKeyfile bool) {
	ui.PrintfSuccessf("\nVault initialized successfully at: %s", ui.SanitizeString(vaultPath))

	if generatedKeyfile {
		fmt.Println("\nSecurity recommendations:")
		fmt.Println("1. Backup your keyfile to a secure location (e.g., USB drive).")
		fmt.Println("2. Never store the keyfile and the vault file in the same location.")
		fmt.Println("3. Consider using a hardware security key for additional protection.")
	}
}

// writeKeyfileSafely writes the keyfile with strict secure permissions.
// Security: Uses O_EXCL to prevent symlink attacks (CWE-377) and file hijacking.
func writeKeyfileSafely(path string, keyfile []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create keyfile directory: %w", err)
	}

	// O_EXCL ensures that if the file or a symlink already exists, the open fails.
	// #nosec G304 -- The path is derived from the user's config environment, not an external web payload
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w at %s", ErrKeyfileExists, path)
		}
		return fmt.Errorf("failed to open keyfile for writing: %w", err)
	}

	// Fallback defer to ensure closure on early return/panic
	defer func() {
		_ = f.Close()
	}()

	if _, err := f.Write(keyfile); err != nil {
		return fmt.Errorf("failed to write keyfile data: %w", err)
	}

	// Explicitly sync to disk to prevent data loss on sudden power failure
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync keyfile to disk: %w", err)
	}

	// Explicitly close to catch flush/close errors
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close keyfile: %w", err)
	}

	return nil
}
