package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
	"github.com/eraceo/Hako/internal/ui"
)

const (
	// MaxKeyfileSize limits the keyfile size to 1MB to prevent OOM attacks.
	// A typical keyfile is 32 bytes to 4KB. 1MB is extremely generous but safe.
	MaxKeyfileSize = 1024 * 1024
)

var (
	// ErrVaultNotFound is returned when the vault file does not exist.
	ErrVaultNotFound = errors.New("vault file not found")
	// ErrKeyfileNotRegular is returned when the keyfile is a directory, device, or pipe.
	ErrKeyfileNotRegular = errors.New("keyfile must be a regular file")
	// ErrKeyfileTooLarge is returned when the keyfile exceeds MaxKeyfileSize.
	ErrKeyfileTooLarge = errors.New("keyfile too large")
	// ErrKeyfileEmpty is returned when the keyfile has 0 bytes.
	ErrKeyfileEmpty = errors.New("keyfile is empty")
)

// loadVault handles the secure loading phase of the vault file.
// It returns a masterPassword enclave which MUST be destroyed by the caller if err == nil.
func loadVault(
	ctx context.Context, cfg *config.Config,
) (*secrets.Vault, *storage.VaultFile, *memory.SecurePassword, error) {
	vaultFile := storage.NewVaultFile(cfg.VaultPath)

	if !vaultFile.Exists() {
		return nil, nil, nil, fmt.Errorf("%w: run 'hako init' to create a new vault", ErrVaultNotFound)
	}

	masterPassword, err := ui.PromptSecurePassword("Master password: ")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read master password: %w", err)
	}

	var vault *secrets.Vault

	// Securely manage the Keyfile lifecycle (Read -> Use -> Wipe).
	// We nest the closures: Keyfile Scope -> Password Scope -> Load.
	// This ensures secrets are available in plaintext ONLY during the decryption operation.
	err = withKeyfile(cfg.KeyfilePath, func(keyfileBytes []byte) error {
		// Securely access the Master Password via Memguard
		return masterPassword.WithPassword(func(passwordBytes []byte) error {
			var loadErr error
			vault, loadErr = vaultFile.Load(ctx, passwordBytes, keyfileBytes)
			if loadErr != nil {
				return fmt.Errorf("failed to load vault: %w", loadErr)
			}
			return nil
		})
	})

	if err != nil {
		// CRITICAL SECURITY: Destroy the enclave immediately if loading failed.
		// We must NEVER leak a valid password enclave if the vault could not be decrypted.
		_ = masterPassword.Destroy()
		return nil, nil, nil, err
	}

	return vault, vaultFile, masterPassword, nil
}

// saveVaultWithFile handles the secure saving phase, ensuring atomic writes and memory hygiene.
func saveVaultWithFile(
	ctx context.Context,
	cfg *config.Config,
	vault *secrets.Vault,
	vaultFile *storage.VaultFile,
	masterPassword *memory.SecurePassword,
) error {
	// Re-read keyfile for saving ensures we don't hold it in RAM during the session.
	// It also acts as a sanity check that the keyfile is still accessible before overwriting the vault.
	return withKeyfile(cfg.KeyfilePath, func(keyfileBytes []byte) error {
		return masterPassword.WithPassword(func(passwordBytes []byte) error {
			if err := vaultFile.Save(ctx, vault, passwordBytes, keyfileBytes); err != nil {
				return fmt.Errorf("failed to save vault: %w", err)
			}
			return nil
		})
	})
}

// withKeyfile is a secure helper that reads a keyfile (if configured),
// passes it to the callback, and strictly wipes the memory immediately after.
func withKeyfile(path string, fn func(keyfile []byte) error) error {
	var keyfile []byte

	if path != "" {
		// Open file securely
		// #nosec G304 -- Path is intentionally user-provided (CLI tool) and validated strictly via Stat below.
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open keyfile at %s: %w", path, err)
		}
		// Explicitly ignore close error for read-only file to satisfy errcheck linter
		defer func() { _ = f.Close() }()

		// Protection against DoS/OOM & Device blocking
		stat, err := f.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat keyfile: %w", err)
		}

		// SECURITY: Strict check to ensure we are reading a regular file.
		// Prevents reading from block devices, named pipes, or sockets which could hang
		// the application or return infinite streams.
		if !stat.Mode().IsRegular() {
			return ErrKeyfileNotRegular
		}

		size := stat.Size()
		if size > MaxKeyfileSize {
			return fmt.Errorf("%w (max %d bytes)", ErrKeyfileTooLarge, MaxKeyfileSize)
		}
		if size == 0 {
			return ErrKeyfileEmpty
		}

		// Optimization: Allocate EXACT size to avoid 'io.ReadAll' reallocations.
		// This keeps the Heap usage strictly minimal and prevents artifacts.
		keyfile = make([]byte, size)

		// Use ReadFull to guarantee we get the expected bytes or fail
		if _, err := io.ReadFull(f, keyfile); err != nil {
			// Ensure we wipe partial reads on error
			memory.SecureZero(keyfile)
			return fmt.Errorf("failed to read keyfile: %w", err)
		}

		// Security: Wipe the heap allocation immediately after the function returns.
		defer memory.SecureZero(keyfile)
	}

	return fn(keyfile)
}
