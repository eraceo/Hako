package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// ErrSamePassword is a sentinel error indicating the new password matches the current one.
var ErrSamePassword = errors.New("new master password must be different from current password")

// NewPasswdCmd creates and returns the passwd command.
func NewPasswdCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "passwd",
		Short: "Change the master password",
		Long: `Change the master password for the vault.
// This command will decrypt the vault with the current password,
prompt for a new password, and re-encrypt the vault with the new password.
It also rotates the encryption salt and AES nonce for added security.`,
		RunE: runPasswd,
	}
}

func runPasswd(cmd *cobra.Command, _ []string) error {
	cfg := config.FromContext(cmd.Context())

	// Load vault (prompts for current master password)
	vault, vaultFile, currentPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		// Log explicit authentication failure
		audit.LogFailure(audit.EventAuthFailure, "Failed to authenticate for password change", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}
	defer func() {
		if currentPassword != nil {
			_ = currentPassword.Destroy()
		}
	}()
	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	ui.PrintfSuccessf("Authenticated successfully. Vault decrypted.\n")

	// Prompt for new password with confirmation
	newPassword, err := ui.PromptSecurePasswordWithConfirmation(
		"Enter new master password: ",
		"Confirm new master password: ",
	)
	if err != nil {
		audit.LogFailure(audit.EventSecurityError, "Password input failed or canceled", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to read new password: %w", err)
	}
	defer func() {
		if newPassword != nil {
			_ = newPassword.Destroy()
		}
	}()

	// Strict Validation & Comparison
	if err := validateAndComparePasswords(currentPassword, newPassword); err != nil {
		audit.LogFailure(audit.EventSecurityError, "New master password validation failed", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	// Re-encrypt and Save Vault
	// We use a closure to handle the keyfile logic uniformly whether it exists or not.
	saveAction := func(keyfileBytes []byte) error {
		// RotateMasterKey guarantees a fresh Argon2 salt is generated and written to the header.
		return newPassword.WithPassword(func(newPassBytes []byte) error {
			return vaultFile.RotateMasterKey(cmd.Context(), vault, newPassBytes, keyfileBytes)
		})
	}

	if cfg.KeyfilePath != "" {
		// SECURITY: Use withKeyfile helper to ensure safe file reading (IsRegular, Limit, Wipe)
		err = withKeyfile(cfg.KeyfilePath, saveAction)
		if err != nil {
			audit.LogFailure(audit.EventVaultSave, "Failed to read keyfile or save vault", map[string]interface{}{
				"keyfile_used": true,
				"error":        err.Error(),
			})
			return fmt.Errorf("failed to process keyfile or save vault: %w", err)
		}
	} else {
		// No keyfile configured
		err = saveAction(nil)
		if err != nil {
			audit.LogFailure(audit.EventVaultSave, "Failed to save vault", map[string]interface{}{
				"keyfile_used": false,
				"error":        err.Error(),
			})
			return fmt.Errorf("failed to re-encrypt and save vault: %w", err)
		}
	}

	// Audit success with context (sanitized)
	audit.LogSuccess(audit.EventVaultSave, "Master password changed successfully", map[string]interface{}{
		"action":       "master_key_rotation",
		"keyfile_used": cfg.KeyfilePath != "",
	})

	// The old master password enclave will be naturally destroyed by the defer block above
	ui.PrintfSuccessf("\nMaster password changed successfully. Vault re-encrypted with new salt.\n")
	return nil
}

// validateAndComparePasswords enforces complexity rules on the new password and
// uses constant-time cryptographic comparison to ensure it differs from the old one.
func validateAndComparePasswords(currentPassword, newPassword *memory.SecurePassword) error {
	validator := secrets.NewValidator()
	err := newPassword.WithPassword(func(passwordBytes []byte) error {
		return validator.ValidateMasterPassword(passwordBytes)
	})
	if err != nil {
		return fmt.Errorf("invalid new master password: %w", err)
	}

	// SECURITY: Handle errors from WithPassword/Access. If the enclave is destroyed
	// or inaccessible, we must not proceed assuming the passwords are different.
	err = currentPassword.WithPassword(func(currBytes []byte) error {
		return newPassword.WithPassword(func(newBytes []byte) error {
			// This ensures the comparison always takes the exact same amount of time
			// regardless of where the mismatch occurs to prevent timing attacks.
			if crypto.SecureCompare(currBytes, newBytes) {
				return ErrSamePassword
			}
			return nil
		})
	})

	return err
}
