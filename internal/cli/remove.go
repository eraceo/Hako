package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// ErrRemoveFailed is returned when an entry removal fails.
var ErrRemoveFailed = errors.New("failed to remove entry")

// NewRemoveCmd creates and returns the remove command.
// This factory pattern prevents global state pollution and is safe for parallel testing.
func NewRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <name|id>",
		Aliases: []string{"remove", "delete"},
		Short:   "Remove a password entry",
		Long: `Remove a password entry from the vault.
By default, this command will ask for confirmation before deletion.
You can specify either the exact name or the unique ID of the entry.`,
		Args: cobra.ExactArgs(1),
		RunE: runRemove,
	}

	// Bind the flag directly to the command instead of using a global variable
	cmd.Flags().BoolP("force", "f", false, "force removal without confirmation")

	return cmd
}

func runRemove(cmd *cobra.Command, args []string) error {
	// Safely retrieve the flag value bound to this specific command execution
	forceRemove, err := cmd.Flags().GetBool("force")
	if err != nil {
		return fmt.Errorf("failed to parse force flag: %w", err)
	}

	nameOrID := args[0]
	cfg := config.FromContext(cmd.Context())

	// Load vault
	vault, vaultFile, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		// Log failure to access vault for deletion
		audit.LogFailure(audit.EventEntryDelete, "Failed to load vault for deletion", map[string]interface{}{
			"target": nameOrID,
			"error":  err.Error(),
		})
		return err
	}
	defer func() {
		if masterPassword != nil {
			_ = masterPassword.Destroy()
		}
	}()
	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	// Resolve the exact entry to guarantee we delete the right one
	entry := vault.GetEntryByName(nameOrID)
	if entry == nil {
		entry = vault.GetEntryByID(secrets.EntryID(nameOrID))
	}

	if entry == nil {
		audit.LogFailure(audit.EventEntryDelete, "Entry not found", map[string]interface{}{
			"target": nameOrID,
		})
		return fmt.Errorf("%w: '%s'", ErrEntryNotFound, ui.SanitizeString(nameOrID))
	}

	// Prepare audit details (Use ID for precision, Name for readability)
	entryName := entry.Name
	auditDetails := map[string]interface{}{
		"id":    entry.ID,
		"name":  entryName,
		"force": forceRemove,
	}

	// Confirm deletion unless forced
	if !forceRemove {
		promptMsg := fmt.Sprintf("Are you sure you want to delete entry '%s'?", ui.SanitizeString(entryName))
		confirmed, confirmErr := ui.PromptConfirm(promptMsg)
		if confirmErr != nil {
			return fmt.Errorf("failed to read confirmation: %w", confirmErr)
		}

		if !confirmed {
			// Log cancellation as a non-successful delete event
			audit.LogFailure(audit.EventEntryDelete, "Deletion canceled by user", auditDetails)
			fmt.Println("Deletion canceled.")
			return nil
		}
	}

	// Remove entry strictly by ID to prevent accidental deletion of duplicates
	// vault.RemoveEntryByID internally calls entry.Zero(), which securely wipes
	// the EphemeralSecrets and metadata from RAM before deleting the object.
	if !vault.RemoveEntryByID(entry.ID) {
		audit.LogFailure(audit.EventEntryDelete, "Internal error during removal", auditDetails)
		return fmt.Errorf("%w: '%s'", ErrRemoveFailed, ui.SanitizeString(entryName))
	}

	// Save vault atomically
	if err := saveVaultWithFile(cmd.Context(), cfg, vault, vaultFile, masterPassword); err != nil {
		audit.LogFailure(audit.EventEntryDelete, "Failed to save vault after deletion", auditDetails)
		return err
	}

	// Log successful deletion
	audit.LogSuccess(audit.EventEntryDelete, "Entry removed successfully", auditDetails)

	// ui.PrintfSuccessf automatically appends a newline, so no \n is needed here.
	ui.PrintfSuccessf("Entry '%s' removed successfully", ui.SanitizeString(entryName))
	return nil
}
