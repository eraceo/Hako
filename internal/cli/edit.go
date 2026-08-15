package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// Sentinel errors to prevent dynamic error generation (err113).
// ErrEntryNotFound is shared and declared in get.go (or remove.go)
var (
	ErrUpdateFailed = errors.New("failed to update entry")
)

// editOptions encapsulates all flag states to prevent mutating global state.
type editOptions struct {
	NameOrID    string
	Username    string
	URL         string
	Notes       string
	Tags        []string
	Generate    bool
	Interactive bool
}

// NewEditCmd creates and returns the edit command.
// This factory pattern prevents global state pollution and is safe for testing.
func NewEditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit <name|id>",
		Short: "Edit a password entry",
		Long: `Edit an existing password entry in the vault.
You can update individual fields using flags or be prompted interactively.`,
		Args: cobra.ExactArgs(1),
		RunE: runEdit,
	}

	cmd.Flags().StringP("user", "u", "", "new username")
	cmd.Flags().String("url", "", "new URL")
	cmd.Flags().StringP("notes", "n", "", "new notes")
	cmd.Flags().StringSliceP("tags", "t", []string{}, "new tags (comma-separated)")
	cmd.Flags().BoolP("generate", "g", false, "generate a new password")

	return cmd
}

func runEdit(cmd *cobra.Command, args []string) error {
	opts, err := parseEditFlags(cmd, args[0])
	if err != nil {
		return err
	}

	cfg := config.FromContext(cmd.Context())

	vault, vaultFile, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	defer func() {
		if masterPassword != nil {
			_ = masterPassword.Destroy() // Release vault decryption enclave
		}
	}()
	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	entry, updatedEntry, err := prepareEntryForEdit(vault, opts.NameOrID)
	if err != nil {
		audit.LogFailure(audit.EventEntryUpdate, "Entry not found for update", map[string]interface{}{
			"query": ui.SanitizeString(opts.NameOrID),
		})
		return err
	}

	// Trap to securely destroy the clone if the update process fails midway
	success := false
	defer func() {
		if !success {
			updatedEntry.Zero()
		}
	}()

	if err := updateEntryFields(cmd, updatedEntry, opts); err != nil {
		return err
	}

	if err := validateUpdatedEntry(updatedEntry); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// vault.UpdateEntry internally handles the destruction (.Zero())
	// of the old entry to prevent OS mlock quota leaks.
	if !vault.UpdateEntry(entry.ID, updatedEntry) {
		audit.LogFailure(audit.EventEntryUpdate, "Failed to update entry in memory", map[string]interface{}{
			"entry_id": entry.ID,
		})
		return fmt.Errorf("%w: '%s'", ErrUpdateFailed, ui.SanitizeString(opts.NameOrID))
	}

	if err := saveVaultWithFile(cmd.Context(), cfg, vault, vaultFile, masterPassword); err != nil {
		return err
	}

	audit.LogSuccess(audit.EventEntryUpdate, "Entry updated successfully", map[string]interface{}{
		"entry_id":   entry.ID,
		"entry_name": entry.Name,
		"tags":       updatedEntry.Tags,
	})

	success = true
	ui.PrintfSuccessf("Entry '%s' updated successfully", ui.SanitizeString(updatedEntry.Name))
	return nil
}

// parseEditFlags safely extracts all flags into the editOptions struct.
func parseEditFlags(cmd *cobra.Command, nameOrID string) (editOptions, error) {
	opts := editOptions{NameOrID: nameOrID}
	var err error

	if opts.Username, err = cmd.Flags().GetString("user"); err != nil {
		return opts, fmt.Errorf("failed to parse user flag: %w", err)
	}
	if opts.URL, err = cmd.Flags().GetString("url"); err != nil {
		return opts, fmt.Errorf("failed to parse url flag: %w", err)
	}
	if opts.Notes, err = cmd.Flags().GetString("notes"); err != nil {
		return opts, fmt.Errorf("failed to parse notes flag: %w", err)
	}
	if opts.Tags, err = cmd.Flags().GetStringSlice("tags"); err != nil {
		return opts, fmt.Errorf("failed to parse tags flag: %w", err)
	}
	if opts.Generate, err = cmd.Flags().GetBool("generate"); err != nil {
		return opts, fmt.Errorf("failed to parse generate flag: %w", err)
	}

	anyFlagChanged := cmd.Flags().Changed("user") ||
		cmd.Flags().Changed("url") ||
		cmd.Flags().Changed("notes") ||
		cmd.Flags().Changed("tags") ||
		cmd.Flags().Changed("generate")

	opts.Interactive = !anyFlagChanged
	return opts, nil
}

// prepareEntryForEdit resolves the entry by Name or ID and creates a safe clone.
func prepareEntryForEdit(vault *secrets.Vault, nameOrID string) (orig *secrets.Entry, updated *secrets.Entry, err error) {
	entry := vault.GetEntryByName(nameOrID)
	if entry == nil {
		entry = vault.GetEntryByID(secrets.EntryID(nameOrID))
	}
	if entry == nil {
		return nil, nil, fmt.Errorf("%w: '%s'", ErrEntryNotFound, ui.SanitizeString(nameOrID))
	}

	updatedEntry, err := entry.Clone()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to clone entry: %w", err)
	}

	return entry, updatedEntry, nil
}

func updateEntryFields(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if err := updateUsername(cmd, entry, opts); err != nil {
		return err
	}
	if err := updatePassword(cmd, entry, opts); err != nil {
		return err
	}
	if err := updateURL(cmd, entry, opts); err != nil {
		return err
	}
	if err := updateNotes(cmd, entry, opts); err != nil {
		return err
	}
	if err := updateTags(cmd, entry, opts); err != nil {
		return err
	}

	entry.UpdatedAt = time.Now()
	return nil
}

func updateUsername(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if opts.Interactive {
		val, err := ui.PromptString("New Username (leave blank to keep current): ")
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
		defer memory.SecureZero(val)
		if len(val) > 0 {
			if len(entry.Username) > 0 {
				memory.SecureZero(entry.Username) // Wipe old ciphertext safely
			}
			entry.Username = secrets.NewEphemeralSecret(val)
		}
		return nil
	}

	if cmd.Flags().Changed("user") {
		providedBytes := []byte(opts.Username)
		defer memory.SecureZero(providedBytes)
		if len(entry.Username) > 0 {
			memory.SecureZero(entry.Username)
		}
		if len(providedBytes) > 0 {
			entry.Username = secrets.NewEphemeralSecret(providedBytes)
		} else {
			entry.Username = nil
		}
	}
	return nil
}

func updatePassword(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if opts.Interactive {
		fmt.Fprintln(os.Stderr, "Enter new password (leave empty to keep current):")
		prompted, err := ui.PromptPassword("Password: ")
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		if len(prompted) > 0 {
			defer memory.SecureZero(prompted)
			if len(entry.Password) > 0 {
				memory.SecureZero(entry.Password)
			}
			entry.Password = secrets.NewEphemeralSecret(prompted)
		}
		return nil
	}

	if cmd.Flags().Changed("generate") && opts.Generate {
		genOpts := secrets.GeneratorOptions{
			Length:     16,
			UseSymbols: true,
			Memorable:  false,
		}
		generated, err := secrets.GeneratePassword(genOpts)
		if err != nil {
			return fmt.Errorf("failed to generate password: %w", err)
		}
		defer memory.SecureZero(generated)

		fmt.Print("Generated new password: ")
		_, _ = os.Stdout.Write(generated)
		fmt.Println()

		if len(entry.Password) > 0 {
			memory.SecureZero(entry.Password)
		}
		entry.Password = secrets.NewEphemeralSecret(generated)
	}
	return nil
}

func updateURL(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if opts.Interactive {
		val, err := ui.PromptString("New URL (leave blank to keep current): ")
		if err != nil {
			return fmt.Errorf("failed to read URL: %w", err)
		}
		defer memory.SecureZero(val)
		if len(val) > 0 {
			if len(entry.URL) > 0 {
				memory.SecureZero(entry.URL)
			}
			entry.URL = secrets.NewEphemeralSecret(val)
		}
		return nil
	}

	if cmd.Flags().Changed("url") {
		providedBytes := []byte(opts.URL)
		defer memory.SecureZero(providedBytes)
		if len(entry.URL) > 0 {
			memory.SecureZero(entry.URL)
		}
		if len(providedBytes) > 0 {
			entry.URL = secrets.NewEphemeralSecret(providedBytes)
		} else {
			entry.URL = nil
		}
	}
	return nil
}

func updateNotes(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if opts.Interactive {
		val, err := ui.PromptString("New Notes (leave blank to keep current): ")
		if err != nil {
			return fmt.Errorf("failed to read notes: %w", err)
		}
		defer memory.SecureZero(val)
		if len(val) > 0 {
			if len(entry.Notes) > 0 {
				memory.SecureZero(entry.Notes)
			}
			entry.Notes = secrets.NewEphemeralSecret(val)
		}
		return nil
	}

	if cmd.Flags().Changed("notes") {
		providedBytes := []byte(opts.Notes)
		defer memory.SecureZero(providedBytes)
		if len(entry.Notes) > 0 {
			memory.SecureZero(entry.Notes)
		}
		if len(providedBytes) > 0 {
			entry.Notes = secrets.NewEphemeralSecret(providedBytes)
		} else {
			entry.Notes = nil
		}
	}
	return nil
}

func updateTags(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if opts.Interactive {
		promptStr := "New Tags (comma-separated, leave blank to keep current): "
		currentTags := strings.Join(entry.Tags, ", ")
		if currentTags != "" {
			promptStr = fmt.Sprintf("New Tags [%s] (leave blank to keep current): ", currentTags)
		}

		newTagsBytes, err := ui.PromptString(promptStr)
		if err != nil {
			return fmt.Errorf("failed to read tags: %w", err)
		}
		defer memory.SecureZero(newTagsBytes)

		if len(newTagsBytes) > 0 {
			rawTags := strings.Split(string(newTagsBytes), ",")
			var cleanTags []string
			for _, t := range rawTags {
				t = strings.TrimSpace(t)
				if t != "" {
					cleanTags = append(cleanTags, t)
				}
			}
			entry.Tags = cleanTags
		}
		return nil
	}

	if cmd.Flags().Changed("tags") {
		entry.Tags = opts.Tags
	}
	return nil
}

// validateUpdatedEntry extracts the current entry data safely and passes it to the strict validator.
// Security: Uses nested Access calls to prevent GC heap allocation of decrypted strings.
func validateUpdatedEntry(entry *secrets.Entry) error {
	validator := secrets.NewValidator()

	return entry.Username.Access(func(uBytes []byte) error {
		return entry.Password.Access(func(pBytes []byte) error {
			return entry.URL.Access(func(urlBytes []byte) error {
				return entry.Notes.Access(func(nBytes []byte) error {
					// We pass the decrypted byte slices directly to ValidateEntry.
					// No more unsafe.String() needed since the validator now enforces []byte for secrets.
					return validator.ValidateEntry(
						entry.Name,
						uBytes,
						pBytes,
						urlBytes,
						nBytes,
						entry.Tags,
					)
				})
			})
		})
	})
}
