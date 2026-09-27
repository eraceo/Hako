package cli

import (
	"bytes"
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
	PassLength  int
	Symbols     bool
	NoSymbols   bool
	Memorable   bool
	NoSimilar   bool
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
	cmd.Flags().IntP("length", "l", 16, "length of generated password")
	cmd.Flags().Bool("symbols", true, "include symbols in generated password")
	cmd.Flags().Bool("no-symbols", false, "exclude symbols in generated password")
	cmd.Flags().Bool("memorable", false, "generate memorable password")
	cmd.Flags().Bool("no-similar", false, "exclude similar characters in generated password")

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
	if opts.PassLength, err = cmd.Flags().GetInt("length"); err != nil {
		return opts, fmt.Errorf("failed to parse length flag: %w", err)
	}
	if opts.Symbols, err = cmd.Flags().GetBool("symbols"); err != nil {
		return opts, fmt.Errorf("failed to parse symbols flag: %w", err)
	}
	if opts.NoSymbols, err = cmd.Flags().GetBool("no-symbols"); err != nil {
		return opts, fmt.Errorf("failed to parse no-symbols flag: %w", err)
	}
	if opts.Memorable, err = cmd.Flags().GetBool("memorable"); err != nil {
		return opts, fmt.Errorf("failed to parse memorable flag: %w", err)
	}
	if opts.NoSimilar, err = cmd.Flags().GetBool("no-similar"); err != nil {
		return opts, fmt.Errorf("failed to parse no-similar flag: %w", err)
	}

	anyFlagChanged := cmd.Flags().Changed("user") ||
		cmd.Flags().Changed("url") ||
		cmd.Flags().Changed("notes") ||
		cmd.Flags().Changed("tags") ||
		cmd.Flags().Changed("generate") ||
		cmd.Flags().Changed("length") ||
		cmd.Flags().Changed("symbols") ||
		cmd.Flags().Changed("no-symbols") ||
		cmd.Flags().Changed("memorable") ||
		cmd.Flags().Changed("no-similar")

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

func promptWithExisting(fieldLabel string, secret secrets.EphemeralSecret) ([]byte, bool, error) {
	if len(secret) == 0 {
		fmt.Fprintf(os.Stderr, "New %s (leave blank to keep, '-' to clear): ", fieldLabel)
		raw, readErr := ui.ReadUnbufferedLine()
		if readErr != nil {
			return nil, false, readErr
		}
		clean := bytes.TrimSpace(raw)
		if isClearCommand(clean) {
			memory.SecureZero(raw)
			return nil, true, nil
		}
		return raw, false, nil
	}

	var input []byte
	var cleared bool
	var readErr error

	accessErr := secret.Access(func(b []byte) error {
		sanitized := ui.SanitizeBytes(b)
		defer memory.SecureZero(sanitized)

		fmt.Fprintf(os.Stderr, "New %s [", fieldLabel)
		_, _ = os.Stderr.Write(sanitized)
		fmt.Fprint(os.Stderr, "] (leave blank to keep, '-' to clear): ")

		raw, err := ui.ReadUnbufferedLine()
		if err != nil {
			readErr = err
			return nil
		}
		clean := bytes.TrimSpace(raw)
		if isClearCommand(clean) {
			memory.SecureZero(raw)
			cleared = true
			return nil
		}
		input = raw
		return nil
	})

	if accessErr != nil {
		return nil, false, accessErr
	}
	if readErr != nil {
		return nil, false, readErr
	}

	return input, cleared, nil
}

func isClearCommand(b []byte) bool {
	if len(b) == 1 && b[0] == '-' {
		return true
	}
	if bytes.EqualFold(b, []byte("clear")) || bytes.EqualFold(b, []byte("none")) {
		return true
	}
	return false
}

func updateUsername(cmd *cobra.Command, entry *secrets.Entry, opts editOptions) error {
	if opts.Interactive {
		val, cleared, err := promptWithExisting("Username", entry.Username)
		if err != nil {
			return fmt.Errorf("failed to read username: %w", err)
		}
		defer memory.SecureZero(val)

		if cleared {
			if len(entry.Username) > 0 {
				memory.SecureZero(entry.Username)
			}
			entry.Username = nil
			return nil
		}

		cleanVal := bytes.TrimSpace(val)
		if len(cleanVal) > 0 {
			if len(entry.Username) > 0 {
				memory.SecureZero(entry.Username) // Wipe old ciphertext safely
			}
			entry.Username = secrets.NewEphemeralSecret(cleanVal)
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
		passLen := opts.PassLength
		if passLen < 1 {
			passLen = 16
		}
		genOpts := secrets.GeneratorOptions{
			Length:     passLen,
			UseSymbols: opts.Symbols && !opts.NoSymbols,
			Memorable:  opts.Memorable,
			NoSimilar:  opts.NoSimilar,
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
		val, cleared, err := promptWithExisting("URL", entry.URL)
		if err != nil {
			return fmt.Errorf("failed to read URL: %w", err)
		}
		defer memory.SecureZero(val)

		if cleared {
			if len(entry.URL) > 0 {
				memory.SecureZero(entry.URL)
			}
			entry.URL = nil
			return nil
		}

		cleanVal := bytes.TrimSpace(val)
		if len(cleanVal) > 0 {
			if len(entry.URL) > 0 {
				memory.SecureZero(entry.URL)
			}
			entry.URL = secrets.NewEphemeralSecret(cleanVal)
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
		val, cleared, err := promptWithExisting("Notes", entry.Notes)
		if err != nil {
			return fmt.Errorf("failed to read notes: %w", err)
		}
		defer memory.SecureZero(val)

		if cleared {
			if len(entry.Notes) > 0 {
				memory.SecureZero(entry.Notes)
			}
			entry.Notes = nil
			return nil
		}

		cleanVal := bytes.TrimSpace(val)
		if len(cleanVal) > 0 {
			if len(entry.Notes) > 0 {
				memory.SecureZero(entry.Notes)
			}
			entry.Notes = secrets.NewEphemeralSecret(cleanVal)
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
		promptStr := "New Tags (comma-separated, leave blank to keep, '-' to clear): "
		currentTags := strings.Join(entry.Tags, ", ")
		if currentTags != "" {
			promptStr = fmt.Sprintf("New Tags [%s] (leave blank to keep, '-' to clear): ", currentTags)
		}

		newTagsBytes, err := ui.PromptString(promptStr)
		if err != nil {
			return fmt.Errorf("failed to read tags: %w", err)
		}
		defer memory.SecureZero(newTagsBytes)

		clean := bytes.TrimSpace(newTagsBytes)
		if isClearCommand(clean) {
			entry.Tags = nil
			return nil
		}

		if len(clean) > 0 {
			rawTags := strings.Split(string(clean), ",")
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
