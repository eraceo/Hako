// Package cli implements the command-line interface for Hako.
package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// Sentinel errors to prevent dynamic error generation (err113).
var (
	ErrEntryExists           = errors.New("entry already exists")
	ErrInvalidPasswordLength = errors.New("invalid password length")
	ErrPasswordMismatch      = errors.New("passwords do not match")
)

// addOptions encapsulates all flag states.
type addOptions struct {
	Name        string
	Username    string
	URL         string
	Notes       string
	Tags        []string
	Generate    bool
	PassLength  int
	Symbols     bool
	Memorable   bool
	Interactive bool
}

// NewAddCmd creates and returns the add command.
func NewAddCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a new password entry",
		Long: `Add a new password entry to the vault.
You can provide the details via flags or be prompted interactively.
Use --generate to automatically generate a secure password.`,
		Args: cobra.ExactArgs(1),
		RunE: runAdd,
	}

	cmd.Flags().StringP("user", "u", "", "username for the entry")
	cmd.Flags().String("url", "", "URL for the entry")
	cmd.Flags().StringP("notes", "n", "", "notes for the entry")
	cmd.Flags().StringSliceP("tags", "t", []string{}, "tags for the entry (comma-separated)")
	cmd.Flags().BoolP("generate", "g", false, "generate a secure password")
	cmd.Flags().Int("length", 16, "length of generated password")
	cmd.Flags().Bool("symbols", true, "include symbols in generated password")
	cmd.Flags().Bool("memorable", false, "generate memorable password")

	return cmd
}

func runAdd(cmd *cobra.Command, args []string) error {
	opts, err := parseAddFlags(cmd, args)
	if err != nil {
		return err
	}

	// Gather Entry Details FIRST.
	// This ensures we don't prompt for the Master Password and keep it in RAM (Memguard)
	// while the user is slowly typing their new entry details.
	entry, err := getEntryDetails(cmd, opts)
	if err != nil {
		return err
	}
	// The entry password is now encrypted in Heap (EphemeralSecret).

	cfg := config.FromContext(cmd.Context())

	// Load Vault (Ask for Master Password NOW)
	vault, vaultFile, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	// Strict cleanup of the Master Password Enclave
	defer func() {
		if masterPassword != nil {
			_ = masterPassword.Destroy()
		}
	}()
	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	// Check for duplicates
	if vault.GetEntryByName(opts.Name) != nil {
		audit.LogFailure(audit.EventEntryAdd, "Entry already exists", map[string]interface{}{
			"name": ui.SanitizeString(opts.Name),
		})
		return fmt.Errorf("%w: '%s'", ErrEntryExists, ui.SanitizeString(opts.Name))
	}

	// Add & Save
	vault.AddEntry(entry)

	if err := saveVaultWithFile(cmd.Context(), cfg, vault, vaultFile, masterPassword); err != nil {
		return err
	}

	audit.LogSuccess(audit.EventEntryAdd, "Entry added successfully", map[string]interface{}{
		"name":      entry.Name,
		"username":  entry.Username.PlaintextLen() > 0, // Log only presence, not value
		"url":       entry.URL.PlaintextLen() > 0,
		"tags":      entry.Tags,
		"generated": opts.Generate,
	})

	ui.PrintfSuccessf("Entry '%s' added successfully", ui.SanitizeString(opts.Name))
	return nil
}

func parseAddFlags(cmd *cobra.Command, args []string) (addOptions, error) {
	username, err := cmd.Flags().GetString("user")
	if err != nil {
		return addOptions{}, err
	}
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return addOptions{}, err
	}
	notes, err := cmd.Flags().GetString("notes")
	if err != nil {
		return addOptions{}, err
	}
	tags, err := cmd.Flags().GetStringSlice("tags")
	if err != nil {
		return addOptions{}, err
	}
	generate, err := cmd.Flags().GetBool("generate")
	if err != nil {
		return addOptions{}, err
	}
	length, err := cmd.Flags().GetInt("length")
	if err != nil {
		return addOptions{}, err
	}
	symbols, err := cmd.Flags().GetBool("symbols")
	if err != nil {
		return addOptions{}, err
	}
	memorable, err := cmd.Flags().GetBool("memorable")
	if err != nil {
		return addOptions{}, err
	}

	anyFlagChanged := cmd.Flags().Changed("user") ||
		cmd.Flags().Changed("url") ||
		cmd.Flags().Changed("notes") ||
		cmd.Flags().Changed("tags") ||
		cmd.Flags().Changed("generate")

	return addOptions{
		Name:        args[0],
		Username:    username,
		URL:         url,
		Notes:       notes,
		Tags:        tags,
		Generate:    generate,
		PassLength:  length,
		Symbols:     symbols,
		Memorable:   memorable,
		Interactive: !anyFlagChanged,
	}, nil
}

func getEntryDetails(cmd *cobra.Command, opts addOptions) (*secrets.Entry, error) {
	var finalUsername []byte
	var err error

	if opts.Interactive {
		finalUsername, err = ui.PromptString("Username: ")
		if err != nil {
			return nil, fmt.Errorf("failed to read username: %w", err)
		}
	} else if cmd.Flags().Changed("user") {
		finalUsername = []byte(opts.Username)
	}
	defer memory.SecureZero(finalUsername)

	// CRITICAL: The password path MUST remain strictly []byte based.
	entryPassword, err := getEntryPassword(opts)
	if err != nil {
		return nil, err
	}
	defer memory.SecureZero(entryPassword)

	var finalURL []byte
	if opts.Interactive {
		finalURL, err = ui.PromptString("URL (optional): ")
		if err != nil {
			return nil, fmt.Errorf("failed to read URL: %w", err)
		}
	} else if cmd.Flags().Changed("url") {
		finalURL = []byte(opts.URL)
	}
	defer memory.SecureZero(finalURL)

	var finalNotes []byte
	if opts.Interactive {
		finalNotes, err = ui.PromptString("Notes (optional): ")
		if err != nil {
			return nil, fmt.Errorf("failed to read notes: %w", err)
		}
	} else if cmd.Flags().Changed("notes") {
		finalNotes = []byte(opts.Notes)
	}
	defer memory.SecureZero(finalNotes)

	var finalTags []string
	if opts.Interactive {
		val, err := ui.PromptString("Tags (comma-separated, optional): ")
		if err != nil {
			return nil, fmt.Errorf("failed to read tags: %w", err)
		}
		defer memory.SecureZero(val)
		if len(val) > 0 {
			parts := strings.Split(string(val), ",")
			for _, t := range parts {
				cleanTag := strings.TrimSpace(t)
				if cleanTag != "" {
					finalTags = append(finalTags, cleanTag)
				}
			}
		}
	} else {
		if cmd.Flags().Changed("tags") {
			finalTags = opts.Tags
		}
	}

	return secrets.NewEntry(
		opts.Name,
		finalUsername,
		entryPassword,
		finalURL,
		finalNotes,
		finalTags,
	)
}

func getEntryPassword(opts addOptions) ([]byte, error) {
	if opts.Generate {
		return generateEntryPassword(opts)
	}

	// Interactive mode: Ask for password and confirmation
	pass1, err := ui.PromptPassword("Password: ")
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	pass2, err := ui.PromptPassword("Confirm Password: ")
	if err != nil {
		memory.SecureZero(pass1)
		return nil, fmt.Errorf("failed to read confirmation: %w", err)
	}
	defer memory.SecureZero(pass2)

	if !bytes.Equal(pass1, pass2) {
		memory.SecureZero(pass1)
		return nil, ErrPasswordMismatch
	}

	return pass1, nil
}

func generateEntryPassword(opts addOptions) ([]byte, error) {
	if opts.PassLength < 1 {
		return nil, fmt.Errorf("%w: must be at least %d", ErrInvalidPasswordLength, 1)
	}

	genOpts := secrets.GeneratorOptions{
		Length:     opts.PassLength,
		UseSymbols: opts.Symbols,
		Memorable:  opts.Memorable,
	}

	entryPassword, err := secrets.GeneratePassword(genOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password: %w", err)
	}

	fmt.Print("Generated password: ")
	_, _ = os.Stdout.Write(entryPassword)
	fmt.Println()

	return entryPassword, nil
}
