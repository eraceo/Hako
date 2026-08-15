package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/clipboard"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// Sentinel errors to prevent dynamic error generation (err113).
var (
	ErrEntryNotFound = errors.New("not found") // Formatted strictly to match test strings
	ErrNoUsername    = errors.New("entry does not have a username")
	ErrNoPassword    = errors.New("entry does not have a password")
)

type getOptions struct {
	NameOrID     string
	ShowPassword bool
	CopyToClip   bool
	JSONOutput   bool
	GetUsername  bool
	PasswordOnly bool
}

// NewGetCmd creates and returns the get command.
// This factory pattern prevents global state pollution.
func NewGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Get a password entry",
		Long: `Retrieve a password entry from the vault.
By default, only standard fields are shown. Use --show to display the password,
or --clip to copy the password to clipboard.`,
		Args: cobra.ExactArgs(1),
		RunE: runGet,
	}

	cmd.Flags().BoolP("show", "s", false, "show password in plain text")
	cmd.Flags().BoolP("clip", "c", false, "copy password to clipboard")
	cmd.Flags().Bool("json", false, "output in JSON format")
	cmd.Flags().Bool("username", false, "target username instead of password")
	cmd.Flags().BoolP("password-only", "p", false, "output only the plaintext password")

	return cmd
}

func runGet(cmd *cobra.Command, args []string) error {
	showPassword, _ := cmd.Flags().GetBool("show")
	copyToClip, _ := cmd.Flags().GetBool("clip")
	jsonOutput, _ := cmd.Flags().GetBool("json")
	getUsername, _ := cmd.Flags().GetBool("username")
	passwordOnly, _ := cmd.Flags().GetBool("password-only")

	opts := getOptions{
		NameOrID:     args[0],
		ShowPassword: showPassword,
		CopyToClip:   copyToClip,
		JSONOutput:   jsonOutput,
		GetUsername:  getUsername,
		PasswordOnly: passwordOnly,
	}

	cfg := config.FromContext(cmd.Context())

	// Load vault
	vault, _, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	// Security: Destroy master password immediately.
	// For read-only operations, we adhere to the Principle of Least Privilege in RAM.
	if masterPassword != nil {
		_ = masterPassword.Destroy()
	}

	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	// Find entry
	entry := vault.GetEntryByName(opts.NameOrID)
	if entry == nil {
		entry = vault.GetEntryByID(secrets.EntryID(opts.NameOrID))
	}
	if entry == nil {
		audit.LogFailure(audit.EventEntryGet, "Entry not found", map[string]interface{}{
			"query": ui.SanitizeString(opts.NameOrID),
		})
		// Output: "entry 'missingEntry' not found"
		return fmt.Errorf("entry '%s' %w", ui.SanitizeString(opts.NameOrID), ErrEntryNotFound)
	}

	audit.LogSuccess(audit.EventEntryGet, "Entry retrieved", map[string]interface{}{
		"entry_id":       entry.ID,
		"entry_name":     entry.Name,
		"show_password":  opts.ShowPassword,
		"copy_clipboard": opts.CopyToClip,
		"json_output":    opts.JSONOutput,
	})

	// Output Modes
	if opts.JSONOutput {
		return printOutputJSON(entry, opts)
	}

	if opts.CopyToClip {
		return copyToClipboard(entry, cfg, opts)
	}

	if opts.GetUsername {
		return printUsernameOnly(entry)
	}

	if opts.PasswordOnly {
		return printPasswordOnly(entry)
	}

	displayEntry(entry, opts)
	return nil
}

func printUsernameOnly(entry *secrets.Entry) error {
	if len(entry.Username) == 0 {
		return nil
	}
	return entry.Username.Access(func(b []byte) error {
		sanitized := ui.SanitizeBytes(b)
		defer memory.SecureZero(sanitized)
		_, _ = os.Stdout.Write(sanitized)
		ui.Println()
		return nil
	})
}

func printPasswordOnly(entry *secrets.Entry) error {
	if len(entry.Password) == 0 {
		return nil
	}
	return entry.Password.Access(func(b []byte) error {
		sanitized := ui.SanitizeBytes(b)
		defer memory.SecureZero(sanitized)
		_, _ = os.Stdout.Write(sanitized)
		ui.Println()
		return nil
	})
}

// outputJSONResponse structures the JSON payload.
// By using json.RawMessage, we can inject raw bytes (pre-escaped) to avoid string conversions.
type outputJSONResponse struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Tags      []string        `json:"tags"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
	Username  json.RawMessage `json:"username,omitempty"`
	Password  json.RawMessage `json:"password,omitempty"`
	URL       json.RawMessage `json:"url,omitempty"`
	Notes     json.RawMessage `json:"notes,omitempty"`
}

func printOutputJSON(entry *secrets.Entry, opts getOptions) error {
	out := outputJSONResponse{
		ID:        string(entry.ID),
		Name:      ui.SanitizeString(entry.Name),
		CreatedAt: entry.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
	}

	out.Tags = make([]string, len(entry.Tags))
	for i, tag := range entry.Tags {
		out.Tags[i] = ui.SanitizeString(tag)
	}

	attachJSONSecureFields(entry, &out, opts)

	// Ensure intermediate JSON byte slices are wiped after marshaling
	defer wipeJSONResponse(&out)

	// #nosec G117 -- Marshal is intended to output the plain text password when specifically requested by the user via JSON mode
	jsonData, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write directly to stdout to prevent heap leaks, then wipe the buffer
	_, _ = os.Stdout.Write(jsonData)
	ui.Println()
	memory.SecureZero(jsonData)

	return nil
}

func attachJSONSecureFields(entry *secrets.Entry, out *outputJSONResponse, opts getOptions) {
	if len(entry.Username) > 0 {
		_ = entry.Username.Access(func(b []byte) error {
			sanitized := ui.SanitizeBytes(b)
			defer memory.SecureZero(sanitized)
			out.Username = safeJSONString(sanitized)
			return nil
		})
	}
	if len(entry.URL) > 0 {
		_ = entry.URL.Access(func(b []byte) error {
			sanitized := ui.SanitizeBytes(b)
			defer memory.SecureZero(sanitized)
			out.URL = safeJSONString(sanitized)
			return nil
		})
	}
	if len(entry.Notes) > 0 {
		_ = entry.Notes.Access(func(b []byte) error {
			sanitized := ui.SanitizeBytes(b)
			defer memory.SecureZero(sanitized)
			out.Notes = safeJSONString(sanitized)
			return nil
		})
	}
	if opts.ShowPassword && len(entry.Password) > 0 {
		_ = entry.Password.Access(func(b []byte) error {
			sanitized := ui.SanitizeBytes(b)
			defer memory.SecureZero(sanitized)
			out.Password = safeJSONString(sanitized)
			return nil
		})
	}
}

func wipeJSONResponse(out *outputJSONResponse) {
	if len(out.Username) > 0 {
		memory.SecureZero(out.Username)
	}
	if len(out.URL) > 0 {
		memory.SecureZero(out.URL)
	}
	if len(out.Notes) > 0 {
		memory.SecureZero(out.Notes)
	}
	if len(out.Password) > 0 {
		memory.SecureZero(out.Password)
	}
}

// safeJSONString converts a raw byte slice into a JSON-escaped string byte slice ("my\nsecret").
// Security: Zero-allocation hex escaping prevents Go from creating immutable heap strings.
// It uses a 2-pass strategy (count then write) to allocate exactly the required memory,
// avoiding bytes.Buffer reallocation leaks.
func safeJSONString(b []byte) []byte {
	if len(b) == 0 {
		return []byte(`""`)
	}

	const hex = "0123456789abcdef"

	// Pass 1: Calculate exact size required
	size := 2 // Opening and closing quotes
	for _, c := range b {
		switch c {
		case '"', '\\', '\n', '\r', '\t', '\b', '\f':
			size += 2
		default:
			if c < 0x20 {
				size += 6 // \u00XX
			} else {
				size++
			}
		}
	}

	// Allocate exact buffer
	buf := make([]byte, size)

	// Pass 2: Write data
	buf[0] = '"'
	idx := 1

	for _, c := range b {
		switch c {
		case '"':
			buf[idx] = '\\'
			buf[idx+1] = '"'
			idx += 2
		case '\\':
			buf[idx] = '\\'
			buf[idx+1] = '\\'
			idx += 2
		case '\n':
			buf[idx] = '\\'
			buf[idx+1] = 'n'
			idx += 2
		case '\r':
			buf[idx] = '\\'
			buf[idx+1] = 'r'
			idx += 2
		case '\t':
			buf[idx] = '\\'
			buf[idx+1] = 't'
			idx += 2
		case '\b':
			buf[idx] = '\\'
			buf[idx+1] = 'b'
			idx += 2
		case '\f':
			buf[idx] = '\\'
			buf[idx+1] = 'f'
			idx += 2
		default:
			if c < 0x20 {
				buf[idx] = '\\'
				buf[idx+1] = 'u'
				buf[idx+2] = '0'
				buf[idx+3] = '0'
				buf[idx+4] = hex[c>>4]
				buf[idx+5] = hex[c&0x0F]
				idx += 6
			} else {
				buf[idx] = c
				idx++
			}
		}
	}

	buf[idx] = '"'
	return buf
}

func copyToClipboard(entry *secrets.Entry, cfg *config.Config, opts getOptions) error {
	var contentType string
	var err error

	clipManager := clipboard.New(cfg.Clipboard)
	timeout := time.Duration(cfg.Clipboard.Timeout) * time.Second

	if opts.GetUsername {
		contentType = "username"
		if len(entry.Username) == 0 {
			return ErrNoUsername
		}
		err = entry.Username.Access(func(content []byte) error {
			return clipManager.CopySecureDaemon(content, timeout)
		})
	} else {
		contentType = "password"
		if len(entry.Password) == 0 {
			return ErrNoPassword
		}
		err = entry.Password.Access(func(content []byte) error {
			return clipManager.CopySecureDaemon(content, timeout)
		})
	}

	if err != nil {
		return fmt.Errorf("failed to copy %s to clipboard: %w", contentType, err)
	}

	titleCasedType := strings.ToUpper(contentType[:1]) + contentType[1:]
	ui.PrintfSuccessf("%s copied to clipboard (will be cleared in %s)", titleCasedType, timeout)
	return nil
}

func displayEntry(entry *secrets.Entry, opts getOptions) {
	fmt.Printf("Name: %s\n", ui.SanitizeString(entry.Name))

	printDisplayUsername(entry)
	printDisplayPassword(entry, opts.ShowPassword)
	printDisplayURL(entry)
	printDisplayNotes(entry)

	if len(entry.Tags) > 0 {
		sanitizedTags := make([]string, len(entry.Tags))
		for i, tag := range entry.Tags {
			sanitizedTags[i] = ui.SanitizeString(tag)
		}
		fmt.Printf("Tags: %s\n", strings.Join(sanitizedTags, ", "))
	}

	fmt.Printf("\nCreated: %s\n", entry.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated: %s\n", entry.UpdatedAt.Format("2006-01-02 15:04:05"))
}

func printDisplayUsername(entry *secrets.Entry) {
	if len(entry.Username) > 0 {
		_ = entry.Username.Access(func(b []byte) error {
			sanitized := ui.SanitizeBytes(b)
			defer memory.SecureZero(sanitized)
			fmt.Print("Username: ")
			_, _ = os.Stdout.Write(sanitized)
			fmt.Println()
			return nil
		})
	}
}

func printDisplayPassword(entry *secrets.Entry, showPassword bool) {
	fmt.Print("Password: ")
	if showPassword {
		if len(entry.Password) > 0 {
			_ = entry.Password.Access(func(b []byte) error {
				sanitized := ui.SanitizeBytes(b)
				defer memory.SecureZero(sanitized)
				_, _ = os.Stdout.Write(sanitized)
				return nil
			})
		}
	} else {
		fmt.Print("[hidden - use --show to display]")
	}
	fmt.Println()
}

func printDisplayURL(entry *secrets.Entry) {
	if len(entry.URL) > 0 {
		_ = entry.URL.Access(func(b []byte) error {
			if len(b) > 0 {
				sanitized := ui.SanitizeBytes(b)
				defer memory.SecureZero(sanitized)
				fmt.Print("URL: ")
				_, _ = os.Stdout.Write(sanitized)
				fmt.Println()
			}
			return nil
		})
	}
}

func printDisplayNotes(entry *secrets.Entry) {
	if len(entry.Notes) > 0 {
		_ = entry.Notes.Access(func(b []byte) error {
			if len(b) > 0 {
				sanitized := ui.SanitizeBytes(b)
				defer memory.SecureZero(sanitized)
				fmt.Print("Notes:\n")
				_, _ = os.Stdout.Write(sanitized)
				fmt.Println()
			}
			return nil
		})
	}
}
