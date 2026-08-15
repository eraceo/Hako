package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
var (
	ErrUnsupportedFormat = errors.New("unsupported export format")
	ErrExportCanceled    = errors.New("export canceled")
	ErrExportOverwrite   = errors.New("cannot export to the vault or keyfile path")
)

type exportOptions struct {
	Format string
	Output string
	Force  bool
}

// NewExportCmd creates and returns the export command.
// This factory pattern prevents global state pollution.
func NewExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export vault data",
		Long: `Export vault data to various formats.
WARNING: Exported data may contain passwords in plain text.
Ensure the output file is properly secured.`,
		RunE: runExport,
	}

	cmd.Flags().String("format", "json", "export format (json, csv)")
	cmd.Flags().StringP("out", "o", "", "output file (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "force export without confirmation")

	return cmd
}

func runExport(cmd *cobra.Command, _ []string) error {
	format, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("out")
	force, _ := cmd.Flags().GetBool("force")

	opts := exportOptions{
		Format: format,
		Output: output,
		Force:  force,
	}

	cfg := config.FromContext(cmd.Context())

	// Security warning and confirmation
	if err := checkExportConfirmation(opts.Force); err != nil {
		if errors.Is(err, ErrExportCanceled) {
			fmt.Println("Export canceled")
			return nil
		}
		return err
	}

	// Load vault
	vault, _, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		return err
	}
	// Destroy master password immediately as we don't need it
	if masterPassword != nil {
		_ = masterPassword.Destroy()
	}

	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	// Determine output writer
	writer, closeWriter, err := setupExportWriter(opts.Output, cfg)
	if err != nil {
		return err
	}
	defer closeWriter()

	// Export based on format using zero-allocation streaming
	switch strings.ToLower(opts.Format) {
	case "json":
		err = exportJSON(vault, writer)
	case "csv":
		err = exportCSV(vault, writer)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}

	if err != nil {
		audit.LogFailure(audit.EventExport, "Export failed", map[string]interface{}{
			"format": opts.Format,
			"error":  err.Error(),
		})
		return fmt.Errorf("failed to export data: %w", err)
	}

	audit.LogSuccess(audit.EventExport, "Vault exported", map[string]interface{}{
		"format":        opts.Format,
		"output_target": opts.Output, // Log filename or empty for stdout
		"entry_count":   len(vault.Entries),
	})

	if opts.Output != "" {
		ui.PrintfSuccessf("Vault exported to %s\n", opts.Output)
		ui.PrintfWarningf("Secure the exported file - it contains plain text passwords!\n")
	}

	return nil
}

func checkExportConfirmation(force bool) error {
	if force {
		return nil
	}

	ui.PrintfWarningf("Export will contain passwords in plain text!")
	confirmed, err := ui.PromptConfirm("Are you sure you want to continue?")
	if err != nil {
		return fmt.Errorf("failed to read confirmation: %w", err)
	}

	if !confirmed {
		return ErrExportCanceled
	}
	return nil
}

func setupExportWriter(outputPath string, cfg *config.Config) (io.Writer, func(), error) {
	if outputPath == "" {
		return os.Stdout, func() {}, nil
	}

	// Security check: Prevent overwriting the vault or keyfile
	cleanPath := filepath.Clean(outputPath)
	absPath, _ := filepath.Abs(cleanPath)
	absVault, _ := filepath.Abs(cfg.VaultPath)
	absKeyfile, _ := filepath.Abs(cfg.KeyfilePath)

	if absPath == absVault || (cfg.KeyfilePath != "" && absPath == absKeyfile) {
		return nil, nil, ErrExportOverwrite
	}

	// Even if paths are different (symlinks), check for file identity
	if _, err := os.Stat(cleanPath); err == nil {
		vInfo, vErr := os.Stat(cfg.VaultPath)
		eInfo, eErr := os.Stat(cleanPath)
		if vErr == nil && eErr == nil && os.SameFile(vInfo, eInfo) {
			return nil, nil, ErrExportOverwrite
		}
	}

	// Open file with strict permissions
	// #nosec G304 - cleanPath is validated by user intent to export to this specific location
	file, err := os.OpenFile(cleanPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open output file: %w", err)
	}

	closeFunc := func() { _ = file.Close() }
	return file, closeFunc, nil
}

type exportJSONEntry struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Username  json.RawMessage `json:"username"`
	Password  json.RawMessage `json:"password"`
	URL       json.RawMessage `json:"url"`
	Notes     json.RawMessage `json:"notes"`
	Tags      []string        `json:"tags"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

func exportJSON(vault *secrets.Vault, w io.Writer) error {
	// Start JSON object
	if _, err := fmt.Fprint(w, "{\n  \"meta\": {\n"); err != nil {
		return err
	}

	metaTemplate := "    \"exported_at\": %q,\n    \"version\": \"1.0\",\n    \"tool\": \"Hako\"\n  },\n  \"entries\": [\n"
	meta := fmt.Sprintf(metaTemplate, time.Now().Format(time.RFC3339))
	if _, err := fmt.Fprint(w, meta); err != nil {
		return err
	}

	// Write entries one by one to minimize memory footprint
	for i, entry := range vault.Entries {
		if err := writeJSONEntry(w, entry, i == 0); err != nil {
			return err
		}
	}

	// Close JSON object
	if _, err := fmt.Fprint(w, "\n  ]\n}\n"); err != nil {
		return err
	}

	return nil
}

func writeJSONEntry(w io.Writer, entry *secrets.Entry, isFirst bool) error {
	if !isFirst {
		if _, err := fmt.Fprint(w, ",\n"); err != nil {
			return err
		}
	}

	out := exportJSONEntry{
		ID:        string(entry.ID),
		Name:      entry.Name, // Exact backup, no UI sanitization
		Tags:      entry.Tags,
		CreatedAt: entry.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
	}

	// Empty JSON string defaults
	emptyJSON := []byte(`""`)
	out.Username = emptyJSON
	out.Password = emptyJSON
	out.URL = emptyJSON
	out.Notes = emptyJSON

	// Securely extract sensitive fields just for serialization
	if len(entry.Username) > 0 {
		_ = entry.Username.Access(func(b []byte) error {
			out.Username = safeJSONString(b)
			return nil
		})
	}
	if len(entry.Password) > 0 {
		_ = entry.Password.Access(func(b []byte) error {
			out.Password = safeJSONString(b)
			return nil
		})
	}
	if len(entry.URL) > 0 {
		_ = entry.URL.Access(func(b []byte) error {
			out.URL = safeJSONString(b)
			return nil
		})
	}
	if len(entry.Notes) > 0 {
		_ = entry.Notes.Access(func(b []byte) error {
			out.Notes = safeJSONString(b)
			return nil
		})
	}

	return encodeAndWipeJSONEntry(w, out)
}

// encodeAndWipeJSONEntry writes a single entry directly to the stream to prevent intermediate json.MarshalIndent heap allocations.
func encodeAndWipeJSONEntry(w io.Writer, out exportJSONEntry) error {
	nameJSON, err := json.Marshal(out.Name)
	if err != nil {
		return err
	}
	defer memory.SecureZero(nameJSON)

	tagsJSON, err := json.Marshal(out.Tags)
	if err != nil {
		return err
	}
	defer memory.SecureZero(tagsJSON)

	if _, err := w.Write([]byte("    {\n")); err != nil {
		return err
	}
	if _, err := w.Write([]byte("      \"id\": ")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%q,\n", out.ID); err != nil {
		return err
	}
	if _, err := w.Write([]byte("      \"name\": ")); err != nil {
		return err
	}
	if _, err := w.Write(nameJSON); err != nil {
		return err
	}
	if _, err := w.Write([]byte(",\n      \"username\": ")); err != nil {
		return err
	}
	if _, err := w.Write(out.Username); err != nil {
		return err
	}
	if _, err := w.Write([]byte(",\n      \"password\": ")); err != nil {
		return err
	}
	if _, err := w.Write(out.Password); err != nil {
		return err
	}
	if _, err := w.Write([]byte(",\n      \"url\": ")); err != nil {
		return err
	}
	if _, err := w.Write(out.URL); err != nil {
		return err
	}
	if _, err := w.Write([]byte(",\n      \"notes\": ")); err != nil {
		return err
	}
	if _, err := w.Write(out.Notes); err != nil {
		return err
	}
	if _, err := w.Write([]byte(",\n      \"tags\": ")); err != nil {
		return err
	}
	if _, err := w.Write(tagsJSON); err != nil {
		return err
	}
	if _, err := w.Write([]byte(",\n      \"created_at\": \"")); err != nil {
		return err
	}
	if _, err := w.Write([]byte(out.CreatedAt)); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\",\n      \"updated_at\": \"")); err != nil {
		return err
	}
	if _, err := w.Write([]byte(out.UpdatedAt)); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\"\n    }")); err != nil {
		return err
	}

	if len(out.Username) > 2 { // len > 2 prevents wiping the literal `""` bytes
		memory.SecureZero(out.Username)
	}
	if len(out.Password) > 2 {
		memory.SecureZero(out.Password)
	}
	if len(out.URL) > 2 {
		memory.SecureZero(out.URL)
	}
	if len(out.Notes) > 2 {
		memory.SecureZero(out.Notes)
	}

	return nil
}

func exportCSV(vault *secrets.Vault, w io.Writer) error {
	// Write header manually
	header := "Name,Username,Password,URL,Notes,Tags,Created,Updated\n"
	if _, err := w.Write([]byte(header)); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write entries one by one using our custom zero-allocation CSV writer
	for _, entry := range vault.Entries {
		if err := writeCSVEntry(w, entry); err != nil {
			return err
		}
	}

	return nil
}

func writeCSVEntry(w io.Writer, entry *secrets.Entry) error {
	if err := writeCSVField(w, []byte(entry.Name)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	if len(entry.Username) > 0 {
		_ = entry.Username.Access(func(b []byte) error { return writeCSVField(w, b) })
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	if len(entry.Password) > 0 {
		_ = entry.Password.Access(func(b []byte) error { return writeCSVField(w, b) })
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	if len(entry.URL) > 0 {
		_ = entry.URL.Access(func(b []byte) error { return writeCSVField(w, b) })
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	if len(entry.Notes) > 0 {
		_ = entry.Notes.Access(func(b []byte) error { return writeCSVField(w, b) })
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	tagsJoined := strings.Join(entry.Tags, ";")
	if err := writeCSVField(w, []byte(tagsJoined)); err != nil {
		return err
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	if _, err := w.Write([]byte(entry.CreatedAt.Format("2006-01-02 15:04:05"))); err != nil {
		return err
	}
	if _, err := w.Write([]byte{','}); err != nil {
		return err
	}

	if _, err := w.Write([]byte(entry.UpdatedAt.Format("2006-01-02 15:04:05"))); err != nil {
		return err
	}
	if _, err := w.Write([]byte{'\n'}); err != nil {
		return err
	}

	return nil
}

// writeCSVField writes a single CSV field directly to an io.Writer without string allocations.
// It applies proper RFC 4180 CSV escaping (quoting fields with commas, newlines, or quotes).
func writeCSVField(w io.Writer, field []byte) error {
	if len(field) == 0 {
		return nil
	}

	needsQuotes := false
	for _, b := range field {
		if b == '"' || b == '\n' || b == '\r' || b == ',' {
			needsQuotes = true
			break
		}
	}

	if !needsQuotes {
		_, err := w.Write(field)
		return err
	}

	// Write quoted and escaped field
	if _, err := w.Write([]byte{'"'}); err != nil {
		return err
	}

	for _, b := range field {
		if b == '"' {
			if _, err := w.Write([]byte{'"', '"'}); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte{b}); err != nil {
				return err
			}
		}
	}

	_, err := w.Write([]byte{'"'})
	return err
}
