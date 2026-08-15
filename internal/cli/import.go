package cli

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// FormatCSV is the identifier for the CSV import format.
const FormatCSV = "csv"

// FormatJSON is the identifier for the JSON (Bitwarden) import format.
const FormatJSON = "json"

// FormatXML is the identifier for the XML (KeePass) import format.
const FormatXML = "xml"

// EventImport is the audit event type for vault import operations.
const EventImport audit.EventType = "vault_import"

// ErrUnsupportedImportFormat is returned when an import format is not recognized.
var ErrUnsupportedImportFormat = errors.New("unsupported format")

// Importer defines the interface for streaming parsers of different credential file formats.
type Importer interface {
	Parse() ([]*secrets.Entry, error)
	Close()
}

// NewImportCmd creates the 'import' sub-command.
func NewImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <file>",
		Short: "Import passwords from other managers",
		Long: `Import passwords from CSV, JSON (Bitwarden), or XML (KeePass) files.
All imports use secure, zero-allocation streaming to protect sensitive data.
Supported formats:
- CSV (Generic): Streamed parsing of standard CSVs.
- JSON (Bitwarden): Streamed secure JSON parsing.
- XML (KeePass): Streamed XML parsing (extracts Titles, Passwords, etc).`,
		Args: cobra.ExactArgs(1),
		RunE: runImport,
	}

	cmd.Flags().StringP("format", "f", "", "import format (csv, json, xml). If not provided, inferred from file extension")

	return cmd
}

func runImport(cmd *cobra.Command, args []string) error {
	importFormat, err := cmd.Flags().GetString("format")
	if err != nil {
		return fmt.Errorf("failed to parse format flag: %w", err)
	}

	filePath := filepath.Clean(args[0])
	cfg := config.FromContext(cmd.Context())

	format, err := detectFormat(filePath, importFormat)
	if err != nil {
		return err
	}

	ui.PrintfInfof("Securely parsing %s file...\n", strings.ToUpper(format))

	var importer Importer
	switch format {
	case FormatJSON:
		importer, err = NewSecureJSONImporter(filePath)
	case FormatCSV:
		importer, err = NewSecureCSVImporter(filePath)
	case FormatXML:
		importer, err = NewSecureKeePassImporter(filePath)
	default:
		return ErrUnsupportedImportFormat
	}

	if err != nil {
		return auditFailure(EventImport, "Failed to open secure stream", filePath, err)
	}
	defer importer.Close()

	entries, err := importer.Parse()
	if err != nil {
		// Zero any partially-parsed entries before returning.
		zeroEntries(entries)
		return auditFailure(EventImport, fmt.Sprintf("Failed to parse %s stream", format), filePath, err)
	}

	if len(entries) == 0 {
		ui.PrintfWarningf("No entries found to import in %s\n", filePath)
		return nil
	}

	ui.PrintfInfof("Found %d entries to import.\n", len(entries))

	return processImportedEntries(cmd, cfg, entries, filePath, format)
}

// auditFailure logs an import failure event and returns a wrapped error.
func auditFailure(event audit.EventType, msg, file string, err error) error {
	audit.LogFailure(event, msg, map[string]interface{}{
		"file":  file,
		"error": err.Error(),
	})
	return fmt.Errorf("%s: %w", msg, err)
}

// zeroEntries securely wipes all EphemeralSecret fields in a slice of entries.
// It must be called whenever entries are abandoned (parse error, save failure, duplicates).
func zeroEntries(entries []*secrets.Entry) {
	for _, e := range entries {
		if e != nil {
			e.Zero()
		}
	}
}

func processImportedEntries(
	cmd *cobra.Command,
	cfg *config.Config,
	entries []*secrets.Entry,
	filePath string,
	format string,
) error {
	// SECURITY: Always zero ALL parsed entries on any exit path, whether the
	// individual entry was imported, skipped, or the save failed.
	// Entries added to the vault are owned by the vault; entries NOT added
	// (duplicates) must be explicitly zeroed here.
	var skippedEntries []*secrets.Entry
	defer func() {
		zeroEntries(skippedEntries)
	}()

	// Vault is loaded AFTER parsing to minimize Master Key exposure time.
	vault, vaultFile, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		// Parsing succeeded but vault is unavailable — zero everything.
		zeroEntries(entries)
		return err
	}

	// SECURITY (Memory - Secret Lifespan): Destroy the master password enclave
	// immediately after the vault is decrypted.
	defer func() {
		if masterPassword != nil {
			_ = masterPassword.Destroy()
		}
	}()
	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	importedCount := 0

	for _, entry := range entries {
		if vault.GetEntryByName(entry.Name) != nil {
			// Duplicate: track for deferred zeroing; do NOT add to vault.
			skippedEntries = append(skippedEntries, entry)
			continue
		}
		vault.AddEntry(entry)
		importedCount++
	}

	skippedCount := len(skippedEntries)

	if importedCount > 0 {
		if err := saveVaultWithFile(cmd.Context(), cfg, vault, vaultFile, masterPassword); err != nil {
			// Save failed: the vault owns the imported entries; zeroEntries is
			// intentionally NOT called on them here — the vault's own cleanup
			// handles those. Skipped entries are handled by the deferred call above.
			return auditFailure(EventImport, "Failed to save vault", filePath, err)
		}

		audit.LogSuccess(EventImport, "Import completed", map[string]interface{}{
			"source_file":    filePath,
			"format":         format,
			"imported_count": importedCount,
			"skipped_count":  skippedCount,
		})

		ui.PrintfSuccessf("Successfully imported %d entries.\n", importedCount)
		ui.PrintfWarningf("Securely delete the source file '%s' now!\n", filePath)
	} else {
		// Even if no entries imported, we must ensure skipped entries are wiped (handled by defer).
		ui.PrintfWarningf("No new entries imported (duplicates skipped).\n")
	}

	if skippedCount > 0 {
		ui.PrintfInfof("Skipped %d duplicate entries.\n", skippedCount)
	}

	// Warn about the memory security limitation for very large imports.
	if importedCount > 10_000 {
		ui.PrintfWarningf("Large import (%d entries): consider restarting hako to flush session RAM.\n", importedCount)
	}

	return nil
}

// detectFormat resolves the import format from the --format flag or the file extension.
func detectFormat(filePath, flagFormat string) (string, error) {
	format := strings.ToLower(flagFormat)
	if format == "" {
		ext := filepath.Ext(filePath)
		if len(ext) > 1 {
			format = strings.ToLower(ext[1:])
		}
	}

	switch format {
	case FormatCSV, FormatJSON, FormatXML:
		return format, nil
	default:
		return "", fmt.Errorf("%w: '%s' (supported: csv, json, xml)", ErrUnsupportedImportFormat, format)
	}
}
