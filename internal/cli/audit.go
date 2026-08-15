package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/ui"
)

// NewAuditCmd creates and returns the audit command.
// This factory pattern prevents global state pollution.
func NewAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit vault security locally",
		Long: `Perform a local security audit of your password vault.
Checks for:
- Weak passwords (insufficient entropy)
- Duplicate passwords (reuse)
- Empty passwords

Note: This audit is performed entirely offline. No data is sent to any server.`,
		RunE: runAudit,
	}

	cmd.AddCommand(NewAuditVerifyCmd())

	return cmd
}

func runAudit(cmd *cobra.Command, _ []string) error {
	cfg := config.FromContext(cmd.Context())

	// Load vault using the shared helper (assumed to be in root.go or helpers.go).
	// returns: vault, vaultPath, masterPassword, error
	vault, _, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		return err
	}

	// Security: Destroy master password immediately.
	// The audit scan only requires the decrypted vault entries (EphemeralSecrets) in memory.
	// We apply the Principle of Least Privilege by wiping the master key before the heavy lifting.
	if masterPassword != nil {
		_ = masterPassword.Destroy()
	}

	ui.PrintfInfof("Starting local security audit...")

	audit.LogSuccess(audit.EventEntryList, "Started security audit scan", nil)

	// CORRECTION: ScanVault requires Context and returns (Report, error).
	report, err := audit.ScanVault(cmd.Context(), vault)
	if err != nil {
		audit.LogFailure(audit.EventSecurityError, "Security audit scan failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("audit scan failed: %w", err)
	}

	audit.LogSuccess(audit.EventEntryList, "Security audit scan completed", map[string]interface{}{
		"total_entries":   report.TotalEntries,
		"security_score":  report.Score,
		"weak_count":      report.WeakCount,
		"duplicate_count": report.DuplicateCount,
	})

	printAuditReport(report)

	return nil
}

// printAuditReport handles the terminal formatting of the security scan results.
func printAuditReport(report *audit.Report) {
	ui.Println("\n" + strings.Repeat("=", 60))
	ui.Printf("SECURITY AUDIT REPORT\n")
	ui.Println(strings.Repeat("=", 60))

	ui.Printf("Total Entries:  %d\n", report.TotalEntries)
	ui.Printf("Security Score: %d/100\n", report.Score)
	ui.Println(strings.Repeat("-", 60))

	if report.WeakCount == 0 && report.DuplicateCount == 0 {
		ui.PrintfSuccessf("No issues found! Your vault is secure.")
		return
	}

	// Setup tabwriter for aligned columns.
	// minwidth=0, tabwidth=0, padding=3, padchar=' ', flags=0
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	_, _ = fmt.Fprintln(w, "SEVERITY\tISSUE\tENTRY\tDETAILS")
	_, _ = fmt.Fprintln(w, "--------\t-----\t-----\t-------")

	for _, issue := range report.Issues {
		severityColor := ""
		switch issue.Severity {
		case audit.SeverityHigh: // Use constants from audit package
			severityColor = "\033[31m" // Red
		case audit.SeverityMedium:
			severityColor = "\033[33m" // Yellow
		case audit.SeverityLow:
			severityColor = "\033[36m" // Cyan
		}
		resetColor := "\033[0m"

		// We include colors in the first column. Tabwriter might miscalculate width slightly
		// due to invisible escape codes, but since all rows have colors, it usually aligns visually.
		_, _ = fmt.Fprintf(w, "%s%s%s\t%s\t%s\t%s\n",
			severityColor, issue.Severity, resetColor,
			issue.Type,
			ui.SanitizeString(truncate(issue.EntryName, 30)), // Cap length and sanitize ANSI
			issue.Description,
		)
	}
	_ = w.Flush()

	fmt.Println(strings.Repeat("-", 60))
	if report.WeakCount > 0 {
		ui.PrintfWarningf("Found %d weak passwords", report.WeakCount)
	}
	if report.DuplicateCount > 0 {
		ui.PrintfWarningf("Found %d duplicated passwords", report.DuplicateCount)
	}
}

// truncate shortens a string to the given max length, appending an ellipsis if necessary.
// It is rune-aware to prevent breaking UTF-8 characters.
func truncate(s string, maxLen int) string {
	if maxLen <= 3 {
		return s
	}

	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}

	// Convert to runes to safely slice
	runes := []rune(s)
	// Check length again after rune conversion to be safe against weird inputs
	if len(runes) <= maxLen {
		return s
	}

	return string(runes[:maxLen-3]) + "..."
}
