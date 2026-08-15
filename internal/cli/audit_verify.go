package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/ui"
)

// NewAuditVerifyCmd creates the 'verify-logs' sub-command under 'audit'.
func NewAuditVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify-logs",
		Short: "Verify audit log cryptographic hash chain integrity",
		Long: `Perform a strict cryptographic verification of the audit log chain.
Checks for:
- PrevHash/Hash continuity across all events
- Archive file integrity (including compressed .gz backups)
- Detection of modified, inserted, or deleted log entries`,
		RunE: runAuditVerifyLogs,
	}

	return cmd
}

func runAuditVerifyLogs(cmd *cobra.Command, _ []string) error {
	cfg := config.FromContext(cmd.Context())

	ui.PrintfInfof("Verifying audit log chain at %s...", cfg.AuditLogPath)

	report, err := audit.VerifyLogChain(cfg.AuditLogPath)
	if err != nil {
		return fmt.Errorf("failed to verify log chain: %w", err)
	}

	switch report.Status {
	case audit.StatusValid:
		ui.PrintfSuccessf("Log chain integrity VERIFIED. Checked %d events across %d file(s). All events intact.",
			report.TotalEventsChecked, report.TotalFilesChecked)
	case audit.StatusTruncatedEOF:
		ui.PrintfWarningf("Log chain truncated at EOF in file %s (line %d). %s",
			report.FirstErrorFile, report.FirstErrorLine, report.ErrorDetails)
	case audit.StatusTampered:
		ui.PrintfErrorf("Log chain TAMPERED or CORRUPTED in file %s (line %d)! Details: %s",
			report.FirstErrorFile, report.FirstErrorLine, report.ErrorDetails)
		return fmt.Errorf("audit log verification failed: integrity compromised at line %d in %s",
			report.FirstErrorLine, report.FirstErrorFile)
	}

	return nil
}
