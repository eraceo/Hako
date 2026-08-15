package cli

import (
	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/ui"
)

// NewSearchCmd returns the search command.
// Instantiating the command via a constructor instead of a global variable prevents
// test pollution and cross-test state leakage during parallel execution.
func NewSearchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search <pattern>",
		Short: "Search password entries",
		Long: `Search for password entries by pattern.
The search looks for case-insensitive matches in entry names, usernames, and URLs.`,
		Args: cobra.ExactArgs(1),
		RunE: runSearch,
	}
	return cmd
}

func runSearch(cmd *cobra.Command, args []string) error {
	pattern := args[0]

	cfg := config.FromContext(cmd.Context())

	// Load vault
	vault, _, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		// Log the failure to access the vault for searching
		audit.LogFailure(audit.EventEntrySearch, "Failed to load vault for search", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}

	// Security: Destroy master password immediately as search is a read-only operation.
	// We adhere to the Principle of Least Privilege in RAM.
	if masterPassword != nil {
		_ = masterPassword.Destroy()
	}

	// Security: Wipe all vault entry ciphertexts from heap once we are done,
	// regardless of the search outcome. Consistent with the Zero() pattern
	// applied in other read-only commands.
	defer vault.Zero()

	// Search entries using zero-allocation byte scanning
	results := vault.SearchEntries(pattern)

	if len(results) == 0 {
		// Audit the empty search
		audit.LogSuccess(audit.EventEntrySearch, "Search completed with no results", map[string]interface{}{
			"results_count": 0,
			// SECURITY: Do NOT log the 'pattern' to avoid persisting accidentally pasted passwords.
		})
		// Security: Do NOT reprint the user's pattern here.
		ui.PrintfInfof("No entries found matching the provided pattern.\n")
		return nil
	}

	// Audit the successful search
	audit.LogSuccess(audit.EventEntrySearch, "Search completed successfully", map[string]interface{}{
		"results_count": len(results),
		// SECURITY: Do NOT log the 'pattern'.
	})

	// Use the centralized UI system for all output to ensure consistent formatting
	// and correct behavior with any future --quiet or --no-color flags.
	ui.PrintfSuccessf("Found %d entries:\n\n", len(results))
	printEntriesTable(results)

	return nil
}
