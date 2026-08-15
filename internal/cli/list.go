package cli

import (
	"encoding/json"
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

// NewListCmd creates and returns the list command.
// This factory pattern prevents global state pollution.
func NewListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List password entries",
		Long: `List all password entries in the vault.
Use --tags to filter entries by specific tags.`,
		RunE: runList,
	}

	cmd.Flags().StringSliceP("tags", "t", []string{}, "filter by tags (comma-separated)")
	cmd.Flags().Bool("json", false, "output in JSON format")

	return cmd
}

func runList(cmd *cobra.Command, _ []string) error {
	filterTags, err := cmd.Flags().GetStringSlice("tags")
	if err != nil {
		return fmt.Errorf("failed to parse tags flag: %w", err)
	}

	listJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return fmt.Errorf("failed to parse json flag: %w", err)
	}

	cfg := config.FromContext(cmd.Context())

	// Load vault
	vault, _, masterPassword, err := loadVault(cmd.Context(), cfg)
	if err != nil {
		audit.LogFailure(audit.EventEntryList, "Failed to load vault for listing", map[string]interface{}{
			"error": err.Error(),
		})
		return err
	}
	// Security: Destroy master password immediately as the list operation is read-only
	if masterPassword != nil {
		_ = masterPassword.Destroy()
	}

	// Security: Wipe vault entries from memory on exit
	defer vault.Zero()

	// Get entries (filtered by tags if specified)
	entries := vault.ListEntries(filterTags)

	// Audit the list operation
	// We log the count to detect potential mass exfiltration attempts.
	audit.LogSuccess(audit.EventEntryList, "Entries listed", map[string]interface{}{
		"count": len(entries),
		"tags":  filterTags,
		"format": func() string {
			if listJSON {
				return "json"
			}
			return "table"
		}(),
	})

	if len(entries) == 0 {
		if len(filterTags) > 0 {
			ui.PrintfInfof("No entries found with tags: %s", ui.SanitizeString(strings.Join(filterTags, ", ")))
		} else {
			ui.PrintfInfof("No entries found in vault")
		}
		return nil
	}

	if listJSON {
		return outputEntriesJSON(entries)
	}

	// Display entries in table format
	ui.Printf("Found %d entries:\n\n", len(entries))
	printEntriesTable(entries)

	return nil
}

// outputEntriesJSONResponse structures the JSON payload.
// Security: Uses json.RawMessage to prevent Go string heap allocations of sensitive data.
type outputEntriesJSONResponse struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Tags      []string        `json:"tags"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
	Username  json.RawMessage `json:"username,omitempty"`
	URL       json.RawMessage `json:"url,omitempty"`
	Notes     json.RawMessage `json:"notes,omitempty"`
}

func outputEntriesJSON(entries []*secrets.Entry) error {
	safeEntries := make([]outputEntriesJSONResponse, len(entries))

	for i, entry := range entries {
		safeEntries[i] = buildJSONResponse(entry)
	}

	// Ensure intermediate JSON bytes backing arrays are wiped after marshaling
	defer wipeJSONResponses(safeEntries)

	jsonData, err := json.MarshalIndent(safeEntries, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write directly to stdout to prevent heap leaks, then wipe the buffer
	_, _ = os.Stdout.Write(jsonData)
	ui.Println()
	memory.SecureZero(jsonData)

	return nil
}

// buildJSONResponse safely maps a vault entry to a JSON response structure.
func buildJSONResponse(entry *secrets.Entry) outputEntriesJSONResponse {
	out := outputEntriesJSONResponse{
		ID:        string(entry.ID),
		Name:      ui.SanitizeString(entry.Name),
		CreatedAt: entry.CreatedAt.Format(time.RFC3339),
		UpdatedAt: entry.UpdatedAt.Format(time.RFC3339),
	}

	// Sanitize tags
	out.Tags = make([]string, len(entry.Tags))
	for j, tag := range entry.Tags {
		out.Tags[j] = ui.SanitizeString(tag)
	}

	// Safely attach secure strings without allocating Go strings
	// safeJSONString is defined in get.go within the cli package
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

	return out
}

// wipeJSONResponses securely zeros the sensitive byte buffers allocated for JSON marshaling.
// It iterates by index to avoid large struct copies.
func wipeJSONResponses(responses []outputEntriesJSONResponse) {
	for i := range responses {
		if len(responses[i].Username) > 0 {
			memory.SecureZero(responses[i].Username)
		}
		if len(responses[i].URL) > 0 {
			memory.SecureZero(responses[i].URL)
		}
		if len(responses[i].Notes) > 0 {
			memory.SecureZero(responses[i].Notes)
		}
	}
}
