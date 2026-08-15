package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/ui"
	"github.com/eraceo/Hako/internal/version"
)

// NewVersionCmd returns the version command.
// Instantiating the command and its flags locally prevents global state mutation
// and ensures deterministic, parallel-safe execution in tests.
func NewVersionCmd() *cobra.Command {
	var versionJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  `Display version information for Hako including build details.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.Get()

			if versionJSON {
				jsonData, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal version info: %w", err)
				}

				// Write bytes directly to stdout to prevent implicit string heap allocations
				_, _ = os.Stdout.Write(jsonData)
				ui.Println()
			} else {
				ui.Println(info.String())
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&versionJSON, "json", false, "output version information in JSON format")

	return cmd
}
