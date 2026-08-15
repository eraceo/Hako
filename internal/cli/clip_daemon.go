package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/clipboard"
	"github.com/eraceo/Hako/internal/config"
)

// NewClipDaemonCmd creates the hidden __clip-daemon command used for background clipboard clearing.
func NewClipDaemonCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "__clip-daemon",
		Short:  "Internal daemon worker to clear clipboard",
		Hidden: true,
		RunE:   runClipDaemon,
	}

	cmd.Flags().String("tool", "", "clipboard tool name")
	cmd.Flags().Duration("timeout", 45*time.Second, "timeout duration before clearing clipboard")

	return cmd
}

func runClipDaemon(cmd *cobra.Command, _ []string) error {
	toolName, _ := cmd.Flags().GetString("tool")
	timeout, _ := cmd.Flags().GetDuration("timeout")

	if toolName == "" {
		return fmt.Errorf("tool parameter cannot be empty")
	}

	// SECURITY: Strict Allowlist Validation
	// Do NOT execute arbitrary tools passed on command line.
	// Must match known allowed tools.
	allowedTools := map[string]bool{
		"wl-copy":  true,
		"xclip":    true,
		"xsel":     true,
		"clip":     true,
		"pbcopy":   true,
		"win32api": true,
	}

	if !allowedTools[toolName] {
		return fmt.Errorf("unauthorized clipboard tool: %s", toolName)
	}

	// Construct Clipboard Manager configured for this specific tool
	cfg := config.ClipboardConfig{
		ToolPreference: []string{toolName},
		Timeout:        int(timeout.Seconds()),
	}
	clipManager := clipboard.New(cfg)

	// Listen for SIGTERM/SIGINT signals or timer expiration
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-ctx.Done():
	}

	// Execute clipboard clearing
	err := clipManager.Clear()

	// Clean up PID lock file
	pidFile, pErr := clipboard.GetPIDFilePath()
	if pErr == nil {
		_ = os.Remove(pidFile)
	}

	return err
}
