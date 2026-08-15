// Package clipboard provides secure clipboard management with auto-clear functionality.
package clipboard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/ui"
)

/*
SECURITY NOTES REGARDING OS CLIPBOARDS:
The clipboard is fundamentally outside the application's secure memory enclave.
Once data is copied, Hako loses physical control over it. Users should be aware that:
- Windows 10+ Clipboard History (Win+V) may retain the password even after a clear.
- macOS Universal Clipboard may sync the password to other iCloud devices.
- Third-party clipboard managers (Parcellite, Clipman, etc.) actively intercept and log copies.
- Linux X11 has multiple clipboards (PRIMARY, CLIPBOARD).

// This package makes a best-effort attempt to securely clear the clipboard after the timeout.
*/

const (
	wlCopy   = "wl-copy"  // Wayland
	xsel     = "xsel"     // X11
	xclip    = "xclip"    // X11
	clip     = "clip"     // Windows
	pbcopy   = "pbcopy"   // macOS
	win32API = "win32api" // Windows Native Win32 API

	// writeTimeout prevents the app from hanging if the clipboard tool is unresponsive
	// (e.g. waiting for a paste event on bare X11 systems).
	writeTimeout = 2 * time.Second
)

var (
	// ErrNoClipboardTool indicates that no supported clipboard utility was found on the system.
	ErrNoClipboardTool = errors.New("no clipboard tool available")
	// ErrUnsupportedTool indicates that the configured clipboard utility is not supported.
	ErrUnsupportedTool = errors.New("unsupported clipboard tool")
	// ErrWriteTimeout indicates the clipboard tool took too long to accept input.
	ErrWriteTimeout = errors.New("clipboard write timed out")
)

// Manager handles clipboard operations.
type Manager struct {
	config   config.ClipboardConfig
	tool     string
	lookPath func(string) (string, error)
	runCmd   func(ctx context.Context, name string, args []string, stdin []byte) error
}

// New creates a new clipboard manager.
func New(cfg config.ClipboardConfig) *Manager {
	manager := &Manager{
		config:   cfg,
		lookPath: exec.LookPath,
		runCmd: func(ctx context.Context, name string, args []string, stdin []byte) error {
			// #nosec G204 -- Controlled input via strict allowlist in Manager methods
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Stdin = bytes.NewReader(stdin)
			return cmd.Run()
		},
	}
	manager.tool = manager.detectTool()
	return manager
}

// detectTool detects the available clipboard tool based on preference.
// STRICT SECURITY: We ONLY check the tools explicitly requested in the configuration.
// We do NOT fall back to scanning the system for random tools if the preference fails.
// This prevents accidental leakage to unknown or cloud-synced clipboard managers.
func (m *Manager) detectTool() string {
	for _, tool := range m.config.ToolPreference {
		if tool == win32API {
			if isWin32Available() {
				return win32API
			}
			continue
		}
		path, err := m.lookPath(tool)
		if err == nil && path != "" {
			return tool
		}
	}
	return ""
}

// Copy copies text to clipboard immediately.
// WARNING: This does NOT clear the clipboard automatically.
// The caller is responsible for the lifecycle and cleanup of the 'text' slice.
func (m *Manager) Copy(text []byte) error {
	return m.writeToClipboard(text)
}

// CopySecure copies text to clipboard and clears it after timeout.
// It blocks until timeout is reached or an interrupt signal is received.
//
// DESTRUCTIVE SIDE-EFFECT: The 'text' slice will be zeroed immediately after
// being copied to the clipboard to minimize RAM exposure.
func (m *Manager) CopySecure(text []byte, timeout time.Duration) error {
	return m.CopySecureSilent(text, timeout, false)
}

// CopySecureDaemon copies text to clipboard and spawns a background daemon to clear it after timeout.
//
// DESTRUCTIVE SIDE-EFFECT: The 'text' slice will be zeroed immediately after
// being copied to the clipboard to minimize RAM exposure.
func (m *Manager) CopySecureDaemon(text []byte, timeout time.Duration) error {
	if m.tool == "" {
		return fmt.Errorf("%w: check your config or install wl-copy/xclip/xsel", ErrNoClipboardTool)
	}

	// Double-Safety: ensure the Go memory buffer is always zeroed on return.
	defer memory.SecureZero(text)

	// Write the payload to the OS clipboard
	if err := m.writeToClipboard(text); err != nil {
		return err
	}

	// CRITICAL SECURITY STEP:
	// Wipe the secret from Go memory IMMEDIATELY after successful handover to the OS.
	memory.SecureZero(text)

	// Try spawning background daemon. If daemon spawning fails, fall back to synchronous CopySecure behavior.
	if err := SpawnDaemon(m.tool, timeout); err != nil {
		return m.CopySecureSilent(text, timeout, true)
	}

	return nil
}

// CopySecureSilent copies text to clipboard and clears it after timeout.
// It allows suppressing the standard UI output for custom handling.
func (m *Manager) CopySecureSilent(text []byte, timeout time.Duration, silent bool) error {
	if m.tool == "" {
		return fmt.Errorf("%w: check your config or install wl-copy/xclip/xsel", ErrNoClipboardTool)
	}

	// Double-Safety: ensure the Go memory buffer is always zeroed on return,
	// regardless of whether the clipboard write succeeded or not.
	defer memory.SecureZero(text)

	// copied tracks whether the secret was successfully handed to the OS clipboard.
	// The deferred Clear() MUST only run if the write succeeded — otherwise it would
	// attempt to clear a clipboard that was never written, and print a misleading
	// "Clipboard cleared automatically" message to the user.
	copied := false
	defer func() {
		if !copied {
			return
		}
		if err := m.Clear(); err != nil {
			ui.PrintfWarningf("Failed to clear OS clipboard: %v\n", err)
		} else if !silent {
			ui.PrintfInfof("Clipboard cleared automatically\n")
		}
	}()

	// Write the payload to the OS clipboard
	if err := m.writeToClipboard(text); err != nil {
		return err
	}

	// CRITICAL SECURITY STEP:
	// Wipe the secret from Go memory IMMEDIATELY after successful handover to the OS.
	// The secret now only exists in the OS Clipboard/Compositor.
	memory.SecureZero(text)

	// Mark the clipboard as written so the deferred Clear() runs on exit.
	copied = true

	if !silent {
		ui.PrintfSuccessf("Content copied to clipboard\n")
		ui.PrintfInfof("Clipboard will be cleared in %v. Press Ctrl+C to clear immediately.\n", timeout)
	}

	// Wait Phase
	// We block here to keep the process alive so we can execute the deferred Clear().
	// Using a Timer is more efficient than a Ticker loop.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// Capture signals to ensure we clear clipboard on Ctrl+C or kill
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	select {
	case <-timer.C:
		// Timeout reached naturally, deferred Clear() will run.
		return nil

	case sig := <-sigChan:
		// User interrupted execution.
		if sig == os.Interrupt {
			fmt.Println() // Clean newline after ^C
		} else {
			ui.PrintfInfof("\nReceived signal: %v, clearing clipboard...\n", sig)
		}
		// Returning triggers the deferred Clear() immediately.
		return nil
	}
}

func (m *Manager) writeToClipboard(text []byte) error {
	if m.tool == "" {
		return ErrNoClipboardTool
	}

	if m.tool == win32API {
		err := writeWindowsClipboard(text)
		if err == nil {
			return nil
		}
		// Fallback to clip.exe if win32api fails at runtime
		if path, lookErr := m.lookPath(clip); lookErr == nil && path != "" {
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			defer cancel()
			return m.runCmd(ctx, clip, nil, text)
		}
		return err
	}

	// Use CommandContext to prevent indefinite hanging if the clipboard manager is frozen
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()

	var args []string

	// Security Allowlist:
	// We only execute binaries that we know how to handle securely.
	// We do NOT execute arbitrary strings from the configuration.
	switch m.tool {
	case wlCopy:
		// Wayland copy usually works by reading stdin.
	case xclip:
		// -silent: don't print status
		// -selection clipboard: use the Ctrl+V buffer, not just middle-click
		args = []string{"-selection", "clipboard", "-silent"}
	case xsel:
		// --clipboard: use Ctrl+V buffer
		// --input: read from stdin
		args = []string{"--clipboard", "--input"}
	case clip:
		// Windows built-in
	case pbcopy:
		// macOS built-in
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedTool, m.tool)
	}

	if err := m.runCmd(ctx, m.tool, args, text); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return ErrWriteTimeout
		}
		return fmt.Errorf("failed to copy to clipboard using %s: %w", m.tool, err)
	}

	return nil
}

// Clear clears the clipboard content aggressively.
func (m *Manager) Clear() error {
	if m.tool == "" {
		return ErrNoClipboardTool
	}

	if m.tool == win32API {
		return clearWindowsClipboard()
	}

	// Context for clearing operations
	ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()

	switch m.tool {
	case wlCopy:
		return m.runCmd(ctx, wlCopy, []string{"--clear"}, nil)

	case xsel:
		// X11: Clear both PRIMARY (middle-click) and CLIPBOARD (Ctrl+V)
		// Ignore errors on primary clear as it's best-effort
		_ = m.runCmd(ctx, xsel, []string{"--primary", "--clear"}, nil)
		return m.runCmd(ctx, xsel, []string{"--clipboard", "--clear"}, nil)

	case xclip:
		// X11: Pipe empty string to both selections
		// Ignore primary error
		_ = m.runCmd(ctx, xclip, []string{"-selection", "primary", "-silent"}, nil)
		return m.runCmd(ctx, xclip, []string{"-selection", "clipboard", "-silent"}, nil)

	case clip:
		// Windows: Just write empty bytes to clip.
		return m.runCmd(ctx, clip, nil, nil)

	case pbcopy:
		// macOS: pbcopy takes stdin and overwrites clipboard
		return m.runCmd(ctx, pbcopy, nil, nil)

	default:
		// SECURITY: Never execute an arbitrary binary from config.
		// m.tool is set by detectTool() which only accepts known tools above.
		// If a new tool is added to detectTool(), it MUST have a case here.
		return fmt.Errorf("%w: %s", ErrUnsupportedTool, m.tool)
	}
}

// IsAvailable checks if clipboard functionality is available.
func (m *Manager) IsAvailable() bool {
	return m.tool != ""
}

// GetTool returns the detected clipboard tool name.
func (m *Manager) GetTool() string {
	return m.tool
}
