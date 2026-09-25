package ui

import (
	"os"

	"golang.org/x/term"
)

// IsColorEnabled checks if ANSI color output is supported and permitted.
// Follows the NO_COLOR specification (https://no-color.org):
//   - If the NO_COLOR environment variable is set (even empty), color is disabled.
//   - If TERM=dumb, color is disabled.
//   - If the output file descriptor is not an interactive terminal, color is disabled.
func IsColorEnabled(fd uintptr) bool {
	if _, exists := os.LookupEnv("NO_COLOR"); exists {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	return term.IsTerminal(int(fd))
}

// ColorRed wraps string with red ANSI code if color is enabled on stdout.
func ColorRed(s string) string {
	if !IsColorEnabled(os.Stdout.Fd()) {
		return s
	}
	return "\033[31m" + s + "\033[0m"
}

// ColorYellow wraps string with yellow ANSI code if color is enabled on stdout.
func ColorYellow(s string) string {
	if !IsColorEnabled(os.Stdout.Fd()) {
		return s
	}
	return "\033[33m" + s + "\033[0m"
}

// ColorCyan wraps string with cyan ANSI code if color is enabled on stdout.
func ColorCyan(s string) string {
	if !IsColorEnabled(os.Stdout.Fd()) {
		return s
	}
	return "\033[36m" + s + "\033[0m"
}

// ColorGreen wraps string with green ANSI code if color is enabled on stdout.
func ColorGreen(s string) string {
	if !IsColorEnabled(os.Stdout.Fd()) {
		return s
	}
	return "\033[32m" + s + "\033[0m"
}

// ColorBold wraps string with bold ANSI code if color is enabled on stdout.
func ColorBold(s string) string {
	if !IsColorEnabled(os.Stdout.Fd()) {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}
