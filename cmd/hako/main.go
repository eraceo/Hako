// Package main is the entry point for the Hako CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/eraceo/Hako/internal/cli"
)

func main() {
	// os.Exit immediately terminates the program, bypassing all deferred functions
	// in the caller. By wrapping the logic in run(), we guarantee that all defers
	// (like context cancellation, memory zeroing, or file unlocking) are executed
	// before the OS reclaims the process.
	os.Exit(run())
}

func run() int {
	// Create a root context that listens for OS interrupt signals (Ctrl+C).
	// On Windows, syscall.SIGTERM is compiled but never sent by the OS;
	// os.Interrupt handles CTRL_C_EVENT correctly cross-platform.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Execute the root Cobra command.
	if err := cli.Execute(ctx); err != nil {
		// we MUST print the error to standard error here.
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	return 0
}
