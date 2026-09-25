package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/awnumar/memguard"

	"github.com/eraceo/Hako/internal/cli"
	"github.com/eraceo/Hako/internal/memory"
)

func main() {
	// os.Exit immediately terminates the program, bypassing all deferred functions
	// in the caller. By wrapping the logic in run(), we guarantee that all defers
	// (like context cancellation, memory zeroing, or file unlocking) are executed
	// before the OS reclaims the process.
	os.Exit(run())
}

func run() int {
	_ = memory.DisableCoreDumps()
	defer memguard.Purge()

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
