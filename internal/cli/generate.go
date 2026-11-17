package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/clipboard"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/entropy"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// Sentinel errors to prevent dynamic error generation (err113).
// Adjusted to match exactly what the test suite expects.
var (
	ErrPasswordTooShort             = errors.New("password length must be at least")
	ErrPasswordTooLong              = errors.New("password length cannot exceed 128")
	ErrMemorableLengthOutOfRange    = errors.New("memorable password word count must be between 3 and 10")
	ErrGenerateFlagRequiresGenerate = errors.New("generation flags require --generate")
)

func validateOrphanGenerateFlags(cmd *cobra.Command, generate bool) error {
	if generate {
		return nil
	}
	for _, flagName := range []string{"length", "symbols", "no-symbols", "memorable", "no-similar"} {
		if cmd.Flags().Changed(flagName) {
			return fmt.Errorf("%w: --%s", ErrGenerateFlagRequiresGenerate, flagName)
		}
	}
	return nil
}

// NewGenerateCmd creates and returns the generate command.
// This factory pattern prevents global state pollution.
func NewGenerateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "gen",
		Aliases: []string{"generate"},
		Short:   "Generate a secure password",
		Long: `Generate a secure password with customizable options.
The generated password can be displayed or copied to clipboard.`,
		RunE: runGenerate,
	}

	cmd.Flags().IntP("length", "l", 16, "password length")
	cmd.Flags().Bool("symbols", true, "include symbols")
	cmd.Flags().Bool("no-symbols", false, "exclude symbols")
	cmd.Flags().Bool("memorable", false, "generate memorable password")
	cmd.Flags().Bool("no-similar", false, "exclude similar characters (0, O, l, 1, etc.)")
	cmd.Flags().BoolP("clip", "c", false, "copy to clipboard")

	cmd.MarkFlagsMutuallyExclusive("symbols", "no-symbols")

	return cmd
}

func prepareGenerateOptions(
	cmd *cobra.Command,
	length int,
	symbols, noSymbols, memorable, noSimilar bool,
) (secrets.GeneratorOptions, error) {
	if memorable {
		if !cmd.Flags().Changed("length") {
			length = 6
		}
		if length < 3 || length > 10 {
			return secrets.GeneratorOptions{}, fmt.Errorf("%w: got %d", ErrMemorableLengthOutOfRange, length)
		}
	} else {
		if length < secrets.MinPasswordLength {
			return secrets.GeneratorOptions{}, fmt.Errorf("%w %d", ErrPasswordTooShort, secrets.MinPasswordLength)
		}
		if length > 128 {
			return secrets.GeneratorOptions{}, ErrPasswordTooLong
		}
	}

	return secrets.GeneratorOptions{
		Length:     length,
		UseSymbols: symbols && !noSymbols,
		Memorable:  memorable,
		NoSimilar:  noSimilar,
	}, nil
}

func runGenerate(cmd *cobra.Command, _ []string) error {
	length, _ := cmd.Flags().GetInt("length")
	symbols, _ := cmd.Flags().GetBool("symbols")
	noSymbols, _ := cmd.Flags().GetBool("no-symbols")
	memorable, _ := cmd.Flags().GetBool("memorable")
	noSimilar, _ := cmd.Flags().GetBool("no-similar")
	clip, _ := cmd.Flags().GetBool("clip")

	opts, err := prepareGenerateOptions(cmd, length, symbols, noSymbols, memorable, noSimilar)
	if err != nil {
		return err
	}

	// Generate password
	password, err := secrets.GeneratePassword(opts)
	if err != nil {
		audit.LogFailure(audit.EventPasswordGen, "Password generation failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to generate password: %w", err)
	}
	defer memory.SecureZero(password) // Always clean up local plaintext slice

	// Show password strength info via unified entropy calculation
	entropyBits := entropy.Calculate(password)
	strengthLabel := entropy.FormatStrengthLabel(entropyBits)

	audit.LogSuccess(audit.EventPasswordGen, "Password generated", map[string]interface{}{
		"length":    opts.Length,
		"memorable": opts.Memorable,
		"strength":  strengthLabel,
	})

	// Handle clipboard copy
	if clip {
		cfg := config.FromContext(cmd.Context())
		clipManager := clipboard.New(cfg.Clipboard)

		if !clipManager.IsAvailable() {
			ui.PrintfWarningf("Clipboard not available, displaying password instead")
			_, _ = os.Stdout.Write(password)
			ui.Println()
		} else {
			timeout := time.Duration(cfg.Clipboard.Timeout) * time.Second
			if err := clipManager.CopySecureDaemon(password, timeout); err != nil {
				return fmt.Errorf("failed to copy password to clipboard: %w", err)
			}
			ui.PrintfSuccessf("Password copied to clipboard (will be cleared in %s)", timeout)
		}
	} else {
		_, _ = os.Stdout.Write(password)
		ui.Println()
	}

	ui.PrintfInfof("Password strength: %s (%.1f bits of entropy)", strengthLabel, entropyBits)

	return nil
}
