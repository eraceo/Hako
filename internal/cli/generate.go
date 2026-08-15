package cli

import (
	"errors"
	"fmt"
	"math"
	"os"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/eraceo/Hako/internal/audit"
	"github.com/eraceo/Hako/internal/clipboard"
	"github.com/eraceo/Hako/internal/config"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// Sentinel errors to prevent dynamic error generation (err113).
// Adjusted to match exactly what the test suite expects.
var (
	ErrPasswordTooShort = errors.New("password length must be at least")
	ErrPasswordTooLong  = errors.New("password length cannot exceed 128")
)

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

func runGenerate(cmd *cobra.Command, _ []string) error {
	length, _ := cmd.Flags().GetInt("length")
	symbols, _ := cmd.Flags().GetBool("symbols")
	noSymbols, _ := cmd.Flags().GetBool("no-symbols")
	memorable, _ := cmd.Flags().GetBool("memorable")
	noSimilar, _ := cmd.Flags().GetBool("no-similar")
	clip, _ := cmd.Flags().GetBool("clip")

	opts := secrets.GeneratorOptions{
		Length:     length,
		UseSymbols: symbols && !noSymbols,
		Memorable:  memorable,
		NoSimilar:  noSimilar,
	}

	// Validate options
	if opts.Length < secrets.MinPasswordLength {
		// Output: "password length must be at least 8"
		return fmt.Errorf("%w %d", ErrPasswordTooShort, secrets.MinPasswordLength)
	}

	if opts.Length > 128 {
		return ErrPasswordTooLong
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

	// Show password strength info
	entropy := calculateEntropy(password)

	audit.LogSuccess(audit.EventPasswordGen, "Password generated", map[string]interface{}{
		"length":    opts.Length,
		"memorable": opts.Memorable,
		"strength":  determineStrength(entropy),
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
			if err := clipManager.CopySecureSilent(password, timeout, false); err != nil {
				return fmt.Errorf("failed to copy password to clipboard: %w", err)
			}
			ui.PrintfSuccessf("Password copied to clipboard (will be cleared in %s)", timeout)
		}
	} else {
		_, _ = os.Stdout.Write(password)
		ui.Println()
	}

	ui.PrintfInfof("Password strength: %s (%.1f bits of entropy)", determineStrength(entropy), entropy)

	return nil
}

// calculateEntropy estimates the password entropy in bits without heap allocations.
func calculateEntropy(password []byte) float64 {
	length := utf8.RuneCount(password)

	if length == 0 {
		return 0
	}

	hasLower, hasUpper, hasDigit, hasSymbol, hasOther := analyzeCharacterSetsBytes(password)

	poolSize := 0
	if hasLower {
		poolSize += 26
	}
	if hasUpper {
		poolSize += 26
	}
	if hasDigit {
		poolSize += 10
	}
	if hasSymbol {
		poolSize += 33 // Number of printable ASCII symbols
	}
	if hasOther {
		// Conservative estimate for Unicode/Extended characters
		poolSize += 50
	}

	if poolSize == 0 {
		return 0
	}

	return float64(length) * math.Log2(float64(poolSize))
}

// analyzeCharacterSetsBytes analyzes the byte slice without string conversion
func analyzeCharacterSetsBytes(password []byte) (lower, upper, digit, symbol, other bool) {
	for i := 0; i < len(password); {
		char, size := utf8.DecodeRune(password[i:])
		i += size

		switch {
		case char >= 'a' && char <= 'z':
			lower = true
		case char >= 'A' && char <= 'Z':
			upper = true
		case char >= '0' && char <= '9':
			digit = true
		case isStandardASCIISymbol(char):
			symbol = true
		default:
			other = true
		}
	}
	return
}

func isStandardASCIISymbol(char rune) bool {
	return (char >= 32 && char <= 47) ||
		(char >= 58 && char <= 64) ||
		(char >= 91 && char <= 96) ||
		(char >= 123 && char <= 126)
}

// determineStrength returns a strength label based on entropy bits
func determineStrength(entropy float64) string {
	switch {
	case entropy >= 128:
		return "Very Strong"
	case entropy >= 80:
		return "Strong"
	case entropy >= 60:
		return "Good"
	case entropy >= 40:
		return "Fair"
	default:
		return "Weak"
	}
}
