// Package entropy provides password strength estimation based on character pools and repetition.
package entropy

import (
	"math"
	"unicode"
	"unicode/utf8"
)

const (
	// MinEntropy is the minimum recommended entropy in bits.
	MinEntropy = 50.0
	// StrongEntropy is the strong entropy threshold in bits.
	StrongEntropy = 80.0
)

// PasswordStrength represents the calculated strength category of a password.
type PasswordStrength int

const (
	// StrengthWeak indicates a weak password that can be easily cracked.
	StrengthWeak PasswordStrength = iota
	// StrengthMedium indicates a moderately secure password.
	StrengthMedium
	// StrengthStrong indicates a highly secure password.
	StrengthStrong
)

// String implements the stringer interface for PasswordStrength.
func (s PasswordStrength) String() string {
	switch s {
	case StrengthWeak:
		return "Weak"
	case StrengthMedium:
		return "Medium"
	case StrengthStrong:
		return "Strong"
	default:
		return "Unknown"
	}
}

// Calculate estimates the entropy of a password in bits.
// It analyzes the character sets used (lowercase, uppercase, digits, symbols),
// and heavily penalizes repetition to reflect true entropy.
//
// Security: This function operates strictly on a byte slice, performs ZERO heap
// allocations (no maps or strings), and prevents sensitive data from leaking to the GC.
func Calculate(password []byte) float64 {
	if len(password) == 0 {
		return 0.0
	}

	var (
		hasLower, hasUpper, hasDigit, hasSymbol bool
		hasSpace, hasOther, hasRawErr           bool
		runeCount, unique                       int
	)

	i := 0
	for i < len(password) {
		r, size := utf8.DecodeRune(password[i:])

		if r == utf8.RuneError && size == 1 {
			hasRawErr = true
		}

		if isRuneUnique(password, i, r, size) {
			unique++
		}

		// Pool size detection
		if r != utf8.RuneError || size != 1 {
			switch {
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				hasSymbol = true
			case unicode.IsSpace(r):
				hasSpace = true
			default:
				hasOther = true
			}
		}

		runeCount++
		i += size
	}

	poolSize := computePoolSize(hasLower, hasUpper, hasDigit, hasSymbol, hasSpace, hasOther, hasRawErr)

	// Effective length calculation:
	// A password like "aaaaaaaaaa" (runeCount=10, unique=1) gets clamped to 1.0.
	// Otherwise, we average the total length and the unique length to penalize repetition.
	var effectiveLength float64
	if unique == 1 {
		effectiveLength = 1.0
	} else {
		effectiveLength = float64(runeCount+unique) / 2.0
	}

	return effectiveLength * math.Log2(float64(poolSize))
}

// isRuneUnique checks if a rune has appeared previously in the password.
// O(N^2) but entirely stack-allocated.
func isRuneUnique(password []byte, currentIndex int, r rune, size int) bool {
	j := 0
	for j < currentIndex {
		prevR, prevSize := utf8.DecodeRune(password[j:])

		// If both are invalid UTF-8 bytes, compare the raw bytes to check uniqueness
		if r == utf8.RuneError && size == 1 && prevR == utf8.RuneError && prevSize == 1 {
			if password[j] == password[currentIndex] {
				return false
			}
		} else if prevR == r {
			return false
		}
		j += prevSize
	}
	return true
}

// computePoolSize calculates the total alphabet pool size based on character classes.
func computePoolSize(lower, upper, digit, symbol, space, other, rawErr bool) int {
	poolSize := 0
	if lower {
		poolSize += 26
	}
	if upper {
		poolSize += 26
	}
	if digit {
		poolSize += 10
	}
	if symbol {
		poolSize += 32
	}
	if space {
		poolSize++
	}
	if other {
		poolSize += 128
	}
	if rawErr || poolSize == 0 {
		poolSize = 256
	}
	return poolSize
}

// EvaluateStrength categorizes a raw entropy float value into a standard PasswordStrength enum.
func EvaluateStrength(entropyVal float64) PasswordStrength {
	switch {
	case entropyVal < MinEntropy:
		return StrengthWeak
	case entropyVal < StrongEntropy:
		return StrengthMedium
	default:
		return StrengthStrong
	}
}
