package entropy

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eraceo/Hako/internal/memory"
)

func TestCalculate(t *testing.T) {
	tests := []struct {
		name     string
		password string
		min      float64
		max      float64
	}{
		{"Empty", "", 0.0, 0.0},

		{"SingleChar", "a", 4.0, 5.0}, // 1 * log2(26) ≈ 4.7

		// "aaaaaaaa" has Length=8, Unique=1. Clamp triggers: EffectiveLength = 1.0.
		// 1.0 * log2(26) ≈ 4.7 bits.
		{"FullRepetition", "aaaaaaaa", 4.0, 5.0},

		// "abababab" has Length=8, Unique=2. EffectiveLength = (8+2)/2 = 5.0.
		// 5.0 * log2(26) ≈ 23.5 bits.
		{"PartialRepetition", "abababab", 23.0, 24.0},

		{"Lowercase", "password", 30.0, 40.0},                         // 8 chars * log2(26) ≈ 37.6
		{"AlphaNumeric", "Password123", 50.0, 70.0},                   // 11 chars * log2(62) ≈ 65.5
		{"LongPassphrase", "CorrectHorseBatteryStaple", 100.0, 150.0}, // 25 chars * log2(52) ≈ 142.5
		{"Symbols", "!@#$%", 20.0, 30.0},                              // 5 chars * log2(32) ≈ 25.0
		{"MixedComplex", "Pa$sw0rd", 40.0, 60.0},                      // 8 chars * log2(94) ≈ 52.4
		// (11+8)/2 = 9.5. Pool = 26 (lower) + 1 (space) = 27. 9.5 * log2(27) ≈ 45.17
		{"WithSpace", "hello world", 35.0, 46.0},

		// "🔑🔑🔑" has Length=3, Unique=1. Clamp triggers: EffectiveLength = 1.0.
		// Pool = 32 (Unicode Symbol). 1.0 * log2(32) = 5.0 bits.
		{"UnicodeEmoji_Repetition", "🔑🔑🔑", 4.0, 6.0},

		// Invalid UTF-8 sequence should default to a raw 256 pool size.
		// Length=3, Unique=3. EffectiveLength = 3.0. 3.0 * log2(256) = 24.0.
		{"InvalidUTF8", string([]byte{0xff, 0xfe, 0xfd}), 23.0, 25.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert string to bytes for testing.
			// SECURITY: In Hako, even in tests, we ensure we don't leave sensitive
			// byte slices lingering for the GC if we can avoid it.
			b := []byte(tt.password)
			defer memory.SecureZero(b)

			got := Calculate(b)

			// Using testify/assert for better error visibility
			assert.GreaterOrEqual(t, got, tt.min, "Entropy too low for %s", tt.name)
			assert.LessOrEqual(t, got, tt.max, "Entropy too high for %s", tt.name)
		})
	}
}

func TestEvaluateStrength(t *testing.T) {
	tests := []struct {
		entropy  float64
		expected PasswordStrength
	}{
		{0.0, StrengthWeak},
		{49.9, StrengthWeak},
		{50.0, StrengthMedium},
		{79.9, StrengthMedium},
		{80.0, StrengthStrong},
		{120.0, StrengthStrong},
	}

	for _, tt := range tests {
		t.Run(strconv.FormatFloat(tt.entropy, 'f', 1, 64), func(t *testing.T) {
			got := EvaluateStrength(tt.entropy)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestPasswordStrength_String(t *testing.T) {
	tests := []struct {
		strength PasswordStrength
		expected string
	}{
		{StrengthWeak, "Weak"},
		{StrengthMedium, "Medium"},
		{StrengthStrong, "Strong"},
		{PasswordStrength(99), "Unknown"}, // Test fallback default case
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.strength.String())
		})
	}
}
