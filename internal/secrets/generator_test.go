package secrets

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validatePasswordCharacterTypes safely checks if a password contains required character types
// using pure byte manipulation.
func validatePasswordCharacterTypes(password []byte) (hasLower, hasUpper, hasDigit, hasSymbol bool) {
	symbolsBytes := []byte(Symbols)
	for _, b := range password {
		switch {
		case b >= 'a' && b <= 'z':
			hasLower = true
		case b >= 'A' && b <= 'Z':
			hasUpper = true
		case b >= '0' && b <= '9':
			hasDigit = true
		case bytes.ContainsRune(symbolsBytes, rune(b)):
			hasSymbol = true
		}
	}
	return
}

func TestGeneratePassword(t *testing.T) {
	opts := DefaultGeneratorOptions()

	password, err := GeneratePassword(opts)
	require.NoError(t, err, "Failed to generate password")
	assert.Len(t, password, opts.Length, "Password length mismatch")

	hasLower, hasUpper, hasDigit, hasSymbol := validatePasswordCharacterTypes(password)
	assert.True(t, hasLower, "Password should contain lowercase letters")
	assert.True(t, hasUpper, "Password should contain uppercase letters")
	assert.True(t, hasDigit, "Password should contain digits")
	assert.True(t, hasSymbol, "Password should contain symbols when UseSymbols is true")
}

func TestGeneratePasswordNoSymbols(t *testing.T) {
	opts := GeneratorOptions{
		Length:     12,
		UseSymbols: false,
		Memorable:  false,
	}

	password, err := GeneratePassword(opts)
	require.NoError(t, err, "Failed to generate password")
	assert.Len(t, password, opts.Length)

	symbolsBytes := []byte(Symbols)
	for _, b := range password {
		assert.False(t, bytes.ContainsRune(symbolsBytes, rune(b)), "Password should not contain symbols: %c", b)
	}
}

func TestGeneratePasswordNoSimilar(t *testing.T) {
	opts := GeneratorOptions{
		Length:     50, // High length to increase probability of hitting a similar char if bug exists
		UseSymbols: false,
		Memorable:  false,
		NoSimilar:  true,
	}

	password, err := GeneratePassword(opts)
	require.NoError(t, err)

	similarChars := []byte("0O1lI|")
	for _, b := range password {
		assert.False(t, bytes.ContainsRune(similarChars, rune(b)), "Password should not contain similar character: %c", b)
	}
}

func TestGenerateMemorablePassword(t *testing.T) {
	t.Run("Standard Length", func(t *testing.T) {
		opts := GeneratorOptions{
			Length:     16,
			UseSymbols: true,
			Memorable:  true,
		}

		password, err := GeneratePassword(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, password)

		// Memorable passwords should contain separators
		hasSeparator := bytes.ContainsAny(password, "-_.!")
		assert.True(t, hasSeparator, "Memorable password should contain separators")
	})

	t.Run("Long Length", func(t *testing.T) {
		opts := GeneratorOptions{
			Length:     25, // Triggers 6 words instead of 4
			UseSymbols: false,
			Memorable:  true,
		}

		password, err := GeneratePassword(opts)
		require.NoError(t, err)
		assert.NotEmpty(t, password)

		// Without symbols, separators are restricted to - and _
		hasSeparator := bytes.ContainsAny(password, "-_")
		assert.True(t, hasSeparator, "Memorable password should contain - or _")
		assert.False(t, bytes.ContainsAny(password, ".!"), "Should not contain . or ! when UseSymbols is false")
	})
}

func TestGeneratePasswordTooShort(t *testing.T) {
	opts := GeneratorOptions{
		Length:     3, // Too short
		UseSymbols: true,
		Memorable:  false,
	}

	_, err := GeneratePassword(opts)
	assert.Error(t, err, "Should fail for password length < 4")
}

func TestGenerateKeyfile(t *testing.T) {
	size := 256
	keyfile, err := GenerateKeyfile(size)
	require.NoError(t, err, "Failed to generate keyfile")
	assert.Len(t, keyfile, size, "Keyfile size mismatch")

	// Generate another keyfile and ensure they're different
	keyfile2, err := GenerateKeyfile(size)
	require.NoError(t, err)
	assert.NotEqual(t, keyfile, keyfile2, "Generated keyfiles should be cryptographically unique")
}

func TestGenerateKeyfileMinimumSize(t *testing.T) {
	keyfile, err := GenerateKeyfile(16)
	require.NoError(t, err)
	assert.Len(t, keyfile, 32, "Keyfile should enforce a minimum of 32 bytes")
}

func TestPasswordUniqueness(t *testing.T) {
	opts := DefaultGeneratorOptions()

	passwords := make(map[string]struct{})
	iterations := 100

	for i := 0; i < iterations; i++ {
		password, err := GeneratePassword(opts)
		require.NoError(t, err)

		passStr := string(password) // Safe here as it's purely for test assertion maps
		_, exists := passwords[passStr]
		assert.False(t, exists, "Generated duplicate password")
		passwords[passStr] = struct{}{}
	}
}

func TestCalculateEntropy(t *testing.T) {
	opts := DefaultGeneratorOptions()
	entropyVal := opts.CalculateEntropy()
	assert.Greater(t, entropyVal, 50.0, "16-char complex password should have > 50 bits of entropy")

	memOpts := GeneratorOptions{Length: 16, Memorable: true}
	memEntropyVal := memOpts.CalculateEntropy()
	assert.Greater(t, memEntropyVal, 30.0, "Memorable password should have reasonable baseline entropy")

	optsActual := DefaultGeneratorOptions()
	password, _ := GeneratePassword(optsActual)
	actualEntropy := CalculateActualEntropy(password)
	assert.Greater(t, actualEntropy, 40.0, "Actual generated password should have high entropy")
}

func BenchmarkGeneratePassword(b *testing.B) {
	opts := DefaultGeneratorOptions()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GeneratePassword(opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateMemorablePassword(b *testing.B) {
	opts := GeneratorOptions{
		Length:     20,
		UseSymbols: true,
		Memorable:  true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := GeneratePassword(opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}
