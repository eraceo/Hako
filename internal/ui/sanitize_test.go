package ui

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/memory"
)

type sanitizeTestCase struct {
	name     string
	input    string
	expected string
}

func getSanitizeStringTestCases() []sanitizeTestCase {
	return []sanitizeTestCase{
		{
			name:     "Normal string",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "OSC with ST terminator",
			input:    "\x1b]0;Title\x1b\\", // ST = ESC backslash
			expected: "",
		},
		{
			name:     "CSI with private parameter",
			input:    "\x1b[?25h", // Show cursor
			expected: "",
		},
		{
			name:     "ANSI color codes (CSI)",
			input:    "\x1b[31mRed\x1b[0m Text",
			expected: "Red Text",
		},
		{
			name:     "ANSI cursor movement (CSI)",
			input:    "Hello\x1b[2J World",
			expected: "Hello World",
		},
		{
			name:     "ANSI terminal links (OSC)",
			input:    "\x1b]8;;http://malicious.com\x07Click Here\x1b]8;;\x07",
			expected: "Click Here",
		},
		{
			name:     "2-byte Fe Escape sequences",
			input:    "Reverse\x1bM Index", // \x1bM is a standard Fe sequence
			expected: "Reverse Index",
		},
		{
			name:     "Control characters (Bell)",
			input:    "Hello\x07World", // Bell character
			expected: "HelloWorld",
		},
		{
			name:     "Newlines, tabs and carriage returns preserved",
			input:    "Line1\r\nLine2\tTabbed",
			expected: "Line1\r\nLine2\tTabbed",
		},
		{
			name:     "Complex ANSI injection",
			input:    "\x1b[2J\x1b[H\x1b[31mCRITICAL ERROR\x1b[0m",
			expected: "CRITICAL ERROR",
		},
	}
}

func TestSanitizeString(t *testing.T) {
	tests := getSanitizeStringTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

type sanitizeBytesTestCase struct {
	name     string
	input    []byte
	expected []byte
}

func getSanitizeBytesTestCases() []sanitizeBytesTestCase {
	return []sanitizeBytesTestCase{
		{
			name:     "Normal bytes",
			input:    []byte("Hello World"),
			expected: []byte("Hello World"),
		},
		{
			name:     "Empty bytes",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "Nil bytes",
			input:    nil,
			expected: nil,
		},
		{
			name:     "ANSI color codes",
			input:    []byte("\x1b[31mRed\x1b[0m"),
			expected: []byte("Red"),
		},
		{
			name:     "2-byte Fe Escape sequences",
			input:    []byte("\x1bMHello"),
			expected: []byte("Hello"),
		},
		{
			name:     "ANSI terminal links (OSC) and Control characters",
			input:    []byte("\x1b]8;;http://malicious.com\x07Hello\x08\x0bWorld\x1b]8;;\x07"),
			expected: []byte("HelloWorld"),
		},
	}
}

func TestSanitizeBytes(t *testing.T) {
	tests := getSanitizeBytesTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeBytes(tt.input)

			// SECURITY: Enforce memory wiping even in tests to prevent leaks
			defer memory.SecureZero(result)

			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeString_Truncation_UTF8_Safety(t *testing.T) {
	// Create a massive payload just over the limit.
	// We build a string of size (MaxInputSize - 1), then append a 4-byte Emoji.
	// This forces the MaxInputSize cut-off to fall exactly in the MIDDLE of the Emoji.
	baseLength := MaxInputSize - 1
	baseStr := strings.Repeat("a", baseLength)
	emoji := "😀" // 4 bytes: F0 9F 98 80

	payload := baseStr + emoji
	require.True(t, len(payload) > MaxInputSize)

	result := SanitizeString(payload)

	// Assertions
	// The result must be strictly smaller or equal to MaxInputSize
	assert.LessOrEqual(t, len(result), MaxInputSize)

	// The length should be exactly baseLength, because the entire 4-byte emoji
	// must be safely dropped to avoid returning a corrupted rune.
	assert.Equal(t, baseLength, len(result))

	// The last character must be 'a', not a corrupted UTF-8 byte
	assert.Equal(t, byte('a'), result[len(result)-1])

	// The resulting string must be perfectly valid UTF-8
	assert.True(t, utf8.ValidString(result), "Truncated string contains invalid UTF-8 bytes")
}

func TestSanitizeBytes_Truncation_UTF8_Safety(t *testing.T) {
	baseLength := MaxInputSize - 2
	baseBytes := []byte(strings.Repeat("b", baseLength))

	// '世' is 3 bytes (E4 B8 96).
	// MaxInputSize falls on the 2nd byte of this character.
	kanji := []byte("世")

	// and guarantee we don't overwrite underlying memory.
	payload := make([]byte, 0, len(baseBytes)+len(kanji))
	payload = append(payload, baseBytes...)
	payload = append(payload, kanji...)

	require.True(t, len(payload) > MaxInputSize)

	result := SanitizeBytes(payload)
	defer memory.SecureZero(result)

	assert.LessOrEqual(t, len(result), MaxInputSize)

	// The entire 3-byte character must be dropped.
	assert.Equal(t, baseLength, len(result))
	assert.Equal(t, byte('b'), result[len(result)-1])
	assert.True(t, utf8.Valid(result), "Truncated byte slice contains invalid UTF-8 bytes")
}
