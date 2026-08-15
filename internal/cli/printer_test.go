package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/secrets"
)

// TestWriteSecureField targets writeSecureField (handling []byte)
func TestWriteSecureField(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		maxWidth int
		expected string
	}{
		{"Short byte slice gets padded", []byte("hello"), 10, "hello     "},
		{"Exact length", []byte("1234567890"), 10, "1234567890"},
		{"Long slice gets truncated", []byte("this is a very long string"), 10, "this is..."},
		{"Empty slice gets padded", nil, 5, "     "},
		{"UTF8 multi-byte truncation", []byte("こんにちは世界"), 6, "こんに..."}, // 3 Japanese runes + "..." = 6 runes
		{"Emoji truncation", []byte("😀😂🤣😊🙃😇"), 5, "😀😂..."},             // 2 emojis + "..." = 5 visual width (approx)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := captureOutput(t, func() {
				// Target the specific []byte function
				writeSecureField(tt.input, tt.maxWidth)
			})

			assert.Equal(t, tt.expected, actual)
			// Check visual length (RuneCount) matches maxWidth (accounting for padding)
			// We use []rune conversion just for the test assertion length check
			assert.Equal(t, tt.maxWidth, len([]rune(actual)), "Output visual length must match maxWidth")
		})
	}
}

// TestWriteStringField targets writeStringField (handling string)
func TestWriteStringField(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxWidth int
		expected string
	}{
		{"Short string gets padded", "Hako", 8, "Hako    "},
		{"Exact length", "Password", 8, "Password"},
		{"Long string gets truncated", "SuperSecretPassword123", 11, "SuperSec..."},
		{"Empty string gets padded", "", 4, "    "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := captureOutput(t, func() {
				// Target the specific string function
				writeStringField(tt.input, tt.maxWidth)
			})

			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestPrintEntriesTable(t *testing.T) {
	// Use the official constructor to ensure proper EphemeralSecret encryption
	// and internal state initialization (AEAD key generation).

	// Entry 1: Standard
	e1, err := secrets.NewEntry(
		"App A",
		[]byte("admin"),
		[]byte("hunter123"),
		[]byte("https://a.com"),
		[]byte("some notes"),
		[]string{"prod", "web"},
	)
	require.NoError(t, err)
	defer e1.Zero()

	// Entry 2: Long values and empty optional fields
	e2, err := secrets.NewEntry(
		"A Very Long Application Name That Exceeds The Limit",
		[]byte("another_very_long_username_here"),
		[]byte("hunter123"),
		nil, // Empty URL
		nil, // Empty Notes
		[]string{"dev"},
	)
	require.NoError(t, err)
	defer e2.Zero()

	// Manually override timestamps to ensure deterministic output if needed,
	// though the table printer doesn't print timestamps currently.
	e1.CreatedAt = time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	e2.CreatedAt = time.Date(2023, 1, 2, 0, 0, 0, 0, time.UTC)

	entries := []*secrets.Entry{e1, e2}

	actualOutput := captureOutput(t, func() {
		printEntriesTable(entries)
	})

	// Assertions on the Table formatting
	// We verify specific substrings are present and aligned.

	// Check Header
	assert.Contains(t, actualOutput, "NAME")
	assert.Contains(t, actualOutput, "USERNAME")
	assert.Contains(t, actualOutput, "URL")
	assert.Contains(t, actualOutput, "TAGS")

	// Check Entry 1
	assert.Contains(t, actualOutput, "App A")
	assert.Contains(t, actualOutput, "admin")
	assert.Contains(t, actualOutput, "https://a.com")
	assert.Contains(t, actualOutput, "prod, web")

	// Check Entry 2 (Truncation)
	// Break the assertion into multiple lines to satisfy the linter (<120 chars)
	hasLongName := strings.Contains(actualOutput, "A Very Long ...")
	assert.True(t, hasLongName, "Name should be truncated correctly")

	hasLongUsername := strings.Contains(actualOutput, "another_very...")
	assert.True(t, hasLongUsername, "Username should be truncated correctly")

	// Assertions on hidden data (Password and Notes should NEVER be in this table output)
	assert.NotContains(t, actualOutput, "hunter123")
	assert.NotContains(t, actualOutput, "some notes")
}
