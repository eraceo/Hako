package ui

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/eraceo/Hako/internal/memory"
)

const (
	// MaxInputSize defines the maximum processed size.
	// Aligned with memory.MaxSecureStringSize (1 MiB) to ensure consistency
	// with the underlying secure storage limits.
	MaxInputSize = memory.MaxSecureStringSize
)

// matchANSIEscape checks if data starts with an ANSI escape sequence.
// It detects:
//   - CSI (Control Sequence Introducer): \x1b\[ ...
//   - OSC (Operating System Command): \x1b\] ... terminated by BEL (\x07) or ST (\x1b\\)
//   - Fe Escape sequences (2 bytes): \x1b followed by 0x40-0x5F (e.g. \x1bM)
//
// Returns the length of the escape sequence in bytes, or 0 if not matched.
func matchANSIEscape(data []byte) int {
	if len(data) < 2 || data[0] != 0x1b {
		return 0
	}

	switch data[1] {
	case '[': // CSI sequence
		i := 2
		// Parameter bytes: 0x30-0x3F ('0'-'?')
		for i < len(data) && data[i] >= 0x30 && data[i] <= 0x3F {
			i++
		}
		// Intermediate bytes: 0x20-0x2F (' '-'/')
		for i < len(data) && data[i] >= 0x20 && data[i] <= 0x2F {
			i++
		}
		// Final byte: 0x40-0x7E ('@'-'~')
		if i < len(data) && data[i] >= 0x40 && data[i] <= 0x7E {
			return i + 1
		}
		return 0

	case ']': // OSC sequence
		i := 2
		for i < len(data) {
			if data[i] == 0x07 { // BEL terminator
				return i + 1
			}
			if data[i] == 0x1b { // Potential ST terminator: \x1b\
				if i+1 < len(data) && data[i+1] == '\\' {
					return i + 2
				}
				return 0
			}
			i++
		}
		return 0

	default:
		// 2-byte Fe Escape sequence: \x1b followed by 0x40-0x5F
		if data[1] >= 0x40 && data[1] <= 0x5F {
			return 2
		}
		return 0
	}
}

// filterRune determines if a character should be preserved for UI display.
func filterRune(r rune) rune {
	// Keep printable characters, newlines, tabs, and carriage returns.
	if unicode.IsPrint(r) || r == '\n' || r == '\t' || r == '\r' {
		return r
	}
	// Drop unwanted control characters.
	return -1
}

// truncateStringSafely enforces MaxInputSize while strictly respecting UTF-8 rune boundaries.
func truncateStringSafely(s string) string {
	if len(s) <= MaxInputSize {
		return s
	}

	// Truncate blindly first
	truncated := s[:MaxInputSize]

	// If the last character is a corrupted rune due to the hard cut, remove it
	r, size := utf8.DecodeLastRuneInString(truncated)
	if r == utf8.RuneError && size <= 1 {
		// Walk back until we find a valid rune boundary
		for truncated != "" {
			truncated = truncated[:len(truncated)-1]
			r, size = utf8.DecodeLastRuneInString(truncated)
			if r != utf8.RuneError || size > 1 {
				break
			}
		}
	}

	return truncated
}

// truncateBytesSafely enforces MaxInputSize while strictly respecting UTF-8 rune boundaries.
func truncateBytesSafely(b []byte) []byte {
	if len(b) <= MaxInputSize {
		return b
	}

	// Truncate blindly first
	truncated := b[:MaxInputSize]

	// If the last character is a corrupted rune due to the hard cut, remove it
	r, size := utf8.DecodeLastRune(truncated)
	if r == utf8.RuneError && size <= 1 {
		// Walk back until we find a valid rune boundary
		for len(truncated) > 0 {
			truncated = truncated[:len(truncated)-1]
			r, size = utf8.DecodeLastRune(truncated)
			if r != utf8.RuneError || size > 1 {
				break
			}
		}
	}

	return truncated
}

// SanitizeString removes ANSI escape codes and non-printable characters from a string.
// It preserves newlines, tabs, and carriage returns. Safe for UTF-8.
func SanitizeString(s string) string {
	if s == "" {
		return ""
	}

	s = truncateStringSafely(s)

	var builder strings.Builder
	builder.Grow(len(s))

	b := []byte(s)
	readIdx := 0

	for readIdx < len(b) {
		if escLen := matchANSIEscape(b[readIdx:]); escLen > 0 {
			readIdx += escLen
			continue
		}

		r, size := utf8.DecodeRune(b[readIdx:])
		if filterRune(r) != -1 {
			builder.Write(b[readIdx : readIdx+size])
		}
		readIdx += size
	}

	return builder.String()
}

// SanitizeBytes removes ANSI escape codes and non-printable characters from a byte slice.
// It preserves newlines, tabs, and carriage returns. Safe for UTF-8.
func SanitizeBytes(b []byte) []byte {
	if len(b) == 0 {
		return b // Preserve original state (nil vs empty slice) to satisfy strict tests
	}

	b = truncateBytesSafely(b)

	// Preallocate single output slice with exact capacity
	out := make([]byte, len(b))
	writeIdx := 0
	readIdx := 0

	for readIdx < len(b) {
		if escLen := matchANSIEscape(b[readIdx:]); escLen > 0 {
			readIdx += escLen
			continue
		}

		r, size := utf8.DecodeRune(b[readIdx:])
		if filterRune(r) != -1 {
			copy(out[writeIdx:writeIdx+size], b[readIdx:readIdx+size])
			writeIdx += size
		}
		readIdx += size
	}

	// SECURITY: Wipe the dirty tail
	if writeIdx < len(out) {
		memory.SecureZero(out[writeIdx:])
	}

	res := out[:writeIdx]
	if len(res) == 0 {
		return []byte{}
	}

	return res
}
