package ui

import (
	"regexp"
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

var (
	// ansiRegex accurately captures ANSI escape sequences.
	// CSI (Control Sequence Introducer): \x1b\[ ...
	// OSC (Operating System Command): \x1b\] ...
	// Fe Escape sequences (2 bytes): \x1b followed by a valid character (e.g., \x1bM)
	// Go's regexp uses RE2, which is strictly O(N) and immune to ReDoS.
	ansiRegex = regexp.MustCompile(`\x1b\[[\x30-\x3F]*[\x20-\x2F]*[\x40-\x7E]` +
		`|\x1b\](?:[^\x07\x1b])*(?:\x07|\x1b\\)` +
		`|\x1b[\x40-\x5F]`)
)

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

	// Remove ANSI escape codes
	s = ansiRegex.ReplaceAllString(s, "")

	// Remove non-printable characters
	return strings.Map(filterRune, s)
}

// SanitizeBytes removes ANSI escape codes and non-printable characters from a byte slice.
//
// SECURITY WARNING: Due to the regexp operation, this function ALWAYS allocates a NEW byte
// slice on the heap, even if the input contains no ANSI codes.
// If passing sensitive decrypted data, the caller MUST defer memory.SecureZero()
// on the returned slice to prevent GC memory leaks.
func SanitizeBytes(b []byte) []byte {
	if len(b) == 0 {
		return b // Preserve original state (nil vs empty slice) to satisfy strict tests
	}

	b = truncateBytesSafely(b)

	// Remove ANSI escape codes (ALLOCATES ON HEAP usually)
	// We use ReplaceAll which allocates a new slice.
	cleaned := ansiRegex.ReplaceAll(b, nil)

	// If ReplaceAll didn't find anything, it returns a reference to the original slice `b`.
	// Since we promise the caller that the returned slice is safe to modify/zero,
	// we MUST force a copy if it's pointing to the original slice, to prevent
	// the caller's deferred `SecureZero()` from destroying the original plaintext.
	if len(cleaned) > 0 && &cleaned[0] == &b[0] {
		cleanedCopy := make([]byte, len(b))
		copy(cleanedCopy, b)
		cleaned = cleanedCopy
	}

	// In-place filtering of non-printable characters.
	// We use two pointers to compact the slice in-place.
	writeIdx := 0
	readIdx := 0

	for readIdx < len(cleaned) {
		r, size := utf8.DecodeRune(cleaned[readIdx:])

		if filterRune(r) != -1 {
			// Copy the rune bytes down to the write head
			if writeIdx != readIdx {
				copy(cleaned[writeIdx:writeIdx+size], cleaned[readIdx:readIdx+size])
			}
			writeIdx += size
		}
		readIdx += size
	}

	// SECURITY: Wipe the "Dirty Tail" before returning.
	// Since we compacted the slice in-place, the bytes from writeIdx to len(cleaned)
	// still contain old data (duplicates of what we just moved or data we skipped).
	// We use memory.SecureZero instead of a manual loop to prevent the compiler from
	// optimizing this away as a dead store (runtime.MemClrNoHeapPointers is not
	// eligible for dead store elimination).
	if writeIdx < len(cleaned) {
		memory.SecureZero(cleaned[writeIdx:])
	}

	// Return the strictly truncated slice
	res := cleaned[:writeIdx]

	// If the final result is empty, return explicit empty slice for test consistency
	if len(res) == 0 {
		return []byte{}
	}

	return res
}
