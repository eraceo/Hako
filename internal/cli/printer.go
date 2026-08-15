package cli

import (
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

const (
	maxNameDisplayLength     = 15
	maxUsernameDisplayLength = 15
	maxURLDisplayLength      = 25
	maxTagsDisplayLength     = 15
	ellipsis                 = "..."
	ellipsisLen              = 3

	// paddingBuffer is a pre-allocated string of spaces used for efficient slicing.
	paddingBuffer = "                                                                                                    "
)

// printEntriesTable prints a list of entries in a formatted, memory-safe table.
func printEntriesTable(entries []*secrets.Entry) {
	if len(entries) == 0 {
		ui.PrintfInfof("No entries found.\n")
		return
	}

	// Header
	ui.Printf("%-15s %-15s %-25s %-15s\n", "NAME", "USERNAME", "URL", "TAGS")
	ui.Println(strings.Repeat("-", 73))

	for _, entry := range entries {
		// NAME (Public Metadata)
		writeStringField(ui.SanitizeString(entry.Name), maxNameDisplayLength)
		writeSpace()

		// USERNAME (Secure)
		if entry.Username != nil {
			err := entry.Username.Access(func(u []byte) error {
				writeSecureField(u, maxUsernameDisplayLength)
				return nil
			})
			if err != nil {
				writePadding(maxUsernameDisplayLength)
			}
		} else {
			writePadding(maxUsernameDisplayLength)
		}
		writeSpace()

		// URL (Secure)
		if entry.URL != nil {
			err := entry.URL.Access(func(url []byte) error {
				writeSecureField(url, maxURLDisplayLength)
				return nil
			})
			if err != nil {
				writePadding(maxURLDisplayLength)
			}
		} else {
			writePadding(maxURLDisplayLength)
		}
		writeSpace()

		// TAGS (Public Metadata)
		tagsStr := strings.Join(entry.Tags, ", ")
		writeStringField(ui.SanitizeString(tagsStr), maxTagsDisplayLength)

		// End of row
		ui.Println()
	}
}

// writeStringField writes a string with truncation (ellipsis) and padding.
func writeStringField(data string, maxWidth int) {
	printFieldLogic(maxWidth, func(i int) (rune, int) {
		if i >= len(data) {
			return utf8.RuneError, 0
		}
		// Zero-allocation slicing of string
		r, size := utf8.DecodeRuneInString(data[i:])
		return r, size
	})
}

// writeSecureField writes sensitive bytes with truncation and padding.
func writeSecureField(data []byte, maxWidth int) {
	printFieldLogic(maxWidth, func(i int) (rune, int) {
		if i >= len(data) {
			return utf8.RuneError, 0
		}
		// Zero-allocation decoding of byte slice
		r, size := utf8.DecodeRune(data[i:])
		return r, size
	})
}

// printFieldLogic contains the shared truncation/padding algorithm.
// It uses a closure to abstract reading from string vs []byte.
func printFieldLogic(maxWidth int, decoder func(int) (rune, int)) {
	if maxWidth < ellipsisLen {
		maxWidth = ellipsisLen
	}

	var printedRunes int
	var byteOffset int
	var needsEllipsis bool

	// Stack-allocated buffer for encoding runes (No 'make' in loop)
	var buf [utf8.UTFMax]byte

	// Print characters up to maxWidth
	for printedRunes < maxWidth {
		// Check truncation threshold BEFORE decoding the current character.
		// If we are at the point where only ellipsis fits, check if the remaining string is actually longer than ellipsis.
		if printedRunes == (maxWidth - ellipsisLen) {
			// Lookahead: Do we have strictly MORE data than the ellipsis length?
			tempOffset := byteOffset
			runesRemaining := 0

			// We check ellipsisLen + 1 characters ahead.
			// If we find that many, it means the string is definitely too long.
			for k := 0; k <= ellipsisLen; k++ {
				_, sz := decoder(tempOffset)
				if sz == 0 {
					break
				}
				tempOffset += sz
				runesRemaining++
			}

			if runesRemaining > ellipsisLen {
				needsEllipsis = true
				break
			}
		}

		r, size := decoder(byteOffset)
		if size == 0 {
			break // End of data
		}

		// SANITIZATION ON-THE-FLY
		// Replace newlines, tabs, and non-graphic chars to preserve table layout.
		if r == '\n' || r == '\t' || !unicode.IsGraphic(r) {
			r = ' ' // Replace with space (safe)
		}

		// Write rune directly to stdout using stack buffer
		n := utf8.EncodeRune(buf[:], r)
		_, _ = os.Stdout.Write(buf[:n])

		byteOffset += size
		printedRunes++
	}

	// Append Ellipsis if needed
	if needsEllipsis {
		_, _ = os.Stdout.WriteString(ellipsis)
		printedRunes += ellipsisLen
	}

	// Fill remaining space with padding
	writePadding(maxWidth - printedRunes)
}

// writePadding writes 'n' spaces efficiently.
func writePadding(n int) {
	if n <= 0 {
		return
	}
	// Loop if padding exceeds our buffer size (rare)
	for n > len(paddingBuffer) {
		_, _ = os.Stdout.WriteString(paddingBuffer)
		n -= len(paddingBuffer)
	}
	_, _ = os.Stdout.WriteString(paddingBuffer[:n])
}

// writeSpace writes a single column separator.
func writeSpace() {
	_, _ = os.Stdout.WriteString(" ")
}
