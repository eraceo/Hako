package cli

import (
	"fmt"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

const (
	defaultNameDisplayLength     = 15
	defaultUsernameDisplayLength = 15
	defaultURLDisplayLength      = 25
	defaultTagsDisplayLength     = 15
	ellipsis                     = "..."
	ellipsisLen                  = 3

	// paddingBuffer is a pre-allocated string of spaces used for efficient slicing.
	paddingBuffer = "                                                                                                    "
)

// computeColumnWidths calculates responsive column widths based on terminal dimensions.
func computeColumnWidths(termWidth int) (wName, wUser, wURL, wTags int) {
	const (
		baseName, baseUser, baseURL, baseTags = 15, 15, 25, 15
		minName, minUser, minURL, minTags     = 10, 10, 12, 6
		maxName, maxUser, maxURL, maxTags     = 35, 30, 80, 25
		baseTotal                             = 73 // 15 + 1 + 15 + 1 + 25 + 1 + 15
		minTotal                              = 41 // 10 + 1 + 10 + 1 + 12 + 1 + 6
	)

	// Fallback to default base widths if non-TTY or detection failed
	if termWidth <= 0 {
		return baseName, baseUser, baseURL, baseTags
	}

	// Terminal narrower than base (41 to 72)
	if termWidth < baseTotal {
		if termWidth <= minTotal {
			return minName, minUser, minURL, minTags
		}
		deficit := baseTotal - termWidth
		wName = baseName - (deficit * 20 / 100)
		if wName < minName {
			wName = minName
		}
		wUser = baseUser - (deficit * 20 / 100)
		if wUser < minUser {
			wUser = minUser
		}
		wURL = baseURL - (deficit * 50 / 100)
		if wURL < minURL {
			wURL = minURL
		}
		wTags = baseTags - (deficit * 10 / 100)
		if wTags < minTags {
			wTags = minTags
		}
		return wName, wUser, wURL, wTags
	}

	// Terminal wider than base (> 73)
	extra := termWidth - baseTotal
	wName = baseName + (extra * 25 / 100)
	if wName > maxName {
		wName = maxName
	}
	wUser = baseUser + (extra * 15 / 100)
	if wUser > maxUser {
		wUser = maxUser
	}
	wURL = baseURL + (extra * 50 / 100)
	if wURL > maxURL {
		wURL = maxURL
	}
	wTags = baseTags + (extra * 10 / 100)
	if wTags > maxTags {
		wTags = maxTags
	}
	return wName, wUser, wURL, wTags
}

// printEntriesTable prints a list of entries in a formatted, memory-safe table.
func printEntriesTable(entries []*secrets.Entry) {
	if len(entries) == 0 {
		ui.PrintfInfof("No entries found.\n")
		return
	}

	termWidth := 0
	if fd := int(os.Stdout.Fd()); term.IsTerminal(fd) {
		if w, _, err := term.GetSize(fd); err == nil {
			termWidth = w
		}
	}

	wName, wUser, wURL, wTags := computeColumnWidths(termWidth)

	// Header
	nameHeader := ui.ColorBold(fmt.Sprintf("%-*s", wName, "NAME"))
	userHeader := ui.ColorBold(fmt.Sprintf("%-*s", wUser, "USERNAME"))
	urlHeader := ui.ColorBold(fmt.Sprintf("%-*s", wURL, "URL"))
	tagsHeader := ui.ColorBold(fmt.Sprintf("%-*s", wTags, "TAGS"))
	ui.Printf("%s %s %s %s\n", nameHeader, userHeader, urlHeader, tagsHeader)

	totalWidth := wName + 1 + wUser + 1 + wURL + 1 + wTags
	ui.Println(strings.Repeat("-", totalWidth))

	for _, entry := range entries {
		// NAME (Public Metadata)
		writeStringField(ui.SanitizeString(entry.Name), wName)
		writeSpace()

		// USERNAME (Secure)
		if entry.Username != nil {
			err := entry.Username.Access(func(u []byte) error {
				writeSecureField(u, wUser)
				return nil
			})
			if err != nil {
				writePadding(wUser)
			}
		} else {
			writePadding(wUser)
		}
		writeSpace()

		// URL (Secure)
		if entry.URL != nil {
			err := entry.URL.Access(func(url []byte) error {
				writeSecureField(url, wURL)
				return nil
			})
			if err != nil {
				writePadding(wURL)
			}
		} else {
			writePadding(wURL)
		}
		writeSpace()

		// TAGS (Public Metadata)
		tagsStr := strings.Join(entry.Tags, ", ")
		writeStringField(ui.SanitizeString(tagsStr), wTags)

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
