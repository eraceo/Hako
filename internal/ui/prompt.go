// Package ui provides secure terminal prompts, user interactions, and formatted output handling.
package ui

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/eraceo/Hako/internal/memory"
)

var (
	// ErrInputTooLong is returned when the user input exceeds the maximum buffer size.
	ErrInputTooLong = errors.New("input too long")
	// ErrInvalidChoice is returned when the user selects an out-of-bounds menu option.
	ErrInvalidChoice = errors.New("invalid choice")
	// ErrPasswordMismatch is returned when the confirmation password does not match.
	ErrPasswordMismatch = errors.New("passwords do not match")
	// ErrInvalidFormat is returned when the input contains non-numeric characters where digits are expected.
	ErrInvalidFormat = errors.New("invalid numeric format")
	// ErrValueOverflow is returned when the numeric input exceeds integer limits.
	ErrValueOverflow = errors.New("choice value overflow")
	// ErrEnclaveNil is returned when an enclave is unexpectedly nil during comparison.
	ErrEnclaveNil = errors.New("confirmation enclave is nil")
	// ErrPasswordEmpty is returned when the user enters an empty password.
	ErrPasswordEmpty = errors.New("password cannot be empty")
)

// readUnbufferedLine reads a line from stdin byte by byte without buffering
// to avoid consuming more input than necessary when piping commands.
// Returns an exact-sized byte slice.
//
// SECURITY CRITICAL: The caller is STRICTLY responsible for wiping the returned
// slice using memory.SecureZero() immediately after use.
func readUnbufferedLine() ([]byte, error) {
	const maxBufferSize = 4096
	// Temporary buffer to hold the incoming bytes
	buf := make([]byte, maxBufferSize)
	// SECURITY: Strictly wipe the ENTIRE 4096-byte buffer before returning,
	// so no residual data or zeroed capacity leaks on the heap.
	defer memory.SecureZero(buf)

	pos := 0
	// Pre-allocate the single byte buffer to avoid allocation in loop
	oneByte := make([]byte, 1)
	defer memory.SecureZero(oneByte)

	for {
		if pos >= maxBufferSize {
			return nil, fmt.Errorf("%w (max %d bytes)", ErrInputTooLong, maxBufferSize)
		}

		n, err := os.Stdin.Read(oneByte)
		if n > 0 {
			b := oneByte[0]
			if b == '\n' {
				break
			}
			buf[pos] = b
			pos++
		}
		if err != nil {
			if err == io.EOF && pos > 0 {
				break
			}
			return nil, err
		}
	}

	if pos > 0 && buf[pos-1] == '\r' {
		buf[pos-1] = 0 // Wipe the \r
		pos--
	}

	// Create an exact-sized copy of the captured input to return to the caller.
	// This prevents returning a slice backed by a massive 4KB array.
	// The `defer memory.SecureZero(buf)` above will wipe `buf` when this function returns.
	exactSized := make([]byte, pos)
	copy(exactSized, buf[:pos])

	return exactSized, nil
}

// PromptPassword prompts for a password without echoing to terminal.
// The caller is strictly responsible for zeroing the returned byte slice.
func PromptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	// #nosec G115 -- os.Stdin.Fd() returns a file descriptor which is a small non-negative integer
	fd := int(os.Stdin.Fd())
	if fd >= 0 && term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		return password, nil
	}

	// Fallback for non-terminal input (pipes, etc.)
	// SECURITY: readUnbufferedLine returns a raw slice that we pass directly to the caller.
	// The contract requires the caller to wipe this.
	password, err := readUnbufferedLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read password from stream: %w", err)
	}

	return password, nil
}

// PromptString prompts for a regular string input.
// Returns a byte slice that the caller MUST wipe.
// This function avoids creating immutable strings for sensitive data.
func PromptString(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	inputBytes, err := readUnbufferedLine()
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	return inputBytes, nil
}

// PromptConfirm prompts for yes/no confirmation.
// Safe for non-sensitive control flow.
func PromptConfirm(prompt string) (bool, error) {
	fmt.Fprintf(os.Stderr, "%s (y/N): ", prompt)

	inputBytes, err := readUnbufferedLine()
	if err != nil {
		return false, fmt.Errorf("failed to read input: %w", err)
	}
	defer memory.SecureZero(inputBytes)

	// Avoid string allocation for simple validation
	cleanBytes := bytes.TrimSpace(inputBytes)
	if len(cleanBytes) == 0 {
		return false, nil
	}

	// Case-insensitive check directly on bytes
	// 'y' = 0x79, 'Y' = 0x59
	if len(cleanBytes) == 1 {
		b := cleanBytes[0]
		return b == 'y' || b == 'Y', nil
	}

	// "yes" check
	if len(cleanBytes) == 3 {
		return (cleanBytes[0] == 'y' || cleanBytes[0] == 'Y') &&
			(cleanBytes[1] == 'e' || cleanBytes[1] == 'E') &&
			(cleanBytes[2] == 's' || cleanBytes[2] == 'S'), nil
	}

	return false, nil
}

// PromptChoice prompts for a choice from a list of options.
// It is strictly Zero-Allocation to respect project standards.
func PromptChoice(prompt string, choices []string) (int, error) {
	fmt.Fprintln(os.Stderr, prompt)
	for i, choice := range choices {
		fmt.Fprintf(os.Stderr, "%d. %s\n", i+1, choice)
	}
	fmt.Fprintf(os.Stderr, "Enter choice (1-%d): ", len(choices))

	inputBytes, err := readUnbufferedLine()
	if err != nil {
		return 0, fmt.Errorf("failed to read choice: %w", err)
	}
	defer memory.SecureZero(inputBytes)

	// Zero-allocation parsing
	cleanBytes := bytes.TrimSpace(inputBytes)
	if len(cleanBytes) == 0 {
		return 0, fmt.Errorf("%w: empty input", ErrInvalidChoice)
	}

	// Manual byte-to-int parsing to avoid string(cleanBytes) allocation
	// We only expect positive integers here.
	choice := 0
	for _, b := range cleanBytes {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("%w: non-digit character", ErrInvalidFormat)
		}

		// Check for overflow.
		// While strictly overkill for a small menu selection, we maintain
		// rigorous input validation here to be consistent with Hako's security standards.
		// We reject any input that cannot fit in a standard int.
		if choice > (int(^uint(0)>>1)-int(b-'0'))/10 {
			return 0, ErrValueOverflow
		}
		choice = choice*10 + int(b-'0')
	}

	if choice < 1 || choice > len(choices) {
		return 0, fmt.Errorf("%w: %d", ErrInvalidChoice, choice)
	}

	return choice - 1, nil
}

// PrintfErrorf prints an error message to stderr.
func PrintfErrorf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}

// PrintfWarningf prints a warning message to stderr.
// Warnings go to stderr (not stdout) to avoid polluting piped output
// (e.g. `hako get | pbpaste` must not include warning text in the piped data).
func PrintfWarningf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Warning: "+format+"\n", args...)
}

// PrintfSuccessf prints a success message to stderr.
func PrintfSuccessf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "✓ "+format+"\n", args...)
}

// PrintfInfof prints an informational message to stderr.
func PrintfInfof(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Info: "+format+"\n", args...)
}

// Printf prints a formatted message to stdout without prefix.
func Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

// Println prints a line to stdout without prefix.
func Println(args ...interface{}) {
	fmt.Println(args...)
}

// PromptSecurePassword prompts for a password and instantly locks it into a Memguard enclave.
//
// SECURITY: Returns ErrPasswordEmpty if the user enters an empty password.
// An empty password would create a 0-length Memguard enclave, which is treated as
// a destroyed enclave — calling .Access() on it panics with "secure buffer is destroyed".
func PromptSecurePassword(prompt string) (*memory.SecurePassword, error) {
	passwordBytes, err := PromptPassword(prompt)
	if err != nil {
		return nil, err
	}
	// Strictly wipe the raw bytes immediately after enclave creation.
	defer memory.SecureZero(passwordBytes)

	// SECURITY: Reject empty passwords before attempting enclave creation.
	// Memguard treats 0-length enclaves as destroyed — .Access() would panic.
	if len(passwordBytes) == 0 {
		return nil, ErrPasswordEmpty
	}

	// NewSecurePasswordFromBytes locks the bytes into Memguard.
	securePass, err := memory.NewSecurePasswordFromBytes(passwordBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure password: %w", err)
	}

	return securePass, nil
}

// PromptSecurePasswordWithConfirmation prompts for password with confirmation securely.
func PromptSecurePasswordWithConfirmation(prompt, confirmPrompt string) (*memory.SecurePassword, error) {
	password, err := PromptSecurePassword(prompt)
	if err != nil {
		return nil, err
	}

	success := false
	defer func() {
		if !success && password != nil {
			_ = password.Destroy()
		}
	}()

	confirmation, err := PromptSecurePassword(confirmPrompt)
	if err != nil {
		return nil, err
	}
	defer func() {
		if confirmation != nil {
			_ = confirmation.Destroy()
		}
	}()

	match := false

	// Compare passwords securely by nesting enclave access.
	err = password.Access(func(p1 []byte) error {
		if confirmation == nil {
			return ErrEnclaveNil
		}
		return confirmation.Access(func(p2 []byte) error {
			// We MUST check lengths first to prevent a crash.
			if len(p1) == len(p2) && subtle.ConstantTimeCompare(p1, p2) == 1 {
				match = true
			}
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("failed to access secure enclaves for comparison: %w", err)
	}

	if !match {
		return nil, ErrPasswordMismatch
	}

	success = true
	return password, nil
}
