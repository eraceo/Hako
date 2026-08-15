// Package memory provides secure memory enclaves and zero-allocation cryptographic memory management.
package memory

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/awnumar/memguard"
)

const (
	// MaxSecureStringSize limits the size of a secure string to prevent OS mlock exhaustion (DoS).
	// Default limit: 1 MiB.
	MaxSecureStringSize = 1 << 20
)

var (
	// ErrBufferDestroyed is returned when attempting to access a destroyed enclave.
	ErrBufferDestroyed = errors.New("secure buffer is destroyed")
	// ErrInvalidSize is returned when attempting to allocate a buffer with a negative size or exceeding limit.
	ErrInvalidSize = errors.New("invalid size")
	// ErrEmptyPassword is returned when attempting to create a secure password from an empty slice.
	ErrEmptyPassword = errors.New("master password cannot be empty")
)

// SecureBuffer represents a thread-safe, memory-locked secure enclave.
// Data is stored encrypted in memory and only decrypted temporarily during Access().
type SecureBuffer struct {
	mu      sync.RWMutex
	enclave *memguard.Enclave
	size    int // size >= 0 means valid, size == -1 means destroyed
}

// SecureString is a semantic wrapper around SecureBuffer for textual secrets.
// As of v1.0, this is mostly kept for legacy operations and payload buffers.
// EphemeralSecret should be preferred for individual parsed vault entries.
type SecureString struct {
	buffer *SecureBuffer
}

// SecurePassword is a semantic wrapper around SecureBuffer for master passwords.
type SecurePassword struct {
	buffer *SecureBuffer
}

// NewSecureBuffer creates a new secure buffer filled with zeros.
func NewSecureBuffer(size int) (*SecureBuffer, error) {
	if size < 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidSize, size)
	}
	if size > MaxSecureStringSize {
		return nil, fmt.Errorf("%w: requested %d bytes exceeds max %d", ErrInvalidSize, size, MaxSecureStringSize)
	}
	// Explicitly handle empty size: no enclave needed, but valid state.
	if size == 0 {
		return &SecureBuffer{size: 0, enclave: nil}, nil
	}

	// Create a LockedBuffer of specific size
	b := memguard.NewBuffer(size)
	// Explicitly wipe it to ensure it contains zeros before sealing
	b.Wipe()
	enclave := b.Seal()

	return &SecureBuffer{
		enclave: enclave,
		size:    size,
	}, nil
}

// NewSecureBufferFromBytes creates a secure buffer from the input slice.
// It actively zeroes the original slice immediately to prevent heap leaks (Defensive paranoia).
func NewSecureBufferFromBytes(data []byte) (*SecureBuffer, error) {
	if len(data) == 0 {
		return &SecureBuffer{size: 0}, nil
	}

	if len(data) > MaxSecureStringSize {
		return nil, fmt.Errorf("%w: requested %d bytes exceeds max %d", ErrInvalidSize, len(data), MaxSecureStringSize)
	}

	// NewBufferFromBytes creates a LockedBuffer and copies data into it.
	// Window of Vulnerability: Here, 'data' exists in Heap and 'b' exists in Locked Memory.
	b := memguard.NewBufferFromBytes(data)
	enclave := b.Seal()

	// Strict Defensive Wiping: Close the window of vulnerability immediately.
	SecureZero(data)

	return &SecureBuffer{
		enclave: enclave,
		size:    len(data),
	}, nil
}

// Access temporarily decrypts the secure buffer into a memory-locked region (mlock)
// and provides the plaintext bytes to the callback function.
//
// SECURITY WARNING:
// The callback function MUST NOT leak the provided byte slice to the heap (e.g., casting to string).
// The callback MUST NOT spin up goroutines using the byte slice.
// The slice is completely zeroed and destroyed the microsecond the callback returns.
func (sb *SecureBuffer) Access(fn func([]byte) error) error {
	// We hold the read lock to ensure 'enclave' is not set to nil (Destroyed) while we use it.
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	// Check if destroyed first (size == -1)
	if sb.size < 0 {
		return ErrBufferDestroyed
	}

	// Handle empty buffer (valid state, no enclave interaction needed)
	if sb.size == 0 {
		return fn([]byte{})
	}

	// Valid size > 0 but enclave is nil -> Inconsistent state (Should not happen)
	if sb.enclave == nil {
		return ErrBufferDestroyed
	}

	// Open() allocates a temporary locked memory region (mlock) and decrypts the Enclave.
	// This operation is thread-safe within Memguard itself.
	lockedBuf, err := sb.enclave.Open()
	if err != nil {
		return fmt.Errorf("failed to decrypt enclave: %w", err)
	}

	// STRICT DEFER: The microsecond fn() finishes or panics, the plaintext is wiped from RAM
	// and the OS VirtualLock/mlock quota is released.
	defer lockedBuf.Destroy()

	return fn(lockedBuf.Bytes())
}

// Zero securely destroys the enclave reference.
// The Go GC will collect the Enclave struct, but because memguard Enclaves are
// encrypted, no plaintext is left in RAM.
func (sb *SecureBuffer) Zero() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	// Idempotency check
	if sb.size < 0 {
		return
	}

	sb.enclave = nil
	sb.size = -1 // Sentinel value to explicitly mark as destroyed
}

// Len returns the size of the decrypted secure buffer.
func (sb *SecureBuffer) Len() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	if sb.size < 0 {
		return 0 // A destroyed buffer appears to have length 0 to the outside
	}
	return sb.size
}

// Destroy completely removes the secure buffer. Alias for Zero().
func (sb *SecureBuffer) Destroy() error {
	sb.Zero()
	return nil
}

// DangerousBytesCopy returns the buffer data in standard heap memory.
// DANGER: This memory will be managed by Go's Garbage Collector and can be swapped to disk.
// ONLY use this when passing data to external libraries that require a standard []byte and
// ensure you call SecureZero() on the result immediately after use.
func (sb *SecureBuffer) DangerousBytesCopy() ([]byte, error) {
	var copiedData []byte
	err := sb.Access(func(data []byte) error {
		copiedData = make([]byte, len(data))
		copy(copiedData, data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return copiedData, nil
}

// --- SecureString Methods ---

// NewSecureStringFromInsecure creates a new secure string from a standard Go string.
// WARNING: The input string `s` is immutable and CANNOT be wiped. It will remain on the Heap
// until Garbage Collected. Only use this for non-sensitive data or when the source is already tainted.
func NewSecureStringFromInsecure(s string) (*SecureString, error) {
	// We convert string to bytes here, creating a copy.
	// This copy will be wiped by NewSecureBufferFromBytes immediately.
	// But `s` remains in memory.
	return NewSecureStringFromBytes([]byte(s))
}

// NewSecureStringFromBytes creates a new secure string from bytes and strictly wipes the input.
func NewSecureStringFromBytes(data []byte) (*SecureString, error) {
	buffer, err := NewSecureBufferFromBytes(data)
	if err != nil {
		return nil, err
	}
	return &SecureString{buffer: buffer}, nil
}

// NewSecureStringFromReader creates a secure string directly from an io.Reader
// without creating intermediate vulnerable heap buffers.
func NewSecureStringFromReader(r io.Reader, length int) (*SecureString, error) {
	if length < 0 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidSize, length)
	}
	if length > MaxSecureStringSize {
		return nil, fmt.Errorf("%w: requested %d bytes exceeds max %d", ErrInvalidSize, length, MaxSecureStringSize)
	}
	if length == 0 {
		return &SecureString{buffer: &SecureBuffer{size: 0}}, nil
	}

	// Read directly into an OS-locked memory region
	b := memguard.NewBuffer(length)

	// ReadFull ensures we read exactly 'length' bytes.
	if _, err := io.ReadFull(r, b.Bytes()); err != nil {
		b.Destroy() // Destroy the locked buffer on error
		return nil, fmt.Errorf("failed to read secure string stream: %w", err)
	}

	enclave := b.Seal() // Encrypts and destroys the LockedBuffer

	return &SecureString{
		buffer: &SecureBuffer{
			enclave: enclave,
			size:    length,
		},
	}, nil
}

// Access temporarily exposes the plaintext string as bytes.
func (ss *SecureString) Access(fn func([]byte) error) error {
	if ss == nil || ss.buffer == nil {
		return ErrBufferDestroyed
	}
	return ss.buffer.Access(fn)
}

// Compare performs a constant-time comparison against another SecureString.
// Symetric API prevents accidental comparison against raw, unprotected heap slices.
// It uses nested enclave access to guarantee absolute zero heap allocation.
func (ss *SecureString) Compare(other *SecureString) bool {
	if ss == nil || ss.buffer == nil || other == nil || other.buffer == nil {
		return false
	}

	if ss == other {
		return true
	}

	var match bool

	// Nested Access: b1 and b2 are read directly from OS-locked memory (mlock).
	// No heap allocations are made.
	// We are holding two read locks here on independent objects.
	// Since RLock is non-blocking for other RLocks, this is safe and deadlock-free.
	err := ss.Access(func(b1 []byte) error {
		return other.Access(func(b2 []byte) error {
			match = SecureCompare(b1, b2)
			return nil
		})
	})

	if err != nil {
		return false
	}

	return match
}

// Len returns the length of the string.
func (ss *SecureString) Len() int {
	if ss == nil || ss.buffer == nil {
		return 0
	}
	return ss.buffer.Len()
}

// Destroy completely removes the secure string from memory.
func (ss *SecureString) Destroy() error {
	if ss != nil && ss.buffer != nil {
		return ss.buffer.Destroy()
	}
	return nil
}

// DangerousStringCopy returns the buffer data as a standard Go string.
// CRITICAL WARNING: This string is immutable, will leak onto the heap, and CANNOT be manually zeroed.
// Only use this for UI display where absolute sanitization is guaranteed.
func (ss *SecureString) DangerousStringCopy() string {
	if ss == nil || ss.buffer == nil {
		return ""
	}
	// We use DangerousBytesCopy to handle the mlock extraction
	b, err := ss.buffer.DangerousBytesCopy()
	if err != nil {
		return ""
	}

	// Convert to string (Heap Allocation)
	s := string(b)

	// Explicitly wipe the intermediate byte slice.
	// We do NOT use defer here to make the lifecycle sequence explicitly clear:
	// Get bytes -> 2. Copy to string -> 3. Wipe bytes -> 4. Return string
	SecureZero(b)

	return s
}

// DangerousBytesCopy returns the buffer data as a standard Go byte slice.
// WARNING: You MUST defer SecureZero() on the returned slice.
func (ss *SecureString) DangerousBytesCopy() ([]byte, error) {
	if ss == nil || ss.buffer == nil {
		return nil, ErrBufferDestroyed
	}
	return ss.buffer.DangerousBytesCopy()
}

// --- SecurePassword Methods ---

// NewSecurePasswordFromBytes creates a secure password and securely wipes the input slice.
func NewSecurePasswordFromBytes(password []byte) (*SecurePassword, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	buffer, err := NewSecureBufferFromBytes(password)
	if err != nil {
		return nil, err
	}
	return &SecurePassword{buffer: buffer}, nil
}

// Access temporarily exposes the plaintext password as bytes.
func (sp *SecurePassword) Access(fn func([]byte) error) error {
	if sp == nil || sp.buffer == nil {
		return ErrBufferDestroyed
	}
	return sp.buffer.Access(fn)
}

// WithPassword is an alias for Access, providing better semantic readability
// when dealing strictly with Master Passwords.
func (sp *SecurePassword) WithPassword(fn func([]byte) error) error {
	return sp.Access(fn)
}

// Len returns the length of the password.
func (sp *SecurePassword) Len() int {
	if sp == nil || sp.buffer == nil {
		return 0
	}
	return sp.buffer.Len()
}

// Destroy completely removes the secure password from memory.
func (sp *SecurePassword) Destroy() error {
	if sp != nil && sp.buffer != nil {
		err := sp.buffer.Destroy()
		sp.buffer = nil
		return err
	}
	return nil
}

// --- Utilities ---

// SecureZero performs secure zeroing of a standard Go memory slice (Heap).
func SecureZero(data []byte) {
	if len(data) > 0 {
		memguard.WipeBytes(data)
	}
}

// SecureCompare performs constant-time byte comparison to prevent timing attacks.
func SecureCompare(a, b []byte) bool {
	// subtle.ConstantTimeCompare handles length mismatch internally
	// (returns 0 immediately if len(a) != len(b)).
	// We avoid an explicit check here to minimize branching and rely on standard lib.
	return subtle.ConstantTimeCompare(a, b) == 1
}
