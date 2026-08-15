// Package tlv provides Tag-Length-Value encoding and decoding directly on pre-allocated
// secure buffers to enforce zero-allocation cryptography and prevent memory leaks.
package tlv

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/eraceo/Hako/internal/memory"
)

// Sentinel errors for TLV decoding/encoding to prevent dynamic error generation.
var (
	ErrStringTooLarge       = errors.New("string exceeds maximum size")
	ErrSecureStringTooLarge = errors.New("secure string exceeds maximum size")
	ErrBytesTooLarge        = errors.New("bytes exceed maximum size")
)

// TLV Tags for Entry fields.
const (
	TagID         = 0x01
	TagName       = 0x02
	TagUsername   = 0x03
	TagPassword   = 0x04
	TagURL        = 0x05
	TagNotes      = 0x06
	TagTags       = 0x07
	TagCreatedAt  = 0x08
	TagUpdatedAt  = 0x09
	TagEndOfEntry = 0xFF
)

const (
	// MaxStringSize is the maximum allowed size for a metadata string field (1 MB).
	MaxStringSize = 1 * 1024 * 1024 // 1 MB (metadata)
	// MaxSecureStringSize is aligned with memory.MaxSecureStringSize (1 MB)
	// to ensure consistency between the transport layer and the secure storage.
	MaxSecureStringSize = memory.MaxSecureStringSize
)

// Marshaler is the interface implemented by an object that can marshal itself into a TLV Encoder.
type Marshaler interface {
	MarshalBinary(e *Encoder) error
}

// Unmarshaler is the interface implemented by an object that can unmarshal itself from a TLV Decoder.
type Unmarshaler interface {
	UnmarshalBinary(d *Decoder) error
}

// Encoder operates directly on a pre-allocated byte slice for ZERO allocations.
type Encoder struct {
	buf []byte
	pos int
}

// NewEncoder creates a new TLV Encoder that writes directly to the provided buffer.
func NewEncoder(buf []byte) *Encoder {
	return &Encoder{buf: buf, pos: 0}
}

// WriteTag writes a single byte TLV tag to the buffer.
func (e *Encoder) WriteTag(tag byte) error {
	if e.pos+1 > len(e.buf) {
		return io.ErrShortBuffer
	}
	e.buf[e.pos] = tag
	e.pos++
	return nil
}

// WriteLength writes a 4-byte big-endian length to the buffer.
func (e *Encoder) WriteLength(length uint32) error {
	if e.pos+4 > len(e.buf) {
		return io.ErrShortBuffer
	}
	binary.BigEndian.PutUint32(e.buf[e.pos:], length)
	e.pos += 4
	return nil
}

// WriteString writes a length-prefixed standard string to the buffer.
func (e *Encoder) WriteString(s string) error {
	if len(s) > MaxStringSize {
		return ErrStringTooLarge
	}

	// Atomic Check: Calculate total required size (Length header + Data)
	totalSize := 4 + len(s)

	// Check if the buffer holds EVERYTHING before writing ANYTHING.
	if e.pos+totalSize > len(e.buf) {
		return io.ErrShortBuffer
	}

	// Write Length
	// We do this manually instead of calling e.WriteLength to avoid redundant checks.
	// #nosec G115 -- Bounds checked above via totalSize
	binary.BigEndian.PutUint32(e.buf[e.pos:], uint32(len(s)))
	e.pos += 4

	// Write Data
	if s != "" {
		// Zero allocation copy directly from string to byte slice
		copy(e.buf[e.pos:], s)
		e.pos += len(s)
	}

	return nil
}

// WriteSecureString writes a length-prefixed secure string to the buffer without leaking it to the heap.
// A nil SecureString or an empty one is encoded as a zero-length field (4 bytes of 0x00).
// On decode, ReadSecureString will return nil for this case — callers must handle nil.
func (e *Encoder) WriteSecureString(ss *memory.SecureString) error {
	if ss == nil || ss.Len() == 0 {
		// Encode as zero-length field. ReadSecureString will return nil on decode.
		return e.WriteLength(0)
	}
	return ss.Access(func(data []byte) error {
		if len(data) > MaxSecureStringSize {
			return ErrSecureStringTooLarge
		}

		// Atomic Check: Calculate total size upfront
		totalSize := 4 + len(data)
		if e.pos+totalSize > len(e.buf) {
			return io.ErrShortBuffer
		}

		// #nosec G115 -- Bounds checked above via math.MaxUint32 check
		length := uint32(len(data))

		// Write Length Header
		binary.BigEndian.PutUint32(e.buf[e.pos:], length)
		e.pos += 4

		// Write Data
		if length > 0 {
			copy(e.buf[e.pos:], data)
			e.pos += int(length)
		}
		return nil
	})
}

// WriteTime writes a length-prefixed 8-byte Unix timestamp to the buffer (4-byte length header 0x00000008 + 8-byte Unix timestamp).
func (e *Encoder) WriteTime(t time.Time) error {
	if e.pos+12 > len(e.buf) {
		return io.ErrShortBuffer
	}
	// Write Length Header (8 bytes for int64 Unix timestamp)
	binary.BigEndian.PutUint32(e.buf[e.pos:], 8)
	e.pos += 4
	// Write Data
	// #nosec G115 -- Two's complement conversion of Unix timestamp is standard
	binary.BigEndian.PutUint64(e.buf[e.pos:], uint64(t.Unix()))
	e.pos += 8
	return nil
}

// WriteBytes writes a length-prefixed byte slice directly to the buffer without allocations.
func (e *Encoder) WriteBytes(b []byte) error {
	if len(b) > MaxSecureStringSize {
		return ErrBytesTooLarge
	}

	// Atomic Check: Calculate total size upfront
	totalSize := 4 + len(b)
	if e.pos+totalSize > len(e.buf) {
		return io.ErrShortBuffer
	}

	// #nosec G115 -- Bounds checked above via math.MaxUint32 check
	length := uint32(len(b))

	// Write Length Header
	binary.BigEndian.PutUint32(e.buf[e.pos:], length)
	e.pos += 4

	// Write Data
	if length > 0 {
		copy(e.buf[e.pos:], b)
		e.pos += int(length)
	}
	return nil
}

// Decoder operates directly on the decrypted Memguard buffer for ZERO allocations.
type Decoder struct {
	buf []byte
	pos int
}

// NewDecoder creates a new TLV Decoder that reads directly from the provided buffer.
func NewDecoder(buf []byte) *Decoder {
	return &Decoder{buf: buf, pos: 0}
}

// ReadTag reads a single byte TLV tag from the buffer.
func (d *Decoder) ReadTag() (byte, error) {
	if d.pos >= len(d.buf) {
		return 0, io.EOF
	}
	t := d.buf[d.pos]
	d.pos++
	return t, nil
}

// ReadLength reads a 4-byte big-endian length from the buffer.
func (d *Decoder) ReadLength() (uint32, error) {
	if d.pos+4 > len(d.buf) {
		return 0, io.ErrUnexpectedEOF
	}
	l := binary.BigEndian.Uint32(d.buf[d.pos:])
	d.pos += 4
	return l, nil
}

// ReadString reads a length-prefixed string from the buffer.
func (d *Decoder) ReadString() (string, error) {
	length, err := d.ReadLength()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	if length > MaxStringSize {
		return "", fmt.Errorf("%w: %d (max %d)", ErrStringTooLarge, length, MaxStringSize)
	}
	if int64(d.pos)+int64(length) > int64(len(d.buf)) {
		return "", io.ErrUnexpectedEOF
	}

	// Native 1-allocation copy (Mandatory because strings must survive the buffer destruction).
	// We slice the buffer, then cast to string, which creates an immutable copy on the Heap.
	// Since this is for non-sensitive data (Names, IDs), heap allocation is acceptable.
	s := string(d.buf[d.pos : d.pos+int(length)])
	d.pos += int(length)
	return s, nil
}

// ReadSecureString reads a length-prefixed secure string directly from the buffer.
//
// SECURITY CRITICAL:
// This creates a new Memguard enclave (allocation + syscall).
// It aggressively WIPES (zeroes) the read bytes from the source buffer `d.buf`.
//
//	This ensures the plaintext only exists in the new enclave and is removed from
//	the main decryption buffer immediately.
//
// Returns nil (not an empty enclave) when length is zero. Callers MUST handle
//
//	nil returns. Memguard treats 0-length enclaves as destroyed — calling .Access()
//	on one panics with "secure buffer is destroyed".
//
// If an error occurs during enclave creation, the source bytes in d.buf
// might already be wiped, but d.pos will NOT be advanced. The decoder is considered
// to be in an unrecoverable state.
func (d *Decoder) ReadSecureString() (*memory.SecureString, error) {
	length, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		// Return nil instead of an empty enclave.
		// Memguard treats 0-length enclaves as destroyed; .Access() would panic.
		// Callers must check for nil before calling .Access() or .Len().
		return nil, nil
	}
	if length > MaxSecureStringSize {
		return nil, fmt.Errorf("%w: %d (max %d)", ErrSecureStringTooLarge, length, MaxSecureStringSize)
	}
	if int64(d.pos)+int64(length) > int64(len(d.buf)) {
		return nil, io.ErrUnexpectedEOF
	}

	// SECURITY MAGIC: We pass the slice pointing directly to the locked Vault buffer.
	// NewSecureStringFromBytes will copy it into a new enclave and IMMEDIATELY zero the original slice.
	slice := d.buf[d.pos : d.pos+int(length)]
	ss, err := memory.NewSecureStringFromBytes(slice)
	if err != nil {
		return nil, err
	}

	d.pos += int(length)
	return ss, nil
}

// ReadTime reads a length-prefixed 8-byte Unix timestamp from the buffer.
func (d *Decoder) ReadTime() (time.Time, error) {
	length, err := d.ReadLength()
	if err != nil {
		return time.Time{}, err
	}
	if length != 8 {
		return time.Time{}, fmt.Errorf("invalid time field length: %d (expected 8)", length)
	}
	if int64(d.pos)+8 > int64(len(d.buf)) {
		return time.Time{}, io.ErrUnexpectedEOF
	}
	// #nosec G115 -- Two's complement conversion of Unix timestamp is standard
	ts := int64(binary.BigEndian.Uint64(d.buf[d.pos:]))
	d.pos += 8
	return time.Unix(ts, 0), nil
}

// Skip advances the decoder's position by the specified length.
func (d *Decoder) Skip(length uint32) error {
	if int64(d.pos)+int64(length) > int64(len(d.buf)) {
		return io.ErrUnexpectedEOF
	}
	d.pos += int(length)
	return nil
}

// ReadBytes reads a length-prefixed byte slice directly from the buffer.
//
// SECURITY WARNING: It returns a direct pointer into the underlying decrypted Memguard buffer.
// The returned slice is only valid as long as the parent buffer is alive and unlocked.
// Once the Vault Load operation completes, this memory will be WIPED.
// Use ReadBytesCopy() if you need the data to persist beyond the current scope.
func (d *Decoder) ReadBytes() ([]byte, error) {
	length, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	if length > MaxSecureStringSize {
		return nil, fmt.Errorf("%w: %d (max %d)", ErrBytesTooLarge, length, MaxSecureStringSize)
	}
	if int64(d.pos)+int64(length) > int64(len(d.buf)) {
		return nil, io.ErrUnexpectedEOF
	}

	// Slice directly into the buffer (O(1) operation, ZERO allocation)
	slice := d.buf[d.pos : d.pos+int(length)]
	d.pos += int(length)

	return slice, nil
}

// ReadBytesCopy reads a length-prefixed byte slice and returns a COPY on the Heap.
//
// WARNING: The returned slice is a standard Go byte slice on the Heap.
// The caller MUST ensure they explicitly wipe it using memory.SecureZero()
// when it is no longer needed.
func (d *Decoder) ReadBytesCopy() ([]byte, error) {
	length, err := d.ReadLength()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	if length > MaxSecureStringSize {
		return nil, fmt.Errorf("%w: %d (max %d)", ErrBytesTooLarge, length, MaxSecureStringSize)
	}
	if int64(d.pos)+int64(length) > int64(len(d.buf)) {
		return nil, io.ErrUnexpectedEOF
	}

	// Allocate new slice on Heap
	b := make([]byte, length)
	copy(b, d.buf[d.pos:d.pos+int(length)])

	d.pos += int(length)
	return b, nil
}
