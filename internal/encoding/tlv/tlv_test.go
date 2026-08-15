package tlv

import (
	"encoding/binary"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/memory"
)

func TestTagAndLength(t *testing.T) {
	t.Parallel()

	// Pre-allocate a generous buffer for the test
	buf := make([]byte, 1024)
	enc := NewEncoder(buf)
	dec := NewDecoder(buf)

	// Test Tags
	require.NoError(t, enc.WriteTag(TagID))
	require.NoError(t, enc.WriteTag(TagEndOfEntry))

	tag, err := dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, byte(TagID), tag)

	tag, err = dec.ReadTag()
	require.NoError(t, err)
	assert.Equal(t, byte(TagEndOfEntry), tag)

	// Test Lengths (Reset the encoder/decoder pointers)
	enc = NewEncoder(buf)
	dec = NewDecoder(buf)

	require.NoError(t, enc.WriteLength(0))
	require.NoError(t, enc.WriteLength(42))
	require.NoError(t, enc.WriteLength(math.MaxUint32))

	length, err := dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(0), length)

	length, err = dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(42), length)

	length, err = dec.ReadLength()
	require.NoError(t, err)
	assert.Equal(t, uint32(math.MaxUint32), length)
}

func TestString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Normal string", "hello world", "hello world"},
		{"Empty string", "", ""},
		{"Special characters", "Hako \x00 Vault 🚀", "Hako \x00 Vault 🚀"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := make([]byte, 1024)
			enc := NewEncoder(buf)
			dec := NewDecoder(buf)

			require.NoError(t, enc.WriteString(tt.input))

			actual, err := dec.ReadString()
			require.NoError(t, err)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestString_Limits(t *testing.T) {
	t.Parallel()

	// Craft a malicious payload indicating a string larger than MaxStringSize
	buf := make([]byte, 4)
	badLength := uint32(MaxStringSize + 1)
	binary.BigEndian.PutUint32(buf, badLength)

	dec := NewDecoder(buf)
	_, err := dec.ReadString()
	require.Error(t, err)
	// UPDATE: Updated expectation to match the new error message in tlv.go
	assert.Contains(t, err.Error(), "string exceeds maximum size")
}

// TestBytes verifies the low-level byte writing used by EphemeralSecrets.
// This replaces the "TestSecureString" which would introduce a circular dependency logic.
func TestBytes(t *testing.T) {
	t.Parallel()

	t.Run("Normal Bytes", func(t *testing.T) {
		buf := make([]byte, 1024)
		enc := NewEncoder(buf)
		dec := NewDecoder(buf)
		input := []byte("binary-data-payload")

		require.NoError(t, enc.WriteBytes(input))

		readBytes, err := dec.ReadBytes()
		require.NoError(t, err)
		assert.Equal(t, input, readBytes)
	})

	t.Run("Empty Bytes", func(t *testing.T) {
		buf := make([]byte, 1024)
		enc := NewEncoder(buf)
		dec := NewDecoder(buf)

		require.NoError(t, enc.WriteBytes([]byte{}))

		readBytes, err := dec.ReadBytes()
		require.NoError(t, err)
		// assert.Equal fails between []byte{} and nil, so we check for nil explicitly.
		assert.Nil(t, readBytes)
	})

	t.Run("Nil Bytes", func(t *testing.T) {
		buf := make([]byte, 1024)
		enc := NewEncoder(buf)
		dec := NewDecoder(buf)

		require.NoError(t, enc.WriteBytes(nil))

		readBytes, err := dec.ReadBytes()
		require.NoError(t, err)
		// Implementation writes length 0 for nil, so we expect nil back.
		assert.Nil(t, readBytes)
	})
}

// TestBytes_SecureIntegration verifies that we can perform the architecture's
// SecureString -> Access -> WriteBytes flow correctly.
func TestBytes_SecureIntegration(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 1024)
	enc := NewEncoder(buf)
	dec := NewDecoder(buf)
	secretData := "super-secret-password"

	// Create SecureString (Simulate source data)
	// We use the FromBytes constructor as defined in memory package
	ss, err := memory.NewSecureStringFromBytes([]byte(secretData))
	require.NoError(t, err)
	defer func() { _ = ss.Destroy() }()

	// Write: Simulate Entry.MarshalBinary logic
	err = ss.Access(func(plaintext []byte) error {
		return enc.WriteBytes(plaintext)
	})
	require.NoError(t, err)

	// Read: Simulate Entry.UnmarshalBinary logic
	readBytes, err := dec.ReadBytesCopy() // Use ReadBytesCopy to simulate real usage
	require.NoError(t, err)
	defer memory.SecureZero(readBytes) // Simulate cleanup in reader

	// Verify
	assert.Equal(t, []byte(secretData), readBytes)
}

func TestBytes_Limits(t *testing.T) {
	t.Parallel()

	// Craft a malicious payload indicating bytes larger than MaxSecureStringSize
	// ReadBytes shares the limit MaxSecureStringSize in tlv.go
	buf := make([]byte, 4)
	badLength := uint32(MaxSecureStringSize + 1)
	binary.BigEndian.PutUint32(buf, badLength)

	dec := NewDecoder(buf)
	_, err := dec.ReadBytes()
	require.Error(t, err)
	// UPDATE: Updated expectation to match the new error message in tlv.go
	assert.Contains(t, err.Error(), "bytes exceed maximum size")
}

func TestTime(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 1024)
	enc := NewEncoder(buf)
	dec := NewDecoder(buf)
	now := time.Now()

	require.NoError(t, enc.WriteTime(now))

	readTime, err := dec.ReadTime()
	require.NoError(t, err)

	// WriteTime truncates nanoseconds to seconds (Unix timestamp).
	assert.Equal(t, now.Unix(), readTime.Unix())
}

func TestEncoder_Limits(t *testing.T) {
	t.Parallel()

	t.Run("WriteString Limit", func(t *testing.T) {
		enc := NewEncoder(make([]byte, MaxStringSize+10))
		largeString := strings.Repeat("a", MaxStringSize+1)
		err := enc.WriteString(largeString)
		assert.ErrorIs(t, err, ErrStringTooLarge)
	})

	t.Run("WriteBytes Limit", func(t *testing.T) {
		enc := NewEncoder(make([]byte, MaxSecureStringSize+10))
		largeBytes := make([]byte, MaxSecureStringSize+1)
		err := enc.WriteBytes(largeBytes)
		assert.ErrorIs(t, err, ErrBytesTooLarge)
	})
}

func TestSecureString(t *testing.T) {
	t.Parallel()

	t.Run("Valid SecureString", func(t *testing.T) {
		buf := make([]byte, 1024)
		enc := NewEncoder(buf)
		dec := NewDecoder(buf)

		secret := "my-secret-password"
		ss, err := memory.NewSecureStringFromBytes([]byte(secret))
		require.NoError(t, err)
		defer ss.Destroy()

		err = enc.WriteSecureString(ss)
		require.NoError(t, err)

		decodedSS, err := dec.ReadSecureString()
		require.NoError(t, err)
		require.NotNil(t, decodedSS)
		defer decodedSS.Destroy()

		err = decodedSS.Access(func(plaintext []byte) error {
			assert.Equal(t, secret, string(plaintext))
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Nil SecureString", func(t *testing.T) {
		buf := make([]byte, 1024)
		enc := NewEncoder(buf)
		dec := NewDecoder(buf)

		err := enc.WriteSecureString(nil)
		require.NoError(t, err)

		decodedSS, err := dec.ReadSecureString()
		require.NoError(t, err)
		assert.Nil(t, decodedSS)
	})

	t.Run("Empty SecureString", func(t *testing.T) {
		buf := make([]byte, 1024)
		enc := NewEncoder(buf)
		dec := NewDecoder(buf)

		ss, err := memory.NewSecureStringFromBytes([]byte{})
		require.NoError(t, err)
		defer ss.Destroy()

		err = enc.WriteSecureString(ss)
		require.NoError(t, err)

		decodedSS, err := dec.ReadSecureString()
		require.NoError(t, err)
		assert.Nil(t, decodedSS)
	})

	t.Run("Oversized SecureString Limit", func(t *testing.T) {
		enc := NewEncoder(make([]byte, MaxSecureStringSize+10))
		largeBuf := make([]byte, MaxSecureStringSize+1)
		ss, err := memory.NewSecureStringFromBytes(largeBuf)
		if err == nil {
			defer ss.Destroy()
			err = enc.WriteSecureString(ss)
			assert.ErrorIs(t, err, ErrSecureStringTooLarge)
		}
	})
}

func TestEncoder_ShortBuffer(t *testing.T) {
	t.Parallel()

	t.Run("WriteTag", func(t *testing.T) {
		enc := NewEncoder(make([]byte, 0))
		err := enc.WriteTag(TagID)
		assert.ErrorIs(t, err, io.ErrShortBuffer)
	})

	t.Run("WriteLength", func(t *testing.T) {
		enc := NewEncoder(make([]byte, 3))
		err := enc.WriteLength(42)
		assert.ErrorIs(t, err, io.ErrShortBuffer)
	})

	t.Run("WriteString", func(t *testing.T) {
		enc := NewEncoder(make([]byte, 5))
		err := enc.WriteString("hello") // Needs 4 bytes length + 5 bytes data = 9 bytes
		assert.ErrorIs(t, err, io.ErrShortBuffer)
	})

	t.Run("WriteTime", func(t *testing.T) {
		enc := NewEncoder(make([]byte, 11)) // Needs 4 bytes length + 8 bytes data = 12 bytes
		err := enc.WriteTime(time.Now())
		assert.ErrorIs(t, err, io.ErrShortBuffer)
	})
}

func TestDecoder_UnexpectedEOF(t *testing.T) {
	t.Parallel()

	t.Run("ReadTag EOF", func(t *testing.T) {
		dec := NewDecoder(make([]byte, 0))
		_, err := dec.ReadTag()
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("ReadLength UnexpectedEOF", func(t *testing.T) {
		dec := NewDecoder(make([]byte, 3))
		_, err := dec.ReadLength()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ReadString UnexpectedEOF", func(t *testing.T) {
		// Put length 10, but buffer is only 4 + 5 = 9 bytes
		buf := make([]byte, 9)
		binary.BigEndian.PutUint32(buf, 10)
		dec := NewDecoder(buf)
		_, err := dec.ReadString()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ReadSecureString UnexpectedEOF", func(t *testing.T) {
		buf := make([]byte, 9)
		binary.BigEndian.PutUint32(buf, 10)
		dec := NewDecoder(buf)
		_, err := dec.ReadSecureString()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ReadTime UnexpectedEOF", func(t *testing.T) {
		buf := make([]byte, 9)
		binary.BigEndian.PutUint32(buf, 8)
		dec := NewDecoder(buf)
		_, err := dec.ReadTime()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ReadBytes UnexpectedEOF", func(t *testing.T) {
		buf := make([]byte, 9)
		binary.BigEndian.PutUint32(buf, 10)
		dec := NewDecoder(buf)
		_, err := dec.ReadBytes()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("ReadBytesCopy UnexpectedEOF", func(t *testing.T) {
		buf := make([]byte, 9)
		binary.BigEndian.PutUint32(buf, 10)
		dec := NewDecoder(buf)
		_, err := dec.ReadBytesCopy()
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})

	t.Run("Skip UnexpectedEOF", func(t *testing.T) {
		dec := NewDecoder(make([]byte, 5))
		err := dec.Skip(10)
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)

		// Success path skip
		err = dec.Skip(3)
		assert.NoError(t, err)
	})
}

func TestDecoder_AdditionalLimits(t *testing.T) {
	t.Parallel()

	t.Run("ReadSecureString Limit", func(t *testing.T) {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, MaxSecureStringSize+1)
		dec := NewDecoder(buf)
		_, err := dec.ReadSecureString()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "secure string exceeds maximum size")
	})
}
