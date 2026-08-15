//nolint:revive // Domain specific internal package name
package crypto

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fastTestArgon2Params returns minimal parameters for fast unit testing.
// DO NOT use these in production.
func fastTestArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      1024, // 1 MiB
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    SaltSize,
		KeySize:     KeySize,
	}
}

func TestGenerateSalt(t *testing.T) {
	t.Parallel()

	salt1, err := GenerateSalt()
	require.NoError(t, err)

	salt2, err := GenerateSalt()
	require.NoError(t, err)

	require.Len(t, salt1, SaltSize)
	assert.NotEqual(t, salt1, salt2, "Generated salts should be cryptographically unique")
}

func TestGenerateNonce(t *testing.T) {
	t.Parallel()

	nonce1, err := GenerateNonce()
	require.NoError(t, err)

	nonce2, err := GenerateNonce()
	require.NoError(t, err)

	require.Len(t, nonce1, NonceSize)
	assert.NotEqual(t, nonce1, nonce2, "Generated nonces should be cryptographically unique")
}

func TestDeriveKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	password := []byte("test-password")
	defer SecureZero(password) // SECURITY: Clean test password

	salt, err := GenerateSalt()
	require.NoError(t, err)

	params := fastTestArgon2Params()

	key, err := DeriveKey(ctx, password, salt, params)
	require.NoError(t, err)
	defer SecureZero(key) // SECURITY: Fulfill the caller contract
	require.Len(t, key, KeySize)

	// Same input should produce same key
	key2, err := DeriveKey(ctx, password, salt, params)
	require.NoError(t, err)
	defer SecureZero(key2)
	assert.Equal(t, key, key2, "Deterministic derivation failed: same input should produce same key")

	// Different password should produce different key
	diffPassword := []byte("different-password")
	defer SecureZero(diffPassword)

	key3, err := DeriveKey(ctx, diffPassword, salt, params)
	require.NoError(t, err)
	defer SecureZero(key3)
	assert.NotEqual(t, key, key3, "Different passwords should produce completely different keys")
}

func TestDeriveKey_ContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	password := []byte("test-password")
	defer SecureZero(password)

	salt, err := GenerateSalt()
	require.NoError(t, err)

	_, err = DeriveKey(ctx, password, salt, fastTestArgon2Params())
	require.ErrorIs(t, err, context.Canceled)
}

func TestEncryptDecryptAEADInPlace(t *testing.T) {
	t.Parallel()

	plaintext := []byte("Strict In-Place Zero-Allocation Encryption Test")
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte((i + 7) % 256) // Deterministic mock key
	}
	defer SecureZero(key)

	// Prepare buffer with exact required capacity
	gcmOverhead := 16 // Standard AES-GCM tag size
	buf := make([]byte, len(plaintext), len(plaintext)+gcmOverhead)
	copy(buf, plaintext)
	defer SecureZero(buf) // SECURITY: Wipe the unified encryption buffer at the end

	// Encrypt In-Place
	nonce, err := GenerateNonce()
	require.NoError(t, err)
	ciphertext, err := EncryptAEADInPlace(buf, nonce, key, nil)
	require.NoError(t, err)
	require.Len(t, nonce, NonceSize)
	require.Len(t, ciphertext, len(plaintext)+gcmOverhead)

	// Verify encryption modified the buffer safely without reallocating
	assert.NotEqual(t, plaintext, ciphertext[:len(plaintext)], "Ciphertext must not match plaintext")
	assert.Same(t, &buf[:cap(buf)][0], &ciphertext[:cap(ciphertext)][0], "Underlying array must not be reallocated")

	// Decrypt In-Place
	decrypted, err := DecryptAEADInPlace(ciphertext, nonce, key, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted, "Decrypted text must match original plaintext")

	// SECURITY CHECK: Verify that the leftover tail (the GCM tag area) was securely zeroed
	tail := ciphertext[len(decrypted):cap(ciphertext)]
	require.Len(t, tail, gcmOverhead)
	for i, b := range tail {
		assert.Equal(t, byte(0), b, "Security breach: Byte at index %d in the leftover buffer tail was not zeroed", i)
	}
}

func TestDecryptAEADInPlace_Corruption(t *testing.T) {
	t.Parallel()

	plaintext := []byte("Message to be corrupted")
	key := make([]byte, KeySize)
	defer SecureZero(key)

	buf := make([]byte, len(plaintext), len(plaintext)+16)
	copy(buf, plaintext)

	nonce, err := GenerateNonce()
	require.NoError(t, err)
	ciphertext, err := EncryptAEADInPlace(buf, nonce, key, nil)
	require.NoError(t, err)

	// Mutate 1 byte of the ciphertext to simulate an attack or disk corruption
	ciphertext[5] ^= 0xFF

	// Attempt Decryption
	decrypted, err := DecryptAEADInPlace(ciphertext, nonce, key, nil)
	require.Error(t, err, "Decryption of corrupted ciphertext must fail (GCM Authentication failure)")
	assert.Nil(t, decrypted)
}

func TestEncryptDecryptWithWrongKey(t *testing.T) {
	t.Parallel()

	plaintext := []byte("Top Secret Data")
	key1 := make([]byte, KeySize)
	key2 := make([]byte, KeySize)
	defer SecureZero(key1)
	defer SecureZero(key2)

	for i := range key1 {
		key1[i] = byte(i % 256)
		key2[i] = byte((i + 1) % 256)
	}

	buf := make([]byte, len(plaintext), len(plaintext)+16)
	copy(buf, plaintext)

	nonce, err := GenerateNonce()
	require.NoError(t, err)
	ciphertext, err := EncryptAEADInPlace(buf, nonce, key1, nil)
	require.NoError(t, err)

	_, err = DecryptAEADInPlace(ciphertext, nonce, key2, nil)
	require.Error(t, err, "Decryption with wrong key must fail")
}

func TestDeriveKeyWithKeyfile(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	password := []byte("test-password")
	defer SecureZero(password)

	keyfile := []byte("test-keyfile-content-32-bytes-minimum")
	defer SecureZero(keyfile)

	salt, err := GenerateSalt()
	require.NoError(t, err)

	params := fastTestArgon2Params()

	// Derive key with keyfile
	key1, err := DeriveKeyWithKeyfile(ctx, password, keyfile, salt, params)
	require.NoError(t, err)
	defer SecureZero(key1)

	// Derive key without keyfile
	key2, err := DeriveKey(ctx, password, salt, params)
	require.NoError(t, err)
	defer SecureZero(key2)

	assert.NotEqual(t, key1, key2, "Keys with and without keyfile must be completely different")

	// Same inputs should produce same key
	key3, err := DeriveKeyWithKeyfile(ctx, password, keyfile, salt, params)
	require.NoError(t, err)
	defer SecureZero(key3)
	assert.Equal(t, key1, key3, "Deterministic derivation failed")

	// Different keyfile
	diffKeyfile := []byte("different-keyfile-content-here")
	defer SecureZero(diffKeyfile)

	key4, err := DeriveKeyWithKeyfile(ctx, password, diffKeyfile, salt, params)
	require.NoError(t, err)
	defer SecureZero(key4)
	assert.NotEqual(t, key1, key4, "Different keyfiles must produce different keys")

	// Different password
	diffPassword := []byte("different-password")
	defer SecureZero(diffPassword)

	key5, err := DeriveKeyWithKeyfile(ctx, diffPassword, keyfile, salt, params)
	require.NoError(t, err)
	defer SecureZero(key5)
	assert.NotEqual(t, key1, key5, "Different passwords must produce different keys")
}

func TestSecureZero(t *testing.T) {
	t.Parallel()

	data := []byte("extremely sensitive data sitting in RAM")
	SecureZero(data)

	expected := make([]byte, len("extremely sensitive data sitting in RAM"))
	assert.Equal(t, expected, data, "Data must be completely zeroed")
}

func TestSecureCompare(t *testing.T) {
	t.Parallel()

	a := []byte("secret")
	b := []byte("secret")
	c := []byte("public")

	assert.True(t, SecureCompare(a, b), "Identical slices must match")
	assert.False(t, SecureCompare(a, c), "Different slices must not match")
}

func TestGenerateRandomBytes(t *testing.T) {
	t.Parallel()

	size := 32
	bytes1, err := GenerateRandomBytes(size)
	require.NoError(t, err)
	require.Len(t, bytes1, size)

	bytes2, err := GenerateRandomBytes(size)
	require.NoError(t, err)

	assert.NotEqual(t, bytes1, bytes2, "Generated random bytes must be unique")
}
