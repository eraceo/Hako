// Package crypto provides cryptographic primitives, key derivation, and zero-allocation AES-GCM encryption.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// SaltSize is the size of the salt used for key derivation (128 bits).
	SaltSize = 16
	// NonceSize is the size of the nonce used for GCM encryption (96 bits).
	NonceSize = 12
	// KeySize is the size of the derived encryption key (256 bits).
	KeySize = 32

	// KeyfileDerivationInfo is the HKDF info string for keyfile derivation.
	KeyfileDerivationInfo = "hako-keyfile-v1"
	// PasswordDerivationInfo is the HKDF info string for password derivation.
	PasswordDerivationInfo = "hako-password-v1"
	// CombinedKeyInfo is the HKDF info string for combining multiple keys.
	CombinedKeyInfo = "hako-combined-v1"
)

var (
	// ErrInvalidKeySize indicates the provided encryption key has an incorrect length.
	ErrInvalidKeySize = errors.New("invalid key size")
	// ErrInvalidNonceSize indicates the provided AES-GCM nonce has an incorrect length.
	ErrInvalidNonceSize = errors.New("invalid nonce size")
	// ErrBufferTooSmall indicates the destination buffer cannot hold the ciphertext and MAC tag.
	ErrBufferTooSmall = errors.New("buffer capacity too small")
)

// Argon2Params contains parameters for Argon2id key derivation.
type Argon2Params struct {
	Memory      uint32 // Memory in KiB
	Iterations  uint32 // Number of iterations
	Parallelism uint8  // Degree of parallelism
	SaltSize    uint32 // Salt size in bytes
	KeySize     uint32 // Derived key size in bytes
}

// DefaultArgon2Params returns secure default parameters for Argon2id (OWASP Recommended).
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      65536, // 64 MiB
		Iterations:  4,
		Parallelism: 4,
		SaltSize:    SaltSize,
		KeySize:     KeySize,
	}
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// GenerateNonce generates a cryptographically secure random nonce for AES-GCM.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// DeriveKey derives a key strictly from a password and salt using Argon2id.
// It uses HKDF to create a domain-separated salt from the master salt.
func DeriveKey(ctx context.Context, password, masterSalt []byte, params Argon2Params) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Domain Separation: Derive a specific salt for password hashing.
	// RFC 5869 Compliance:
	// - Secret (IKM): nil.
	// Passing nil is valid per RFC 5869 §2.2. It defaults to a string of zeros.
	//   Here, the entropy comes strictly from the 'salt' parameter (masterSalt), which is random.
	// - Salt: masterSalt (public, random entropy source).
	// - Info: Domain specific string.
	hkdfReader := hkdf.New(sha256.New, nil, masterSalt, []byte(PasswordDerivationInfo))

	derivedSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(hkdfReader, derivedSalt); err != nil {
		return nil, fmt.Errorf("failed to derive password salt: %w", err)
	}

	// x/crypto/argon2 inherently allocates the output slice on the heap.
	// The caller is strictly responsible for calling defer SecureZero() on the returned key.
	key := argon2.IDKey(
		password,
		derivedSalt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeySize,
	)

	// Clean up the intermediate derived salt immediately
	SecureZero(derivedSalt)

	return key, nil
}

// DeriveMasterKey is the unified entry point for key derivation.
// It routes to DeriveKeyWithKeyfile if a keyfile is provided, or DeriveKey otherwise.
func DeriveMasterKey(ctx context.Context, password, keyfile, masterSalt []byte, params Argon2Params) ([]byte, error) {
	if len(keyfile) > 0 {
		return DeriveKeyWithKeyfile(ctx, password, keyfile, masterSalt, params)
	}
	return DeriveKey(ctx, password, masterSalt, params)
}

// DeriveKeyWithKeyfile derives a master key from both a password and a keyfile.
//
// Security Note: This function performs two parallel Argon2id derivations.
// While parallelized, resource contention (CPU/Memory) makes this path slower than
// a single derivation on most systems. Use DeriveMasterKey to hide this difference.
func DeriveKeyWithKeyfile(
	ctx context.Context,
	password, keyfile, masterSalt []byte,
	params Argon2Params,
) ([]byte, error) {
	var passwordKey, keyfileKey []byte
	var errPass, errFile error
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		passwordKey, errPass = DeriveKey(ctx, password, masterSalt, params)
	}()
	go func() {
		defer wg.Done()
		keyfileKey, errFile = deriveKeyfileKey(ctx, keyfile, masterSalt, params)
	}()
	wg.Wait()

	// Safety net: ensure wipe on panic or error
	defer func() {
		SecureZero(passwordKey)
		SecureZero(keyfileKey)
	}()

	if errPass != nil {
		return nil, fmt.Errorf("derive password key: %w", errPass)
	}
	if errFile != nil {
		return nil, fmt.Errorf("derive keyfile key: %w", errFile)
	}

	finalKey, err := combineKeys(passwordKey, keyfileKey, masterSalt)

	// Optimization: Immediate wipe to minimize memory window exposure.
	// The deferred calls will run later, but wiping zeros with zeros is idempotent and safe.
	SecureZero(passwordKey)
	SecureZero(keyfileKey)

	return finalKey, err
}

func deriveKeyfileKey(ctx context.Context, keyfile, masterSalt []byte, params Argon2Params) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Domain Separation for Keyfile
	// Secret=nil, Salt=masterSalt (See DeriveKey comments)
	hkdfReader := hkdf.New(sha256.New, nil, masterSalt, []byte(KeyfileDerivationInfo))

	derivedSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(hkdfReader, derivedSalt); err != nil {
		return nil, fmt.Errorf("failed to derive keyfile salt: %w", err)
	}

	key := argon2.IDKey(
		keyfile,
		derivedSalt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeySize,
	)

	SecureZero(derivedSalt)
	return key, nil
}

// combineKeys securely merges two independent key materials using HKDF.
func combineKeys(passwordKey, keyfileKey, masterSalt []byte) ([]byte, error) {
	// Concatenate keys to form the Input Keying Material (IKM).
	// Canonical Order: PasswordKey || KeyfileKey
	// This order MUST remain fixed for future compatibility (v1 format).
	ikm := make([]byte, len(passwordKey)+len(keyfileKey))
	// Ensure IKM is wiped even if HKDF fails
	defer SecureZero(ikm)

	copy(ikm[:len(passwordKey)], passwordKey)
	copy(ikm[len(passwordKey):], keyfileKey)

	// Use HKDF-Expand to mix them securely.
	// Secret (IKM): The concatenated keys.
	// Salt: The master vault salt.
	// Info: Domain separation string.
	hkdfReader := hkdf.New(sha256.New, ikm, masterSalt, []byte(CombinedKeyInfo))
	finalKey := make([]byte, KeySize)

	if _, err := io.ReadFull(hkdfReader, finalKey); err != nil {
		SecureZero(finalKey)
		return nil, fmt.Errorf("HKDF failed during key combination: %w", err)
	}

	return finalKey, nil
}

// EncryptAEADInPlace encrypts data in-place using AES-256-GCM.
// The plaintextBuf MUST have a capacity of at least len(plaintextBuf) + 16 (Overhead).
// Returns the slice containing the ciphertext + tag.
//
// This function requires the nonce to be provided.
func EncryptAEADInPlace(plaintextBuf, nonce, key, aad []byte) (ciphertext []byte, err error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Strict capacity check to prevent runtime allocation of the destination
	requiredCap := len(plaintextBuf) + gcm.Overhead()
	if cap(plaintextBuf) < requiredCap {
		return nil, fmt.Errorf("%w: cap %d < required %d", ErrBufferTooSmall, cap(plaintextBuf), requiredCap)
	}

	// Encrypt in-place.
	// We pass plaintextBuf[:0] as dst to overwrite the buffer from the start.
	// We pass plaintextBuf as src.
	// Go's crypto/cipher explicitly supports this for "Same backing array".
	ciphertext = gcm.Seal(plaintextBuf[:0], nonce, plaintextBuf, aad)

	return ciphertext, nil
}

// DecryptAEADInPlace decrypts ciphertext using AES-256-GCM, reusing the input buffer.
// The input ciphertext buffer is overwritten with the plaintext.
// WARNING: On error, the buffer content is destroyed/undefined and must be discarded.
func DecryptAEADInPlace(ciphertextBuf, nonce, key, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, KeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidNonceSize, gcm.NonceSize(), len(nonce))
	}

	// Decrypt in-place.
	// This works safely because we are shrinking the buffer (removing the Tag).
	plaintext, err := gcm.Open(ciphertextBuf[:0], nonce, ciphertextBuf, aad)
	if err != nil {
		// Defensive wipe of the entire input buffer to ensure no artifacts remain
		SecureZero(ciphertextBuf)
		return nil, fmt.Errorf("failed to decrypt or authenticate vault: %w", err)
	}

	// Wipe the tail (where the MAC tag used to be).
	// Wipe the MAC tag residue (last 16 bytes).
	// We use slicing to the end of the buffer (implied len) to avoid accessing capacity.
	if len(plaintext) < len(ciphertextBuf) {
		SecureZero(ciphertextBuf[len(plaintext):])
	}

	return plaintext, nil
}

// SecureZero securely zeros a byte slice.
func SecureZero(data []byte) {
	memguard.WipeBytes(data)
}

// SecureCompare performs constant-time comparison.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func GenerateRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}
