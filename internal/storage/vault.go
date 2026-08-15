// Package storage provides secure file system operations, atomic saves,
// and binary encoding/decoding for Hako vaults.
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/awnumar/memguard"

	"github.com/eraceo/Hako/internal/crypto"
	hakoBinary "github.com/eraceo/Hako/internal/encoding/tlv"
	"github.com/eraceo/Hako/internal/secrets"
)

const (
	// MagicBytes is the magic header for vault files (8 bytes).
	MagicBytes = "HAKOv001"
	// Version is the current vault file format version.
	Version = 1

	// MaxVaultSize limits the vault file size to prevent memory exhaustion (DoS)
	// and integer overflow on 32-bit systems. 64 MiB is enough for millions of entries.
	MaxVaultSize = 64 * 1024 * 1024

	// Argon2 Parameter Offsets (Relative to the start of the Params block)
	arg2OffMemory      = 0
	arg2OffIterations  = 4
	arg2OffParallelism = 8
	arg2OffSaltSize    = 9
	arg2OffKeySize     = 13

	// Argon2ParamsEncodedSize is the size of the encoded Argon2 parameters:
	// Memory (4) + Iterations (4) + Parallelism (1) + SaltSize (4) + KeySize (4)
	Argon2ParamsEncodedSize = 17

	// Header Offsets (Calculated dynamically to ensure consistency)
	offsetMagic   = 0
	offsetVersion = 8
	offsetSalt    = offsetVersion + 1                      // 9
	offsetParams  = offsetSalt + crypto.SaltSize           // 25
	offsetNonce   = offsetParams + Argon2ParamsEncodedSize // 42

	// HeaderSize is the fixed size of the vault header.
	// Calculation: Magic(8) + Version(1) + Salt(16) + Params(17) + Nonce(12) = 54 bytes.
	HeaderSize = offsetNonce + crypto.NonceSize

	// MinMemory is the minimum memory for Argon2 (1 MiB)
	MinMemory = 1024
	// MaxMemory is the maximum memory for Argon2 (64 MiB)
	MaxMemory = 64 * 1024
	// MinIterations is the minimum number of Argon2 iterations
	MinIterations = 1
	// MaxIterations is the maximum number of Argon2 iterations
	MaxIterations = 100
	// MinParallelism is the minimum Argon2 parallelism
	MinParallelism = 1
	// MaxParallelism is the maximum Argon2 parallelism
	MaxParallelism = 4
)

// magicBytesSlice is a pre-allocated byte slice of MagicBytes to avoid
// repeated []byte(MagicBytes) conversions that would allocate on the heap.
var magicBytesSlice = []byte(MagicBytes)

// Standardize Sentinel Errors to prevent heap-allocated dynamic errors
// and allow programmatic error matching using errors.Is().
var (
	ErrInvalidPath        = errors.New("invalid file path")
	ErrPathTraversal      = errors.New("path traversal detected")
	ErrNotRegularFile     = errors.New("not a regular file")
	ErrRaceCondition      = errors.New("file changed between check and open (possible race condition or symlink attack)")
	ErrInvalidVault       = errors.New("not a valid Hako vault")
	ErrInvalidFileSize    = errors.New("invalid file size or empty vault")
	ErrUnsupportedVersion = errors.New("unsupported vault version")
	ErrInvalidMagic       = errors.New("invalid vault file: wrong magic bytes")
	ErrInvalidParam       = errors.New("invalid cryptographic parameter")
	ErrVaultNotExist      = errors.New("vault file does not exist")
	ErrSymlinkBackup      = errors.New("refusing to backup symlink")
	ErrVaultTooLarge      = errors.New("vault file exceeds maximum supported size")
)

// VaultHeader represents the vault file header.
type VaultHeader struct {
	Magic        [8]byte
	Version      uint8
	Salt         [crypto.SaltSize]byte
	Argon2Params crypto.Argon2Params
	Nonce        [crypto.NonceSize]byte
}

// VaultFile handles encrypted vault file operations.
type VaultFile struct {
	path   string
	header VaultHeader
}

// NewVaultFile creates a new VaultFile instance with the specified path.
func NewVaultFile(path string) *VaultFile {
	return &VaultFile{
		path: filepath.Clean(path),
	}
}

// Header returns a copy of the vault file header.
func (vf *VaultFile) Header() VaultHeader {
	return vf.header
}

// validateFilePath strictly validates that a file path is safe to use.
// This prevents relative path traversal (../) and null bytes.
// It does NOT restrict absolute paths (e.g. /etc/passwd); the caller must ensure
// the root directory is safe via configuration validation.
func validateFilePath(path string) error {
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("%w: contains invalid null-byte characters", ErrInvalidPath)
	}

	cleanPath := filepath.Clean(path)

	// Block path traversal (e.g., starts with "../")
	if cleanPath == ".." || strings.HasPrefix(cleanPath, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s", ErrPathTraversal, path)
	}

	return nil
}

// verifyOverwriteSafety checks if it's safe to overwrite the target file.
// Security: Prevents TOCTOU and symlink attacks when saving an existing vault.
func (vf *VaultFile) verifyOverwriteSafety() error {
	info, err := os.Lstat(vf.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Safe to create new file
	}
	if err != nil {
		return fmt.Errorf("failed to stat target file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: refusing to overwrite (mode: %s)", ErrNotRegularFile, info.Mode())
	}

	// Double-check by opening the file to resolve race conditions
	file, err := os.Open(vf.path)
	if err != nil {
		return fmt.Errorf("failed to open target file for verification: %w", err)
	}
	defer func() { _ = file.Close() }()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat opened file: %w", err)
	}
	if !os.SameFile(info, fileInfo) {
		return ErrRaceCondition
	}

	// Verify it's actually a Hako vault before destroying it.
	// Use a stack-allocated array to avoid a heap allocation for a non-secret value.
	var magic [len(MagicBytes)]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return fmt.Errorf("%w: target file is too short or empty", ErrInvalidVault)
	}

	// Use bytes.Equal instead of string(magic) to avoid a heap allocation.
	if !bytes.Equal(magic[:], magicBytesSlice) {
		return fmt.Errorf("%w: refusing to overwrite non-Hako file", ErrInvalidVault)
	}

	return nil
}

// Exists checks if the vault file exists on disk.
func (vf *VaultFile) Exists() bool {
	_, err := os.Stat(vf.path)
	return err == nil
}

// Initialize creates a new vault file with the given parameters.
func (vf *VaultFile) Initialize(ctx context.Context, password, keyfile []byte, params crypto.Argon2Params) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := validateFilePath(vf.path); err != nil {
		return fmt.Errorf("invalid vault path: %w", err)
	}

	// Ensure directory is private (0700)
	if err := os.MkdirAll(filepath.Dir(vf.path), 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}
	// defer executes after Save() returns. vf.header.Salt is a value copy,
	// so the copy is already safe before Save() is called. This wipe closes the
	// window of vulnerability on the original heap-allocated slice from GenerateSalt.
	defer crypto.SecureZero(salt)

	copy(vf.header.Magic[:], MagicBytes)
	vf.header.Version = Version
	copy(vf.header.Salt[:], salt)
	vf.header.Argon2Params = params

	vault := secrets.NewVault()
	return vf.Save(ctx, vault, password, keyfile)
}

// Load loads, decrypts, and unmarshals the vault into memory.
func (vf *VaultFile) Load(ctx context.Context, password, keyfile []byte) (*secrets.Vault, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	file, err := os.Open(vf.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open vault file: %w", err)
	}
	defer func() { _ = file.Close() }()

	// These methods are expected to be in vault_unix.go / vault_windows.go
	if err = vf.CheckPermissions(file); err != nil {
		return nil, fmt.Errorf("security check failed: %w", err)
	}
	if err = vf.CheckDirectoryPermissions(); err != nil {
		return nil, fmt.Errorf("directory security check failed: %w", err)
	}

	if headerErr := vf.readHeader(file); headerErr != nil {
		return nil, fmt.Errorf("failed to read header: %w", headerErr)
	}

	fi, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	encryptedSize := fi.Size() - int64(HeaderSize)
	if encryptedSize <= 0 {
		return nil, ErrInvalidFileSize
	}
	if encryptedSize > MaxVaultSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrVaultTooLarge, encryptedSize)
	}

	// Security: Load the whole encrypted payload into ONE enclave before decrypting
	buf := memguard.NewBuffer(int(encryptedSize))
	defer buf.Destroy()

	if _, err = io.ReadFull(file, buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	return vf.decryptAndUnmarshal(ctx, buf, password, keyfile)
}

func (vf *VaultFile) decryptAndUnmarshal(
	ctx context.Context,
	buf *memguard.LockedBuffer,
	password, keyfile []byte,
) (*secrets.Vault, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	key, keyErr := crypto.DeriveMasterKey(ctx, password, keyfile, vf.header.Salt[:], vf.header.Argon2Params)
	if keyErr != nil {
		return nil, fmt.Errorf("failed to derive key: %w", keyErr)
	}
	defer crypto.SecureZero(key)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// DecryptAEADInPlace performs decryption inside the Memguard buffer.
	// plaintext is a slice referencing the locked buffer memory.
	aad := vf.buildAAD()
	plaintext, err := crypto.DecryptAEADInPlace(buf.Bytes(), vf.header.Nonce[:], key, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt vault: %w", err)
	}
	// Defensively zero the reference slice struct, although the backing array is managed by Memguard.
	defer crypto.SecureZero(plaintext)

	// Version check is already performed in readHeader.

	vault := &secrets.Vault{}
	// ZERO-ALLOCATION DECODER
	// This will parse the plaintext. The decoder ensures that sensitive fields (like Passwords)
	// are immediately encrypted into EphemeralSecrets (Heap) so they survive
	// when buf.Destroy() is called at the end of Load().
	decoder := hakoBinary.NewDecoder(plaintext)

	if err := vault.UnmarshalBinary(decoder); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
	}

	return vault, nil
}

// Save encrypts and atomically saves the vault to disk.
// If the vault file already exists, a backup is created BEFORE overwriting.
// This guarantees that a pre-existing vault is never lost due to disk full errors,
// power failures, or any other I/O interruption during the atomic rename.
func (vf *VaultFile) Save(ctx context.Context, vault *secrets.Vault, password, keyfile []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	vf.header.Version = Version

	// Key Derivation (Slow Operation)
	key, keyErr := crypto.DeriveMasterKey(ctx, password, keyfile, vf.header.Salt[:], vf.header.Argon2Params)
	if keyErr != nil {
		return fmt.Errorf("failed to derive key: %w", keyErr)
	}
	defer crypto.SecureZero(key)

	if err := ctx.Err(); err != nil {
		return err
	}

	// Serialization and Allocation
	vaultSize := vault.Size()
	const tagSize = 16
	totalSize := vaultSize + tagSize

	buf := memguard.NewBuffer(totalSize)
	defer buf.Destroy()

	encoder := hakoBinary.NewEncoder(buf.Bytes()[:vaultSize])
	if err := vault.MarshalBinary(encoder); err != nil {
		return fmt.Errorf("failed to serialize vault: %w", err)
	}

	// In-Place Encryption (Fast Operation)
	nonce, err := crypto.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	defer crypto.SecureZero(nonce)
	copy(vf.header.Nonce[:], nonce)

	aad := vf.buildAAD()
	ciphertext, err := crypto.EncryptAEADInPlace(buf.Bytes()[:vaultSize], nonce, key, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault: %w", err)
	}

	// Safety Checks
	if err := vf.verifyOverwriteSafety(); err != nil {
		return fmt.Errorf("overwrite safety check failed: %w", err)
	}

	// 4.5. Pre-Write Backup
	// SECURITY: If a vault already exists on disk, we MUST back it up before
	// overwriting. The atomic rename in step 5 protects against partial writes,
	// but not against post-rename disk full errors that could truncate the new file.
	// A backup is the only guarantee that the user's data survives any I/O failure.
	// A backup failure is treated as a fatal error: we refuse to overwrite without a safety net.
	if vf.Exists() {
		if err := vf.Backup(ctx); err != nil {
			return fmt.Errorf("pre-write backup failed, aborting save to protect existing vault: %w", err)
		}
	}

	// Atomic Write Pattern
	tempPath := vf.path + ".tmp"
	if err := vf.writeSafeTempFile(ctx, tempPath, ciphertext); err != nil {
		return fmt.Errorf("failed to write temp vault: %w", err)
	}

	// PLATFORM SPECIFIC: Atomic Rename (MoveFileEx on Windows, Rename on Unix)
	if err := vf.atomicRename(tempPath, vf.path); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to finalize vault write: %w", err)
	}

	return nil
}

// RotateMasterKey generates a new salt and re-encrypts the vault with the new credentials.
func (vf *VaultFile) RotateMasterKey(ctx context.Context, vault *secrets.Vault, newPassword, newKeyfile []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}
	defer crypto.SecureZero(salt)

	copy(vf.header.Salt[:], salt)
	return vf.Save(ctx, vault, newPassword, newKeyfile)
}

// UpdateKDFParams updates the Argon2id parameters, generates a fresh salt, and re-encrypts the vault.
// It preserves atomic safety by rolling back the in-memory header if saving to disk fails.
func (vf *VaultFile) UpdateKDFParams(ctx context.Context, vault *secrets.Vault, password, keyfile []byte, newParams crypto.Argon2Params) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}
	defer crypto.SecureZero(salt)

	oldSalt := vf.header.Salt
	oldParams := vf.header.Argon2Params

	copy(vf.header.Salt[:], salt)
	vf.header.Argon2Params = newParams

	if err := vf.Save(ctx, vault, password, keyfile); err != nil {
		// Atomic memory rollback on disk write error
		vf.header.Salt = oldSalt
		vf.header.Argon2Params = oldParams
		return err
	}
	return nil
}

// writeSafeTempFile writes the header and ciphertext to a temp file safely.
// It enforces 0600 permissions AT CREATION (Atomic) and uses O_EXCL to prevent races.
func (vf *VaultFile) writeSafeTempFile(ctx context.Context, path string, ciphertext []byte) error {
	if err := validateFilePath(path); err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Security: O_EXCL ensures we don't follow pre-existing symlinks.
	// Security: 0600 ensures the file is private from the moment it hits the disk.
	// #nosec G304 -- Path is validated and controlled by the application config
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		// If temp file exists (stale run), remove and retry ONCE.
		if removeErr := os.Remove(path); removeErr != nil {
			return fmt.Errorf("failed to clear stale temp file: %w", removeErr)
		}
		// Check context cancellation before the retry to avoid unnecessary work
		// if the operation has already been canceled between the Remove and the retry.
		if err := ctx.Err(); err != nil {
			return err
		}
		// #nosec G304 -- Path is validated and controlled by the application config
		file, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return fmt.Errorf("failed to create secure temp file: %w", err)
	}

	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(path)
		}
	}()

	// Write Header
	if err := vf.writeHeader(file); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write Ciphertext
	if _, err := file.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write encrypted data: %w", err)
	}

	// Sync to disk to ensure data integrity before rename
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file: %w", err)
	}

	// Double check permissions (Defense in depth)
	// Usually irrelevant if OpenFile worked, but good for compliance.
	if err := vf.RestrictPermissions(file); err != nil {
		return fmt.Errorf("failed to verify permissions: %w", err)
	}

	failed = false
	return nil
}

// buildAAD constructs the Additional Authenticated Data from the header.
func (vf *VaultFile) buildAAD() []byte {
	var headerBuf [offsetNonce]byte
	copy(headerBuf[offsetMagic:offsetVersion], vf.header.Magic[:])
	headerBuf[offsetVersion] = vf.header.Version
	copy(headerBuf[offsetSalt:offsetParams], vf.header.Salt[:])

	pBase := offsetParams
	binary.LittleEndian.PutUint32(headerBuf[pBase+arg2OffMemory:pBase+arg2OffIterations], vf.header.Argon2Params.Memory)
	binary.LittleEndian.PutUint32(
		headerBuf[pBase+arg2OffIterations:pBase+arg2OffParallelism],
		vf.header.Argon2Params.Iterations,
	)
	headerBuf[pBase+arg2OffParallelism] = vf.header.Argon2Params.Parallelism
	binary.LittleEndian.PutUint32(headerBuf[pBase+arg2OffSaltSize:pBase+arg2OffKeySize], vf.header.Argon2Params.SaltSize)
	binary.LittleEndian.PutUint32(
		headerBuf[pBase+arg2OffKeySize:pBase+Argon2ParamsEncodedSize],
		vf.header.Argon2Params.KeySize,
	)

	return headerBuf[:]
}

// readHeader reads and validates the vault file header securely.
func (vf *VaultFile) readHeader(file *os.File) error {
	var headerBuf [HeaderSize]byte
	if _, err := io.ReadFull(file, headerBuf[:]); err != nil {
		return fmt.Errorf("failed to read vault header: %w", err)
	}

	// Magic
	// Use bytes.Equal instead of string() conversion to avoid a heap allocation.
	if !bytes.Equal(headerBuf[offsetMagic:offsetVersion], magicBytesSlice) {
		return ErrInvalidMagic
	}
	copy(vf.header.Magic[:], headerBuf[offsetMagic:offsetVersion])

	// Version
	vf.header.Version = headerBuf[offsetVersion]
	if vf.header.Version == 0 || vf.header.Version > Version {
		return fmt.Errorf("%w: %d (current: %d)", ErrUnsupportedVersion, vf.header.Version, Version)
	}
	// Salt
	copy(vf.header.Salt[:], headerBuf[offsetSalt:offsetParams])

	// Argon2 Params
	// Calculate absolute offsets based on start of params block
	pBase := offsetParams
	vf.header.Argon2Params.Memory = binary.LittleEndian.Uint32(headerBuf[pBase+arg2OffMemory : pBase+arg2OffIterations])
	vf.header.Argon2Params.Iterations = binary.LittleEndian.Uint32(
		headerBuf[pBase+arg2OffIterations : pBase+arg2OffParallelism],
	)
	vf.header.Argon2Params.Parallelism = headerBuf[pBase+arg2OffParallelism]
	vf.header.Argon2Params.SaltSize = binary.LittleEndian.Uint32(headerBuf[pBase+arg2OffSaltSize : pBase+arg2OffKeySize])
	vf.header.Argon2Params.KeySize = binary.LittleEndian.Uint32(
		headerBuf[pBase+arg2OffKeySize : pBase+Argon2ParamsEncodedSize],
	)

	// Strict Parameter Validation
	if vf.header.Argon2Params.Memory < MinMemory || vf.header.Argon2Params.Memory > MaxMemory {
		return fmt.Errorf("%w: memory %d", ErrInvalidParam, vf.header.Argon2Params.Memory)
	}
	if vf.header.Argon2Params.Iterations < MinIterations || vf.header.Argon2Params.Iterations > MaxIterations {
		return fmt.Errorf("%w: iterations %d", ErrInvalidParam, vf.header.Argon2Params.Iterations)
	}
	if vf.header.Argon2Params.Parallelism < MinParallelism || vf.header.Argon2Params.Parallelism > MaxParallelism {
		return fmt.Errorf("%w: parallelism %d", ErrInvalidParam, vf.header.Argon2Params.Parallelism)
	}
	// Validate SaltSize and KeySize against the expected constants.
	// An attacker supplying a forged vault header could trigger an OOM crash or
	// force Argon2 to derive an incorrectly-sized key, bypassing authentication.
	if vf.header.Argon2Params.SaltSize != crypto.SaltSize {
		return fmt.Errorf("%w: salt size %d", ErrInvalidParam, vf.header.Argon2Params.SaltSize)
	}
	if vf.header.Argon2Params.KeySize != crypto.KeySize {
		return fmt.Errorf("%w: key size %d", ErrInvalidParam, vf.header.Argon2Params.KeySize)
	}

	// Nonce
	copy(vf.header.Nonce[:], headerBuf[offsetNonce:offsetNonce+crypto.NonceSize])

	return nil
}

// writeHeader writes the vault file header securely.
func (vf *VaultFile) writeHeader(file *os.File) error {
	var headerBuf [HeaderSize]byte

	copy(headerBuf[offsetMagic:offsetVersion], vf.header.Magic[:])
	headerBuf[offsetVersion] = vf.header.Version
	copy(headerBuf[offsetSalt:offsetParams], vf.header.Salt[:])

	pBase := offsetParams
	binary.LittleEndian.PutUint32(headerBuf[pBase+arg2OffMemory:pBase+arg2OffIterations], vf.header.Argon2Params.Memory)
	binary.LittleEndian.PutUint32(
		headerBuf[pBase+arg2OffIterations:pBase+arg2OffParallelism],
		vf.header.Argon2Params.Iterations,
	)
	headerBuf[pBase+arg2OffParallelism] = vf.header.Argon2Params.Parallelism
	binary.LittleEndian.PutUint32(headerBuf[pBase+arg2OffSaltSize:pBase+arg2OffKeySize], vf.header.Argon2Params.SaltSize)
	binary.LittleEndian.PutUint32(
		headerBuf[pBase+arg2OffKeySize:pBase+Argon2ParamsEncodedSize],
		vf.header.Argon2Params.KeySize,
	)

	copy(headerBuf[offsetNonce:offsetNonce+crypto.NonceSize], vf.header.Nonce[:])

	if _, err := file.Write(headerBuf[:]); err != nil {
		return fmt.Errorf("failed to write vault header: %w", err)
	}
	return nil
}

// Backup creates a backup of the vault file atomically.
func (vf *VaultFile) Backup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if !vf.Exists() {
		return ErrVaultNotExist
	}

	backupPath := vf.path + ".backup"
	tempBackupPath := backupPath + ".tmp"

	if err := validateFilePath(backupPath); err != nil {
		return fmt.Errorf("invalid backup path: %w", err)
	}

	src, err := vf.openAndVerifySourceForBackup()
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	// Reusing the robust write logic for backup copy
	if err := vf.writeSafeBackupCopy(src, tempBackupPath); err != nil {
		return err
	}

	// PLATFORM SPECIFIC: Atomic Rename for backup
	if err := vf.atomicRename(tempBackupPath, backupPath); err != nil {
		_ = os.Remove(tempBackupPath)
		return fmt.Errorf("failed to finalize backup: %w", err)
	}

	return nil
}

// openAndVerifySourceForBackup performs TOCTOU and Symlink verification on the source vault.
func (vf *VaultFile) openAndVerifySourceForBackup() (*os.File, error) {
	fi, err := os.Lstat(vf.path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat source file: %w", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkBackup, vf.path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s", ErrNotRegularFile, vf.path)
	}

	src, err := os.Open(vf.path)
	if err != nil {
		return nil, fmt.Errorf("failed to open source file: %w", err)
	}

	srcInfo, err := src.Stat()
	if err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("failed to stat opened source file: %w", err)
	}
	if !os.SameFile(fi, srcInfo) {
		_ = src.Close()
		return nil, fmt.Errorf("source file changed: %w", ErrRaceCondition)
	}

	// Use a stack-allocated array and bytes.Equal to avoid heap allocations
	// on a non-secret, but frequently-read value.
	var magic [len(MagicBytes)]byte
	if _, err = io.ReadFull(src, magic[:]); err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("failed to read magic bytes from source: %w", err)
	}
	if !bytes.Equal(magic[:], magicBytesSlice) {
		_ = src.Close()
		return nil, fmt.Errorf("source validation: %w", ErrInvalidVault)
	}

	if _, err = src.Seek(0, 0); err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("failed to seek to beginning of source file: %w", err)
	}

	return src, nil
}

// writeSafeBackupCopy securely copies src to tempPath using O_EXCL and 0600.
func (vf *VaultFile) writeSafeBackupCopy(src *os.File, tempPath string) error {
	// Explicitly validate tempPath, removing the need for #nosec annotations.
	if err := validateFilePath(tempPath); err != nil {
		return fmt.Errorf("invalid temp backup path: %w", err)
	}

	// Security: Create with 0600 immediately.
	// #nosec G304 -- Path is validated and controlled by the application config
	dst, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			return fmt.Errorf("failed to remove existing temp backup: %w", removeErr)
		}
		// #nosec G304 -- Path is validated and controlled by the application config
		dst, err = os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	}
	if err != nil {
		return fmt.Errorf("failed to create temp backup file: %w", err)
	}

	failed := true
	defer func() {
		_ = dst.Close()
		if failed {
			_ = os.Remove(tempPath)
		}
	}()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	if err := dst.Sync(); err != nil {
		return fmt.Errorf("failed to sync backup: %w", err)
	}

	failed = false
	return nil
}
