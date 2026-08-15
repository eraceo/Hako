package storage

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
)

const osWindows = "windows"

// fastTestArgon2Params returns minimal parameters for fast unit testing.
func fastTestArgon2Params() crypto.Argon2Params {
	return crypto.Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    crypto.SaltSize,
		KeySize:     crypto.KeySize,
	}
}

// prepareSecureTempDir generates a temporary directory and enforces strict 0700 permissions
// on Unix systems to satisfy Hako's aggressive directory security checks.
func prepareSecureTempDir(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	if runtime.GOOS != osWindows {
		// #nosec G302 -- Directories require execution permission (0700) to be traversed
		require.NoError(t, os.Chmod(tmpDir, 0700), "failed to secure test directory")
	}
	return tmpDir
}

func TestVaultFile_Initialize(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)

	params := fastTestArgon2Params()

	// Initialize with NO keyfile (nil)
	err := vf.Initialize(context.Background(), password, nil, params)
	require.NoError(t, err)

	assert.True(t, vf.Exists())
	// Use public getter or check file content directly if fields are private
	// Since vault.go exports VaultHeader and its fields, direct access is fine for white-box testing
	assert.Equal(t, uint8(Version), vf.header.Version)
	assert.Equal(t, string(MagicBytes), string(vf.header.Magic[:]))
}

func TestVaultFile_SaveLoad(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)

	params := fastTestArgon2Params()

	// Initialize
	err := vf.Initialize(context.Background(), password, nil, params)
	require.NoError(t, err)

	// Create some data
	vault := secrets.NewVault()
	entryPass := []byte("entrypass123")

	// NewEntry consumes the slice, so we must not use entryPass afterwards or assume it has data
	// But defer Zero() on entryPass is redundant because NewEntry zeroes it.
	// However, for test robustness, we can create a copy if needed.
	// Here NewEntry takes ownership.
	entry, err := secrets.NewEntry(
		"Test Entry",
		[]byte("user"),
		entryPass,
		[]byte("http://example.com"),
		[]byte("notes"),
		[]string{"tag"},
	)
	require.NoError(t, err)
	// Entry must be zeroed when done
	defer entry.Zero()

	vault.AddEntry(entry)

	// Save
	err = vf.Save(context.Background(), vault, password, nil)
	require.NoError(t, err)

	// Load
	loadedVault, err := vf.Load(context.Background(), password, nil)
	require.NoError(t, err)

	defer func() {
		if loadedVault != nil {
			for _, e := range loadedVault.Entries {
				e.Zero()
			}
		}
	}()

	require.NotNil(t, loadedVault)
	assert.Len(t, loadedVault.Entries, 1)
	assert.Equal(t, "Test Entry", loadedVault.Entries[0].Name)

	// Load with wrong password
	wrongPass := []byte("wrongpass")
	defer memory.SecureZero(wrongPass)
	_, err = vf.Load(context.Background(), wrongPass, nil)
	assert.Error(t, err)
}

func TestVaultFile_Keyfile(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault_keyfile.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)

	keyfile := []byte("keyfile_content")
	defer memory.SecureZero(keyfile)

	params := fastTestArgon2Params()

	// Initialize WITH keyfile
	err := vf.Initialize(context.Background(), password, keyfile, params)
	require.NoError(t, err)

	// Load WITH keyfile
	loadedVault, err := vf.Load(context.Background(), password, keyfile)
	require.NoError(t, err)
	require.NotNil(t, loadedVault)

	defer func() {
		for _, e := range loadedVault.Entries {
			e.Zero()
		}
	}()

	// Load WITHOUT keyfile (should fail)
	_, err = vf.Load(context.Background(), password, nil)
	assert.Error(t, err)

	// Load with WRONG keyfile
	wrongKeyfile := []byte("wrong_keyfile")
	defer memory.SecureZero(wrongKeyfile)
	_, err = vf.Load(context.Background(), password, wrongKeyfile)
	assert.Error(t, err)
}

func TestVaultFile_Backup(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)
	params := fastTestArgon2Params()

	err := vf.Initialize(context.Background(), password, nil, params)
	require.NoError(t, err)

	err = vf.Backup(context.Background())
	require.NoError(t, err)

	backupPath := vaultPath + ".backup"
	assert.FileExists(t, backupPath)

	// Verify backup content is identical
	origContent, err := os.ReadFile(vaultPath) //nolint:gosec
	require.NoError(t, err)
	backupContent, err := os.ReadFile(backupPath) //nolint:gosec
	require.NoError(t, err)
	assert.Equal(t, origContent, backupContent)
}

func TestValidateFilePath(t *testing.T) {
	absPath := "/absolute/path"
	if runtime.GOOS == osWindows {
		absPath = `C:\absolute\path`
	}

	tests := []struct {
		name        string
		path        string
		wantErr     bool
		expectedErr error
	}{
		{"SafePath", "safe/path", false, nil},
		{"AbsolutePath", absPath, false, nil},
		{"PathTraversal", "../traversal", true, ErrPathTraversal},
		{"DeepPathTraversal", "safe/../../traversal", true, ErrPathTraversal},
		{"NullByteInjection", "path/with\x00null", true, ErrInvalidPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				if tt.expectedErr != nil {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVaultFile_DoSProtection(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault_dos.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)
	params := fastTestArgon2Params()

	// Create valid vault
	err := vf.Initialize(context.Background(), password, nil, params)
	require.NoError(t, err)

	// Corrupt Memory Parameter in Header
	content, err := os.ReadFile(vaultPath) //nolint:gosec
	require.NoError(t, err)

	// Magic(8) + Version(1) + Salt(16) = 25 bytes offset
	// Memory is uint32 (4 bytes) at offset 25
	require.Greater(t, len(content), 30)

	// Set Memory to 0x00100000 (1 MiB in LittleEndian is 00 00 10 00, wait... 1GB is huge)
	// MaxMemory is 64*1024 = 65536 = 0x00010000
	// Let's set it to 0x00100000 (1048576 = 1GB)
	// Little Endian: 00 00 10 00
	// Wait, 0x00100000 = 1,048,576
	// 0x00010000 = 65,536 (Max)
	// So 0x00020000 = 131,072 (Double max)
	// Byte sequence for 0x00020000 LE: 00 00 02 00
	offset := 25
	content[offset] = 0x00
	content[offset+1] = 0x00
	content[offset+2] = 0x02 // 0x020000 = 131072 > 65536
	content[offset+3] = 0x00

	err = os.WriteFile(vaultPath, content, 0600)
	require.NoError(t, err)

	// Attempt Load -> Expect ErrInvalidParam
	_, err = vf.Load(context.Background(), password, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidParam)
}

func TestVaultFile_OverwriteProtection(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "valid_vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)
	params := fastTestArgon2Params()
	vault := secrets.NewVault()

	// Initialize Valid Vault
	err := vf.Initialize(context.Background(), password, nil, params)
	require.NoError(t, err)

	// Test Overwrite with Non-Vault File
	targetPath := filepath.Join(tmpDir, "config.txt")
	err = os.WriteFile(targetPath, []byte("not a vault"), 0600)
	require.NoError(t, err)

	vfBad := NewVaultFile(targetPath)
	vfBad.header.Argon2Params = params

	// Should fail because it detects a file exists but isn't a Hako vault
	err = vfBad.Save(context.Background(), vault, password, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVault)
}

func TestVaultFile_AtomicReplacement(t *testing.T) {
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "atomic_vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)
	params := fastTestArgon2Params()

	// Create Initial Vault (Version 1)
	vault1 := secrets.NewVault()
	entry1, err := secrets.NewEntry("Entry1", []byte("user"), []byte("longpassword1"), []byte{}, []byte{}, nil)
	require.NoError(t, err, "Failed to create entry 1")
	vault1.AddEntry(entry1)

	err = vf.Initialize(context.Background(), password, nil, params)
	require.NoError(t, err)
	err = vf.Save(context.Background(), vault1, password, nil)
	require.NoError(t, err)

	// Create Second Vault Content (Version 2)
	vault2 := secrets.NewVault()
	entry2, err := secrets.NewEntry("Entry2", []byte("user"), []byte("longpassword2"), []byte{}, []byte{}, nil)
	require.NoError(t, err, "Failed to create entry 2")
	vault2.AddEntry(entry2)

	// Perform Save (Atomic Overwrite)
	err = vf.Save(context.Background(), vault2, password, nil)
	require.NoError(t, err, "Save should atomically overwrite existing vault")

	// Verify Content matches Version 2
	loadedVault, err := vf.Load(context.Background(), password, nil)
	require.NoError(t, err)
	require.Len(t, loadedVault.Entries, 1, "Loaded vault should contain exactly 1 entry")
	assert.Equal(t, "Entry2", loadedVault.Entries[0].Name)
}

func TestVaultFile_Save_CreatesBackupBeforeOverwrite(t *testing.T) {
	// Verifies that Save() automatically creates a .backup file when overwriting
	// an existing vault, and that the backup contains the PRE-SAVE state.
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)
	params := fastTestArgon2Params()

	// Initialize and save vault with Entry V1
	require.NoError(t, vf.Initialize(context.Background(), password, nil, params))

	vaultV1, err := vf.Load(context.Background(), password, nil)
	require.NoError(t, err)
	defer vaultV1.Zero()

	entryV1Pass := []byte("passwordV100")
	defer memory.SecureZero(entryV1Pass)
	entryV1, err := secrets.NewEntry("EntryV1", []byte("user"), entryV1Pass, nil, nil, nil)
	require.NoError(t, err)
	vaultV1.AddEntry(entryV1)
	require.NoError(t, vf.Save(context.Background(), vaultV1, password, nil))

	// Capture the raw bytes of the V1 vault (this is what the backup should contain)
	originalBytes, err := os.ReadFile(vaultPath) // #nosec G304
	require.NoError(t, err)

	// Save again with Entry V2 — this MUST trigger an automatic backup
	vaultV2, err := vf.Load(context.Background(), password, nil)
	require.NoError(t, err)
	defer vaultV2.Zero()

	entryV2Pass := []byte("passwordV200")
	defer memory.SecureZero(entryV2Pass)
	entryV2, err := secrets.NewEntry("EntryV2", []byte("user"), entryV2Pass, nil, nil, nil)
	require.NoError(t, err)
	vaultV2.AddEntry(entryV2)
	require.NoError(t, vf.Save(context.Background(), vaultV2, password, nil))

	// backup file exists
	backupPath := vaultPath + ".backup"
	assert.FileExists(t, backupPath, "Backup file must be created automatically before overwrite")

	// backup contains the PRE-SAVE (V1) state, not V2
	backupBytes, err := os.ReadFile(backupPath) // #nosec G304
	require.NoError(t, err)
	assert.Equal(t, originalBytes, backupBytes,
		"Backup must contain the vault state BEFORE the second Save(), not after")

	// the live vault is correctly updated (contains V2 data)
	loadedVault, err := vf.Load(context.Background(), password, nil)
	require.NoError(t, err)
	defer loadedVault.Zero()
	require.Len(t, loadedVault.Entries, 2, "Live vault should contain both V1 and V2 entries")
}

func TestVaultFile_Save_NoBackupOnInitialize(t *testing.T) {
	// Verifies that Initialize() (which internally calls Save() on a non-existent file)
	// does NOT create a spurious .backup file.
	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault_new.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)

	require.NoError(t, vf.Initialize(context.Background(), password, nil, fastTestArgon2Params()))

	backupPath := vaultPath + ".backup"
	assert.NoFileExists(t, backupPath,
		"No backup file should be created when initializing a new vault")
}

func TestVaultFile_Save_BackupFailureAbortsSave(t *testing.T) {
	// Verifies that if the backup directory becomes read-only (simulating a disk full
	// or permission error), Save() returns an error and does NOT overwrite the vault.
	if runtime.GOOS == osWindows {
		t.Skip("Directory permission manipulation is not reliable on Windows")
	}

	tmpDir := prepareSecureTempDir(t)
	vaultPath := filepath.Join(tmpDir, "vault.bin")
	vf := NewVaultFile(vaultPath)

	password := []byte("password123")
	defer memory.SecureZero(password)
	params := fastTestArgon2Params()

	// Create a valid initial vault
	require.NoError(t, vf.Initialize(context.Background(), password, nil, params))
	originalBytes, err := os.ReadFile(vaultPath) // #nosec G304
	require.NoError(t, err)

	// Make the directory read-only to force the backup to fail
	// #nosec G302 -- Intentionally restrictive for this test scenario
	require.NoError(t, os.Chmod(tmpDir, 0500))
	// Restore permissions so t.TempDir() cleanup can delete the directory
	t.Cleanup(func() {
		// #nosec G302 -- Tests specifically demand 0700 to pass internal security audits
		_ = os.Chmod(tmpDir, 0700)
	})

	// Attempt a Save — the backup step should fail
	vault2 := secrets.NewVault()
	err = vf.Save(context.Background(), vault2, password, nil)
	require.Error(t, err, "Save must fail if the pre-write backup cannot be created")
	assert.Contains(t, err.Error(), "pre-write backup failed")

	// Restore permissions and verify the live vault is UNCHANGED
	// #nosec G302 -- Tests specifically demand 0700 to pass internal security audits
	require.NoError(t, os.Chmod(tmpDir, 0700))
	currentBytes, err := os.ReadFile(vaultPath) // #nosec G304
	require.NoError(t, err)
	assert.Equal(t, originalBytes, currentBytes,
		"The live vault must be untouched when the backup step fails")
}
