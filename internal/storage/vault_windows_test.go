//go:build windows

package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsPermissions(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	vaultPath := filepath.Join(tmpDir, "windows_perm_test.vault")
	vf := NewVaultFile(vaultPath)

	// Create file using standard Go OpenFile (matches vault.go logic)
	// We use O_RDWR | O_CREATE | O_EXCL to simulate exactly how Hako creates the temp file.
	// Go's os.OpenFile on Windows maps to CreateFile with GENERIC_READ|GENERIC_WRITE,
	// which implicitly grants WRITE_DAC (permission to change permissions) to the owner.
	file, err := os.OpenFile(vaultPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	require.NoError(t, err, "Failed to create temp vault file")

	// Use t.Cleanup to ensure the file handle is closed strictly at the end of this test
	t.Cleanup(func() {
		_ = file.Close()
	})

	// Restrict permissions (SDDL logic)
	// This verifies that our Windows-specific ACL code works on a standard Go file handle.
	// SECURITY: We MUST use require.NoError here. If Hako cannot restrict NTFS permissions
	// to the current user, the vault is exposed to other local users.
	err = vf.RestrictPermissions(file)
	require.NoError(t, err, "RestrictPermissions strictly failed to apply SDDL ACLs")

	// Check permissions (Verify Owner)
	err = vf.CheckPermissions(file)
	assert.NoError(t, err, "CheckPermissions should succeed because the current user owns the file")

	// Test Error Case (Simulate passing a bad or non-file Handle)
	// We use os.DevNull ("NUL" on Windows) which does not have standard file SDDL ownership.
	devNull, err := os.Open(os.DevNull)
	require.NoError(t, err)
	defer func() { _ = devNull.Close() }()

	err = vf.CheckPermissions(devNull)
	assert.Error(t, err, "CheckPermissions should fail on a non-regular file handle like NUL")
}

func TestWindowsAtomicRename(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target.txt")
	tempPath := filepath.Join(tmpDir, "temp.txt")
	vf := NewVaultFile(targetPath)

	// Create the target file (simulating an existing vault)
	err := os.WriteFile(targetPath, []byte("old content"), 0600)
	require.NoError(t, err)

	// Create the temp file (simulating the new encrypted vault)
	err = os.WriteFile(tempPath, []byte("new content"), 0600)
	require.NoError(t, err)

	// Perform Atomic Rename (MoveFileEx)
	// This should succeed and overwrite target.txt even though it exists.
	// Standard os.Rename on Windows would fail here with "Access is denied" or "File exists".
	err = vf.atomicRename(tempPath, targetPath)
	require.NoError(t, err, "atomicRename failed on Windows")

	// Verify Content
	content, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("new content"), content, "Target file content should be updated")

	// Verify Temp is gone
	_, err = os.Stat(tempPath)
	assert.True(t, os.IsNotExist(err), "Temp file should be removed after rename")
}
