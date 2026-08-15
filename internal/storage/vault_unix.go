//go:build !windows

package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Unix-specific Sentinel Errors.
var (
	ErrInsecureFilePerms = errors.New("vault file has insecure permissions (should be 0600)")
	ErrInsecureFileOwner = errors.New("vault file is not owned by the current user")
	ErrInsecureDirPerms  = errors.New("vault directory has insecure permissions (should be 0700)")
	ErrInsecureDirOwner  = errors.New("vault directory is not owned by the current user")
)

// atomicRename uses standard os.Rename which is atomic on POSIX systems.
func (vf *VaultFile) atomicRename(tempPath, targetPath string) error {
	return os.Rename(tempPath, targetPath)
}

// CheckPermissions verifies that the vault file has secure permissions (0600) and correct ownership.
func (vf *VaultFile) CheckPermissions(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat vault file: %w", err)
	}

	mode := info.Mode()

	// Check if file is readable/writable by group or others (mask 0077 must be 0)
	if mode&0077 != 0 {
		return fmt.Errorf("%w: %04o", ErrInsecureFilePerms, mode&0777)
	}

	// SECURITY: Verify owner.
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// #nosec G115 -- os.Getuid() returns int, stat.Uid is uint32. Comparison is safe.
		if stat.Uid != uint32(os.Getuid()) {
			return fmt.Errorf("%w (uid: %d)", ErrInsecureFileOwner, stat.Uid)
		}
	}

	return nil
}

// CheckDirectoryPermissions verifies that the vault directory has secure permissions (0700).
func (vf *VaultFile) CheckDirectoryPermissions() error {
	dir := filepath.Dir(vf.path)

	// SECURITY: Use os.Stat to follow symlinks and check the actual target directory permissions.
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // Directory doesn't exist yet, safe for creation
		}
		return fmt.Errorf("failed to stat vault directory: %w", err)
	}

	mode := info.Mode()

	// Check if directory is accessible by group or others
	if mode&0077 != 0 {
		return fmt.Errorf("%w: %04o", ErrInsecureDirPerms, mode&0777)
	}

	// Verify owner
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		// #nosec G115 -- Safe comparison
		if stat.Uid != uint32(os.Getuid()) {
			return ErrInsecureDirOwner
		}
	}

	return nil
}

// RestrictPermissions sets secure permissions (0600) on the vault file.
// Used after creating a temp file to ensure it's locked down.
func (vf *VaultFile) RestrictPermissions(file *os.File) error {
	return file.Chmod(0600)
}
