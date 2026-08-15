//go:build windows

package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32                                              = windows.NewLazySystemDLL("advapi32.dll")
	procGetSecurityInfo                                      = modadvapi32.NewProc("GetSecurityInfo")
	procConvertSecurityDescriptorToStringSecurityDescriptorW = modadvapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
)

// sddlRevision1 is the required revision for SDDL strings (SDDL_REVISION_1).
const sddlRevision1 = 1

// getFileSDDL retrieves the DACL of the file as an SDDL string using raw syscalls.
func getFileSDDL(handle windows.Handle) (string, error) {
	var pSecurityDescriptor uintptr
	var pSidOwner, pSidGroup, pDacl, pSacl uintptr

	ret, _, err := procGetSecurityInfo.Call(
		uintptr(handle),
		uintptr(windows.SE_FILE_OBJECT),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&pSidOwner)),
		uintptr(unsafe.Pointer(&pSidGroup)),
		uintptr(unsafe.Pointer(&pDacl)),
		uintptr(unsafe.Pointer(&pSacl)),
		uintptr(unsafe.Pointer(&pSecurityDescriptor)),
	)

	if ret != 0 {
		return "", fmt.Errorf("GetSecurityInfo syscall failed: %w", err)
	}
	if pSecurityDescriptor == 0 {
		return "", fmt.Errorf("GetSecurityInfo returned null descriptor")
	}

	defer windows.LocalFree(windows.Handle(pSecurityDescriptor))

	var stringSD *uint16
	var stringLen uint32

	ret, _, err = procConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		pSecurityDescriptor,
		uintptr(sddlRevision1),
		uintptr(windows.DACL_SECURITY_INFORMATION),
		uintptr(unsafe.Pointer(&stringSD)),
		uintptr(unsafe.Pointer(&stringLen)),
	)

	if ret == 0 {
		if err != nil && err != windows.ERROR_SUCCESS {
			return "", fmt.Errorf("SDDL conversion syscall failed: %w", err)
		}
		return "", fmt.Errorf("SDDL conversion syscall failed with unknown error")
	}

	defer windows.LocalFree(windows.Handle(unsafe.Pointer(stringSD)))

	return windows.UTF16PtrToString(stringSD), nil
}

// atomicRename uses MoveFileEx with MOVEFILE_REPLACE_EXISTING.
func (vf *VaultFile) atomicRename(tempPath, targetPath string) error {
	srcPtr, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return fmt.Errorf("invalid source path: %w", err)
	}

	dstPtr, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return fmt.Errorf("invalid destination path: %w", err)
	}

	flags := windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_COPY_ALLOWED | windows.MOVEFILE_WRITE_THROUGH

	if err := windows.MoveFileEx(srcPtr, dstPtr, uint32(flags)); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	return nil
}

// CheckPermissions verifies that the vault file is owned by the current user and has strict ACLs.
func (vf *VaultFile) CheckPermissions(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("security check failed: file is not a regular file")
	}

	handle := windows.Handle(file.Fd())

	// A. Owner Check
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("failed to get owner info: %w", err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("failed to get owner SID: %w", err)
	}

	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("failed to get current user token: %w", err)
	}

	isOwner := windows.EqualSid(owner, tokenUser.User.Sid)
	if !isOwner {
		// Fallback: Check for Administrators
		adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
		if err == nil && windows.EqualSid(owner, adminSid) {
			groups, err := token.GetTokenGroups()
			if err == nil {
				for _, g := range groups.AllGroups() {
					if windows.EqualSid(g.Sid, adminSid) {
						isOwner = true
						break
					}
				}
			}
		}
	}

	if !isOwner {
		return fmt.Errorf("security check failed: file owner mismatch")
	}

	// B. ACL Allowlist Check
	sddl, err := getFileSDDL(handle)
	if err != nil {
		return fmt.Errorf("failed to validate ACLs: %w", err)
	}

	currentUserSID := tokenUser.User.Sid.String()
	allowedSIDs := map[string]bool{
		currentUserSID: true,
		"SY":           true, // System
		"BA":           true, // Administrators
		"LA":           true, // Local Administrator (SID alias)
		"S-1-5-18":     true, // System (SID)
		"S-1-5-32-544": true, // Administrators (SID)
	}

	aceSegments := strings.Split(sddl, "(")

	for _, segment := range aceSegments {
		segment = strings.TrimSuffix(segment, ")")
		parts := strings.Split(segment, ";")

		if len(parts) >= 6 && parts[0] == "A" {
			sid := parts[5]
			if !allowedSIDs[sid] {
				return fmt.Errorf("security check failed: unauthorized account '%s' (SDDL: %s)", sid, segment)
			}
		}
	}

	return nil
}

// CheckDirectoryPermissions is a no-op on Windows.
func (vf *VaultFile) CheckDirectoryPermissions() error {
	return nil
}

// RestrictPermissions sets explicit ACLs using SetNamedSecurityInfo.
// We use the file path instead of the handle because the os.File handle lacks WRITE_DAC permissions.
func (vf *VaultFile) RestrictPermissions(file *os.File) error {
	path := file.Name()
	absPath, err := filepath.Abs(path)
	if err == nil {
		path = absPath
	}

	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return fmt.Errorf("failed to get current user token: %w", err)
	}

	// SDDL: Disable Inheritance (P), Allow Full Access (FA) to Current User
	sddl := fmt.Sprintf("D:P(A;;FA;;;%s)", tokenUser.User.Sid.String())

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("failed to create security descriptor: %w", err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("failed to extract DACL: %w", err)
	}

	// Use Named API to let Windows handle the opening with correct permissions (WRITE_DAC)
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to apply secure ACLs on %s: %w", path, err)
	}

	return nil
}
