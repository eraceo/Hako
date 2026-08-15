//go:build windows

package clipboard

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

const (
	cfUnicodeText = 13 // CF_UNICODETEXT

	gmemMoveable = 0x0002
	gmemZeroInit = 0x0040
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenClipboard            = user32.NewProc("OpenClipboard")
	procCloseClipboard           = user32.NewProc("CloseClipboard")
	procEmptyClipboard           = user32.NewProc("EmptyClipboard")
	procSetClipboardData         = user32.NewProc("SetClipboardData")
	procRegisterClipboardFormatW = user32.NewProc("RegisterClipboardFormatW")

	procGlobalAlloc  = kernel32.NewProc("GlobalAlloc")
	procGlobalLock   = kernel32.NewProc("GlobalLock")
	procGlobalUnlock = kernel32.NewProc("GlobalUnlock")
	procGlobalFree   = kernel32.NewProc("GlobalFree")
)

func isWin32Available() bool {
	return true
}

func openClipboardWithRetry() error {
	const maxRetries = 10
	const delay = 25 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		res, _, _ := procOpenClipboard.Call(0)
		if res != 0 {
			return nil
		}
		time.Sleep(delay)
	}
	return errors.New("clipboard locked by another application")
}

func wipeUint16(buf []uint16) {
	for i := range buf {
		buf[i] = 0
	}
}

func getFormatID(formatName string) (uint32, error) {
	p, err := syscall.UTF16PtrFromString(formatName)
	if err != nil {
		return 0, err
	}
	res, _, err := procRegisterClipboardFormatW.Call(uintptr(unsafe.Pointer(p)))
	if res == 0 {
		return 0, fmt.Errorf("RegisterClipboardFormatW(%s) failed: %v", formatName, err)
	}
	return uint32(res), nil
}

func setClipboardText(text []byte) error {
	u16 := utf16.Encode([]rune(string(text)))
	u16WithNull := append(u16, 0)
	defer wipeUint16(u16WithNull)

	bytesCount := uintptr(len(u16WithNull) * 2)

	hMem, _, err := procGlobalAlloc.Call(uintptr(gmemMoveable|gmemZeroInit), bytesCount)
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc failed: %v", err)
	}

	ptr, _, err := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("GlobalLock failed: %v", err)
	}

	dst := (*[1 << 30]uint16)(unsafe.Pointer(ptr))[:len(u16WithNull):len(u16WithNull)]
	copy(dst, u16WithNull)

	procGlobalUnlock.Call(hMem)

	res, _, err := procSetClipboardData.Call(uintptr(cfUnicodeText), hMem)
	if res == 0 {
		procGlobalFree.Call(hMem) // Must free if SetClipboardData fails
		return fmt.Errorf("SetClipboardData(CF_UNICODETEXT) failed: %v", err)
	}

	return nil
}

func setClipboardDWORD(formatID uint32, value uint32) error {
	bytesCount := uintptr(4)

	hMem, _, err := procGlobalAlloc.Call(uintptr(gmemMoveable|gmemZeroInit), bytesCount)
	if hMem == 0 {
		return fmt.Errorf("GlobalAlloc failed: %v", err)
	}

	ptr, _, err := procGlobalLock.Call(hMem)
	if ptr == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("GlobalLock failed: %v", err)
	}

	*(*uint32)(unsafe.Pointer(ptr)) = value

	procGlobalUnlock.Call(hMem)

	res, _, err := procSetClipboardData.Call(uintptr(formatID), hMem)
	if res == 0 {
		procGlobalFree.Call(hMem)
		return fmt.Errorf("SetClipboardData(%d) failed: %v", formatID, err)
	}

	return nil
}

func writeWindowsClipboard(text []byte) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := openClipboardWithRetry(); err != nil {
		return err
	}
	defer procCloseClipboard.Call()

	res, _, err := procEmptyClipboard.Call()
	if res == 0 {
		return fmt.Errorf("EmptyClipboard failed: %v", err)
	}

	if err := setClipboardText(text); err != nil {
		return err
	}

	exclusionFormats := []string{
		"ExcludeClipboardContentFromMonitorProcessing",
		"CanIncludeInClipboardHistory",
		"CanUploadToCloudClipboard",
		"ClipboardViewerIgnore",
	}

	for _, name := range exclusionFormats {
		fmtID, err := getFormatID(name)
		if err != nil {
			continue
		}
		_ = setClipboardDWORD(fmtID, 0)
	}

	return nil
}

func clearWindowsClipboard() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := openClipboardWithRetry(); err != nil {
		return err
	}
	defer procCloseClipboard.Call()

	res, _, err := procEmptyClipboard.Call()
	if res == 0 {
		return fmt.Errorf("EmptyClipboard failed: %v", err)
	}
	return nil
}
