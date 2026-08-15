//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

type fileLock struct {
	f *os.File
}

func acquireFileLock(lockPath string) (*fileLock, error) {
	if lockPath == "" {
		return nil, nil
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	var overlapped windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (fl *fileLock) release() {
	if fl == nil || fl.f == nil {
		return
	}
	var overlapped windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(fl.f.Fd()), 0, 1, 0, &overlapped)
	_ = fl.f.Close()
}
