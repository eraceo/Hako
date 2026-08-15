//go:build !windows

package audit

import (
	"os"
	"syscall"
)

type fileLock struct {
	f *os.File
}

func acquireFileLock(lockPath string) (*fileLock, error) {
	if lockPath == "" {
		return nil, nil
	}
	// #nosec G304 -- Internal audit lock file path
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (fl *fileLock) release() {
	if fl == nil || fl.f == nil {
		return
	}
	_ = syscall.Flock(int(fl.f.Fd()), syscall.LOCK_UN)
	_ = fl.f.Close()
}
