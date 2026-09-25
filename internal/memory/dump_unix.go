//go:build (darwin || dragonfly || freebsd || netbsd || openbsd || solaris) && !linux

package memory

import (
	"golang.org/x/sys/unix"
)

// DisableCoreDumps disables core dump generation on non-Linux Unix systems.
func DisableCoreDumps() error {
	var rlim unix.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	return unix.Setrlimit(unix.RLIMIT_CORE, &rlim)
}
