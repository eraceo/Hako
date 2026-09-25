//go:build linux

package memory

import (
	"golang.org/x/sys/unix"
)

// DisableCoreDumps disables core dump generation and unauthorized ptrace memory inspection on Linux.
func DisableCoreDumps() error {
	// PR_SET_DUMPABLE = 0 prevents unprivileged ptrace and restricts core dumps
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	var rlim unix.Rlimit
	rlim.Cur = 0
	rlim.Max = 0
	return unix.Setrlimit(unix.RLIMIT_CORE, &rlim)
}
