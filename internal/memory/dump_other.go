//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !solaris && !windows

package memory

// DisableCoreDumps is a no-op stub for other architectures.
func DisableCoreDumps() error {
	return nil
}
