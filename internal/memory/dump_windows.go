//go:build windows

package memory

// DisableCoreDumps is a no-op on Windows systems where core dumps are managed by OS WER policies.
func DisableCoreDumps() error {
	return nil
}
