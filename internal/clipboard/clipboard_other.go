//go:build !windows

package clipboard

func isWin32Available() bool {
	return false
}

func writeWindowsClipboard(text []byte) error {
	return ErrUnsupportedTool
}

func clearWindowsClipboard() error {
	return ErrUnsupportedTool
}
