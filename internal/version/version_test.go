package version_test

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/eraceo/Hako/internal/version"
)

func TestGet(t *testing.T) {
	// Do not use t.Parallel() here as we are mutating package-level global variables.

	// Save original values to restore them after the test
	origVersion := version.Version
	origCommit := version.Commit
	origDate := version.Date
	t.Cleanup(func() {
		version.Version = origVersion
		version.Commit = origCommit
		version.Date = origDate
	})

	// Set test values
	version.Version = "1.2.3"
	version.Commit = "abcdef123456"
	version.Date = "2023-01-01"

	info := version.Get()

	assert.Equal(t, "1.2.3", info.Version)
	assert.Equal(t, "abcdef123456", info.Commit)
	assert.Equal(t, "2023-01-01", info.Date)
	assert.Equal(t, runtime.Version(), info.GoVersion)
	assert.Equal(t, fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH), info.Platform)
}

func TestInfo_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		info     version.Info
		expected string
	}{
		{
			name: "Long commit hash is truncated to 7 characters",
			info: version.Info{
				Version:   "0.1.0",
				Commit:    "abcdef123456",
				Date:      "2023-01-01",
				GoVersion: "go1.25.0",
				Platform:  "linux/amd64",
			},
			expected: "Hako 0.1.0 (abcdef1) built on 2023-01-01 with go1.25.0 for linux/amd64",
		},
		{
			name: "Short commit hash remains unchanged",
			info: version.Info{
				Version:   "0.1.0",
				Commit:    "abc",
				Date:      "2023-01-01",
				GoVersion: "go1.25.0",
				Platform:  "linux/amd64",
			},
			expected: "Hako 0.1.0 (abc) built on 2023-01-01 with go1.25.0 for linux/amd64",
		},
		{
			name: "Empty commit hash",
			info: version.Info{
				Version:   "dev",
				Commit:    "",
				Date:      "unknown",
				GoVersion: "go1.25.0",
				Platform:  "darwin/arm64",
			},
			expected: "Hako dev () built on unknown with go1.25.0 for darwin/arm64",
		},
		{
			name: "Commit hash with multi-byte runes (Emoji Truncation)",
			info: version.Info{
				Version: "0.1.0",
				// d(1) e(2) v(3) -(4) 🔥(5) -(6) 1(7) 2(8) 3(9) -> should be truncated after '1'
				Commit:    "dev-🔥-123",
				Date:      "2023-01-01",
				GoVersion: "go1.25.0",
				Platform:  "linux/amd64",
			},
			expected: "Hako 0.1.0 (dev-🔥-1) built on 2023-01-01 with go1.25.0 for linux/amd64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.info.String())
		})
	}
}

func TestInfo_Short(t *testing.T) {
	t.Parallel()

	info := version.Info{
		Version: "0.1.0",
	}

	assert.Equal(t, "Hako 0.1.0", info.Short())
}
