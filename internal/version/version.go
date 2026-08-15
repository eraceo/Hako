// Package version provides build information and version constants for the application.
//
//nolint:revive // Domain specific internal package name
package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the current version of the application.
	// Overridden at build time via -ldflags "-X 'github.com/eraceo/Hako/internal/version.Version=...'"
	Version = "dev"
	// Commit is the git commit hash.
	// Overridden at build time via -ldflags "-X 'github.com/eraceo/Hako/internal/version.Commit=...'"
	Commit = "unknown"
	// Date is the build date.
	// Overridden at build time via -ldflags "-X 'github.com/eraceo/Hako/internal/version.Date=...'"
	Date = "unknown"
)

// Info contains version information.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
}

// Get returns the current version information.
func Get() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// String returns a formatted, human-readable version string.
func (i Info) String() string {
	commit := i.Commit
	commitRunes := []rune(commit)
	if len(commitRunes) > 7 {
		commit = string(commitRunes[:7])
	}

	return fmt.Sprintf("Hako %s (%s) built on %s with %s for %s",
		i.Version, commit, i.Date, i.GoVersion, i.Platform)
}

// Short returns a short version string.
func (i Info) Short() string {
	return "Hako " + i.Version
}
