package clipboard

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPIDFilePath(t *testing.T) {
	t.Parallel()

	path, err := GetPIDFilePath()
	require.NoError(t, err)
	assert.NotEmpty(t, path)
	assert.True(t, filepath.IsAbs(path) || path != "")
}

func TestKillExistingDaemon_NoFile(t *testing.T) {
	t.Parallel()

	// Should execute without panic or error when no PID file exists
	assert.NotPanics(t, func() {
		KillExistingDaemon()
	})
}

func TestKillExistingDaemon_StalePIDFile(t *testing.T) {
	// Create a temporary PID file with a non-existent PID
	pidFile, err := GetPIDFilePath()
	require.NoError(t, err)

	err = os.MkdirAll(filepath.Dir(pidFile), 0700)
	require.NoError(t, err)

	// Write an invalid/dead PID (e.g. 999999)
	err = os.WriteFile(pidFile, []byte(strconv.Itoa(999999)), 0600)
	require.NoError(t, err)

	// KillExistingDaemon should clean up the stale PID file
	KillExistingDaemon()

	_, err = os.Stat(pidFile)
	assert.True(t, os.IsNotExist(err), "Stale PID file should be removed")
}
