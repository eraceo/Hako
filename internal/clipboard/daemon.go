package clipboard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// GetPIDFilePath returns the path to the clipboard daemon PID lock file.
func GetPIDFilePath() (string, error) {
	var dir string
	if xdgConfigHome := os.Getenv("XDG_CONFIG_HOME"); xdgConfigHome != "" {
		dir = filepath.Join(xdgConfigHome, "hako")
	} else {
		userConfig, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(userConfig, "hako")
	}
	return filepath.Join(dir, "clip.pid"), nil
}

// KillExistingDaemon checks if a daemon PID lock file exists, and terminates the running process.
func KillExistingDaemon() {
	pidFile, err := GetPIDFilePath()
	if err != nil {
		return
	}
	// #nosec G304 -- PID lockfile path is constructed securely within user config directory
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		_ = os.Remove(pidFile)
		return
	}

	// Attempt to kill existing daemon
	_ = killProcess(pid)

	// Clean up stale PID file
	_ = os.Remove(pidFile)
}

// SpawnDaemon spawns a background, detached hako process to clear the clipboard after timeout.
func SpawnDaemon(tool string, timeout time.Duration) error {
	// First, terminate any previously running daemon process
	KillExistingDaemon()

	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// #nosec G204 -- Spawns current executable with strict internal sub-command and validated tool flag
	cmd := exec.Command(execPath, "__clip-daemon", "--tool", tool, "--timeout", timeout.String())
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil

	prepareDaemonCmd(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start background daemon: %w", err)
	}

	// Write the PID file
	pidFile, err := GetPIDFilePath()
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(pidFile), 0700)
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0600)
	}

	return nil
}
