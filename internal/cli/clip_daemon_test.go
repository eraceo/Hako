package cli

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClipDaemonCmd_Hidden(t *testing.T) {
	t.Parallel()

	cmd := NewClipDaemonCmd()
	assert.True(t, cmd.Hidden, "__clip-daemon command must be hidden")
	assert.Equal(t, "__clip-daemon", cmd.Name())
}

func TestClipDaemonCmd_EmptyTool(t *testing.T) {
	t.Parallel()

	rootCmd := NewRootCmd()
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"__clip-daemon", "--tool", ""})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool parameter cannot be empty")
}

func TestClipDaemonCmd_UnauthorizedTool(t *testing.T) {
	t.Parallel()

	rootCmd := NewRootCmd()
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"__clip-daemon", "--tool", "malicious_script.sh"})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized clipboard tool")
}
