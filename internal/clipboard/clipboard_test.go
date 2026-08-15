package clipboard

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/config"
)

// getTestSystemTools returns the standard tools expected for the current OS.
func getTestSystemTools() []string {
	switch runtime.GOOS {
	case "windows":
		return []string{"clip"}
	case "darwin":
		return []string{"pbcopy"}
	default:
		return []string{"wl-copy", "xclip", "xsel"}
	}
}

func TestNew_ConfigPreference(t *testing.T) {
	t.Parallel()

	// Security Test: Fail Closed behavior.
	cfg := config.ClipboardConfig{
		ToolPreference: []string{"nonexistent_tool_123", "another_fake_tool_456"},
	}

	manager := New(cfg)
	require.NotNil(t, manager)

	// Since the tools don't exist, the manager must NOT be available.
	assert.False(t, manager.IsAvailable(), "Manager should not be available if preferred tools are missing")
	assert.Equal(t, "", manager.GetTool())
}

func TestClipboardIntegration_RealTool(t *testing.T) {
	// Initialize with explicit system defaults
	cfg := config.ClipboardConfig{
		ToolPreference: getTestSystemTools(),
	}
	manager := New(cfg)

	// Graceful skip for CI/Docker environments
	if !manager.IsAvailable() {
		t.Skip("No clipboard tool available on this system, skipping integration test")
	}

	t.Logf("Testing with detected tool: %s", manager.GetTool())

	// Test Copy
	contentStr := "test_content_integration"
	contentBuf := make([]byte, len(contentStr))
	copy(contentBuf, contentStr)

	err := manager.Copy(contentBuf)
	assert.NoError(t, err, "Copy should succeed")

	// Test Clear
	err = manager.Clear()
	assert.NoError(t, err, "Clear should succeed")
}

func TestCopySecure_NoTool(t *testing.T) {
	t.Parallel()

	// Force configuration with a non-existent tool
	cfg := config.ClipboardConfig{
		ToolPreference: []string{"tool_that_does_not_exist"},
	}
	manager := New(cfg)

	if manager.IsAvailable() {
		t.Skip("Default clipboard tool detected despite invalid config, test environment is dirty")
	}

	secretBuf := []byte("secret")
	safeBuf := make([]byte, len(secretBuf))
	copy(safeBuf, secretBuf)

	err := manager.CopySecure(secretBuf, 100*time.Millisecond)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoClipboardTool, "Should return ErrNoClipboardTool when no tool is available")
}

func TestCopySecure_Timeout(t *testing.T) {
	manager := New(config.ClipboardConfig{
		ToolPreference: getTestSystemTools(),
	})

	if !manager.IsAvailable() {
		t.Skip("No clipboard tool available")
	}

	// Prepare sensitive data
	secretStr := "sensitive_data"
	secretBuf := make([]byte, len(secretStr))
	copy(secretBuf, secretStr)

	start := time.Now()
	timeout := 200 * time.Millisecond

	// Blocking execution
	err := manager.CopySecure(secretBuf, timeout)

	elapsed := time.Since(start)
	assert.NoError(t, err)

	// Verify Blocking duration
	assert.GreaterOrEqual(t, int64(elapsed), int64(timeout), "CopySecure should block for the duration of the timeout")

	// CRITICAL SECURITY CHECK: Zero-Allocation verify
	expectedZero := make([]byte, len(secretStr))
	assert.Equal(t, expectedZero, secretBuf, "Buffer must be zeroed (wiped) after CopySecure returns")
}

// --- Mock-based Tests for High Coverage ---

type mockCmdCall struct {
	Name  string
	Args  []string
	Stdin []byte
}

func setupMockManager(tool string, lookPathErr error, runCmdErr error) (*Manager, *[]mockCmdCall) {
	var calls []mockCmdCall
	m := &Manager{
		config: config.ClipboardConfig{
			ToolPreference: []string{tool},
		},
		lookPath: func(t string) (string, error) {
			if lookPathErr != nil {
				return "", lookPathErr
			}
			return "/mock/bin/" + t, nil
		},
		runCmd: func(ctx context.Context, name string, args []string, stdin []byte) error {
			if runCmdErr != nil {
				return runCmdErr
			}
			calls = append(calls, mockCmdCall{Name: name, Args: args, Stdin: stdin})
			return nil
		},
	}
	m.tool = m.detectTool()
	return m, &calls
}

func TestMock_CopyAndClear_Tools(t *testing.T) {
	tools := []string{"wl-copy", "xclip", "xsel", "clip", "pbcopy"}

	for _, tool := range tools {
		t.Run("Tool_"+tool, func(t *testing.T) {
			m, calls := setupMockManager(tool, nil, nil)
			assert.True(t, m.IsAvailable())
			assert.Equal(t, tool, m.GetTool())

			// Copy test
			text := []byte("secret_payload")
			err := m.Copy(text)
			assert.NoError(t, err)
			require.Len(t, *calls, 1)
			assert.Equal(t, tool, (*calls)[0].Name)
			assert.Equal(t, text, (*calls)[0].Stdin)

			// Clear test
			err = m.Clear()
			assert.NoError(t, err)
			// Depending on the tool, we expect 1 or 2 calls for Clear
			if tool == "xsel" || tool == "xclip" {
				assert.GreaterOrEqual(t, len(*calls), 2)
			} else {
				assert.GreaterOrEqual(t, len(*calls), 1)
			}
		})
	}
}

func TestMock_CopySecureSilent_Success(t *testing.T) {
	m, calls := setupMockManager("wl-copy", nil, nil)
	text := []byte("secure_data")

	start := time.Now()
	err := m.CopySecureSilent(text, 10*time.Millisecond, true)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, elapsed, 10*time.Millisecond)

	// Verify that wl-copy was called for copy, then wl-copy --clear was called
	require.Len(t, *calls, 2)
	assert.Equal(t, "wl-copy", (*calls)[0].Name)
	assert.Empty(t, (*calls)[0].Args)
	assert.Equal(t, "wl-copy", (*calls)[1].Name)
	assert.Equal(t, []string{"--clear"}, (*calls)[1].Args)

	// Verify buffer is zeroed
	expectedZero := make([]byte, len("secure_data"))
	assert.Equal(t, expectedZero, text)
}

func TestMock_CopySecure_NonSilent(t *testing.T) {
	m, calls := setupMockManager("wl-copy", nil, nil)
	text := []byte("secure_data")

	err := m.CopySecure(text, 10*time.Millisecond)
	assert.NoError(t, err)
	require.Len(t, *calls, 2)
}

func TestMock_CopySecure_ClearError(t *testing.T) {
	var calls []mockCmdCall
	m := &Manager{
		config: config.ClipboardConfig{
			ToolPreference: []string{"wl-copy"},
		},
		lookPath: func(t string) (string, error) {
			return "/mock/bin/" + t, nil
		},
		runCmd: func(ctx context.Context, name string, args []string, stdin []byte) error {
			calls = append(calls, mockCmdCall{Name: name, Args: args, Stdin: stdin})
			if len(args) > 0 && args[0] == "--clear" {
				return errors.New("clear failed")
			}
			return nil
		},
	}
	m.tool = m.detectTool()

	text := []byte("secure_data")
	err := m.CopySecureSilent(text, 10*time.Millisecond, false)
	assert.NoError(t, err)
	require.Len(t, calls, 2)
}

func TestMock_CopySecure_Error(t *testing.T) {
	// 1. No tool available
	mNoTool, _ := setupMockManager("wl-copy", errors.New("not found"), nil)
	err := mNoTool.Copy(nil)
	assert.ErrorIs(t, err, ErrNoClipboardTool)

	err = mNoTool.Clear()
	assert.ErrorIs(t, err, ErrNoClipboardTool)

	// 2. Command run error
	mErr, _ := setupMockManager("wl-copy", nil, errors.New("command failed"))
	err = mErr.Copy([]byte("hello"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "command failed")

	// 3. Command timeout (simulated via Context deadline exceeded)
	mTimeout, _ := setupMockManager("wl-copy", nil, context.DeadlineExceeded)
	err = mTimeout.Copy([]byte("hello"))
	assert.ErrorIs(t, err, ErrWriteTimeout)
}

func TestMock_UnsupportedTool(t *testing.T) {
	// Initialize with custom unsupported tool name
	m := &Manager{
		config: config.ClipboardConfig{
			ToolPreference: []string{"custom-unsupported-tool"},
		},
		lookPath: func(t string) (string, error) {
			return "/mock/bin/" + t, nil
		},
		runCmd: func(ctx context.Context, name string, args []string, stdin []byte) error {
			return nil
		},
	}
	m.tool = m.detectTool()

	err := m.Copy([]byte("data"))
	assert.ErrorIs(t, err, ErrUnsupportedTool)

	err = m.Clear()
	assert.ErrorIs(t, err, ErrUnsupportedTool)
}

func TestDefaultRunCmd(t *testing.T) {
	m := New(config.ClipboardConfig{})
	cmdName := "echo"
	args := []string{"hello"}
	if runtime.GOOS == "windows" {
		cmdName = "cmd"
		args = []string{"/c", "echo", "hello"}
	}
	err := m.runCmd(context.Background(), cmdName, args, nil)
	assert.NoError(t, err)
}
