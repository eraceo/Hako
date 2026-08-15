//go:build !windows

package clipboard

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMock_CopySecureSilent_Interrupt_SIGINT(t *testing.T) {
	m, calls := setupMockManager("wl-copy", nil, nil)
	text := []byte("secure_data")

	// Start a goroutine to send ourselves SIGINT/Ctrl+C
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
	}()

	start := time.Now()
	err := m.CopySecureSilent(text, 5*time.Second, true)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.Less(t, elapsed, 1*time.Second)

	// Verify clear was called
	require.Len(t, *calls, 2)
	assert.Equal(t, "wl-copy", (*calls)[0].Name)
	assert.Equal(t, []string{"--clear"}, (*calls)[1].Args)
}

func TestMock_CopySecureSilent_Interrupt_SIGTERM(t *testing.T) {
	m, calls := setupMockManager("wl-copy", nil, nil)
	text := []byte("secure_data")

	// Start a goroutine to send ourselves SIGTERM
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	start := time.Now()
	err := m.CopySecureSilent(text, 5*time.Second, false)
	elapsed := time.Since(start)

	assert.NoError(t, err)
	assert.Less(t, elapsed, 1*time.Second)

	// Verify clear was called
	require.Len(t, *calls, 2)
	assert.Equal(t, "wl-copy", (*calls)[0].Name)
	assert.Equal(t, []string{"--clear"}, (*calls)[1].Args)
}
