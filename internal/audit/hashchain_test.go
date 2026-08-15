package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputeEventHash_Determinism(t *testing.T) {
	now := time.Now().UTC()
	event1 := Event{
		Timestamp: now,
		EventType: EventVaultInit,
		Success:   true,
		Message:   "Initialized vault",
		ProcessID: 1234,
		SessionID: "sess_test",
		Details: map[string]interface{}{
			"a": "1",
			"b": "2",
		},
	}

	event2 := Event{
		Timestamp: now,
		EventType: EventVaultInit,
		Success:   true,
		Message:   "Initialized vault",
		ProcessID: 1234,
		SessionID: "sess_test",
		Details: map[string]interface{}{
			"b": "2",
			"a": "1",
		},
	}

	hash1 := ComputeEventHash(GenesisHash, &event1)
	hash2 := ComputeEventHash(GenesisHash, &event2)

	assert.NotEmpty(t, hash1)
	assert.Equal(t, hash1, hash2, "ComputeEventHash must be deterministic regardless of detail map key iteration order")
}

func TestVerifyLogChain_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger := NewLogger(logPath, true)
	logger.LogSuccess(EventVaultInit, "Vault init", nil)
	logger.LogSuccess(EventEntryAdd, "Entry added", map[string]interface{}{"entry": "github.com"})
	logger.LogFailure(EventAuthFailure, "Wrong password", nil)

	report, err := VerifyLogChain(logPath)
	require.NoError(t, err)
	assert.Equal(t, StatusValid, report.Status)
	assert.Equal(t, 3, report.TotalEventsChecked)
	assert.Equal(t, 3, report.ValidEventsCount)
	assert.Equal(t, 1, report.TotalFilesChecked)
}

func TestVerifyLogChain_TamperedMessage(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger := NewLogger(logPath, true)
	logger.LogSuccess(EventVaultInit, "Vault init", nil)
	logger.LogSuccess(EventEntryAdd, "Entry added", map[string]interface{}{"entry": "github.com"})

	// Read log file, alter message in second line, write back
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	require.Equal(t, 2, len(lines))

	var ev Event
	err = json.Unmarshal([]byte(lines[1]), &ev)
	require.NoError(t, err)

	ev.Message = "TAMPERED MESSAGE"
	tamperedJSON, err := json.Marshal(ev)
	require.NoError(t, err)

	lines[1] = string(tamperedJSON)
	err = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)
	require.NoError(t, err)

	report, err := VerifyLogChain(logPath)
	require.NoError(t, err)
	assert.Equal(t, StatusTampered, report.Status)
	assert.Equal(t, 2, report.FirstErrorLine)
	assert.Contains(t, report.ErrorDetails, "Hash mismatch")
}

func TestVerifyLogChain_DeletedLine(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger := NewLogger(logPath, true)
	logger.LogSuccess(EventVaultInit, "Line 1", nil)
	logger.LogSuccess(EventEntryAdd, "Line 2", nil)
	logger.LogSuccess(EventEntryGet, "Line 3", nil)

	content, err := os.ReadFile(logPath)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	require.Equal(t, 3, len(lines))

	// Remove second line
	lines = []string{lines[0], lines[2]}
	err = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)
	require.NoError(t, err)

	report, err := VerifyLogChain(logPath)
	require.NoError(t, err)
	assert.Equal(t, StatusTampered, report.Status)
	assert.Equal(t, 2, report.FirstErrorLine)
	assert.Contains(t, report.ErrorDetails, "PrevHash mismatch")
}

func TestVerifyLogChain_RotationWithCompression(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Logger with tiny max size (50 bytes) to force rotation on every event
	logger := NewLoggerWithOptions(logPath, true, 50, 3, true, true)

	for i := 0; i < 5; i++ {
		logger.LogSuccess(EventEntryAdd, "Event log message", map[string]interface{}{"idx": i})
		time.Sleep(10 * time.Millisecond)
	}

	report, err := VerifyLogChain(logPath)
	require.NoError(t, err)
	assert.Equal(t, StatusValid, report.Status)
	assert.True(t, report.TotalFilesChecked > 1, "Should have checked multiple log archive files")
	assert.True(t, report.TotalEventsChecked > 0)
}
