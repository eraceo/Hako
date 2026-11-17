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

func TestVerifyLogChain_AnchorAndHeadTruncation(t *testing.T) {
	t.Run("Detects head truncation on single active file without anchor", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "audit.log")

		logger := NewLogger(logPath, true)
		logger.LogSuccess(EventVaultInit, "Event 1", nil)
		logger.LogSuccess(EventEntryAdd, "Event 2", nil)

		content, err := os.ReadFile(logPath) // #nosec G304
		require.NoError(t, err)
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		require.Len(t, lines, 2)

		// Attacker truncates the first line
		require.NoError(t, os.WriteFile(logPath, []byte(lines[1]+"\n"), 0600))

		report, err := VerifyLogChain(logPath)
		require.NoError(t, err)
		assert.Equal(t, StatusTampered, report.Status)
	})

	t.Run("Preserves continuity with maxBackups=0 via anchor and catches head truncation", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "audit.log")

		logger := NewLoggerWithOptions(logPath, true, 50, 0, false, true)
		for i := 0; i < 4; i++ {
			logger.LogSuccess(EventEntryAdd, "Rotated single file event", map[string]interface{}{"i": i})
		}

		assert.FileExists(t, logPath+".anchor")
		report, err := VerifyLogChain(logPath)
		require.NoError(t, err)
		assert.Equal(t, StatusValid, report.Status)

		// Corrupt anchor file -> StatusTampered
		require.NoError(t, os.WriteFile(logPath+".anchor", []byte("badhash\n"), 0600))
		report, err = VerifyLogChain(logPath)
		require.NoError(t, err)
		assert.Equal(t, StatusTampered, report.Status)
	})

	t.Run("Detects deleted head event after rotation eviction using anchor", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "audit.log")

		// maxBackups=1, no compression for easy line removal test
		logger := NewLoggerWithOptions(logPath, true, 50, 1, false, true)
		for i := 0; i < 4; i++ {
			logger.LogSuccess(EventEntryAdd, "Eviction anchor test", map[string]interface{}{"i": i})
		}

		assert.FileExists(t, logPath+".anchor")
		report, err := VerifyLogChain(logPath)
		require.NoError(t, err)
		assert.Equal(t, StatusValid, report.Status)

		// Delete archive .1 while leaving .anchor and active log -> active log PrevHash != anchor
		require.NoError(t, os.Remove(logPath+".1"))
		report, err = VerifyLogChain(logPath)
		require.NoError(t, err)
		assert.Equal(t, StatusTampered, report.Status)
	})

	t.Run("Scanner error on >10MB unparseable line is not misclassified as StatusTruncatedEOF", func(t *testing.T) {
		tmpDir := t.TempDir()
		logPath := filepath.Join(tmpDir, "huge_line.log")
		hugeLine := "{" + strings.Repeat("a", 11*1024*1024)
		require.NoError(t, os.WriteFile(logPath, []byte(hugeLine), 0600))

		_, err := VerifyLogChain(logPath)
		require.Error(t, err)
	})
}
