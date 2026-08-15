// Package audit provides security auditing capabilities for vaults.
package audit

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/eraceo/Hako/internal/config"
)

// EventType represents the type of audit event
type EventType string

const (
	// EventVaultInit represents a vault initialization event
	EventVaultInit EventType = "vault_init"
	// EventVaultLoad represents a vault loading event
	EventVaultLoad EventType = "vault_load"
	// EventVaultSave represents a vault save operation
	EventVaultSave EventType = "vault_save"
	// EventVaultImport represents a bulk import event
	EventVaultImport EventType = "vault_import"
	// EventEntryAdd represents an entry addition event
	EventEntryAdd EventType = "entry_add"
	// EventEntryGet represents an entry retrieval event
	EventEntryGet EventType = "entry_get"
	// EventEntryUpdate represents an entry update event
	EventEntryUpdate EventType = "entry_update"
	// EventEntryDelete represents an entry deletion event
	EventEntryDelete EventType = "entry_delete"
	// EventEntrySearch represents an entry search event
	EventEntrySearch EventType = "entry_search"
	// EventEntryList represents an entry listing event
	EventEntryList EventType = "entry_list"
	// EventPasswordGen represents a password generation event
	EventPasswordGen EventType = "password_generate"
	// EventExport represents a vault export event
	EventExport EventType = "vault_export"
	// EventSecurityError represents a security error event
	EventSecurityError EventType = "security_error"
	// EventAuthFailure represents an authentication failure event
	EventAuthFailure EventType = "auth_failure"
	// EventKDFUpdate represents a KDF parameter update / vault rekey event
	EventKDFUpdate EventType = "kdf_update"

	// maxSanitizeDepth prevents stack overflow in recursive reflection
	maxSanitizeDepth = 10
	// maxCollectionSize prevents OOM by limiting slice/map processing width
	maxCollectionSize = 50
	// maxStringLength limits the size of logged strings to prevent log flooding
	maxStringLength = 2048

	// RedactedValue is the placeholder used for sensitive fields.
	RedactedValue = "[REDACTED]"
)

var (
	// sensitiveKeys defines keys that trigger redaction.
	// We use strict matching to avoid false positives.
	sensitiveKeys = []string{
		"password", "passwd", "secret", "token",
		"credential", "passphrase", "private_key",
		"master_key", "salt", "hash", "api_key",
		"auth_key", "access_key",
	}
)

// Event represents a security audit event with cryptographic hash chaining
type Event struct {
	Timestamp time.Time              `json:"timestamp"`
	EventType EventType              `json:"event_type"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	ProcessID int                    `json:"process_id"`
	SessionID string                 `json:"session_id,omitempty"`
	PrevHash  string                 `json:"prev_hash"`
	Hash      string                 `json:"hash"`
}

// Logger handles secure audit logging.
// It is safe for concurrent use.
type Logger struct {
	mu              sync.Mutex // Protects file writes
	logPath         string
	enabled         bool
	sessionID       string
	maxSizeBytes    int64
	maxBackups      int
	compress        bool
	enableHashChain bool
	lastHash        string
}

// NewLogger creates a new audit logger with default rotation and hash chain options.
func NewLogger(logPath string, enabled bool) *Logger {
	return NewLoggerWithOptions(logPath, enabled, 10*1024*1024, 5, true, true)
}

// NewLoggerWithOptions creates a new audit logger with custom rotation and hash chain options.
func NewLoggerWithOptions(logPath string, enabled bool, maxSizeBytes int64, maxBackups int, compress bool, enableHashChain bool) *Logger {
	return &Logger{
		logPath:         logPath,
		enabled:         enabled,
		sessionID:       generateSecureSessionID(),
		maxSizeBytes:    maxSizeBytes,
		maxBackups:      maxBackups,
		compress:        compress,
		enableHashChain: enableHashChain,
	}
}

// LogEvent logs an audit event with the specified parameters
func (al *Logger) LogEvent(eventType EventType, success bool, message string, details map[string]interface{}) {
	if !al.enabled {
		return
	}

	// Sanitize details deeply to prevent logging sensitive data.
	var cleanDetails map[string]interface{}
	if details != nil {
		sanitized := al.sanitizeRecursive(details, 0)

		if sanitized == nil {
			cleanDetails = nil
		} else if m, ok := sanitized.(map[string]interface{}); ok {
			cleanDetails = m
		} else {
			cleanDetails = map[string]interface{}{
				"audit_warning": "details_sanitization_type_mismatch",
				"raw_type":      fmt.Sprintf("%T", sanitized),
			}
		}
	}

	event := Event{
		Timestamp: time.Now().UTC(),
		EventType: eventType,
		Success:   success,
		Message:   message,
		Details:   cleanDetails,
		ProcessID: os.Getpid(),
		SessionID: al.sessionID,
	}

	if err := al.writeEvent(&event); err != nil {
		// Log to stderr if audit logging fails.
		// Use explicit Fprintf to avoid relying on global loggers.
		// #nosec G104 -- Best effort fallback logging
		_, _ = fmt.Fprintf(os.Stderr, "Hako Audit Error: %v\n", err)
	}
}

// LogSuccess logs a successful operation
func (al *Logger) LogSuccess(eventType EventType, message string, details map[string]interface{}) {
	al.LogEvent(eventType, true, message, details)
}

// LogFailure logs a failed operation
func (al *Logger) LogFailure(eventType EventType, message string, details map[string]interface{}) {
	al.LogEvent(eventType, false, message, details)
}

// LogSecurityEvent logs a security-related event
func (al *Logger) LogSecurityEvent(message string, details map[string]interface{}) {
	al.LogEvent(EventSecurityError, false, message, details)
}

// writeEvent writes an audit event to the log file securely.
func (al *Logger) writeEvent(event *Event) error {
	// Ensure log directory exists first so file locking succeeds on first run
	if al.logPath != "" {
		if err := os.MkdirAll(filepath.Dir(al.logPath), 0700); err != nil {
			return fmt.Errorf("failed to create audit log directory: %w", err)
		}
	}

	// Inter-process file locking to prevent multi-process log corruption
	if al.logPath != "" {
		lock, _ := acquireFileLock(al.logPath + ".lock")
		if lock != nil {
			defer lock.release()
		}
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	// Populate HashChain (Always refresh lastHash under lock for multi-process safety)
	if al.enableHashChain {
		al.lastHash = readLastHash(al.logPath)
		event.PrevHash = al.lastHash
		event.Hash = ComputeEventHash(event.PrevHash, event)
		al.lastHash = event.Hash
	}

	// Serialize event to JSON first to fail fast before touching FS.
	eventJSON, err := json.Marshal(event)
	if err != nil {
		fallbackEvent := Event{
			Timestamp: event.Timestamp,
			EventType: EventSecurityError,
			Success:   false,
			Message:   "AUDIT_FAILURE: Failed to serialize original event",
			Details:   map[string]interface{}{"error": err.Error()},
			ProcessID: event.ProcessID,
			SessionID: event.SessionID,
			PrevHash:  event.PrevHash,
		}
		if al.enableHashChain {
			fallbackEvent.Hash = ComputeEventHash(fallbackEvent.PrevHash, &fallbackEvent)
			al.lastHash = fallbackEvent.Hash
		}
		eventJSON, _ = json.Marshal(fallbackEvent)
	}

	// Append newline directly to the byte slice to ensure atomic write of the line
	eventJSON = append(eventJSON, '\n')

	// Check rotation threshold
	if al.maxSizeBytes > 0 && al.logPath != "" {
		if info, err := os.Stat(al.logPath); err == nil {
			if info.Size()+int64(len(eventJSON)) > al.maxSizeBytes {
				if rotErr := al.rotate(); rotErr != nil {
					_, _ = fmt.Fprintf(os.Stderr, "Hako Audit Rotation Error: %v\n", rotErr)
				}
			}
		}
	}

	// Open strictly for appending with 0600 permissions.
	file, err := os.OpenFile(al.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}

	defer func() {
		_ = file.Close()
	}()

	if _, err := file.Write(eventJSON); err != nil {
		return fmt.Errorf("failed to write audit event: %w", err)
	}

	return nil
}

// rotate performs log rotation by shifting backups and optionally compressing the oldest.
func (al *Logger) rotate() error {
	if al.logPath == "" {
		return nil
	}

	if al.maxBackups <= 0 {
		return os.Remove(al.logPath)
	}

	// Remove backup exceeding maxBackups if it exists
	oldestBase := fmt.Sprintf("%s.%d", al.logPath, al.maxBackups)
	_ = os.Remove(oldestBase)
	_ = os.Remove(oldestBase + ".gz")

	// Shift backup files: log.N -> log.N+1
	for i := al.maxBackups - 1; i >= 1; i-- {
		srcBase := fmt.Sprintf("%s.%d", al.logPath, i)
		dstBase := fmt.Sprintf("%s.%d", al.logPath, i+1)

		if _, err := os.Stat(srcBase + ".gz"); err == nil {
			_ = os.Rename(srcBase+".gz", dstBase+".gz")
		} else if _, err := os.Stat(srcBase); err == nil {
			_ = os.Rename(srcBase, dstBase)
		}
	}

	// Move active logPath to logPath.1
	firstBackup := al.logPath + ".1"
	_ = os.Rename(al.logPath, firstBackup)

	// Optionally compress logPath.1 into logPath.1.gz
	if al.compress {
		compressFile(firstBackup)
	}

	return nil
}

// compressFile compresses srcPath to srcPath.gz using gzip and removes srcPath cleanly.
func compressFile(srcPath string) {
	// #nosec G304 -- Internal log file path for rotation compression
	src, err := os.Open(srcPath)
	if err != nil {
		return
	}

	dstPath := srcPath + ".gz"
	// #nosec G304 -- Internal log file path for rotation compression
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		_ = src.Close()
		return
	}

	gz := gzip.NewWriter(dst)
	_, copyErr := io.Copy(gz, src)
	closeGzErr := gz.Close()
	closeDstErr := dst.Close()
	closeSrcErr := src.Close()

	if copyErr == nil && closeGzErr == nil && closeDstErr == nil && closeSrcErr == nil {
		_ = os.Remove(srcPath)
	}
}

// readLastHash reads the hash of the last valid event in logPath or its archives using file discovery.
func readLastHash(logPath string) string {
	if logPath == "" {
		return GenesisHash
	}

	files, err := discoverLogFiles(logPath)
	if err != nil || len(files) == 0 {
		return GenesisHash
	}

	// Read backwards starting from the most recent file in discovery order
	for i := len(files) - 1; i >= 0; i-- {
		hash := func() string {
			filePath := files[i].path
			// #nosec G304 -- Internal log file path for hash calculation
			f, err := os.Open(filePath)
			if err != nil {
				return ""
			}
			defer func() { _ = f.Close() }()

			var reader io.Reader = f
			if strings.HasSuffix(filePath, ".gz") {
				gzReader, err := gzip.NewReader(f)
				if err != nil {
					return ""
				}
				defer func() { _ = gzReader.Close() }()
				reader = gzReader
			}

			scanner := bufio.NewScanner(reader)
			buf := make([]byte, 64*1024)
			scanner.Buffer(buf, 10*1024*1024)

			var lastLineHash string
			for scanner.Scan() {
				lineText := strings.TrimSpace(scanner.Text())
				if lineText == "" {
					continue
				}
				var ev Event
				if err := json.Unmarshal([]byte(lineText), &ev); err == nil && ev.Hash != "" {
					lastLineHash = ev.Hash
				}
			}
			return lastLineHash
		}()

		if hash != "" {
			return hash
		}
	}

	return GenesisHash
}

// sanitizeRecursive recursively removes sensitive information using reflection.
// It includes depth and width checks to prevent stack overflow and OOM on cyclic/huge structures.
func (al *Logger) sanitizeRecursive(value interface{}, depth int) interface{} {
	if value == nil {
		return nil
	}

	if depth > maxSanitizeDepth {
		return "[MAX_DEPTH_REACHED]"
	}

	v := reflect.ValueOf(value)

	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return al.sanitizeRecursive(v.Elem().Interface(), depth+1)

	case reflect.Map:
		// Limit map processing to prevent DoS
		mapLen := v.Len()
		if mapLen > maxCollectionSize {
			mapLen = maxCollectionSize
		}

		// Convert any map to map[string]interface{} with sanitized values
		sanitizedMap := make(map[string]interface{}, mapLen)
		iter := v.MapRange()
		count := 0
		for iter.Next() {
			if count >= mapLen {
				sanitizedMap["..."] = fmt.Sprintf("[TRUNCATED: %d items total]", v.Len())
				break
			}

			key := iter.Key()
			val := iter.Value()

			// We only process string keys for redaction logic.
			keyStr := fmt.Sprintf("%v", key.Interface())

			if al.isKeySensitive(keyStr) {
				sanitizedMap[keyStr] = RedactedValue
			} else {
				sanitizedMap[keyStr] = al.sanitizeRecursive(val.Interface(), depth+1)
			}
			count++
		}
		return sanitizedMap

	case reflect.Slice, reflect.Array:
		// Limit slice processing to prevent DoS (OOM)
		sliceLen := v.Len()
		cappedLen := sliceLen
		truncated := false

		if sliceLen > maxCollectionSize {
			cappedLen = maxCollectionSize
			truncated = true
		}

		sanitizedSlice := make([]interface{}, 0, cappedLen+1)
		for i := 0; i < cappedLen; i++ {
			sanitizedSlice = append(sanitizedSlice, al.sanitizeRecursive(v.Index(i).Interface(), depth+1))
		}

		if truncated {
			sanitizedSlice = append(sanitizedSlice, fmt.Sprintf("[TRUNCATED: %d items total]", sliceLen))
		}
		return sanitizedSlice

	case reflect.String:
		str := v.String()
		if len(str) > maxStringLength {
			return truncateString(str, maxStringLength) + "...[TRUNCATED]"
		}
		return str

	case reflect.Struct:
		// Convert structs to map representation to allow sanitization of fields
		sanitizedStruct := make(map[string]interface{}, v.NumField())
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			// Only export public fields
			if field.PkgPath != "" {
				continue
			}

			keyStr := field.Name
			val := v.Field(i)

			if al.isKeySensitive(keyStr) {
				sanitizedStruct[keyStr] = RedactedValue
			} else {
				sanitizedStruct[keyStr] = al.sanitizeRecursive(val.Interface(), depth+1)
			}
		}
		return sanitizedStruct

	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		// Primitives are safe
		return value

	default:
		return fmt.Sprintf("<type:%T>", value)
	}
}

// truncateString safely truncates a string to n bytes while respecting UTF-8 boundaries.
func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for s != "" {
		r, size := utf8.DecodeLastRuneInString(s)
		if r == utf8.RuneError && size == 1 {
			s = s[:len(s)-1]
		} else {
			break
		}
	}
	return s
}

// isKeySensitive checks if a key string triggers redaction.
func (al *Logger) isKeySensitive(key string) bool {
	if key == "" {
		return false
	}
	keyLower := strings.ToLower(key)
	for _, sensitiveKey := range sensitiveKeys {
		if strings.Contains(keyLower, sensitiveKey) {
			return true
		}
	}
	return false
}

// generateSecureSessionID generates a cryptographically secure session identifier.
func generateSecureSessionID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback_%d_%d", time.Now().UnixNano(), os.Getpid())
	}
	return "sess_" + hex.EncodeToString(b)
}

// Global audit logger instance
var (
	globalLogger *Logger
	globalMu     sync.RWMutex
	// defaultDisabledLogger ensures we always have a valid pointer even if Init is skipped.
	defaultDisabledLogger = NewLogger("", false)
)

// InitGlobalLogger initializes the global audit logger safely with default options.
func InitGlobalLogger(logPath string, enabled bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = NewLogger(logPath, enabled)
}

// InitGlobalLoggerFromConfig initializes the global audit logger from application Config.
func InitGlobalLoggerFromConfig(cfg *config.Config) {
	globalMu.Lock()
	defer globalMu.Unlock()
	maxSizeBytes := int64(cfg.AuditMaxSizeMB) * 1024 * 1024
	globalLogger = NewLoggerWithOptions(cfg.AuditLogPath, true, maxSizeBytes, cfg.AuditMaxBackups, cfg.AuditCompress, cfg.AuditEnableHashChain)
}

// InitGlobalLoggerWithOptions initializes the global audit logger with full customization.
func InitGlobalLoggerWithOptions(logPath string, enabled bool, maxSizeBytes int64, maxBackups int, compress bool, enableHashChain bool) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = NewLoggerWithOptions(logPath, enabled, maxSizeBytes, maxBackups, compress, enableHashChain)
}

// GetGlobalLogger returns the global audit logger safely.
func GetGlobalLogger() *Logger {
	globalMu.RLock()
	logger := globalLogger
	globalMu.RUnlock()

	if logger == nil {
		return defaultDisabledLogger
	}
	return logger
}

// Convenience functions for global logger

// LogSuccess logs a successful event using the global logger
func LogSuccess(eventType EventType, message string, details map[string]interface{}) {
	GetGlobalLogger().LogSuccess(eventType, message, details)
}

// LogFailure logs a failed event using the global logger
func LogFailure(eventType EventType, message string, details map[string]interface{}) {
	GetGlobalLogger().LogFailure(eventType, message, details)
}

// LogSecurityEvent logs a security event using the global logger
func LogSecurityEvent(message string, details map[string]interface{}) {
	GetGlobalLogger().LogSecurityEvent(message, details)
}
