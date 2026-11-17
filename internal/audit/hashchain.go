package audit

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ErrInvalidAuditAnchor indicates an audit rotation anchor file is malformed or corrupted.
var ErrInvalidAuditAnchor = errors.New("invalid audit log anchor")

// GenesisHash is the fixed zero-hash used as prev_hash for the very first event in a vault log history.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// VerificationStatus represents the outcome of a log integrity scan.
type VerificationStatus string

const (
	// StatusValid indicates the entire log chain (including archives) is 100% intact.
	StatusValid VerificationStatus = "VALID"
	// StatusTampered indicates an event has been modified, inserted, or deleted.
	StatusTampered VerificationStatus = "TAMPERED"
	// StatusTruncatedEOF indicates an unparseable truncated line at the very end of the file (e.g. crash during write).
	StatusTruncatedEOF VerificationStatus = "TRUNCATED_EOF"
)

// VerifyReport contains the results of a log chain integrity audit.
type VerifyReport struct {
	Status             VerificationStatus `json:"status"`
	TotalFilesChecked  int                `json:"total_files_checked"`
	TotalEventsChecked int                `json:"total_events_checked"`
	ValidEventsCount   int                `json:"valid_events_count"`
	FirstErrorLine     int                `json:"first_error_line,omitempty"`
	FirstErrorFile     string             `json:"first_error_file,omitempty"`
	ErrorDetails       string             `json:"error_details,omitempty"`
}

// ComputeEventHash computes a deterministic, canonical SHA-256 hash for an Event.
// V1 compatibility contract: Event.Details is hashed via standard encoding/json.Marshal
// (sorted map keys) and fields not included in v1 (e.g., UserAgent) are intentionally omitted
// so existing audit logs remain verifiable without migration.
func ComputeEventHash(prevHash string, event *Event) string {
	if prevHash == "" {
		prevHash = GenesisHash
	}

	var detailsJSON string
	if event.Details != nil {
		b, err := json.Marshal(event.Details)
		if err == nil {
			detailsJSON = string(b)
		}
	}

	payload := fmt.Sprintf("%s|%d|%s|%t|%s|%d|%s|%s",
		prevHash,
		event.Timestamp.UnixNano(),
		event.EventType,
		event.Success,
		event.Message,
		event.ProcessID,
		event.SessionID,
		detailsJSON,
	)

	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}

// VerifyLogChain performs a strict verification of the audit log chain across logPath and its archives.
func VerifyLogChain(logPath string) (*VerifyReport, error) {
	report := &VerifyReport{
		Status: StatusValid,
	}

	files, err := discoverLogFiles(logPath)
	if err != nil {
		return nil, fmt.Errorf("failed to discover log files: %w", err)
	}

	if len(files) == 0 {
		// No log files found is considered valid empty
		return report, nil
	}

	report.TotalFilesChecked = len(files)
	expectedPrevHash := GenesisHash
	lineIndex := 0

	for fileIdx, fileInfo := range files {
		err := func() error {
			filePath := fileInfo.path
			// #nosec G304 -- Path is discovered from internal audit log directory
			f, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("failed to open log file %s: %w", filePath, err)
			}
			defer func() { _ = f.Close() }()

			var reader io.Reader = f
			if strings.HasSuffix(filePath, ".gz") {
				gzReader, err := gzip.NewReader(f)
				if err != nil {
					return fmt.Errorf("failed to decompress gzip log file %s: %w", filePath, err)
				}
				defer func() { _ = gzReader.Close() }()
				reader = gzReader
			}

			scanner := bufio.NewScanner(reader)
			// Support long log lines
			buf := make([]byte, 64*1024)
			scanner.Buffer(buf, 10*1024*1024)

			fileLineNum := 0
			isLastFile := fileIdx == len(files)-1

			for scanner.Scan() {
				lineText := strings.TrimSpace(scanner.Text())
				if lineText == "" {
					continue
				}

				lineIndex++
				fileLineNum++

				var event Event
				if err := json.Unmarshal([]byte(lineText), &event); err != nil {
					// Check if this is a truncated line at the very EOF of the current log file.
					// Inspect scanner.Err() first so I/O or buffer errors are never misclassified as StatusTruncatedEOF.
					if isLastFile && !scanner.Scan() {
						if scanErr := scanner.Err(); scanErr != nil {
							return fmt.Errorf("error reading log file %s: %w", filePath, scanErr)
						}
						report.Status = StatusTruncatedEOF
						report.FirstErrorLine = fileLineNum
						report.FirstErrorFile = filepath.Base(filePath)
						report.ErrorDetails = fmt.Sprintf("Unparseable truncated EOF line: %v", err)
						return nil
					}

					report.Status = StatusTampered
					report.FirstErrorLine = fileLineNum
					report.FirstErrorFile = filepath.Base(filePath)
					report.ErrorDetails = fmt.Sprintf("Malformed JSON on line %d: %v", fileLineNum, err)
					return nil
				}

				// For the very first event encountered in verification:
				// - If an .anchor file exists, enforce exact continuity across evicted rotations.
				// - If no .anchor exists and only the active file is present, require GenesisHash (detects head truncation).
				// - If no .anchor exists and rotated archives exist, adopt event.PrevHash for v1 backward compatibility.
				if lineIndex == 1 {
					anchorHash, anchorErr := readAnchorHash(logPath)
					switch {
					case anchorErr == nil:
						expectedPrevHash = anchorHash
					case os.IsNotExist(anchorErr):
						if len(files) == 1 {
							expectedPrevHash = GenesisHash
						} else {
							expectedPrevHash = event.PrevHash
						}
					case errors.Is(anchorErr, ErrInvalidAuditAnchor):
						report.Status = StatusTampered
						report.FirstErrorLine = fileLineNum
						report.FirstErrorFile = filepath.Base(logPath + anchorFileSuffix)
						report.ErrorDetails = "Corrupted or invalid audit log anchor hash"
						return nil
					default:
						return fmt.Errorf("failed to read audit log anchor: %w", anchorErr)
					}
				}

				// Check 1: PrevHash match
				if event.PrevHash != expectedPrevHash {
					report.Status = StatusTampered
					report.FirstErrorLine = fileLineNum
					report.FirstErrorFile = filepath.Base(filePath)
					report.ErrorDetails = fmt.Sprintf("PrevHash mismatch at line %d: expected %s, got %s",
						fileLineNum, expectedPrevHash, event.PrevHash)
					return nil
				}

				// Check 2: Hash self-consistency
				expectedHash := ComputeEventHash(event.PrevHash, &event)
				if event.Hash != expectedHash {
					report.Status = StatusTampered
					report.FirstErrorLine = fileLineNum
					report.FirstErrorFile = filepath.Base(filePath)
					report.ErrorDetails = fmt.Sprintf("Hash mismatch at line %d: expected %s, got %s",
						fileLineNum, expectedHash, event.Hash)
					return nil
				}

				expectedPrevHash = event.Hash
				report.ValidEventsCount++
				report.TotalEventsChecked++
			}

			if err := scanner.Err(); err != nil {
				return fmt.Errorf("error reading log file %s: %w", filePath, err)
			}
			return nil
		}()

		if err != nil {
			return nil, err
		}
		if report.Status != StatusValid {
			return report, nil
		}
	}

	return report, nil
}

type logFileInfo struct {
	path  string
	index int // backup index (e.g. 5 for audit.log.5.gz, 0 for audit.log)
}

// discoverLogFiles finds logPath and any backup archives in chronological order (.N.gz -> ... -> .1.gz -> .1 -> logPath).
func discoverLogFiles(logPath string) ([]logFileInfo, error) {
	dir := filepath.Dir(logPath)
	base := filepath.Base(logPath)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	archiveMap := make(map[int]logFileInfo)
	var activeFile *logFileInfo

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		fullPath := filepath.Join(dir, name)

		if name == base {
			activeFile = &logFileInfo{path: fullPath, index: 0}
			continue
		}

		// Match patterns like audit.log.1, audit.log.1.gz
		if strings.HasPrefix(name, base+".") {
			isGz := strings.HasSuffix(name, ".gz")
			suffix := strings.TrimPrefix(name, base+".")
			suffix = strings.TrimSuffix(suffix, ".gz")
			if idx, err := strconv.Atoi(suffix); err == nil && idx > 0 {
				if _, exists := archiveMap[idx]; exists {
					if isGz {
						archiveMap[idx] = logFileInfo{path: fullPath, index: idx}
					}
				} else {
					archiveMap[idx] = logFileInfo{path: fullPath, index: idx}
				}
			}
		}
	}

	var archives []logFileInfo
	for _, file := range archiveMap {
		archives = append(archives, file)
	}

	// Sort archives in descending order of index (oldest first: 5, 4, 3, 2, 1)
	sort.Slice(archives, func(i, j int) bool {
		return archives[i].index > archives[j].index
	})

	if activeFile != nil {
		archives = append(archives, *activeFile)
	}

	return archives, nil
}
