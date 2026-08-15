// Package audit provides security auditing capabilities for vaults.
package audit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/eraceo/Hako/internal/entropy"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
)

// IssueType represents the type of security issue found
type IssueType string

const (
	// IssueWeakPassword indicates a password with insufficient entropy
	IssueWeakPassword IssueType = "WEAK_PASSWORD"
	// IssueDuplicate indicates a reused password
	IssueDuplicate IssueType = "DUPLICATE_PASSWORD"
	// IssueScanError indicates a failure to read an entry
	IssueScanError IssueType = "SCAN_ERROR"

	// SeverityHigh indicates a critical security issue.
	SeverityHigh = "High"
	// SeverityMedium indicates a moderate security issue.
	SeverityMedium = "Medium"
	// SeverityLow indicates a minor security issue or warning.
	SeverityLow = "Low"

	// MaxDuplicateNamesInDescription limits the number of entry names displayed in a duplicate warning.
	MaxDuplicateNamesInDescription = 3
)

// Issue represents a security finding
type Issue struct {
	Type        IssueType
	EntryID     string
	EntryName   string
	Description string
	Severity    string
}

// Report contains the results of a vault audit
type Report struct {
	TotalEntries   int
	WeakCount      int
	DuplicateCount int     // Total number of entries sharing a password with at least one other entry
	ReuseCount     int     // Number of distinct reused password groups (clusters)
	Issues         []Issue // Detailed list of all findings
	Score          int     // 0-100 security score (normalized)
}

// ScanVault performs a security audit on the vault.
// It decrypts each entry strictly in RAM using secrets.Access() to analyze entropy.
func ScanVault(ctx context.Context, vault *secrets.Vault) (*Report, error) {
	report := &Report{
		TotalEntries: len(vault.Entries),
		Issues:       make([]Issue, 0),
	}

	// Generate a session-bound HMAC key to safely hash passwords for duplicate detection
	// without exposing the actual passwords or raw hashes in memory.
	// This protects against cold boot attacks or memory dumps during the scan.
	hmacKey, err := generateHMACKey()
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}
	defer memory.SecureZero(hmacKey)

	// Key = HMAC-SHA256(plaintext_password), Value = List of entries sharing this password.
	// keys and values are stored on the Go Heap. Since keys are ephemeral HMACs
	// (useless without hmacKey which is wiped), this is an acceptable risk trade-off
	// for performance and memory safety vs manual arena management.
	passHashMap := make(map[string][]*secrets.Entry)

	for _, entry := range vault.Entries {
		// Respect cancellation (CLI Ctrl+C) to keep the app responsive
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		hashStr, err := scanEntry(entry, hmacKey, report)
		if err != nil {
			report.Issues = append(report.Issues, Issue{
				Type:        IssueScanError,
				EntryID:     string(entry.ID),
				EntryName:   entry.Name,
				Description: fmt.Sprintf("Failed to decrypt/scan: %v", err),
				Severity:    SeverityLow,
			})
			continue
		}

		// Only track non-empty passwords for duplicates.
		// Empty passwords are handled as "WeakPassword" issues separately.
		if hashStr != "" {
			passHashMap[hashStr] = append(passHashMap[hashStr], entry)
		}
	}

	processDuplicates(passHashMap, report)

	// Deterministic sort for the report UI using Stable sort.
	// Primary: Severity (High > Medium > Low)
	// Secondary: Entry Name (A-Z)
	// Tertiary: Issue Type (for consistency)
	sort.SliceStable(report.Issues, func(i, j int) bool {
		si := severityRank(report.Issues[i].Severity)
		sj := severityRank(report.Issues[j].Severity)
		if si != sj {
			return si > sj // Higher rank first (High=3 > Low=1)
		}
		if report.Issues[i].EntryName != report.Issues[j].EntryName {
			return report.Issues[i].EntryName < report.Issues[j].EntryName
		}
		return report.Issues[i].Type < report.Issues[j].Type
	})

	report.Score = calculateScore(report.TotalEntries, report.WeakCount, report.DuplicateCount)

	return report, nil
}

// severityRank assigns a numeric value to severity for sorting.
func severityRank(s string) int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// generateHMACKey creates a random ephemeral key.
func generateHMACKey() ([]byte, error) {
	hmacKey := make([]byte, 32)
	// SECURITY: Strict check on RNG. Use crypto/rand, never math/rand.
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("failed to generate random HMAC key: %w", err)
	}
	return hmacKey, nil
}

// scanEntry accesses the encrypted EphemeralSecret safely and analyzes it.
// Returns the HMAC-SHA256 hash of the plaintext password.
func scanEntry(entry *secrets.Entry, hmacKey []byte, report *Report) (string, error) {
	var hashStr string

	// Use the secrets.Access helper to securely access plaintext.
	// This uses the internal buffer pool and ensures zeroing after closure.
	// The closure signature requires returning an error, which we propagate.
	err := entry.Password.Access(func(plaintext []byte) error {
		// Case 1: Empty password
		if len(plaintext) == 0 {
			report.WeakCount++
			report.Issues = append(report.Issues, Issue{
				Type:        IssueWeakPassword,
				EntryID:     string(entry.ID),
				EntryName:   entry.Name,
				Description: "Password is empty",
				Severity:    SeverityHigh,
			})
			return nil // Return empty hash, handled in loop
		}

		// Case 2: Weak entropy
		// entropy.Calculate works on []byte, no string allocation needed.
		entropyVal := entropy.Calculate(plaintext)
		strength := entropy.EvaluateStrength(entropyVal)

		if strength == entropy.StrengthWeak {
			report.WeakCount++
			report.Issues = append(report.Issues, Issue{
				Type:        IssueWeakPassword,
				EntryID:     string(entry.ID),
				EntryName:   entry.Name,
				Description: "Password has insufficient entropy (weak)",
				Severity:    SeverityHigh,
			})
		}

		// Generate HMAC for duplicate detection
		// We intentionally include weak passwords in duplicate detection.
		// A password that is BOTH weak AND reused is a critical compounding risk.
		h := hmac.New(sha256.New, hmacKey)
		if _, err := h.Write(plaintext); err != nil {
			return err
		}
		hashStr = hex.EncodeToString(h.Sum(nil))
		return nil
	})

	if err != nil {
		return "", err
	}
	return hashStr, nil
}

// processDuplicates updates the report with any reused passwords found in the map.
func processDuplicates(passHashMap map[string][]*secrets.Entry, report *Report) {
	for _, entries := range passHashMap {
		if len(entries) <= 1 {
			continue
		}

		// Found a cluster of duplicates
		count := len(entries)
		report.DuplicateCount += count
		report.ReuseCount++ // Increments for each *group* of duplicates

		// Create an issue for EACH entry involved in the duplication
		for _, entry := range entries {
			report.Issues = append(report.Issues, Issue{
				Type:        IssueDuplicate,
				EntryID:     string(entry.ID),
				EntryName:   entry.Name,
				Description: formatDuplicateDescription(entries, entry.ID),
				Severity:    SeverityMedium,
			})
		}
	}
}

// formatDuplicateDescription creates a readable list of WHERE else this password is used.
func formatDuplicateDescription(cluster []*secrets.Entry, excludeID secrets.EntryID) string {
	var others []string
	count := 0

	// Gather names of OTHER entries in the cluster
	for _, e := range cluster {
		if e.ID != excludeID {
			others = append(others, e.Name)
			count++
			if count >= MaxDuplicateNamesInDescription {
				break
			}
		}
	}

	// Sort names for deterministic output (prevents flickering in UI tests)
	sort.Strings(others)

	desc := "Password reused in: " + strings.Join(others, ", ")
	remaining := len(cluster) - 1 - len(others)
	if remaining > 0 {
		desc += fmt.Sprintf(", and %d more", remaining)
	}
	return desc
}

// calculateScore computes the final 0-100 vault security score.
// It is normalized by the total number of entries to be fair to large vaults.
func calculateScore(totalEntries, weakCount, duplicateCount int) int {
	if totalEntries == 0 {
		return 100
	}

	// Percentage based scoring
	// Weak passwords are penalized heavily (100% impact)
	// Duplicate passwords are penalized moderately (50% impact)
	weakPct := float64(weakCount) / float64(totalEntries) * 100
	dupPct := float64(duplicateCount) / float64(totalEntries) * 100

	penalty := weakPct + (dupPct * 0.5)
	score := 100 - int(penalty)

	if score < 0 {
		return 0
	}
	return score
}
