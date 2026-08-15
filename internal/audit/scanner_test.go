package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
)

// Helper to securely create a dummy entry using the EphemeralSecret architecture.
// It accepts a byte slice to prevent string immutability leaks.
func createTestEntry(id, name string, password []byte) *secrets.Entry {
	// We only initialize Password because ScanVault only analyzes the password field.
	// Other fields (Username, URL, Notes) remain nil/empty, which is safe for this specific test.
	return &secrets.Entry{
		ID:       secrets.EntryID(id),
		Name:     name,
		Password: secrets.NewEphemeralSecret(password),
	}
}

// TestScanVault comprehensively tests the security audit scanner using Table-Driven Tests.
func TestScanVault(t *testing.T) {
	// Define the raw test data structure
	type entryData struct {
		id   string
		name string
		pass string // Hardcoded string literals for test definition convenience
	}

	tests := []struct {
		name                   string
		entries                []entryData
		expectedDuplicateCount int
		expectedReuseCount     int
		expectedWeakCount      int
		expectedScore          int
		expectedIssueTypes     []IssueType
	}{
		{
			name: "Perfectly secure vault",
			entries: []entryData{
				{"1", "Bank", "Str0ng!P@ssw0rd2024_Secure"},
				{"2", "Email", "An0th3r_V3ry_Str0ng!P@ss"},
			},
			expectedDuplicateCount: 0,
			expectedReuseCount:     0,
			expectedWeakCount:      0,
			expectedScore:          100,
			expectedIssueTypes:     nil, // No issues expected
		},
		{
			name: "Vault with duplicates only",
			// Calculation:
			// Total: 3
			// Dupes: 2. DupPct = 66.66%. Penalty = 33.33.
			// Score: 100 - 33 = 67
			entries: []entryData{
				{"1", "SiteA", "Hunter2_is_my_l0ng_p@ssw0rd!"},
				{"2", "SiteB", "Hunter2_is_my_l0ng_p@ssw0rd!"}, // Duplicate of SiteA
				{"3", "SiteC", "Unique_Str0ng_P@ssw0rd!"},
			},
			expectedDuplicateCount: 2,
			expectedReuseCount:     1,
			expectedWeakCount:      0,
			expectedScore:          67,
			expectedIssueTypes:     []IssueType{IssueDuplicate, IssueDuplicate},
		},
		{
			name: "Vault with weak passwords only",
			// Calculation:
			// Total: 3
			// Weak: 2. WeakPct = 66.66%. Penalty = 66.66.
			// Score: 100 - 66 = 34
			entries: []entryData{
				{"1", "Game", "12345"},   // Weak
				{"2", "Forum", "qwerty"}, // Weak
				{"3", "Bank", "Str0ng!P@ssw0rd2024_Secure"},
			},
			expectedDuplicateCount: 0,
			expectedReuseCount:     0,
			expectedWeakCount:      2,
			expectedScore:          34,
			expectedIssueTypes:     []IssueType{IssueWeakPassword, IssueWeakPassword},
		},
		{
			name: "Vault with mixed issues (weak and duplicated)",
			// Calculation:
			// Total: 2
			// Weak: 2. WeakPct = 100%.
			// Dupe: 2. DupPct = 100%.
			// Penalty: 100 + 50 = 150.
			// Score: 0 (clamped)
			entries: []entryData{
				{"1", "WeakAndDupeA", "12345"}, // Weak & Duplicate
				{"2", "WeakAndDupeB", "12345"}, // Weak & Duplicate
			},
			expectedDuplicateCount: 2, // Both entries count towards duplicates
			expectedReuseCount:     1, // One cluster of duplicates
			expectedWeakCount:      2, // Both are weak
			expectedScore:          0,
			// Order matches logic: Scan loop adds Weak -> then processDuplicates adds Duplicate
			expectedIssueTypes: []IssueType{IssueWeakPassword, IssueWeakPassword, IssueDuplicate, IssueDuplicate},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup Vault
			vault := &secrets.Vault{
				Entries: make([]*secrets.Entry, 0, len(tt.entries)),
			}

			// Securely populate the vault
			for _, ed := range tt.entries {
				passBytes := []byte(ed.pass)
				entry := createTestEntry(ed.id, ed.name, passBytes)
				memory.SecureZero(passBytes) // Wipe source slice immediately
				vault.Entries = append(vault.Entries, entry)
			}

			// Ensure all ephemeral enclaves are destroyed after the test to prevent leaks
			defer func() {
				for _, e := range vault.Entries {
					e.Zero()
				}
			}()

			// Execute Scanner
			report, err := ScanVault(context.Background(), vault)
			require.NoError(t, err, "ScanVault should not fail")

			// Assert Metric Counts
			assert.Equal(t, tt.expectedDuplicateCount, report.DuplicateCount, "Duplicate count mismatch")
			assert.Equal(t, tt.expectedReuseCount, report.ReuseCount, "Reuse count mismatch")
			assert.Equal(t, tt.expectedWeakCount, report.WeakCount, "Weak count mismatch")
			assert.Equal(t, tt.expectedScore, report.Score, "Security score mismatch")

			// Assert Issue Types
			var actualIssueTypes []IssueType
			for _, issue := range report.Issues {
				actualIssueTypes = append(actualIssueTypes, issue.Type)
			}

			// Verify that the correct number and types of issues were generated
			// ElementsMatch ignores order, which is good for robustness
			assert.ElementsMatch(t, tt.expectedIssueTypes, actualIssueTypes, "Report issues mismatch")
		})
	}
}
