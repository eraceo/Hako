package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
)

// TestTruncate ensures strings are truncated securely by runes (UTF-8 aware)
// to prevent breaking ANSI sequences or multi-byte characters in the terminal.
// Pure unit test, no Cobra or Mocks needed.
func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"Short string", "hello", 10, "hello"},
		{"Exact max length", "1234567890", 10, "1234567890"},
		{"Truncate normal string", "this is a very long string", 10, "this is..."},
		{"Truncate with emojis", "🚨🚨🚨🚨🚨", 4, "🚨..."}, // 4 runes: 1 emoji + 3 dots
		{"Max is very small", "hello", 3, "hello"},   // Should return as-is if max <= 3
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.max)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// setupAuditVault creates a specific vault state for the audit tests.
// It deliberately injects weak and duplicated passwords to trigger the scanner.
func setupAuditVault(t *testing.T, path string, masterPass string, secureOnly bool) {
	t.Helper()
	vaultFile := storage.NewVaultFile(path)
	masterBytes := []byte(masterPass)
	defer memory.SecureZero(masterBytes)

	// Initialize with fast crypto
	fastParams := crypto.Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    16,
		KeySize:     32,
	}
	require.NoError(t, vaultFile.Initialize(context.Background(), masterBytes, nil, fastParams))

	vault, err := vaultFile.Load(context.Background(), masterBytes, nil)
	require.NoError(t, err)

	defer func() {
		for _, e := range vault.Entries {
			e.Zero()
		}
	}()

	// Entry 1: Strong Password (Always added)
	// We pass []byte for username, url, and notes to comply with the strict zero-allocation API.
	strongPass := []byte("Str0ng!P@ssw0rd2024_Secure")
	e1, err := secrets.NewEntry("Bank", []byte("user1"), strongPass, nil, nil, nil)
	require.NoError(t, err)
	vault.AddEntry(e1)

	if !secureOnly {
		// Entry 2: Weak Password
		// Must be exactly 8 chars to bypass minimum length validation,
		// but only numbers so entropy is evaluated as WEAK by the scanner.
		weakPass := []byte("12345678")
		var e2 *secrets.Entry
		e2, err = secrets.NewEntry("Game", []byte("user2"), weakPass, nil, nil, nil)
		require.NoError(t, err)
		vault.AddEntry(e2)

		// Entries 3 & 4: Duplicated Passwords
		// We allocate two separate byte slices because NewEntry consumes and zeros the input slice!
		dupPass1 := []byte("hunter2_is_my_password")
		var e3 *secrets.Entry
		e3, err = secrets.NewEntry("SiteA", []byte("user3"), dupPass1, nil, nil, nil)
		require.NoError(t, err)
		vault.AddEntry(e3)

		dupPass2 := []byte("hunter2_is_my_password")
		var e4 *secrets.Entry
		e4, err = secrets.NewEntry("SiteB", []byte("user4"), dupPass2, nil, nil, nil)
		require.NoError(t, err)
		vault.AddEntry(e4)
	}

	err = vaultFile.Save(context.Background(), vault, masterBytes, nil)
	require.NoError(t, err)
}

func getAuditCmdTestCases(testMasterPass string) []TestCase {
	return []TestCase{
		{
			Name:           "Audit insecure vault (finds issues)",
			Args:           []string{"audit"},
			SimulatedInput: testMasterPass + "\n",
			ExpectedContains: []string{
				"SECURITY AUDIT REPORT",
				"Total Entries:  4",
				"Found 1 weak passwords",
				"Found 2 duplicated passwords",
			},
			SetupVault: func(t *testing.T, path string) {
				setupAuditVault(t, path, testMasterPass, false)
			},
		},
		{
			Name:           "Audit secure vault (no issues)",
			Args:           []string{"audit"},
			SimulatedInput: testMasterPass + "\n",
			ExpectedContains: []string{
				"SECURITY AUDIT REPORT",
				"Total Entries:  1",
				"No issues found! Your vault is secure.",
			},
			SetupVault: func(t *testing.T, path string) {
				setupAuditVault(t, path, testMasterPass, true)
			},
		},
		{
			Name:           "Fails when vault is missing",
			Args:           []string{"audit"},
			SimulatedInput: testMasterPass + "\n",
			MissingVault:   true,
			ExpectedError:  "vault file not found",
		},
	}
}

func TestAuditCmd(t *testing.T) {
	const testMasterPass = "audit_master_pass"
	tests := getAuditCmdTestCases(testMasterPass)

	for _, tt := range tests {
		RunCLICommandTest(t, tt)
	}
}
