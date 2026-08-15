package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
)

// createTaggedVault uses direct internal APIs to construct a vault with specific tags
// required for filtering tests, without simulating slow CLI commands.
func createTaggedVault(t *testing.T, path string, masterPass string, empty bool) {
	t.Helper()
	vaultFile := storage.NewVaultFile(path)
	masterBytes := []byte(masterPass)
	defer memory.SecureZero(masterBytes)

	// Initialize with explicit fast crypto parameters to avoid CI timeouts
	fastParams := crypto.Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    16,
		KeySize:     32,
	}
	require.NoError(t, vaultFile.Initialize(context.Background(), masterBytes, nil, fastParams))

	if !empty {
		vault, err := vaultFile.Load(context.Background(), masterBytes, nil)
		require.NoError(t, err)

		// Ensure vault is wiped from memory after setup
		defer func() {
			for _, e := range vault.Entries {
				e.Zero()
			}
		}()

		// Entry 1: Work tag
		pass1 := []byte("SuperPass1") // MUST be >= 8 chars for validator
		defer memory.SecureZero(pass1)
		e1, err := secrets.NewEntry(
			"AppA",
			[]byte("userA"),
			pass1,
			[]byte("https://a.com"),
			nil, // Empty notes
			[]string{"work", "dev"},
		)
		require.NoError(t, err)
		vault.AddEntry(e1)

		// Entry 2: Personal tag
		pass2 := []byte("SuperPass2") // MUST be >= 8 chars for validator
		defer memory.SecureZero(pass2)
		e2, err := secrets.NewEntry(
			"AppB",
			[]byte("userB"),
			pass2,
			[]byte("https://b.com"),
			nil, // Empty notes
			[]string{"personal"},
		)
		require.NoError(t, err)
		vault.AddEntry(e2)

		err = vaultFile.Save(context.Background(), vault, masterBytes, nil)
		require.NoError(t, err)
	}
}

func getListCmdTestCases(testMasterPass string) []TestCase {
	return []TestCase{
		{
			Name:             "List empty vault",
			Args:             []string{"list"},
			SimulatedInput:   testMasterPass + "\n",
			ExpectedContains: []string{"No entries found in vault"},
			SetupVault: func(t *testing.T, path string) {
				createTaggedVault(t, path, testMasterPass, true)
			},
		},
		{
			Name:           "List all entries",
			Args:           []string{"list"},
			SimulatedInput: testMasterPass + "\n",
			ExpectedContains: []string{
				"Found 2 entries:",
				"AppA",
				"AppB",
			},
			SetupVault: func(t *testing.T, path string) {
				createTaggedVault(t, path, testMasterPass, false)
			},
		},
		{
			Name:           "List filtered by tags (matches 1)",
			Args:           []string{"list", "--tags", "work"},
			SimulatedInput: testMasterPass + "\n",
			ExpectedContains: []string{
				"Found 1 entries:",
				"AppA",
			},
			SetupVault: func(t *testing.T, path string) {
				createTaggedVault(t, path, testMasterPass, false)
			},
		},
		{
			Name:           "List filtered by tags (no match)",
			Args:           []string{"list", "--tags", "gaming"},
			SimulatedInput: testMasterPass + "\n",
			ExpectedContains: []string{
				"No entries found with tags: gaming",
			},
			SetupVault: func(t *testing.T, path string) {
				createTaggedVault(t, path, testMasterPass, false)
			},
		},
		{
			Name:           "List JSON output",
			Args:           []string{"list", "--json"},
			SimulatedInput: testMasterPass + "\n",
			ExpectedContains: []string{
				`"name": "AppA"`,
				`"name": "AppB"`,
				`"username": "userA"`,
				`"tags": [`,
				`"work"`,
			},
			SetupVault: func(t *testing.T, path string) {
				createTaggedVault(t, path, testMasterPass, false)
			},
		},
		{
			Name:           "Fails when vault is missing",
			Args:           []string{"list"},
			SimulatedInput: testMasterPass + "\n",
			MissingVault:   true,
			ExpectedError:  "vault file not found",
		},
	}
}

func TestListCmd(t *testing.T) {
	const testMasterPass = "list_master_pass"
	tests := getListCmdTestCases(testMasterPass)

	for _, tt := range tests {
		RunCLICommandTest(t, tt)
	}
}
