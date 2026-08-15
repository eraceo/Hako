package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/secrets"
)

type getTestCase struct {
	name             string
	args             []string
	simulatedInput   string
	expectedContains []string
	expectedOmit     []string
	expectedError    string
}

func getGetCmdTestCases(testMasterPass string) []getTestCase {
	// setupTestVaultWithEntry creates an entry with:
	// Username: "oldUser"
	// Password: "OldPassword123!"
	// URL: "https://old.com"
	return []getTestCase{
		{
			name:           "Get standard entry (hides password)",
			args:           []string{"get", "targetEntry"},
			simulatedInput: testMasterPass + "\n",
			expectedContains: []string{
				"Name: targetEntry",
				"Username: oldUser",
				"[hidden - use --show to display]",
				"URL: https://old.com",
			},
			expectedOmit: []string{"OldPassword123!"},
		},
		{
			name:           "Get entry with --show (displays password)",
			args:           []string{"get", "targetEntry", "--show"},
			simulatedInput: testMasterPass + "\n",
			expectedContains: []string{
				"Name: targetEntry",
				"Username: oldUser",
				"Password: OldPassword123!",
			},
			expectedOmit: []string{"[hidden - use --show to display]"},
		},
		{
			name:           "Get only username with --username",
			args:           []string{"get", "targetEntry", "--username"},
			simulatedInput: testMasterPass + "\n",
			expectedContains: []string{
				"oldUser",
			},
			expectedOmit: []string{"Name: targetEntry", "OldPassword123!"},
		},
		{
			name:           "Get JSON output (hides password by default)",
			args:           []string{"get", "targetEntry", "--json"},
			simulatedInput: testMasterPass + "\n",
			expectedContains: []string{
				`"name": "targetEntry"`,
				`"username": "oldUser"`,
			},
			expectedOmit: []string{`"password": "OldPassword123!"`},
		},
		{
			name:           "Get JSON output with --show (displays password)",
			args:           []string{"get", "targetEntry", "--json", "--show"},
			simulatedInput: testMasterPass + "\n",
			expectedContains: []string{
				`"name": "targetEntry"`,
				`"username": "oldUser"`,
				`"password": "OldPassword123!"`,
			},
		},
		{
			name:           "Get only password with --password-only",
			args:           []string{"get", "targetEntry", "--password-only"},
			simulatedInput: testMasterPass + "\n",
			expectedContains: []string{
				"OldPassword123!",
			},
			expectedOmit: []string{"Name: targetEntry", "Username: oldUser"},
		},
		{
			name:           "Fails on non-existent entry",
			args:           []string{"get", "missingEntry"},
			simulatedInput: testMasterPass + "\n",
			expectedError:  "entry 'missingEntry' not found",
		},
	}
}

func TestGetCmd(t *testing.T) {
	const testMasterPass = "masterpass123"
	tempDir := t.TempDir()
	tests := getGetCmdTestCases(testMasterPass)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean Environment
			viper.Reset()

			vaultName := "get_vault_" + strings.ReplaceAll(tt.name, " ", "_") + ".hako"
			testVaultPath := filepath.Clean(filepath.Join(tempDir, vaultName))

			viper.Set("argon2_iterations", 1)
			viper.Set("argon2_memory", 1024)
			viper.Set("argon2_parallelism", 1)

			// Setup Vault State using shared helper (Fixes DUPL)
			if tt.name == "Fails on non-existent entry" {
				setupTestVault(t, testVaultPath, testMasterPass, nil)
			} else {
				// Creates "targetEntry" with "oldUser" / "OldPassword123!"
				setupTestVaultWithEntry(t, testVaultPath, testMasterPass, "targetEntry")
			}

			// Prepare strict arguments
			cmdArgs := append([]string{}, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+testVaultPath, "--keyfile=none")

			// Execute target command
			actualOutput, err := executeCommandWithMocks(t, cmdArgs, tt.simulatedInput)

			// Assertions
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}
			require.NoError(t, err)

			for _, expected := range tt.expectedContains {
				assert.Contains(t, actualOutput, expected)
			}
			for _, omit := range tt.expectedOmit {
				assert.NotContains(t, actualOutput, omit, "Output should NOT contain this value")
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Unit Tests (unchanged)
// -----------------------------------------------------------------------------

// Helper struct for unmarshalling the output to verify it
type jsonEntry struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	// #nosec G117 -- Mock struct used exclusively for testing JSON output matching
	Password string   `json:"password,omitempty"`
	URL      string   `json:"url"`
	Notes    string   `json:"notes"`
	Tags     []string `json:"tags"`
}

type printJSONTestCase struct {
	name         string
	showPassword bool
	wantPassword string
}

func getPrintOutputJSONTestCases() []printJSONTestCase {
	return []printJSONTestCase{
		{
			name:         "Hide password by default",
			showPassword: false,
			wantPassword: "",
		},
		{
			name:         "Show password when requested",
			showPassword: true,
			wantPassword: "secret-password",
		},
	}
}

func TestPrintOutputJSON(t *testing.T) {
	// Setup test entry using Ephemeral Secrets
	entry := &secrets.Entry{
		ID:        "test-id",
		Name:      "test-entry",
		Username:  secrets.NewEphemeralSecret([]byte("test-user")),
		Password:  secrets.NewEphemeralSecret([]byte("secret-password")),
		URL:       secrets.NewEphemeralSecret([]byte("https://example.com")),
		Notes:     secrets.NewEphemeralSecret([]byte("test notes")),
		Tags:      []string{"tag1", "tag2"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	defer entry.Zero() // Securely wipe all ephemeral ciphers after test

	tests := getPrintOutputJSONTestCases()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := getOptions{
				ShowPassword: tt.showPassword,
				JSONOutput:   true,
			}

			// Capture output synchronously using our local helper
			jsonData := captureOutput(t, func() {
				err := printOutputJSON(entry, opts)
				require.NoError(t, err)
			})

			var result jsonEntry
			err := json.Unmarshal([]byte(jsonData), &result)
			require.NoError(t, err, "Failed to unmarshal JSON output")

			assert.Equal(t, "test-entry", result.Name)
			assert.Equal(t, "test-user", result.Username)
			assert.Equal(t, "https://example.com", result.URL)
			assert.Equal(t, "test notes", result.Notes)
			assert.Equal(t, []string{"tag1", "tag2"}, result.Tags)

			if tt.wantPassword == "" {
				assert.Empty(t, result.Password, "Password should be omitted")
			} else {
				assert.Equal(t, tt.wantPassword, result.Password, "Password mismatch")
			}
		})
	}
}

func TestSafeJSONString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Empty",
			input:    []byte(""),
			expected: []byte(`""`),
		},
		{
			name:     "Standard String",
			input:    []byte("hello_world"),
			expected: []byte(`"hello_world"`),
		},
		{
			name:     "Control Characters (Newline, Tab)",
			input:    []byte("hello\n\tworld"),
			expected: []byte(`"hello\n\tworld"`),
		},
		{
			name:     "Quotes and Slashes",
			input:    []byte(`"hello\world"`),
			expected: []byte(`"\"hello\\world\""`),
		},
		{
			name:     "Hex Escaping (Less than 0x20)",
			input:    []byte{0x01, 0x02},
			expected: []byte(`"\u0001\u0002"`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeJSONString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
