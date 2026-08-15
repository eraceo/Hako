package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportCmd(t *testing.T) {
	const testMasterPass = "import_master_pass"
	tempDir := t.TempDir()

	// Path for the shared vault used across tests
	sharedVaultPath := filepath.Clean(filepath.Join(tempDir, "import_shared.vault"))

	// Setup Files
	csvPath := filepath.Join(tempDir, "valid.csv")
	jsonPath := filepath.Join(tempDir, "valid.json")
	xmlPath := filepath.Join(tempDir, "valid.xml")
	invalidPath := filepath.Join(tempDir, "invalid.txt")

	// Passwords must be >8 characters to pass validation
	createFile(t, csvPath, `Name,Username,Password,URL
CSV_Entry,csv_user,csv_password123,http://csv.com`)

	createFile(t, jsonPath, `{
		"items": [{
			"name": "JSON_Entry",
			"login": {"username": "json_u", "password": "json_password123"}
		}]
	}`)

	createFile(t, xmlPath, `
		<KeePassFile><Root><Group><Entry>
			<String><Key>Title</Key><Value>XML_Entry</Value></String>
			<String><Key>Password</Key><Value>xml_password123</Value></String>
		</Entry></Group></Root></KeePassFile>
	`)

	createFile(t, invalidPath, "This is not a valid format")

	// Initialize Vault (Assumption: setupTestVault helper exists in test_helpers.go)
	setupTestVault(t, sharedVaultPath, testMasterPass, []string{})

	// Define Test Cases
	tests := []struct {
		name             string
		args             []string
		expectedContains []string
		expectedError    string
	}{
		{
			name: "Import CSV Successfully",
			args: []string{csvPath},
			expectedContains: []string{
				"parsing CSV file",
				"Successfully imported 1 entries",
			},
		},
		{
			name: "Import JSON Successfully",
			args: []string{jsonPath},
			expectedContains: []string{
				"parsing JSON file",
				"Successfully imported 1 entries",
			},
		},
		{
			name: "Import XML Successfully",
			args: []string{xmlPath},
			expectedContains: []string{
				"parsing XML file",
				"Successfully imported 1 entries",
			},
		},
		{
			name: "Duplicate Detection (Import CSV Again)",
			args: []string{csvPath},
			expectedContains: []string{
				// The specific "Skipping duplicate entry" line is optional/debug.
				// We rely on the summary.
				"No new entries imported",
				"Skipped 1 duplicate entries",
			},
		},
		{
			name:          "File Not Found",
			args:          []string{"nonexistent.csv"},
			expectedError: "no such file or directory",
		},
		{
			name:          "Unsupported Extension",
			args:          []string{invalidPath},
			expectedError: "unsupported format: 'txt'",
		},
		{
			name:          "Explicit Format Flag Mismatch",
			args:          []string{invalidPath, "--format=csv"},
			expectedError: "parse csv stream", // Updated to match actual error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Isolate Viper
			viper.Reset()
			viper.Set("argon2_iterations", 1) // Fast crypto for tests
			viper.Set("argon2_memory", 1024)

			// Construct Args: command + file + flags + global flags
			cmdArgs := []string{"import"}
			cmdArgs = append(cmdArgs, tt.args...)
			cmdArgs = append(cmdArgs, "--vault="+sharedVaultPath, "--keyfile=none")

			// Execute with mocks
			output, err := executeCommandWithMocks(t, cmdArgs, testMasterPass+"\n")

			if tt.expectedError != "" {
				require.Error(t, err)
				if tt.name == "File Not Found" && runtime.GOOS == "windows" {
					assert.Contains(t, err.Error(), "The system cannot find the file specified")
				} else {
					assert.Contains(t, err.Error(), tt.expectedError)
				}
			} else {
				require.NoError(t, err)
				for _, exp := range tt.expectedContains {
					assert.Contains(t, output, exp)
				}
			}
		})
	}
}

func createFile(t *testing.T, path, content string) {
	t.Helper()
	err := os.WriteFile(path, []byte(content), 0600)
	require.NoError(t, err)
}
