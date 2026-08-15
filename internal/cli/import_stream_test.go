package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/secrets"
)

// --- Helper ---

func assertSecret(t *testing.T, secret secrets.EphemeralSecret, expected string) {
	t.Helper()
	err := secret.Access(func(plaintext []byte) error {
		assert.Equal(t, expected, string(plaintext))
		return nil
	})
	assert.NoError(t, err)
}

// --- JSON Tests ---

func TestSecureJSONImporter_Bitwarden(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		jsonContent   string
		expectEntries int
		verify        func(t *testing.T, entries []*secrets.Entry)
		expectError   bool
	}{
		{
			name: "Valid Single Entry",
			jsonContent: `{
				"items": [
					{
						"name": "GitHub",
						"notes": "My git notes",
						"login": {
							"username": "coder",
							"password": "secure_password_123",
							"uris": [{"uri": "https://github.com"}]
						}
					}
				]
			}`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assert.Equal(t, "GitHub", e.Name)
				assertSecret(t, e.Username, "coder")
				assertSecret(t, e.Password, "secure_password_123")
				assertSecret(t, e.URL, "https://github.com")
				assertSecret(t, e.Notes, "My git notes")
			},
		},
		{
			name: "Escaped Characters",
			jsonContent: `{
				"items": [
					{
						"name": "Escapes",
						"login": {
							"username": "simpleuser",
							"password": "pass\\word\"quote123",
							"uris": []
						}
					}
				]
			}`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0] // Fixed: Declared 'e'
				assertSecret(t, e.Username, "simpleuser")
				assertSecret(t, e.Password, "pass\\word\"quote123")
			},
		},
		{
			name: "Unicode Characters",
			jsonContent: `{
				"items": [
					{
						"name": "Unicode",
						"notes": "Note with \u00A9 and \u20AC",
						"login": {
							"username": "user_with_unicode", 
							"password": "pass\u20ACword123",
							"uris": []
						}
					}
				]
			}`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assertSecret(t, e.Notes, "Note with © and €")
				assertSecret(t, e.Password, "pass€word123")
			},
		},
		{
			name: "Multiple Entries",
			jsonContent: `{
				"items": [
					{
						"name": "Entry1",
						"login": { "username": "u1", "password": "password1234" }
					},
					{
						"name": "Entry2",
						"login": { "username": "u2", "password": "password2345" }
					}
				]
			}`,
			expectEntries: 2,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) < 2 {
					return
				}
				assert.Equal(t, "Entry1", entries[0].Name)
				assert.Equal(t, "Entry2", entries[1].Name)
			},
		},
		{
			name: "Malformed But Recoverable",
			jsonContent: `{
				"items": [
					{ "name": "Valid1", "login": {"username": "u1", "password": "password123"} },
					{ "name": "Broken", "login": { "username": "u2", "password" } }, 
					{ "name": "Valid2", "login": {"username": "u3", "password": "password345"} }
				]
			}`,
			// The parser skips the broken entry (missing colon/value) and attempts recovery
			expectEntries: 2,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) < 2 {
					return
				}
				assert.Equal(t, "Valid1", entries[0].Name)
				assert.Equal(t, "Valid2", entries[1].Name)
			},
		},
		{
			name: "URI containing closing bracket",
			jsonContent: `{
				"items": [
					{
						"name": "Entry with bracket URI",
						"login": {
							"username": "user1",
							"password": "password123",
							"uris": [
								{"uri": "https://example.com/options?tab=]"},
								{"uri": "https://another-url.com"}
							]
						}
					},
					{
						"name": "Second Entry",
						"login": {
							"username": "user2",
							"password": "password456"
						}
					}
				]
			}`,
			expectEntries: 2,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) < 2 {
					return
				}
				assert.Equal(t, "Entry with bracket URI", entries[0].Name)
				assertSecret(t, entries[0].URL, "https://example.com/options?tab=]")
				assert.Equal(t, "Second Entry", entries[1].Name)
				assertSecret(t, entries[1].Username, "user2")
			},
		},
		{
			name: "Fatal Error Returns Partially Parsed Entries",
			jsonContent: `{
				"items": [
					{
						"name": "Parsed Entry",
						"login": {
							"username": "user1",
							"password": "password123"
						}
					},
					x
				]
			}`,
			expectError: true,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				assert.NotEmpty(t, entries)
				assert.Equal(t, "Parsed Entry", entries[0].Name)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, "test.json")
			err := os.WriteFile(filePath, []byte(tt.jsonContent), 0600)
			require.NoError(t, err)

			importer, err := NewSecureJSONImporter(filePath)
			require.NoError(t, err)
			defer importer.Close()

			entries, err := importer.Parse()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectEntries, len(entries))
				if tt.verify != nil {
					tt.verify(t, entries)
				}
			}
		})
	}
}

// --- CSV Tests ---

func TestSecureCSVImporter(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		csvContent    string
		expectEntries int
		verify        func(t *testing.T, entries []*secrets.Entry)
		expectError   bool
	}{
		{
			name: "Standard CSV",
			csvContent: `Name,Username,Password,URL
Test App,jdoe,secret123,https://example.com`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assert.Equal(t, "Test App", e.Name)
				assertSecret(t, e.Username, "jdoe")
				assertSecret(t, e.Password, "secret123")
				assertSecret(t, e.URL, "https://example.com")
			},
		},
		{
			name: "Quoted Fields with Commas",
			csvContent: `Name,Notes,Password
"App, Inc.", "Note with , comma", "pass,word123"`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assert.Equal(t, "App, Inc.", e.Name)
				assertSecret(t, e.Notes, "Note with , comma")
				assertSecret(t, e.Password, "pass,word123")
			},
		},
		{
			name: "Flexible Headers (Case Insensitive)",
			csvContent: `account,LOGIN,pass,website
MyBank,me,secret1234,https://bank.com`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assert.Equal(t, "MyBank", e.Name)
				assertSecret(t, e.Username, "me")
				assertSecret(t, e.Password, "secret1234")
				assertSecret(t, e.URL, "https://bank.com")
			},
		},
		{
			name: "Empty Lines",
			csvContent: `Name,Password
App1,password123

App2,password123
`,
			expectEntries: 2,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) < 2 {
					return
				}
				assert.Equal(t, "App1", entries[0].Name)
				assert.Equal(t, "App2", entries[1].Name)
			},
		},
		{
			name:        "Arena Overflow",
			csvContent:  "Name,Password\nApp," + strings.Repeat("A", 130*1024) + "\n",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, "test.csv")
			err := os.WriteFile(filePath, []byte(tt.csvContent), 0600)
			require.NoError(t, err)

			importer, err := NewSecureCSVImporter(filePath)
			require.NoError(t, err)
			defer importer.Close()

			entries, err := importer.Parse()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectEntries, len(entries))
				if tt.verify != nil {
					tt.verify(t, entries)
				}
			}
		})
	}
}

// --- XML (KeePass) Tests ---

func TestSecureKeePassImporter(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name          string
		xmlContent    string
		expectEntries int
		verify        func(t *testing.T, entries []*secrets.Entry)
		expectError   bool
	}{
		{
			name: "Simple KeePass Entry",
			xmlContent: `
<KeePassFile>
	<Root>
		<Group>
			<Entry>
				<String>
					<Key>Title</Key>
					<Value>My Entry</Value>
				</String>
				<String>
					<Key>UserName</Key>
					<Value>user1</Value>
				</String>
				<String>
					<Key>Password</Key>
					<Value>pass123456</Value>
				</String>
			</Entry>
		</Group>
	</Root>
</KeePassFile>`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assert.Equal(t, "My Entry", e.Name)
				assertSecret(t, e.Username, "user1")
				assertSecret(t, e.Password, "pass123456")
			},
		},
		{
			name: "Nested Groups and Multiple Entries",
			xmlContent: `
<KeePassFile>
	<Root>
		<Group>
			<Entry>
				<String><Key>Title</Key><Value>E1</Value></String>
				<String><Key>Password</Key><Value>pass123456</Value></String>
			</Entry>
			<Group>
				<Entry>
					<String><Key>Title</Key><Value>E2</Value></String>
					<String><Key>Password</Key><Value>pass123456</Value></String>
				</Entry>
			</Group>
		</Group>
	</Root>
</KeePassFile>`,
			expectEntries: 2,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) < 2 {
					return
				}
				assert.Equal(t, "E1", entries[0].Name)
				assert.Equal(t, "E2", entries[1].Name)
			},
		},
		{
			name: "Attributes and Spaces",
			xmlContent: `
<Entry>
	<String>
		<Key  >Title</Key>
		<Value protected="true">Spaced Entry</Value>
	</String>
	<String><Key>Password</Key><Value>pass123456</Value></String>
</Entry>`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				assert.Equal(t, "Spaced Entry", entries[0].Name)
			},
		},
		{
			name: "Self-closing XML tags",
			xmlContent: `
<KeePassFile>
	<Root>
		<Group>
			<Entry>
				<String>
					<Key />
					<Value>Empty Key</Value>
				</String>
				<String>
					<Key>Title</Key>
					<Value>Valid Entry</Value>
				</String>
				<String>
					<Key>UserName</Key>
					<Value />
				</String>
				<String>
					<Key>Password</Key>
					<Value>pass123456</Value>
				</String>
			</Entry>
		</Group>
	</Root>
</KeePassFile>`,
			expectEntries: 1,
			verify: func(t *testing.T, entries []*secrets.Entry) {
				if len(entries) == 0 {
					return
				}
				e := entries[0]
				assert.Equal(t, "Valid Entry", e.Name)
				assertSecret(t, e.Username, "")
				assertSecret(t, e.Password, "pass123456")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tempDir, "test.xml")
			err := os.WriteFile(filePath, []byte(tt.xmlContent), 0600)
			require.NoError(t, err)

			importer, err := NewSecureKeePassImporter(filePath)
			require.NoError(t, err)
			defer importer.Close()

			entries, err := importer.Parse()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectEntries, len(entries))
				if tt.verify != nil {
					tt.verify(t, entries)
				}
			}
		})
	}
}
