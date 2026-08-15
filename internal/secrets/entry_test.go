package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hakoBinary "github.com/eraceo/Hako/internal/encoding/tlv"
)

// assertEphemeralSecretEquals securely compares an EphemeralSecret content with expected bytes.
func assertEphemeralSecretEquals(t *testing.T, secret EphemeralSecret, expected []byte, msg string) {
	t.Helper()
	require.NotEmpty(t, secret, "EphemeralSecret is empty: "+msg)

	err := secret.Access(func(b []byte) error {
		// SECURITY: Using assert.Equal on []byte prevents string casting allocation
		// and gives excellent diff output if the test fails.
		assert.Equal(t, expected, b, msg)
		return nil
	})
	require.NoError(t, err, "Failed to access EphemeralSecret: "+msg)
}

func TestEntry_Binary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		entryName string
		username  string
		password  []byte
		url       string
		notes     string
		tags      []string
	}{
		{
			name:      "Full Entry",
			entryName: "test-full",
			username:  "user123",
			password:  []byte("mysecretpassword"),
			url:       "http://example.com",
			notes:     "some secure notes",
			tags:      []string{"tag1", "tag2"},
		},
		{
			name:      "Minimal Entry",
			entryName: "test-minimal",
			username:  "",
			password:  []byte("shortpass"),
			url:       "",
			notes:     "",
			tags:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy the password because NewEntry WILL zero the input slice
			passCopy := make([]byte, len(tt.password))
			copy(passCopy, tt.password)

			entry, err := NewEntry(
				tt.entryName,
				[]byte(tt.username),
				tt.password,
				[]byte(tt.url),
				[]byte(tt.notes),
				tt.tags,
			)
			require.NoError(t, err)
			defer entry.Zero()

			// SECURITY CHECK: Verify that NewEntry securely zeroed the input password slice
			for i, b := range tt.password {
				assert.Equal(t, byte(0), b, "Byte at index %d of input password was not zeroed", i)
			}

			// Marshal using zero-allocation encoder on a direct byte slice
			// Allocate a generous buffer (e.g., 4096 bytes) for the entry
			buf := make([]byte, 4096)
			encoder := hakoBinary.NewEncoder(buf)
			require.NoError(t, entry.MarshalBinary(encoder))

			// Unmarshal using zero-allocation decoder
			var entry2 Entry
			decoder := hakoBinary.NewDecoder(buf)
			require.NoError(t, entry2.UnmarshalBinary(decoder))
			defer entry2.Zero()

			// Verify Standard Fields
			assert.Equal(t, entry.ID, entry2.ID)
			assert.Equal(t, entry.Name, entry2.Name)
			assert.Equal(t, entry.Tags, entry2.Tags)

			// Time precision might differ slightly due to binary serialization (truncates nanoseconds)
			assert.Equal(t, entry.CreatedAt.Unix(), entry2.CreatedAt.Unix())

			// Verify Ephemeral Secrets using helper
			assertEphemeralSecretEquals(t, entry2.Password, passCopy, "Password mismatch")

			if tt.username != "" {
				assertEphemeralSecretEquals(t, entry2.Username, []byte(tt.username), "Username mismatch")
			} else {
				assert.Equal(t, 0, entry2.Username.PlaintextLen())
			}

			if tt.url != "" {
				assertEphemeralSecretEquals(t, entry2.URL, []byte(tt.url), "URL mismatch")
			} else {
				assert.Equal(t, 0, entry2.URL.PlaintextLen())
			}

			if tt.notes != "" {
				assertEphemeralSecretEquals(t, entry2.Notes, []byte(tt.notes), "Notes mismatch")
			} else {
				assert.Equal(t, 0, entry2.Notes.PlaintextLen())
			}
		})
	}
}

func TestEntry_Zero(t *testing.T) {
	t.Parallel()

	password := []byte("zerotest")

	entry, err := NewEntry(
		"test",
		[]byte("user"),
		password,
		[]byte("http://example.com"),
		[]byte("notes"),
		nil,
	)
	require.NoError(t, err)

	// Call Zero directly
	entry.Zero()

	// Ensure ephemeral secrets are wiped and pointers/slices are nil or empty
	assert.Empty(t, entry.Password)
	assert.Empty(t, entry.Username)
	assert.Empty(t, entry.URL)
	assert.Empty(t, entry.Notes)
}

func TestEntry_Clone(t *testing.T) {
	t.Parallel()

	passCopy := []byte("cloneme!")
	password := make([]byte, len(passCopy))
	copy(password, passCopy)

	entry, err := NewEntry(
		"original",
		[]byte("user"),
		password,
		[]byte("https://test.com"),
		[]byte("notes"),
		[]string{"dev"},
	)
	require.NoError(t, err)
	defer entry.Zero()

	clone, err := entry.Clone()
	require.NoError(t, err)
	defer clone.Zero()

	// Verify identity and standard fields
	assert.Equal(t, entry.ID, clone.ID)
	assert.Equal(t, entry.Name, clone.Name)

	// Verify deep copy of slices
	assert.Equal(t, entry.Tags, clone.Tags)
	if len(entry.Tags) > 0 {
		// Verify that the memory addresses are different
		assert.NotSame(t, &entry.Tags[0], &clone.Tags[0], "Tags slice should be a deep copy")
	}

	// Verify deep copy of ephemeral secrets
	assertEphemeralSecretEquals(t, clone.Password, passCopy, "Cloned password mismatch")

	// Ensure the underlying encrypted buffers are separate in memory
	assert.NotSame(t, &entry.Password[0], &clone.Password[0], "Password ephemeral secret should be a deep copy")
}

func TestVault_SearchEntries(t *testing.T) {
	t.Parallel()

	v := NewVault()

	// Using distinct slices for passwords to avoid zeroing issues in tests
	pass1 := []byte("pass1123")
	e1, err := NewEntry("Github", []byte("eraceo"), pass1, []byte("https://github.com"), nil, nil)
	require.NoError(t, err)

	pass2 := []byte("pass2234")
	e2, err := NewEntry("Gitlab", []byte("dev-user"), pass2, []byte("https://gitlab.internal"), []byte("work stuff"), nil)
	require.NoError(t, err)

	v.AddEntry(e1)
	v.AddEntry(e2)

	defer func() {
		e1.Zero()
		e2.Zero()
	}()

	tests := []struct {
		name          string
		query         string
		expectedCount int
	}{
		{
			name:          "Search by Name (case insensitive)",
			query:         "git",
			expectedCount: 2, // Matches Github and Gitlab
		},
		{
			name:          "Search by Username (inside ephemeral enclave)",
			query:         "eraceo",
			expectedCount: 1, // Matches e1
		},
		{
			name:          "Search by URL (inside ephemeral enclave)",
			query:         "internal",
			expectedCount: 1, // Matches e2
		},
		{
			name:          "No match",
			query:         "NOTFOUND",
			expectedCount: 0,
		},
		{
			name:          "Empty query",
			query:         "",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := v.SearchEntries(tt.query)
			assert.Len(t, results, tt.expectedCount)
		})
	}
}

// TestContainsBytes verifies the zero-allocation fuzzy search helper
func TestContainsBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		data     []byte
		patLower string
		expected bool
	}{
		{[]byte("Hello World"), "world", true},
		{[]byte("Hello World"), "hello", true},
		{[]byte("Hello World"), "foo", false},
		{[]byte("UPPERCASE"), "uppercase", true},
		{[]byte("MixedCase123"), "case123", true},
		{[]byte("Short"), "longerpattern", false},
		{[]byte(""), "pattern", false},
		{[]byte("pattern"), "", false},
	}

	for _, tt := range tests {
		t.Run(string(tt.data)+"_"+tt.patLower, func(t *testing.T) {
			result := containsBytes(tt.data, tt.patLower)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVault_Zero(t *testing.T) {
	t.Parallel()

	pass1 := []byte("password123")
	e1, err := NewEntry("E1", []byte("u1"), pass1, nil, nil, nil)
	require.NoError(t, err)
	pass2 := []byte("password456")
	e2, err := NewEntry("E2", []byte("u2"), pass2, nil, nil, nil)
	require.NoError(t, err)

	v := &Vault{
		Entries: []*Entry{e1, e2},
	}

	// Verify entries exist and are populated
	require.Len(t, v.Entries, 2)
	require.NotEmpty(t, e1.Password)
	require.NotEmpty(t, e2.Password)

	// Wipe
	v.Zero()

	// Verify vault slice is cleared
	assert.Nil(t, v.Entries)

	// Verify individual entries are zeroed
	assert.Empty(t, e1.Password)
	assert.Empty(t, e2.Password)
}
