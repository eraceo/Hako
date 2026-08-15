package test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/eraceo/Hako/internal/crypto"
	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/storage"
)

// fastTestArgon2Params returns minimal parameters for fast unit testing.
// DO NOT use these in production.
func fastTestArgon2Params() crypto.Argon2Params {
	return crypto.Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltSize:    crypto.SaltSize,
		KeySize:     crypto.KeySize,
	}
}

// assertEphemeralSecretEquals securely compares an EphemeralSecret content with expected bytes.
func assertEphemeralSecretEquals(t *testing.T, secret secrets.EphemeralSecret, expected []byte, msg string) {
	t.Helper()
	require.NotEmpty(t, secret, "EphemeralSecret is empty: "+msg)

	var match bool
	err := secret.Access(func(b []byte) error {
		match = crypto.SecureCompare(b, expected)
		return nil
	})
	require.NoError(t, err, "Failed to access EphemeralSecret: "+msg)
	assert.True(t, match, msg)
}

// setupTestVault creates a temporary vault for testing cleanly.
// Uses testing.TB to support both Tests and Benchmarks.
func setupTestVault(tb testing.TB) (vaultFile *storage.VaultFile, masterPassword, keyfile []byte) {
	tempDir := tb.TempDir() // Native Go test temp dir, automatically cleaned up

	// Without this, tests will fail on Linux/WSL.
	// #nosec G302 -- Directories require execution permission (0700) to be traversed
	require.NoError(tb, os.Chmod(tempDir, 0700))

	// Always use absolute paths via filepath.Join.
	vaultPath := filepath.Join(tempDir, "test-vault.bin")

	masterPassword = []byte("test-master-password-123")
	keyfile = []byte("test-keyfile-content-for-security")
	vaultFile = storage.NewVaultFile(vaultPath)

	return vaultFile, masterPassword, keyfile
}

func TestVaultInitialize(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	err := vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params())
	require.NoError(t, err, "Failed to initialize vault")
	assert.True(t, vaultFile.Exists(), "Vault file should exist after initialization")
}

func TestVaultLoadEmpty(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	require.NoError(t, vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params()))

	vault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err, "Failed to load vault")
	assert.Empty(t, vault.Entries, "New vault should be empty")
}

func TestVaultAddAndSaveEntries(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	require.NoError(t, vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params()))

	vault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)

	// NewEntry safely wipes the passed byte array, so we pass a fresh allocation
	entry1, err := secrets.NewEntry(
		"github",
		[]byte("testuser"),
		[]byte("testpass123"),
		[]byte("https://github.com"),
		[]byte("Dev account"),
		[]string{"dev", "personal"},
	)
	require.NoError(t, err)
	defer entry1.Zero() // Ensures ciphertexts are zeroed after test

	entry2, err := secrets.NewEntry(
		"email",
		[]byte("test@example.com"),
		[]byte("emailpass456"),
		[]byte("https://gmail.com"),
		[]byte("Email account"),
		[]string{"email"},
	)
	require.NoError(t, err)
	defer entry2.Zero()

	vault.AddEntry(entry1)
	vault.AddEntry(entry2)

	err = vaultFile.Save(context.Background(), vault, masterPassword, keyfile)
	require.NoError(t, err, "Failed to save vault")
}

func TestVaultReloadAndVerifyEntries(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	require.NoError(t, vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params()))

	vault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)

	entry1, err := secrets.NewEntry(
		"github",
		[]byte("testuser"),
		[]byte("testpass123"),
		[]byte("https://github.com"),
		[]byte("Dev"),
		[]string{"dev"},
	)
	require.NoError(t, err)
	defer entry1.Zero()

	entry2, err := secrets.NewEntry(
		"email",
		[]byte("test@example.com"),
		[]byte("emailpass456"),
		[]byte("https://gmail.com"),
		[]byte("Email"),
		[]string{"email"},
	)
	require.NoError(t, err)
	defer entry2.Zero()

	vault.AddEntry(entry1)
	vault.AddEntry(entry2)

	require.NoError(t, vaultFile.Save(context.Background(), vault, masterPassword, keyfile))

	// Test reload
	reloadedVault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err, "Failed to reload vault")
	defer func() {
		for _, e := range reloadedVault.Entries {
			e.Zero()
		}
	}()

	require.Len(t, reloadedVault.Entries, 2)

	githubEntry := reloadedVault.GetEntryByName("github")
	require.NotNil(t, githubEntry, "GitHub entry not found")

	// Use secure helper for checking ephemeral enclaves
	assertEphemeralSecretEquals(t, githubEntry.Username, []byte("testuser"), "Username mismatch")
	assertEphemeralSecretEquals(t, githubEntry.Password, []byte("testpass123"), "Password mismatch")
}

func TestVaultSearchAndFilter(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	require.NoError(t, vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params()))
	vault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)

	entry1, err := secrets.NewEntry(
		"github",
		[]byte("testuser"),
		[]byte("testpass123"),
		[]byte("https://github.com"),
		[]byte("Dev"),
		[]string{"dev", "personal"},
	)
	require.NoError(t, err)
	defer entry1.Zero()

	vault.AddEntry(entry1)
	require.NoError(t, vaultFile.Save(context.Background(), vault, masterPassword, keyfile))

	reloadedVault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)
	defer func() {
		for _, e := range reloadedVault.Entries {
			e.Zero()
		}
	}()

	// Test search
	searchResults := reloadedVault.SearchEntries("github")
	assert.Len(t, searchResults, 1, "Expected 1 search result")

	// Test tag filtering
	devEntries := reloadedVault.ListEntries([]string{"dev"})
	assert.Len(t, devEntries, 1, "Expected 1 dev entry")
}

func TestVaultUpdateAndRemoveEntries(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	require.NoError(t, vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params()))
	vault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)

	entry1, err := secrets.NewEntry(
		"github",
		[]byte("testuser"),
		[]byte("testpass123"),
		[]byte("https://github.com"),
		[]byte("Dev"),
		[]string{"dev"},
	)
	require.NoError(t, err)
	defer entry1.Zero()

	entry2, err := secrets.NewEntry(
		"email",
		[]byte("test@example.com"),
		[]byte("emailpass456"),
		[]byte("https://gmail.com"),
		[]byte("Email"),
		[]string{"email"},
	)
	require.NoError(t, err)
	defer entry2.Zero()

	vault.AddEntry(entry1)
	vault.AddEntry(entry2)
	require.NoError(t, vaultFile.Save(context.Background(), vault, masterPassword, keyfile))

	reloadedVault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)

	// Test update
	githubEntry := reloadedVault.GetEntryByName("github")
	require.NotNil(t, githubEntry)

	// SECURITY: Properly zero out the old ciphertext before replacing it
	memory.SecureZero(githubEntry.Password)
	githubEntry.Password = secrets.NewEphemeralSecret([]byte("newpassword789"))

	assert.True(t, reloadedVault.UpdateEntry(githubEntry.ID, githubEntry))

	// Test remove
	assert.True(t, reloadedVault.RemoveEntryByName("email"))
	assert.Len(t, reloadedVault.Entries, 1)

	// Save and verify final state
	require.NoError(t, vaultFile.Save(context.Background(), reloadedVault, masterPassword, keyfile))

	finalVault, err := vaultFile.Load(context.Background(), masterPassword, keyfile)
	require.NoError(t, err)
	defer func() {
		for _, e := range finalVault.Entries {
			e.Zero()
		}
	}()

	finalGithubEntry := finalVault.GetEntryByName("github")
	require.NotNil(t, finalGithubEntry)
	assertEphemeralSecretEquals(t, finalGithubEntry.Password, []byte("newpassword789"), "Updated password mismatch")
}

func TestVaultAuthenticationFailures(t *testing.T) {
	vaultFile, masterPassword, keyfile := setupTestVault(t)

	require.NoError(t, vaultFile.Initialize(context.Background(), masterPassword, keyfile, fastTestArgon2Params()))

	// Test wrong password
	_, err := vaultFile.Load(context.Background(), []byte("wrong-password"), keyfile)
	assert.Error(t, err, "Loading with wrong password should fail")

	// Test wrong keyfile
	_, err = vaultFile.Load(context.Background(), masterPassword, []byte("wrong-keyfile-content"))
	assert.Error(t, err, "Loading with wrong keyfile should fail")
}

func TestPasswordGeneration(t *testing.T) {
	opts := secrets.DefaultGeneratorOptions()
	password, err := secrets.GeneratePassword(opts)
	require.NoError(t, err)
	assert.Len(t, password, opts.Length)
	memory.SecureZero(password) // Cleanup test payload

	memorableOpts := secrets.GeneratorOptions{
		Length:     20,
		UseSymbols: true,
		Memorable:  true,
	}
	memorablePassword, err := secrets.GeneratePassword(memorableOpts)
	require.NoError(t, err)
	assert.NotEmpty(t, memorablePassword)
	memory.SecureZero(memorablePassword)

	// Test uniqueness
	passwords := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		pwd, err := secrets.GeneratePassword(opts)
		require.NoError(t, err)

		pwdStr := string(pwd)
		_, exists := passwords[pwdStr]
		assert.False(t, exists, "Generated duplicate password")
		passwords[pwdStr] = struct{}{}

		memory.SecureZero(pwd)
	}
}

func TestCryptoSecurity(t *testing.T) {
	password := []byte("test-password-123")
	plaintext := []byte("This is sensitive data that needs protection")

	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	params := fastTestArgon2Params()

	key, err := crypto.DeriveKey(context.Background(), password, salt, params)
	require.NoError(t, err)
	defer memory.SecureZero(key)

	// Prepare exact buffer for In-Place encryption (length + 16 bytes MAC overhead)
	buf := make([]byte, len(plaintext), len(plaintext)+16)
	copy(buf, plaintext)

	nonce, err := crypto.GenerateNonce()
	require.NoError(t, err)
	ciphertext, err := crypto.EncryptAEADInPlace(buf, nonce, key, nil)
	require.NoError(t, err)

	decrypted, err := crypto.DecryptAEADInPlace(ciphertext, nonce, key, nil)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted, "Decrypted data doesn't match original")

	// Verify different salt = different key
	salt2, err := crypto.GenerateSalt()
	require.NoError(t, err)

	key2, err := crypto.DeriveKey(context.Background(), password, salt2, params)
	require.NoError(t, err)
	defer memory.SecureZero(key2)

	assert.False(t, crypto.SecureCompare(key, key2), "Different salts should produce different keys")
}

func BenchmarkVaultOperations(b *testing.B) {
	b.ReportAllocs() // SECURITY: Always track memory leaks in benchmarks

	vaultFile, masterPassword, _ := setupTestVault(b)
	params := fastTestArgon2Params()

	require.NoError(b, vaultFile.Initialize(context.Background(), masterPassword, nil, params))

	vault := secrets.NewVault()
	for i := 0; i < 100; i++ {
		entry, err := secrets.NewEntry(
			fmt.Sprintf("entry-%d", i),
			[]byte(fmt.Sprintf("user-%d", i)),
			[]byte(fmt.Sprintf("password-%d", i)),
			[]byte(fmt.Sprintf("https://example-%d.com", i)),
			[]byte(fmt.Sprintf("Notes for entry %d", i)),
			[]string{"benchmark", "test"},
		)
		require.NoError(b, err)
		vault.AddEntry(entry)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		require.NoError(b, vaultFile.Save(context.Background(), vault, masterPassword, nil))

		loadedVault, loadErr := vaultFile.Load(context.Background(), masterPassword, nil)
		require.NoError(b, loadErr)

		// Final explicit cleanup (though EphemeralSecrets won't crash the OS)
		for _, e := range loadedVault.Entries {
			e.Zero()
		}
	}

	// Final cleanup for the initially created vault
	for _, e := range vault.Entries {
		e.Zero()
	}
}
