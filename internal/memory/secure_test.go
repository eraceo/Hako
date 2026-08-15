package memory

import (
	"bytes"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureString_ZeroAndDestroy(t *testing.T) {
	password := "supersecret"

	// API UPDATE: Use the explicit 'Insecure' constructor name
	ss, err := NewSecureStringFromInsecure(password)
	require.NoError(t, err, "Failed to create SecureString")

	// Verify the string was stored correctly
	assert.Equal(t, password, ss.DangerousStringCopy())
	assert.Equal(t, len(password), ss.Len())

	// Destroy the string
	require.NoError(t, ss.Destroy(), "Failed to destroy SecureString")

	// After destroy, interactions safely return defaults or errors
	assert.Empty(t, ss.DangerousStringCopy(), "SecureString should be strictly empty after Destroy")
	assert.Equal(t, 0, ss.Len(), "Length should be 0 after Destroy")

	err = ss.Access(func(_ []byte) error { return nil })
	assert.ErrorIs(t, err, ErrBufferDestroyed, "Access should fail after Destroy")
}

func TestSecureString_FromReader(t *testing.T) {
	// Simulate a stream (e.g., file or stdin)
	secretData := "streamed-password-value"
	reader := strings.NewReader(secretData)

	// Create from reader (verifies the fix for the missing return statement)
	ss, err := NewSecureStringFromReader(reader, len(secretData))
	require.NoError(t, err)
	defer func() { _ = ss.Destroy() }()

	assert.Equal(t, len(secretData), ss.Len())
	assert.Equal(t, secretData, ss.DangerousStringCopy())
}

func TestSecureString_Compare(t *testing.T) {
	s1, _ := NewSecureStringFromInsecure("secret1")
	s2, _ := NewSecureStringFromInsecure("secret1") // Same content, diff object
	s3, _ := NewSecureStringFromInsecure("secret2") // Diff content
	defer func() {
		_ = s1.Destroy()
		_ = s2.Destroy()
		_ = s3.Destroy()
	}()

	// Equality check (Nested Access deadlock check)
	assert.True(t, s1.Compare(s2), "Identical strings should return true")
	assert.True(t, s2.Compare(s1), "Commutative comparison failed")

	// Inequality check
	assert.False(t, s1.Compare(s3), "Different strings should return false")

	// Self check
	// Gocritic: We precisely test (s1 == s1)
	//nolint:gocritic
	assert.True(t, s1.Compare(s1), "Self comparison should return true")

	// Destroyed check
	_ = s3.Destroy()
	assert.False(t, s1.Compare(s3), "Comparison with destroyed string should return false")
}

func TestSecureBuffer_AccessWipesInput(t *testing.T) {
	originalData := []byte("highly-sensitive-data-in-ram")

	// Make a copy because NewSecureBufferFromBytes MUST wipe the input array
	dataToPass := make([]byte, len(originalData))
	copy(dataToPass, originalData)

	sb, err := NewSecureBufferFromBytes(dataToPass)
	require.NoError(t, err, "Failed to create secure buffer")
	defer func() { _ = sb.Destroy() }()

	// Verify that the buffer correctly stored the data
	err = sb.Access(func(b []byte) error {
		assert.Equal(t, originalData, b, "Access callback got wrong data")
		return nil
	})
	assert.NoError(t, err, "Access failed")

	// SECURITY CHECK: Prove that NewSecureBufferFromBytes wiped the input array!
	expectedWiped := make([]byte, len(originalData)) // Array of purely 0x00
	assert.Equal(t, expectedWiped, dataToPass, "CRITICAL: Input data array was not wiped by the constructor!")
}

func TestSecureBuffer_DestroyedAccess(t *testing.T) {
	sb, err := NewSecureBufferFromBytes([]byte("temporary-secret"))
	require.NoError(t, err)

	err = sb.Access(func(_ []byte) error { return nil })
	require.NoError(t, err)

	_ = sb.Destroy()

	err = sb.Access(func(_ []byte) error { return nil })
	assert.ErrorIs(t, err, ErrBufferDestroyed, "Accessing a destroyed buffer must return ErrBufferDestroyed")
}

func TestSecurePassword_CompareAndWipe(t *testing.T) {
	passwordInput := []byte("master-key-1234")
	passCopy := make([]byte, len(passwordInput))
	copy(passCopy, passwordInput)

	sp, err := NewSecurePasswordFromBytes(passCopy)
	require.NoError(t, err)
	defer func() { _ = sp.Destroy() }()

	// Check Input wiping
	expectedWiped := make([]byte, len(passwordInput))
	assert.Equal(t, expectedWiped, passCopy, "SecurePassword constructor did not wipe input array")

	// Check length
	assert.Equal(t, len(passwordInput), sp.Len())

	// Test Compare using WithPassword
	var match bool
	err = sp.WithPassword(func(b []byte) error {
		match = SecureCompare(b, passwordInput)
		return nil
	})
	require.NoError(t, err)
	assert.True(t, match, "WithPassword read corrupted data")
}

// TestSecureBuffer_ConcurrentAccess proves that our Early-Unlock fix in Access()
// works perfectly and prevents deadlocks during high concurrency.
func TestSecureBuffer_ConcurrentAccess(t *testing.T) {
	originalData := []byte("concurrent_secret")
	dataToPass := make([]byte, len(originalData))
	copy(dataToPass, originalData)

	sb, err := NewSecureBufferFromBytes(dataToPass)
	require.NoError(t, err, "Failed to create secure buffer")
	defer func() { _ = sb.Destroy() }()

	var wg sync.WaitGroup
	workers := 50

	// Semaphore to prevent OS VirtualLock/mlock quota exhaustion.
	// memguard locks memory pages in RAM. Doing this 50 times concurrently
	// instantly crashes Windows/Linux due to strict user quota limits.
	// We limit active hardware locks to 10 at a time.
	maxConcurrentHardwareLocks := 10
	sem := make(chan struct{}, maxConcurrentHardwareLocks)

	// Launch 50 goroutines trying to access the Enclave
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire hardware lock token
			sem <- struct{}{}
			defer func() { <-sem }()

			err := sb.Access(func(b []byte) error {
				assert.True(t, bytes.Equal(b, originalData), "Concurrent access read corrupted data")
				return nil
			})
			assert.NoError(t, err, "Concurrent access failed")
		}()
	}

	// Wait for all goroutines to finish. If there is a deadlock, the test will timeout.
	wg.Wait()
}
