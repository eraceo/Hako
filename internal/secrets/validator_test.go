package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError_Error(t *testing.T) {
	err := Error{Field: "password", Message: "too short"}
	assert.Equal(t, "validation error for field 'password': too short", err.Error())
}

func TestValidateName(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid standard name", "test-entry_1", false},
		{"empty name", "", true},
		{"too long name", strings.Repeat("a", MaxNameLength+1), true},
		{"valid with special characters", "My@Bank Account!", false},
		{"valid with unicode", "Crédit Agricole 🏦", false},
		{"invalid with null byte", "test\x00entry", true},
		{"invalid with control char", "test\nentry", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateName(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateUsername(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"valid standard username", []byte("johndoe"), false},
		{"valid email", []byte("john.doe@example.com"), false},
		{"valid email with alias", []byte("john+spam@example.com"), false},
		{"empty username", []byte(""), false}, // Optional
		{"too long username", []byte(strings.Repeat("a", MaxUsernameLength+1)), true},
		{"valid spaces", []byte("john doe"), false},
		{"valid characters", []byte("john!doe"), false},
		{"valid unicode username", []byte("иван_петров"), false},
		{"invalid with control char", []byte("john\ndoe"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateUsername(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"valid password", []byte("securepassword123"), false},
		{"empty password", []byte(""), true},
		{"valid short password", []byte("short"), false},
		{"too long password", []byte(strings.Repeat("a", MaxPasswordLength+1)), true},
		{"invalid utf8 sequence", []byte{0xff, 0xfe, 0xfd}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidatePassword(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMasterPassword(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"valid master password", []byte("securepassword123"), false},
		{"empty master password", []byte(""), true},
		{"too short master password", []byte("short"), true},
		{"too long master password", []byte(strings.Repeat("a", MaxPasswordLength+1)), true},
		{"minimum length master password", []byte(strings.Repeat("a", MinPasswordLength)), false},
		{"invalid utf8 sequence", []byte{0xff, 0xfe, 0xfd}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateMasterPassword(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"valid https URL", []byte("https://example.com"), false},
		{"valid http URL", []byte("http://example.com"), false},
		{"empty URL", []byte(""), false}, // URL is optional
		{"too long URL", []byte("https://" + strings.Repeat("a", MaxURLLength)), true},
		{"invalid URL", []byte("not-a-url"), true},
		{"URL without scheme", []byte("example.com"), true},
		{"valid ftp scheme", []byte("ftp://example.com"), false},
		{"invalid javascript scheme", []byte("javascript:alert(1)"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateURL(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateNotes(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{"valid notes", []byte("Some important notes\nLine 2"), false},
		{"empty notes", []byte(""), false}, // Optional
		{"too long notes", []byte(strings.Repeat("a", MaxNotesLength+1)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateNotes(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTags(t *testing.T) {
	validator := NewValidator()

	// Safely generate too many tags without duplicates
	tooManyTags := make([]string, MaxTagsCount+1)
	for i := range tooManyTags {
		tooManyTags[i] = fmt.Sprintf("tag%d", i)
	}

	tests := []struct {
		name    string
		input   []string
		wantErr bool
	}{
		{"valid tags", []string{"work", "important", "env-prod"}, false},
		{"empty tags slice", []string{}, false},
		{"too many tags", tooManyTags, true},
		{"duplicate tags exact", []string{"work", "work"}, true},
		{"duplicate tags case insensitive", []string{"Work", "work"}, true},
		{"empty tag element", []string{"work", ""}, true},
		{"too long tag", []string{strings.Repeat("a", MaxTagLength+1)}, true},
		{"invalid tag characters", []string{"work@home"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateTags(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateEntry(t *testing.T) {
	validator := NewValidator()

	t.Run("valid full entry", func(t *testing.T) {
		err := validator.ValidateEntry(
			"My Bank",
			[]byte("user@bank.com"),
			[]byte("SuperSecretP4ssw0rd!"),
			[]byte("https://bank.com"),
			[]byte("Account number: 123"),
			[]string{"finance", "personal"},
		)
		assert.NoError(t, err)
	})

	t.Run("invalid field triggers error", func(t *testing.T) {
		err := validator.ValidateEntry(
			"", // Empty name triggers error
			[]byte("user@bank.com"),
			[]byte("SuperSecretP4ssw0rd!"),
			[]byte("https://bank.com"),
			[]byte(""),
			nil,
		)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})
}

func TestRemoveControlChars(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"  hello  ", "hello"}, // Trims outer spaces
		{"hello\nworld", "hello\nworld"},
		{"hello\tworld", "hello\tworld"},
		{"hello\rworld", "hello\rworld"},
		{"hello\x00world", "helloworld"},
		{"hello\x1b[31mworld", "hello[31mworld"}, // ANSI escape code broken (ESC removed)
	}

	for _, test := range tests {
		result := RemoveControlChars(test.input)
		assert.Equal(t, test.expected, result)
	}
}

func BenchmarkValidateEntry(b *testing.B) {
	validator := NewValidator()
	password := []byte("securepassword123")
	username := []byte("testuser")
	url := []byte("https://example.com")
	notes := []byte("Some notes")
	tags := []string{"work", "important"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = validator.ValidateEntry(
			"test-entry",
			username,
			password,
			url,
			notes,
			tags,
		)
	}
}
