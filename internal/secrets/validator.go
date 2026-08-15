// Package secrets provides the core data structures and RAM-level encryption
// (ephemeral secrets) for securely managing vault entries in memory without
// exhausting OS memory lock quotas.
package secrets

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

const (
	// MaxNameLength is the maximum allowed length for entry names to prevent DoS.
	MaxNameLength = 100
	// MaxUsernameLength is the maximum allowed length for usernames to prevent DoS.
	MaxUsernameLength = 100
	// MaxPasswordLength is the maximum allowed length for passwords to prevent DoS.
	MaxPasswordLength = 1000
	// MaxURLLength is the maximum allowed length for URLs to prevent DoS.
	MaxURLLength = 2048
	// MaxNotesLength is the maximum allowed length for notes to prevent DoS.
	MaxNotesLength = 10000
	// MaxTagLength is the maximum allowed length for tags to prevent DoS.
	MaxTagLength = 50
	// MaxTagsCount is the maximum number of tags allowed per entry.
	MaxTagsCount = 20

	// MinPasswordLength is the minimum required length for passwords.
	MinPasswordLength = 8
	// MinNameLength is the minimum required length for entry names.
	MinNameLength = 1
)

var (
	// tagRegex strictly limits tags to alphanumeric and basic separators.
	// This implicitly enforces ASCII, making subsequent UTF-8 checks redundant.
	tagRegex = regexp.MustCompile(`^[-a-zA-Z0-9._]+$`)

	// allowedURLSchemes defines the whitelist of accepted URL protocols.
	// Must be strictly lowercase to match url.Parse behavior.
	allowedURLSchemes = []string{"http", "https", "ftp", "ftps", "ssh", "ldap", "ldaps"}
)

// Error represents a business rule violation for a specific field.
type Error struct {
	Field   string
	Message string
}

// Error implements the standard error interface.
func (e Error) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s", e.Field, e.Message)
}

// Validator handles business rule validation for Vault entries.
type Validator struct{}

// NewValidator creates and returns a new Validator instance.
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateName validates an entry name (Title).
// Name is a public TLV string (0x02), so accepting a Go string is safe here.
func (v *Validator) ValidateName(name string) error {
	if name == "" {
		return Error{Field: "name", Message: "name cannot be empty"}
	}

	if !utf8.ValidString(name) {
		return Error{Field: "name", Message: "name contains invalid UTF-8 characters"}
	}

	if utf8.RuneCountInString(name) > MaxNameLength {
		return Error{
			Field:   "name",
			Message: fmt.Sprintf("name too long (max %d characters)", MaxNameLength),
		}
	}

	// Reject control characters (like newlines or null bytes) in the title
	for _, r := range name {
		if unicode.IsControl(r) {
			return Error{Field: "name", Message: "name cannot contain control characters"}
		}
	}

	return nil
}

// ValidateUsername validates a username strictly from bytes.
// It allows any valid UTF-8 printable graphic character but rejects control characters.
func (v *Validator) ValidateUsername(username []byte) error {
	if len(username) == 0 {
		return nil // Username is optional
	}

	if !utf8.Valid(username) {
		return Error{Field: "username", Message: "username contains invalid UTF-8 characters"}
	}

	if utf8.RuneCount(username) > MaxUsernameLength {
		return Error{
			Field:   "username",
			Message: fmt.Sprintf("username too long (max %d characters)", MaxUsernameLength),
		}
	}

	// Iterate over runes in the byte slice to reject control characters
	for i := 0; i < len(username); {
		r, size := utf8.DecodeRune(username[i:])
		if unicode.IsControl(r) {
			return Error{Field: "username", Message: "username cannot contain control characters"}
		}
		i += size
	}

	return nil
}

// ValidatePassword validates a password directly from a byte slice.
func (v *Validator) ValidatePassword(password []byte) error {
	if len(password) == 0 {
		return Error{Field: "password", Message: "password cannot be empty"}
	}

	if !utf8.Valid(password) {
		return Error{Field: "password", Message: "password contains invalid UTF-8 characters"}
	}

	runeCount := utf8.RuneCount(password)

	if runeCount > MaxPasswordLength {
		return Error{
			Field:   "password",
			Message: fmt.Sprintf("password too long (max %d characters)", MaxPasswordLength),
		}
	}

	return nil
}

// ValidateMasterPassword validates a master password directly from a byte slice,
// enforcing a minimum length of 8 characters for security.
func (v *Validator) ValidateMasterPassword(password []byte) error {
	if err := v.ValidatePassword(password); err != nil {
		return err
	}

	runeCount := utf8.RuneCount(password)
	if runeCount < MinPasswordLength {
		return Error{
			Field:   "password",
			Message: fmt.Sprintf("master password too short (min %d characters)", MinPasswordLength),
		}
	}

	return nil
}

// ValidateURL validates a web or service URL directly from bytes.
func (v *Validator) ValidateURL(urlBytes []byte) error {
	if len(urlBytes) == 0 {
		return nil // URL is optional
	}

	if !utf8.Valid(urlBytes) {
		return Error{Field: "url", Message: "URL contains invalid UTF-8 characters"}
	}

	if utf8.RuneCount(urlBytes) > MaxURLLength {
		return Error{
			Field:   "url",
			Message: fmt.Sprintf("URL too long (max %d characters)", MaxURLLength),
		}
	}

	// Zero-Allocation String (unsafe): Standard library requires string.
	// We create a temporary string pointer strictly bounded to this function's lifecycle
	// to prevent heap allocation of the sensitive base URL.
	//
	// SECURITY NOTICE: While `unsafe.String` avoids the initial allocation,
	// `url.ParseRequestURI` MAY allocate new strings on the Heap if it needs to
	// unescape characters (e.g., "%20" -> " "). If the URL contains sensitive data
	// in escaped form, it might leak to the Heap via `net/url`.
	// We accept this risk as implementing a custom zero-alloc RFC3986 parser is
	// more dangerous than relying on the standard library.
	//
	// #nosec G103 -- Zero-allocation string conversion strictly required.
	unsafeURL := unsafe.String(unsafe.SliceData(urlBytes), len(urlBytes))

	parsedURL, err := url.ParseRequestURI(unsafeURL)
	if err != nil {
		// Do not return the error itself as it might contain the sensitive URL string
		return Error{Field: "url", Message: "invalid URL format"}
	}

	// ParseRequestURI validates absolute URIs, so Scheme should be present.
	// However, it allows absolute paths (e.g. "/foo"), which have empty schemes.
	// We strictly require a scheme to prevent ambiguous relative paths.
	if parsedURL.Scheme == "" {
		return Error{Field: "url", Message: "URL must include a scheme (http, https, etc.)"}
	}

	// Validate scheme without allocating a new lower-cased string.
	// net/url guarantees parsedURL.Scheme is lower-cased.
	isValidScheme := false
	for _, scheme := range allowedURLSchemes {
		if parsedURL.Scheme == scheme {
			isValidScheme = true
			break
		}
	}

	if !isValidScheme {
		return Error{Field: "url", Message: "unsupported URL scheme"}
	}

	return nil
}

// ValidateNotes validates the free-form notes field directly from bytes.
func (v *Validator) ValidateNotes(notes []byte) error {
	if len(notes) == 0 {
		return nil
	}

	if !utf8.Valid(notes) {
		return Error{Field: "notes", Message: "notes contain invalid UTF-8 characters"}
	}

	if utf8.RuneCount(notes) > MaxNotesLength {
		return Error{
			Field:   "notes",
			Message: fmt.Sprintf("notes too long (max %d characters)", MaxNotesLength),
		}
	}

	return nil
}

// ValidateTags validates an array of metadata tags.
// Tags are public TLV strings (0x07), so using Go strings is safe.
func (v *Validator) ValidateTags(tags []string) error {
	if len(tags) > MaxTagsCount {
		return Error{
			Field:   "tags",
			Message: fmt.Sprintf("too many tags (max %d)", MaxTagsCount),
		}
	}

	// Pre-allocate map with exact size since we checked the max count above.
	seen := make(map[string]struct{}, len(tags))

	for i, tag := range tags {
		if tag == "" {
			return Error{Field: "tags", Message: fmt.Sprintf("tag at index %d is empty", i)}
		}

		// Optimization: The regex strictly enforces ASCII characters.
		// Therefore, checking utf8.ValidString or RuneCount is redundant.
		// length in bytes == length in runes.
		if len(tag) > MaxTagLength {
			return Error{
				Field:   "tags",
				Message: fmt.Sprintf("tag '%s' too long (max %d characters)", tag, MaxTagLength),
			}
		}

		if !tagRegex.MatchString(tag) {
			return Error{
				Field:   "tags",
				Message: fmt.Sprintf("tag '%s' contains invalid characters", tag),
			}
		}

		// Check for duplicates (case-insensitive)
		// Since tags are public metadata, allocation for ToLower is acceptable here.
		tagLower := strings.ToLower(tag)
		if _, exists := seen[tagLower]; exists {
			return Error{Field: "tags", Message: "duplicate tag detected: " + tag}
		}
		seen[tagLower] = struct{}{}
	}

	return nil
}

// ValidateEntry runs all validation checks against a complete entry payload.
// Sensitive fields MUST be passed as byte slices to prevent memory leaks.
// Explicit types used in signature for clarity.
func (v *Validator) ValidateEntry(
	name string,
	username []byte,
	password []byte,
	urlBytes []byte,
	notes []byte,
	tags []string,
) error {
	if err := v.ValidateName(name); err != nil {
		return err
	}
	if err := v.ValidateUsername(username); err != nil {
		return err
	}
	if err := v.ValidatePassword(password); err != nil {
		return err
	}
	if err := v.ValidateURL(urlBytes); err != nil {
		return err
	}
	if err := v.ValidateNotes(notes); err != nil {
		return err
	}
	if err := v.ValidateTags(tags); err != nil {
		return err
	}

	return nil
}

// RemoveControlChars strips unprintable control characters from a string,
// leaving newlines, tabs, and carriage returns intact.
// WARNING: Do NOT use this function on sensitive decrypted fields (Username, Password, etc.)
// as it requires a string and will cause Heap allocations. Use it only for Name or Tags.
func RemoveControlChars(s string) string {
	if s == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		// Keep printable chars, newlines, tabs, and carriage returns
		if !unicode.IsControl(r) || r == '\n' || r == '\t' || r == '\r' {
			b.WriteRune(r)
		}
	}

	return strings.TrimSpace(b.String())
}
