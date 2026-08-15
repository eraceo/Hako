// Package secrets provides the core data structures and RAM-level encryption
// (ephemeral secrets) for securely managing vault entries in memory without
// exhausting OS memory lock quotas.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	hakoBinary "github.com/eraceo/Hako/internal/encoding/tlv"
	"github.com/eraceo/Hako/internal/memory"
)

// Standardize Sentinel Errors to prevent heap-allocated dynamic errors.
var (
	ErrCorruptedSecret = errors.New("corrupted ephemeral secret")
	ErrTooManyEntries  = errors.New("too many entries")
)

// Global ephemeral AES-GCM key per CLI execution session.
var (
	ephemeralAEAD         cipher.AEAD
	ephemeralNonceCounter uint64
	ephemeralOnce         sync.Once
)

// plaintextBufferPool reuses decryption buffers to prevent allocation churn
// during massive vault saves or searches.
// SECURITY: We pool pointers (*[]byte) to avoid interface{} heap allocations (SA6002).
var plaintextBufferPool = sync.Pool{
	New: func() interface{} {
		// Default to 1KB, capable of holding most secrets/URLs
		b := make([]byte, 1024)
		return &b
	},
}

func getEphemeralAEAD() cipher.AEAD {
	ephemeralOnce.Do(func() {
		key := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			panic("hako: failed to generate ephemeral RAM key: " + err.Error())
		}

		block, err := aes.NewCipher(key)

		// SECURITY NOTE — Accepted Risk :
		// aes.NewCipher(key) expands `key` into AES-256 round keys stored in
		// aesCipher.enc and aesCipher.dec — two []uint32 heap allocations totalling
		// ~240 bytes (15 rounds × 4 uint32 × 4 bytes). These round keys are
		// cryptographically equivalent to the original key material.
		// memory.SecureZero(key) wipes the original 32-byte slice only. The expanded
		// round keys in aesCipher are unreachable via the public cipher.Block interface
		// and persist on the Go heap for the entire process lifetime.
		// This is an accepted limitation of crypto/aes in Go (no public key schedule
		// zeroing API). EphemeralSecrets exist solely to bypass OS mlock quota crashes
		// when decrypting thousands of vault entries — they do not claim to resist a
		// live root-level attacker. The master password and root key remain exclusively
		// in mlock'd Memguard enclaves, which is the correct security boundary for
		// Hako's threat model.
		memory.SecureZero(key) // Wipe original key immediately after schedule expansion

		if err != nil {
			// aes.NewCipher only fails for invalid key sizes. A hardcoded 32-byte key
			// cannot trigger this — but the check is kept for compiler/vet compliance.
			panic("hako: failed to init ephemeral block: " + err.Error())
		}

		var errGCM error
		ephemeralAEAD, errGCM = cipher.NewGCM(block)
		if errGCM != nil {
			panic("hako: failed to init ephemeral GCM: " + errGCM.Error())
		}
	})
	return ephemeralAEAD
}

// EphemeralSecret holds sensitive data encrypted in RAM (Heap).
// It solves the OS limit issue of Memguard by using a session-bound AES-GCM key.
type EphemeralSecret []byte

// NewEphemeralSecret encrypts plaintext using the session's ephemeral key.
func NewEphemeralSecret(plaintext []byte) EphemeralSecret {
	if len(plaintext) == 0 {
		return nil
	}
	aead := getEphemeralAEAD()
	nonceSize := aead.NonceSize()

	// SECURITY: Pre-allocate (Nonce + Plaintext + Overhead).
	// This forces aead.Seal to execute In-Place to avoid hidden heap allocations.
	buf := make([]byte, nonceSize+len(plaintext)+aead.Overhead())
	nonce := buf[:nonceSize]

	// Use an atomic counter instead of rand.Reader to guarantee zero collisions
	// during a single session and avoid unnecessary system calls.
	counter := atomic.AddUint64(&ephemeralNonceCounter, 1)
	binary.LittleEndian.PutUint64(nonce, counter)

	// #nosec G407 -- Counter-based nonces are secure for ephemeral memory-only enclaves
	aead.Seal(buf[:nonceSize], nonce, plaintext, nil)
	return EphemeralSecret(buf)
}

// PlaintextLen returns the length of the underlying plaintext.
func (s EphemeralSecret) PlaintextLen() int {
	if len(s) == 0 {
		return 0
	}
	aead := getEphemeralAEAD()
	return len(s) - aead.NonceSize() - aead.Overhead()
}

// Access safely decrypts the secret into a temporary buffer.
// It uses a sync.Pool to reuse buffers, drastically reducing GC pressure during Save/Search.
func (s EphemeralSecret) Access(cb func(plaintext []byte) error) error {
	if len(s) == 0 {
		return cb(nil)
	}
	aead := getEphemeralAEAD()
	if len(s) < aead.NonceSize() {
		return ErrCorruptedSecret
	}

	nonce := s[:aead.NonceSize()]
	ciphertext := s[aead.NonceSize():]

	// Calculate required size
	reqSize := len(ciphertext) - aead.Overhead()

	// Get buffer pointer from pool to prevent SA6002 allocation
	ptrPtr := plaintextBufferPool.Get().(*[]byte)
	ptr := *ptrPtr

	// Ensure capacity
	if cap(ptr) < reqSize {
		ptr = make([]byte, reqSize)
	}
	ptBuf := ptr[:reqSize]

	// Security: Always wipe full capacity and return the buffer to pool after use
	defer func() {
		fullBuf := ptr[:cap(ptr)]
		memory.SecureZero(fullBuf)

		// Prevent oversized buffers from bloating the pool
		const maxPooledCap = 64 * 1024 // 64 KB
		if cap(ptr) <= maxPooledCap {
			ptr = ptr[:0]
			*ptrPtr = ptr
			plaintextBufferPool.Put(ptrPtr)
		}
	}()

	plaintext, err := aead.Open(ptBuf[:0], nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("ephemeral decrypt failed: %w", err)
	}

	return cb(plaintext)
}

// Entry represents a secure password entry in the vault.
type Entry struct {
	ID        EntryID
	Name      string
	Username  EphemeralSecret
	Password  EphemeralSecret
	URL       EphemeralSecret
	Notes     EphemeralSecret
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Vault represents the complete vault structure holding all entries.
type Vault struct {
	Entries []*Entry
	Meta    VaultMeta
}

// VaultMeta contains vault metadata.
type VaultMeta struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	Version   string
}

// Zero securely wipes all entries in the vault from RAM.
func (v *Vault) Zero() {
	for _, entry := range v.Entries {
		if entry != nil {
			entry.Zero()
		}
	}
	// Clear the slice to remove references
	v.Entries = nil
}

// Size returns the size in bytes of the serialized vault.
func (v *Vault) Size() int {
	size := (4 + 8) + (4 + 8) + 4 + len(v.Meta.Version) + 4
	for _, e := range v.Entries {
		if e == nil {
			continue
		}
		size += e.Size()
	}
	return size
}

// MarshalBinary implements BinaryMarshaler using zero-allocation Encoder.
func (v *Vault) MarshalBinary(e *hakoBinary.Encoder) error {
	if err := e.WriteTime(v.Meta.CreatedAt); err != nil {
		return fmt.Errorf("write meta created_at: %w", err)
	}
	if err := e.WriteTime(v.Meta.UpdatedAt); err != nil {
		return fmt.Errorf("write meta updated_at: %w", err)
	}
	if err := e.WriteString(v.Meta.Version); err != nil {
		return fmt.Errorf("write meta version: %w", err)
	}

	if len(v.Entries) > math.MaxUint32 {
		return ErrTooManyEntries
	}
	// #nosec G115 -- Checked bounds above
	if err := e.WriteLength(uint32(len(v.Entries))); err != nil {
		return fmt.Errorf("write entry count: %w", err)
	}

	for _, entry := range v.Entries {
		if entry == nil {
			continue
		}
		if err := entry.MarshalBinary(e); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalBinary implements BinaryUnmarshaler using zero-allocation Decoder.
func (v *Vault) UnmarshalBinary(d *hakoBinary.Decoder) error {
	var err error
	if v.Meta.CreatedAt, err = d.ReadTime(); err != nil {
		return fmt.Errorf("read meta created_at: %w", err)
	}
	if v.Meta.UpdatedAt, err = d.ReadTime(); err != nil {
		return fmt.Errorf("read meta updated_at: %w", err)
	}
	if v.Meta.Version, err = d.ReadString(); err != nil {
		return fmt.Errorf("read meta version: %w", err)
	}

	count, err := d.ReadLength()
	if err != nil {
		return fmt.Errorf("read entry count: %w", err)
	}
	// Hard limit to prevent OOM attacks (100k entries)
	if count > 100000 {
		return fmt.Errorf("%w: %d", ErrTooManyEntries, count)
	}

	v.Entries = make([]*Entry, 0, count)
	for i := uint32(0); i < count; i++ {
		entry := &Entry{}
		if err := entry.UnmarshalBinary(d); err != nil {
			// Wipe partially loaded data on error
			v.Zero()
			entry.Zero()
			return fmt.Errorf("unmarshal entry %d: %w", i, err)
		}
		v.Entries = append(v.Entries, entry)
	}
	return nil
}

// Size returns the exact plaintext size in bytes.
func (e *Entry) Size() int {
	if e == nil {
		return 0
	}
	size := 0
	size += 1 + 4 + len(e.ID)
	size += 1 + 4 + len(e.Name)
	size += 1 + 4 + e.Username.PlaintextLen()
	size += 1 + 4 + e.Password.PlaintextLen()
	size += 1 + 4 + e.URL.PlaintextLen()
	size += 1 + 4 + e.Notes.PlaintextLen()

	for _, t := range e.Tags {
		size += 1 + 4 + len(t)
	}

	size += 2 * (1 + 4 + 8) // Timestamps (Tag 1B + Length 4B + Unix 8B)
	size++                  // EndOfEntry
	return size
}

// MarshalBinary serializes the Entry securely.
func (e *Entry) MarshalBinary(enc *hakoBinary.Encoder) error {
	if err := e.writeStringField(enc, hakoBinary.TagID, string(e.ID)); err != nil {
		return err
	}
	if err := e.writeStringField(enc, hakoBinary.TagName, e.Name); err != nil {
		return err
	}
	if err := e.writeEphemeralField(enc, hakoBinary.TagUsername, e.Username); err != nil {
		return err
	}
	if err := e.writeEphemeralField(enc, hakoBinary.TagPassword, e.Password); err != nil {
		return err
	}
	if err := e.writeEphemeralField(enc, hakoBinary.TagURL, e.URL); err != nil {
		return err
	}
	if err := e.writeEphemeralField(enc, hakoBinary.TagNotes, e.Notes); err != nil {
		return err
	}

	for _, tag := range e.Tags {
		if err := e.writeStringField(enc, hakoBinary.TagTags, tag); err != nil {
			return err
		}
	}

	if err := e.writeTimeField(enc, hakoBinary.TagCreatedAt, e.CreatedAt); err != nil {
		return err
	}
	if err := e.writeTimeField(enc, hakoBinary.TagUpdatedAt, e.UpdatedAt); err != nil {
		return err
	}

	return enc.WriteTag(hakoBinary.TagEndOfEntry)
}

func (e *Entry) writeStringField(enc *hakoBinary.Encoder, tag byte, s string) error {
	if err := enc.WriteTag(tag); err != nil {
		return err
	}
	return enc.WriteString(s)
}

func (e *Entry) writeEphemeralField(enc *hakoBinary.Encoder, tag byte, secret EphemeralSecret) error {
	if err := enc.WriteTag(tag); err != nil {
		return err
	}
	// Bypass memguard: Write decrypted bytes directly to the encoder
	return secret.Access(func(plaintext []byte) error {
		return enc.WriteBytes(plaintext)
	})
}

func (e *Entry) writeTimeField(enc *hakoBinary.Encoder, tag byte, t time.Time) error {
	if err := enc.WriteTag(tag); err != nil {
		return err
	}
	return enc.WriteTime(t)
}

// UnmarshalBinary reads the entry and converts sensitive data straight to Ephemeral Secrets.
func (e *Entry) UnmarshalBinary(d *hakoBinary.Decoder) error {
	for {
		tag, err := d.ReadTag()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if tag == hakoBinary.TagEndOfEntry {
			break
		}
		if err := e.readField(d, tag); err != nil {
			return err
		}
	}
	return nil
}

func (e *Entry) readField(d *hakoBinary.Decoder, tag byte) error {
	var err error
	switch tag {
	case hakoBinary.TagID:
		var idStr string
		idStr, err = d.ReadString()
		e.ID = EntryID(idStr)
	case hakoBinary.TagName:
		e.Name, err = d.ReadString()
	case hakoBinary.TagUsername:
		e.Username, err = readEphemeralSecret(d)
	case hakoBinary.TagPassword:
		e.Password, err = readEphemeralSecret(d)
	case hakoBinary.TagURL:
		e.URL, err = readEphemeralSecret(d)
	case hakoBinary.TagNotes:
		e.Notes, err = readEphemeralSecret(d)
	case hakoBinary.TagTags:
		var tagStr string
		tagStr, err = d.ReadString()
		if err == nil {
			e.Tags = append(e.Tags, tagStr)
		}
	case hakoBinary.TagCreatedAt:
		e.CreatedAt, err = d.ReadTime()
	case hakoBinary.TagUpdatedAt:
		e.UpdatedAt, err = d.ReadTime()
	default:
		// Unknown tag: skip
		var length uint32
		if length, err = d.ReadLength(); err == nil && length > 0 {
			err = d.Skip(length)
		}
	}
	return err
}

func readEphemeralSecret(d *hakoBinary.Decoder) (EphemeralSecret, error) {
	// Zero-allocation read: pts points DIRECTLY to the decrypted Memguard buffer
	pt, err := d.ReadBytes()
	if err != nil {
		return nil, err
	}
	if len(pt) == 0 {
		return nil, nil
	}

	// Encrypt immediately into Heap (EphemeralSecret)
	es := NewEphemeralSecret(pt)

	// SECURITY: Shred the plaintext in the source buffer immediately.
	// Since 'pt' is a slice of the main decrypted vault buffer, this aggressively
	// zeroes out the secret from the master buffer as soon as we've read it.
	memory.SecureZero(pt)

	return es, nil
}

// NewEntry creates a new password entry with strict validation.
// Sensitive fields MUST be passed as []byte to prevent string heap leaks.
func NewEntry(name string, username, password, urlBytes, notes []byte, tags []string) (*Entry, error) {
	// Defensively wipe all sensitive input slices
	defer memory.SecureZero(username)
	defer memory.SecureZero(password)
	defer memory.SecureZero(urlBytes)
	defer memory.SecureZero(notes)

	validator := NewValidator()

	// Clean public strings
	name = RemoveControlChars(name)
	var sanitizedTags []string
	if tags != nil {
		sanitizedTags = make([]string, len(tags))
		for i, tag := range tags {
			sanitizedTags[i] = RemoveControlChars(tag)
		}
	}

	if err := validator.ValidateEntry(name, username, password, urlBytes, notes, sanitizedTags); err != nil {
		return nil, fmt.Errorf("invalid entry data: %w", err)
	}

	now := time.Now()
	return &Entry{
		ID:        NewEntryID(),
		Name:      name,
		Username:  NewEphemeralSecret(username),
		Password:  NewEphemeralSecret(password),
		URL:       NewEphemeralSecret(urlBytes),
		Notes:     NewEphemeralSecret(notes),
		Tags:      sanitizedTags,
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// Zero securely wipes the ephemeral ciphertexts and metadata from RAM.
func (e *Entry) Zero() {
	if e == nil {
		return
	}
	if len(e.Password) > 0 {
		memory.SecureZero(e.Password)
		e.Password = nil
	}
	if len(e.Username) > 0 {
		memory.SecureZero(e.Username)
		e.Username = nil
	}
	if len(e.URL) > 0 {
		memory.SecureZero(e.URL)
		e.URL = nil
	}
	if len(e.Notes) > 0 {
		memory.SecureZero(e.Notes)
		e.Notes = nil
	}
	if len(e.Tags) > 0 {
		for i := range e.Tags {
			e.Tags[i] = ""
		}
		e.Tags = nil
	}
	e.Name = ""
}

// Clone creates a deep copy of the entry securely.
func (e *Entry) Clone() (*Entry, error) {
	newEntry := &Entry{
		ID:        e.ID,
		Name:      e.Name,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}

	if e.Tags != nil {
		newEntry.Tags = make([]string, len(e.Tags))
		copy(newEntry.Tags, e.Tags)
	}

	cloneSecret := func(s EphemeralSecret) EphemeralSecret {
		if len(s) == 0 {
			return nil
		}
		c := make([]byte, len(s))
		copy(c, s)
		return EphemeralSecret(c)
	}

	newEntry.Username = cloneSecret(e.Username)
	newEntry.Password = cloneSecret(e.Password)
	newEntry.URL = cloneSecret(e.URL)
	newEntry.Notes = cloneSecret(e.Notes)

	return newEntry, nil
}

// NewVault creates a new empty vault.
func NewVault() *Vault {
	now := time.Now()
	return &Vault{
		Entries: make([]*Entry, 0),
		Meta: VaultMeta{
			CreatedAt: now,
			UpdatedAt: now,
			Version:   "1.0",
		},
	}
}

// AddEntry securely adds an entry to the vault.
func (v *Vault) AddEntry(entry *Entry) {
	if entry == nil {
		return
	}
	v.Entries = append(v.Entries, entry)
	v.Meta.UpdatedAt = time.Now()
}

// GetEntryByID retrieves an entry by its unique ID.
func (v *Vault) GetEntryByID(id EntryID) *Entry {
	for _, entry := range v.Entries {
		if entry.ID == id {
			return entry
		}
	}
	return nil
}

// GetEntryByName retrieves an entry by its exact name.
func (v *Vault) GetEntryByName(name string) *Entry {
	for _, entry := range v.Entries {
		if entry.Name == name {
			return entry
		}
	}
	return nil
}

// RemoveEntryByID securely removes and destroys an entry by its ID.
func (v *Vault) RemoveEntryByID(id EntryID) bool {
	for i, entry := range v.Entries {
		if entry.ID != id {
			continue
		}
		entry.Zero() // Destroy ciphertext

		copy(v.Entries[i:], v.Entries[i+1:])
		v.Entries[len(v.Entries)-1] = nil
		v.Entries = v.Entries[:len(v.Entries)-1]

		v.Meta.UpdatedAt = time.Now()
		return true
	}
	return false
}

// RemoveEntryByName securely removes and destroys an entry by its name.
func (v *Vault) RemoveEntryByName(name string) bool {
	for i, entry := range v.Entries {
		if entry.Name != name {
			continue
		}
		entry.Zero() // Destroy ciphertext

		copy(v.Entries[i:], v.Entries[i+1:])
		v.Entries[len(v.Entries)-1] = nil
		v.Entries = v.Entries[:len(v.Entries)-1]

		v.Meta.UpdatedAt = time.Now()
		return true
	}
	return false
}

// UpdateEntry securely replaces an existing entry.
func (v *Vault) UpdateEntry(id EntryID, updatedEntry *Entry) bool {
	replaceEntry := func(index int, oldEntry *Entry) {
		if oldEntry != updatedEntry {
			oldEntry.Zero()
		}
		updatedEntry.ID = oldEntry.ID
		updatedEntry.CreatedAt = oldEntry.CreatedAt
		updatedEntry.UpdatedAt = time.Now()
		v.Entries[index] = updatedEntry
		v.Meta.UpdatedAt = time.Now()
	}

	for i, entry := range v.Entries {
		if entry.ID != id {
			continue
		}
		replaceEntry(i, entry)
		return true
	}
	return false
}

// ListEntries returns all entries, optionally filtered by tags.
func (v *Vault) ListEntries(filterTags []string) []*Entry {
	if len(filterTags) == 0 {
		return v.Entries
	}

	var filtered []*Entry
	for _, entry := range v.Entries {
		if hasAnyTag(entry.Tags, filterTags) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// SearchEntries performs an in-memory secure fuzzy search.
func (v *Vault) SearchEntries(pattern string) []*Entry {
	var results []*Entry
	if pattern == "" {
		return results
	}

	patternLower := strings.ToLower(pattern)

	for _, entry := range v.Entries {
		match := false

		if strings.Contains(strings.ToLower(entry.Name), patternLower) {
			match = true
		}

		// Decrypt sensitive fields temporarily for search
		if !match && len(entry.Username) > 0 {
			_ = entry.Username.Access(func(data []byte) error {
				if containsBytes(data, patternLower) {
					match = true
				}
				return nil
			})
		}

		if !match && len(entry.URL) > 0 {
			_ = entry.URL.Access(func(data []byte) error {
				if containsBytes(data, patternLower) {
					match = true
				}
				return nil
			})
		}

		if match {
			results = append(results, entry)
		}
	}
	return results
}

func hasAnyTag(entryTags, filterTags []string) bool {
	for _, filterTag := range filterTags {
		for _, entryTag := range entryTags {
			if strings.EqualFold(entryTag, filterTag) {
				return true
			}
		}
	}
	return false
}

// containsBytes performs a zero-allocation ASCII case-insensitive search.
func containsBytes(data []byte, patLower string) bool {
	patLen := len(patLower)
	dataLen := len(data)

	if patLen == 0 || patLen > dataLen {
		return false
	}

	for i := 0; i <= dataLen-patLen; i++ {
		match := true
		for j := 0; j < patLen; j++ {
			b := data[i+j]
			if b >= 'A' && b <= 'Z' {
				b += 32 // ToLower for ASCII
			}
			// Safe byte comparison against lower-cased pattern string
			if b != patLower[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
