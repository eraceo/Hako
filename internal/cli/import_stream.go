package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/awnumar/memguard"

	"github.com/eraceo/Hako/internal/memory"
	"github.com/eraceo/Hako/internal/secrets"
	"github.com/eraceo/Hako/internal/ui"
)

// --- Constants & Errors ---

var (
	// ErrArenaOverflow is returned when a parsed field exceeds the arena buffer capacity.
	ErrArenaOverflow = errors.New("arena buffer overflow: entry field too large")
	// ErrInvalidFormat is returned when the input file format is malformed.
	ErrInvalidFormat = errors.New("malformed input format")
	// ErrTooManyEntries is returned when the import file exceeds the maximum allowed entries.
	ErrTooManyEntries = errors.New("import file exceeds maximum entry limit")
	// ErrFieldTooLarge is returned when a specific field exceeds the maximum size.
	ErrFieldTooLarge = errors.New("field value exceeds maximum allowed size")
	// ErrBufferInconsistency is returned when XML parsing detects corrupted bounds.
	ErrBufferInconsistency = errors.New("buffer inconsistency parsing tag")
	// ErrUnexpectedTag is returned when an unexpected closing XML tag is found.
	ErrUnexpectedTag = errors.New("unexpected closing tag")
	// ErrImportFileNotRegular is returned when the import path is not a regular file.
	ErrImportFileNotRegular = errors.New("import file must be a regular file")
)

const (
	bufferSize    = 16 * 1024
	arenaSize     = 128 * 1024
	maxEntries    = 100_000   // Hard cap to prevent DoS via huge files
	maxFieldBytes = 64 * 1024 // 64KB per field — sane upper bound for passwords/notes
)

// --- 1. Secure Streaming Reader ---

// SecureReader provides a buffered, memguard-backed reader for parsing sensitive files.
type SecureReader struct {
	file   *os.File
	buffer *memguard.LockedBuffer
	view   []byte
	offset int
	limit  int
	eof    bool
}

// NewSecureReader initializes a SecureReader for the given file path.
func NewSecureReader(filePath string) (*SecureReader, error) {
	// #nosec G304 -- User-provided path, validated by caller
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	// SECURITY: Ensure we are reading a regular file.
	// Prevents reading from block devices, named pipes, or sockets which could hang
	// the application or return infinite streams (DoS).
	stat, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to stat import file: %w", err)
	}
	if !stat.Mode().IsRegular() {
		_ = f.Close()
		return nil, ErrImportFileNotRegular
	}

	lb := memguard.NewBuffer(bufferSize)
	return &SecureReader{
		file:   f,
		buffer: lb,
		view:   lb.Bytes(),
	}, nil
}

// Close securely destroys the underlying buffer and closes the file handle.
func (r *SecureReader) Close() error {
	if r.buffer != nil {
		r.buffer.Destroy()
		r.buffer = nil
	}
	return r.file.Close()
}

func (r *SecureReader) Read(p []byte) (n int, err error) {
	if r.offset >= r.limit {
		if r.eof {
			return 0, io.EOF
		}
		if err := r.refill(); err != nil {
			return 0, err
		}
	}
	n = copy(p, r.view[r.offset:r.limit])
	r.offset += n
	return n, nil
}

// ReadByte reads and returns a single byte from the secure buffer.
func (r *SecureReader) ReadByte() (byte, error) {
	if r.offset >= r.limit {
		if r.eof {
			return 0, io.EOF
		}
		if err := r.refill(); err != nil {
			return 0, err
		}
	}
	b := r.view[r.offset]
	r.offset++
	return b, nil
}

// Peek returns the next byte without advancing the reader's offset.
func (r *SecureReader) Peek() (byte, error) {
	if r.offset >= r.limit {
		if r.eof {
			return 0, io.EOF
		}
		if err := r.refill(); err != nil {
			return 0, err
		}
	}
	return r.view[r.offset], nil
}

func (r *SecureReader) refill() error {
	r.offset = 0
	r.limit = 0
	memory.SecureZero(r.view)

	n, err := r.file.Read(r.view)
	if n > 0 {
		r.limit = n
	}
	if err != nil {
		if err == io.EOF {
			r.eof = true
			if n > 0 {
				return nil
			}
			return io.EOF
		}
		return err
	}
	return nil
}

// --- 2. Arena Buffer ---

// ArenaBuffer provides a secure, reusable memory space for parsing operations.
type ArenaBuffer struct {
	buffer *memguard.LockedBuffer
	view   []byte
	offset int
}

// NewArenaBuffer initializes a new memguard-backed arena.
func NewArenaBuffer() *ArenaBuffer {
	lb := memguard.NewBuffer(arenaSize)
	return &ArenaBuffer{
		buffer: lb,
		view:   lb.Bytes(),
	}
}

// Destroy securely wipes and frees the arena buffer.
func (a *ArenaBuffer) Destroy() {
	if a.buffer != nil {
		a.buffer.Destroy()
		a.buffer = nil
	}
}

// Reset zeros the used portion of the arena and resets the offset.
func (a *ArenaBuffer) Reset() {
	if a.offset > 0 {
		memory.SecureZero(a.view[:a.offset])
		a.offset = 0
	}
}

// AllocByte securely appends a byte to the arena buffer.
func (a *ArenaBuffer) AllocByte(b byte) error {
	if a.offset >= len(a.view) {
		return ErrArenaOverflow
	}
	a.view[a.offset] = b
	a.offset++
	return nil
}

// copyBytes returns a Go-heap copy of arena data, safe to use after arena.Reset().
// This is intentional: sensitive fields are copied into secrets.Entry which manages
// its own lifecycle; the arena is then zeroed.
func (a *ArenaBuffer) copyBytes(start, end int) []byte {
	if start >= end {
		return nil
	}
	dst := make([]byte, end-start)
	copy(dst, a.view[start:end])
	return dst
}

// --- 3. Shared Utilities ---

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

func (r *SecureReader) skipWhitespace() (byte, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		if !isSpace(b) {
			return b, nil
		}
	}
}

func (r *SecureReader) skipWhitespaceAndPeek() (byte, error) {
	for {
		b, err := r.Peek()
		if err != nil {
			return 0, err
		}
		if !isSpace(b) {
			return b, nil
		}
		_, _ = r.ReadByte()
	}
}

// --- 4. Secure CSV Importer ---

// SecureCSVImporter parses CSV files securely into Vault entries.
type SecureCSVImporter struct {
	reader *SecureReader
	arena  *ArenaBuffer
	header map[string]int
}

// NewSecureCSVImporter initializes a secure CSV parser.
func NewSecureCSVImporter(filePath string) (*SecureCSVImporter, error) {
	reader, err := NewSecureReader(filePath)
	if err != nil {
		return nil, err
	}
	return &SecureCSVImporter{
		reader: reader,
		arena:  NewArenaBuffer(),
		header: make(map[string]int),
	}, nil
}

// Close destroys the internal secure buffers and closes the reader.
func (c *SecureCSVImporter) Close() {
	if c.reader != nil {
		_ = c.reader.Close()
	}
	if c.arena != nil {
		c.arena.Destroy()
	}
}

// Parse reads the CSV stream and returns a list of parsed secrets.Entry.
func (c *SecureCSVImporter) Parse() ([]*secrets.Entry, error) {
	headerFields, err := c.parseRecord()
	if err != nil {
		return nil, fmt.Errorf("reading CSV header: %w", err)
	}
	for i, field := range headerFields {
		key := strings.ToLower(strings.TrimSpace(string(field)))
		c.header[key] = i
	}
	c.arena.Reset()

	var entries []*secrets.Entry
	idx := 0

	for {
		if len(entries) >= maxEntries {
			return entries, ErrTooManyEntries
		}

		fields, err := c.parseRecord()
		if len(fields) > 0 {
			entry := c.buildEntry(fields, idx)
			if entry != nil {
				entries = append(entries, entry)
			}
			idx++
			c.arena.Reset()
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return entries, err
		}
	}

	return entries, nil
}

func (c *SecureCSVImporter) parseRecord() ([][]byte, error) {
	var fields [][]byte
	inQuote := false
	start := c.arena.offset

	// flushField now copies bytes out of the arena so they survive arena.Reset().
	flushField := func() {
		end := c.arena.offset
		raw := c.arena.copyBytes(start, end)
		// Trim trailing spaces from field value
		fields = append(fields, bytes.TrimSpace(raw))
		start = c.arena.offset
	}

	for {
		b, err := c.reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				if c.arena.offset > start || len(fields) > 0 {
					flushField()
				}
				return fields, io.EOF
			}
			return nil, err
		}

		if inQuote {
			if b == '"' {
				next, err := c.reader.Peek()
				if err == nil && next == '"' {
					_, _ = c.reader.ReadByte() // consume escaped quote
					if err := c.arena.AllocByte('"'); err != nil {
						return nil, err
					}
				} else {
					inQuote = false
				}
			} else {
				if err := c.arena.AllocByte(b); err != nil {
					return nil, err
				}
			}
		} else {
			switch b {
			case '"':
				inQuote = true
			case ',':
				flushField()
			case '\r':
				continue
			case '\n':
				flushField()
				return fields, nil
			default:
				// Skip leading whitespace outside quotes
				if isSpace(b) && c.arena.offset == start {
					continue
				}
				if err := c.arena.AllocByte(b); err != nil {
					return nil, err
				}
			}
		}
	}
}

func (c *SecureCSVImporter) buildEntry(fields [][]byte, idx int) *secrets.Entry {
	getValue := func(keys ...string) []byte {
		for _, k := range keys {
			if i, ok := c.header[k]; ok && i < len(fields) {
				v := bytes.TrimSpace(fields[i])
				if len(v) > 0 {
					return v
				}
			}
		}
		return nil
	}

	nameBytes := getValue("name", "title", "account", "service")
	username := getValue("username", "user", "login", "email")
	password := getValue("password", "pass", "key")
	url := getValue("url", "uri", "link", "website")
	notes := getValue("notes", "comment", "desc", "description")

	var name string
	if len(nameBytes) > 0 {
		name = string(nameBytes)
	} else {
		name = fmt.Sprintf("Imported CSV Entry %d", idx+1)
	}

	var tags []string
	if tagBytes := getValue("tags", "group", "category"); len(tagBytes) > 0 {
		parts := strings.FieldsFunc(string(tagBytes), func(r rune) bool {
			return r == ',' || r == ';'
		})
		for _, p := range parts {
			if t := strings.TrimSpace(p); t != "" {
				tags = append(tags, t)
			}
		}
	}

	entry, err := secrets.NewEntry(name, username, password, url, notes, tags)
	if err != nil {
		ui.PrintfWarningf("Skipping invalid CSV entry %d: %v", idx+1, err)
		return nil
	}
	return entry
}

// --- 5. Secure KeePass XML Importer ---

// SecureKeePassImporter parses KeePass XML exports securely into Vault entries.
type SecureKeePassImporter struct {
	reader *SecureReader
	arena  *ArenaBuffer
}

// NewSecureKeePassImporter initializes a secure KeePass XML parser.
func NewSecureKeePassImporter(filePath string) (*SecureKeePassImporter, error) {
	reader, err := NewSecureReader(filePath)
	if err != nil {
		return nil, err
	}
	return &SecureKeePassImporter{
		reader: reader,
		arena:  NewArenaBuffer(),
	}, nil
}

// Close destroys the internal secure buffers and closes the reader.
func (k *SecureKeePassImporter) Close() {
	if k.reader != nil {
		_ = k.reader.Close()
	}
	if k.arena != nil {
		k.arena.Destroy()
	}
}

// Parse reads the XML stream and returns a list of parsed secrets.Entry.
func (k *SecureKeePassImporter) Parse() ([]*secrets.Entry, error) {
	var entries []*secrets.Entry

	for {
		if len(entries) >= maxEntries {
			return entries, ErrTooManyEntries
		}

		if err := k.skipUntilTag("Entry"); err != nil {
			if err == io.EOF {
				break
			}
			return entries, err
		}

		entry, err := k.parseEntryBlock()
		if err != nil {
			if err == io.EOF {
				break
			}
			ui.PrintfWarningf("Skipping malformed XML entry: %v", err)
		} else if entry != nil {
			entries = append(entries, entry)
		}

		k.arena.Reset()
	}

	return entries, nil
}

func (k *SecureKeePassImporter) parseEntryBlock() (*secrets.Entry, error) {
	// Collect heap copies of field values; arena will be reset after this call.
	var name, username, password, url, notes []byte

	for {
		tag, isClose, selfClosing, err := k.nextTag()
		if err != nil {
			return nil, err
		}

		tagStr := string(tag)

		if isClose && tagStr == "Entry" {
			break
		}

		if selfClosing {
			continue
		}

		if tagStr == "String" {
			key, val, err := k.parseStringPair()
			if err != nil {
				return nil, err
			}

			switch string(key) {
			case "Title":
				name = val
			case "UserName":
				username = val
			case "Password":
				password = val
			case "URL":
				url = val
			case "Notes":
				notes = val
			}
		}
	}

	entryName := "Imported KeePass Entry"
	if len(name) > 0 {
		entryName = string(name)
	}

	return secrets.NewEntry(entryName, username, password, url, notes, nil)
}

func (k *SecureKeePassImporter) parseStringPair() (key []byte, val []byte, err error) {
	for {
		tag, isClose, selfClosing, errTag := k.nextTag()
		if errTag != nil {
			return nil, nil, errTag
		}
		tagStr := string(tag)

		if isClose && tagStr == "String" {
			break
		}

		if selfClosing {
			switch tagStr {
			case "Key":
				key = []byte{}
			case "Value":
				val = []byte{}
			}
			continue
		}

		switch tagStr {
		case "Key":
			raw, e := k.readElementContent("Key")
			if e != nil {
				return nil, nil, e
			}
			// Copy out of arena before it might be reused
			key = make([]byte, len(raw))
			copy(key, raw)

		case "Value":
			raw, e := k.readElementContent("Value")
			if e != nil {
				return nil, nil, e
			}
			val = make([]byte, len(raw))
			copy(val, raw)
		}
	}
	return key, val, nil
}

// readElementContent reads bytes between an open tag and its matching close tag.
// The original implementation had a broken `end` calculation that subtracted
// len(closeTag) from arena.offset after readTagName had already advanced it,
// leading to incorrect slice bounds. We now record `start` before any arena writes
// and `end` before calling readTagName (which writes into the arena).
func (k *SecureKeePassImporter) readElementContent(tagName string) ([]byte, error) {
	start := k.arena.offset

	for {
		b, err := k.reader.ReadByte()
		if err != nil {
			return nil, err
		}

		if b == '<' {
			next, peekErr := k.reader.Peek()
			if peekErr != nil {
				return nil, peekErr
			}

			if next == '/' {
				_, _ = k.reader.ReadByte() // consume '/'

				// Record end of content BEFORE readTagName writes into arena
				contentEnd := k.arena.offset

				closeTag, _, err := k.readTagNameOnly()
				if err != nil {
					return nil, err
				}

				if string(closeTag) == tagName {
					// Validate bounds
					if contentEnd < start {
						return nil, fmt.Errorf("%w: <%s>", ErrBufferInconsistency, tagName)
					}
					// Return a heap copy — arena will be reset by caller
					return k.arena.copyBytes(start, contentEnd), nil
				}
				// Wrong closing tag: put the bytes back conceptually by not returning.
				// This is a malformed document; return an error.
				return nil, fmt.Errorf("%w: </%s> inside <%s>", ErrUnexpectedTag, closeTag, tagName)
			}
			// '<' that is not a close tag — treat as literal (CDATA-like)
			_ = k.arena.AllocByte(b)
		} else {
			if err := k.arena.AllocByte(b); err != nil {
				return nil, err
			}
		}
	}
}

// readTagNameOnly reads a tag name up to '>' or whitespace (attributes), consuming the '>'.
// Unlike readTagName, it does NOT write into the arena — it returns a temp heap slice.
// The old readTagName wrote into the arena which corrupted the content offset tracking.
func (k *SecureKeePassImporter) readTagNameOnly() (name []byte, selfClosing bool, err error) {
	skipAttrs := false

	for {
		b, err := k.reader.ReadByte()
		if err != nil {
			return nil, false, err
		}
		if b == '>' {
			return name, selfClosing, nil
		}
		if b == '/' {
			selfClosing = true
			continue
		}
		if isSpace(b) {
			skipAttrs = true
			continue
		}
		if skipAttrs {
			continue
		}
		name = append(name, b)
	}
}

func (k *SecureKeePassImporter) skipUntilTag(target string) error {
	for {
		tag, isClose, _, err := k.nextTag()
		if err != nil {
			return err
		}
		if !isClose && string(tag) == target {
			return nil
		}
	}
}

// nextTag finds the next XML tag and returns its name, whether it's a closing tag, and if it's self-closing.
// isClose is now correctly set when a '/' is found after '<'.
func (k *SecureKeePassImporter) nextTag() (name []byte, isClose, isSelfClosing bool, err error) {
	for {
		b, err := k.reader.ReadByte()
		if err != nil {
			return nil, false, false, err
		}
		if b != '<' {
			continue
		}

		next, peekErr := k.reader.Peek()
		if peekErr != nil {
			// EOF right after '<' — malformed document
			return nil, false, false, peekErr
		}

		if next == '/' {
			isClose = true
			_, _ = k.reader.ReadByte() // consume '/'
		} else if next == '!' || next == '?' {
			// Skip comments (<!--) and processing instructions (<?)
			_ = k.skipUntilByte('>')
			continue
		}

		tag, selfClosing, err := k.readTagNameOnly()
		return tag, isClose, selfClosing, err
	}
}

func (k *SecureKeePassImporter) skipUntilByte(target byte) error {
	for {
		b, err := k.reader.ReadByte()
		if err != nil {
			return err
		}
		if b == target {
			return nil
		}
	}
}

// --- 6. Secure JSON Importer ---

// SecureJSONImporter parses Bitwarden/generic JSON exports securely into Vault entries.
type SecureJSONImporter struct {
	reader *SecureReader
	arena  *ArenaBuffer
}

// NewSecureJSONImporter initializes a secure JSON parser.
func NewSecureJSONImporter(filePath string) (*SecureJSONImporter, error) {
	reader, err := NewSecureReader(filePath)
	if err != nil {
		return nil, err
	}
	return &SecureJSONImporter{
		reader: reader,
		arena:  NewArenaBuffer(),
	}, nil
}

// Close destroys the internal secure buffers and closes the reader.
func (p *SecureJSONImporter) Close() {
	if p.reader != nil {
		_ = p.reader.Close()
	}
	if p.arena != nil {
		p.arena.Destroy()
	}
}

// Parse reads the JSON stream and returns a list of parsed secrets.Entry.
func (p *SecureJSONImporter) Parse() ([]*secrets.Entry, error) {
	var entries []*secrets.Entry

	// Scan for the "items" key at any nesting level
	if err := p.seekToItemsArray(); err != nil {
		return nil, err
	}

	if err := p.expect('['); err != nil {
		return nil, fmt.Errorf("expected '[' after \"items\": %w", err)
	}

	for {
		if len(entries) >= maxEntries {
			return entries, ErrTooManyEntries
		}

		next, err := p.reader.skipWhitespaceAndPeek()
		if err != nil {
			return entries, err
		}
		if next == ']' {
			_, _ = p.reader.ReadByte()
			break
		}
		if next == ',' {
			_, _ = p.reader.ReadByte()
			continue
		}
		if next != '{' {
			return entries, fmt.Errorf("%w: expected '{', got '%c'", ErrInvalidFormat, next)
		}

		entry, err := p.parseEntryObject()
		if err != nil {
			ui.PrintfWarningf("Skipping malformed entry: %v", err)
			_ = p.skipStructure('}')
		} else if entry != nil {
			entries = append(entries, entry)
		}

		p.arena.Reset()
	}

	return entries, nil
}

// seekToItemsArray scans the top-level JSON object for the key "items" and
// positions the reader right before the value (the '[' of the array).
// The original code consumed the ':' inside the loop but then tried to
// consume it again outside, breaking on any file where "items" wasn't the first key.
func (p *SecureJSONImporter) seekToItemsArray() error {
	// Expect the top-level '{'
	if err := p.expect('{'); err != nil {
		return fmt.Errorf("%w: expected top-level JSON object", ErrInvalidFormat)
	}

	for {
		next, err := p.reader.skipWhitespaceAndPeek()
		if err != nil {
			return fmt.Errorf("%w: 'items' array not found", ErrInvalidFormat)
		}
		if next == '}' {
			return fmt.Errorf("%w: 'items' array not found", ErrInvalidFormat)
		}
		if next == ',' {
			_, _ = p.reader.ReadByte()
			continue
		}

		key, err := p.parseString()
		if err != nil {
			return err
		}
		if err := p.expect(':'); err != nil {
			return err
		}

		if bytes.Equal(key, []byte("items")) {
			return nil // reader is now positioned before the array value
		}

		// Skip this value entirely and continue
		if err := p.skipValue(); err != nil {
			return err
		}
	}
}

func (p *SecureJSONImporter) parseEntryObject() (*secrets.Entry, error) {
	if _, err := p.reader.ReadByte(); err != nil { // consume '{'
		return nil, err
	}

	var name, username, password, url, notes []byte

	for {
		next, err := p.reader.skipWhitespaceAndPeek()
		if err != nil {
			return nil, err
		}
		if next == '}' {
			_, _ = p.reader.ReadByte()
			break
		}
		if next == ',' {
			_, _ = p.reader.ReadByte()
			continue
		}

		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if err := p.expect(':'); err != nil {
			return nil, err
		}

		switch {
		case bytes.Equal(key, []byte("name")):
			name, err = p.parseStringValue()
		case bytes.Equal(key, []byte("notes")):
			notes, err = p.parseStringValue()
		case bytes.Equal(key, []byte("login")):
			username, password, url, err = p.parseLoginObject()
		default:
			err = p.skipValue()
		}

		if err != nil {
			return nil, err
		}
	}

	entryName := "Imported Entry"
	if len(name) > 0 {
		entryName = string(name)
	}

	return secrets.NewEntry(entryName, username, password, url, notes, nil)
}

func (p *SecureJSONImporter) parseLoginObject() ([]byte, []byte, []byte, error) {
	var username, password, url []byte

	if err := p.expect('{'); err != nil {
		return nil, nil, nil, err
	}

	for {
		next, errPeek := p.reader.skipWhitespaceAndPeek()
		if errPeek != nil {
			return nil, nil, nil, errPeek
		}
		if next == '}' {
			_, _ = p.reader.ReadByte()
			break
		}
		if next == ',' {
			_, _ = p.reader.ReadByte()
			continue
		}

		key, errKey := p.parseString()
		if errKey != nil {
			return nil, nil, nil, errKey
		}
		if err := p.expect(':'); err != nil {
			return nil, nil, nil, err
		}

		var errVal error
		switch {
		case bytes.Equal(key, []byte("username")):
			username, errVal = p.parseStringValue()
		case bytes.Equal(key, []byte("password")):
			password, errVal = p.parseStringValue()
		case bytes.Equal(key, []byte("uris")):
			url, errVal = p.parseFirstURI()
		default:
			errVal = p.skipValue()
		}

		if errVal != nil {
			return nil, nil, nil, errVal
		}
	}
	return username, password, url, nil
}

func (p *SecureJSONImporter) parseFirstURI() ([]byte, error) {
	if err := p.expect('['); err != nil {
		return nil, err
	}

	next, err := p.reader.skipWhitespaceAndPeek()
	if err != nil {
		return nil, err
	}
	if next == ']' {
		_, _ = p.reader.ReadByte()
		return nil, nil
	}

	if err := p.expect('{'); err != nil {
		return nil, err
	}

	var uri []byte
	for {
		next, err := p.reader.skipWhitespaceAndPeek()
		if err != nil {
			return nil, err
		}
		if next == '}' {
			_, _ = p.reader.ReadByte()
			break
		}
		if next == ',' {
			_, _ = p.reader.ReadByte()
			continue
		}

		key, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if err := p.expect(':'); err != nil {
			return nil, err
		}

		if bytes.Equal(key, []byte("uri")) {
			uri, err = p.parseStringValue()
		} else {
			err = p.skipValue()
		}
		if err != nil {
			return nil, err
		}
	}

	// Skip remaining URI objects in the array
	if err := p.skipStructure(']'); err != nil {
		return nil, err
	}

	return uri, nil
}

func (p *SecureJSONImporter) parseString() ([]byte, error) {
	b, err := p.reader.skipWhitespace()
	if err != nil {
		return nil, err
	}
	if b != '"' {
		return nil, fmt.Errorf("%w: expected '\"', got '%c'", ErrInvalidFormat, b)
	}
	return p.readStringContent()
}

func (p *SecureJSONImporter) parseStringValue() ([]byte, error) {
	// Peek: handle JSON null gracefully
	next, err := p.reader.skipWhitespaceAndPeek()
	if err != nil {
		return nil, err
	}
	if next == 'n' {
		// consume "null"
		for range []byte("null") {
			_, _ = p.reader.ReadByte()
		}
		return nil, nil
	}
	return p.parseString()
}

func (p *SecureJSONImporter) readStringContent() ([]byte, error) {
	start := p.arena.offset

	for {
		b, err := p.reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '"' {
			break
		}
		if b == '\\' {
			if err := p.handleEscape(); err != nil {
				return nil, err
			}
		} else {
			if err := p.arena.AllocByte(b); err != nil {
				return nil, err
			}
		}

		// Guard against a single field exhausting the arena
		if p.arena.offset-start > maxFieldBytes {
			return nil, ErrFieldTooLarge
		}
	}

	result := p.arena.copyBytes(start, p.arena.offset)
	return result, nil
}

func (p *SecureJSONImporter) handleEscape() error {
	next, err := p.reader.ReadByte()
	if err != nil {
		return err
	}
	var c byte
	switch next {
	case '"', '\\', '/':
		c = next
	case 'b':
		c = '\b'
	case 'f':
		c = '\f'
	case 'n':
		c = '\n'
	case 'r':
		c = '\r'
	case 't':
		c = '\t'
	case 'u':
		return p.handleUnicodeEscape()
	default:
		_ = p.arena.AllocByte('\\')
		c = next
	}
	return p.arena.AllocByte(c)
}

// handleUnicodeEscape handles \uXXXX sequences including surrogate pairs (\uD800–\uDFFF).
// The original code did not handle UTF-16 surrogate pairs, which would encode
// invalid runes into UTF-8. This implementation correctly combines surrogate pairs.
func (p *SecureJSONImporter) handleUnicodeEscape() error {
	r1, ok := p.readHexRune()
	if !ok {
		return p.arena.AllocByte('?')
	}

	// Check for high surrogate (U+D800–U+DBFF)
	if r1 >= 0xD800 && r1 <= 0xDBFF {
		// Must be followed by \uXXXX low surrogate
		b1, err := p.reader.ReadByte()
		if err != nil {
			return err
		}
		b2, err := p.reader.ReadByte()
		if err != nil {
			return err
		}
		if b1 == '\\' && b2 == 'u' {
			r2, ok2 := p.readHexRune()
			if ok2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
				// Valid surrogate pair — decode to a single rune
				r1 = 0x10000 + (r1-0xD800)*0x400 + (r2 - 0xDC00)
			} else {
				// Invalid pair — emit replacement char
				r1 = utf8.RuneError
			}
		} else {
			r1 = utf8.RuneError
		}
	} else if r1 >= 0xDC00 && r1 <= 0xDFFF {
		// Lone low surrogate — invalid
		r1 = utf8.RuneError
	}

	if p.arena.offset+utf8.UTFMax > len(p.arena.view) {
		return ErrArenaOverflow
	}

	n := utf8.EncodeRune(p.arena.view[p.arena.offset:], r1)
	p.arena.offset += n
	return nil
}

func (p *SecureJSONImporter) readHexRune() (rune, bool) {
	var hex [4]byte
	for i := 0; i < 4; i++ {
		b, err := p.reader.ReadByte()
		if err != nil {
			return 0, false
		}
		hex[i] = b
	}
	return decodeHexRune(hex[:])
}

func (p *SecureJSONImporter) expect(expected byte) error {
	b, err := p.reader.skipWhitespace()
	if err != nil {
		return err
	}
	if b != expected {
		return fmt.Errorf("%w: expected '%c', got '%c'", ErrInvalidFormat, expected, b)
	}
	return nil
}

// skipStructure skips to the closing delimiter of the current structure,
// respecting nesting and string literals.
// The original skipValue was called as skipUntil('}') which would stop on
// the first '}' inside a nested string or object. This version properly tracks
// nesting depth and skips over quoted strings.
func (p *SecureJSONImporter) skipStructure(closeChar byte) error {
	open := byte('{')
	if closeChar == ']' {
		open = '['
	}
	depth := 1

	for depth > 0 {
		b, err := p.reader.ReadByte()
		if err != nil {
			return err
		}
		switch b {
		case '"':
			// Skip string content
			if err := p.skipStringContent(); err != nil {
				return err
			}
		case open:
			depth++
		case closeChar:
			depth--
		}
	}
	return nil
}

func (p *SecureJSONImporter) skipStringContent() error {
	for {
		b, err := p.reader.ReadByte()
		if err != nil {
			return err
		}
		if b == '"' {
			return nil
		}
		if b == '\\' {
			if _, err := p.reader.ReadByte(); err != nil {
				return err
			}
		}
	}
}

func (p *SecureJSONImporter) skipValue() error {
	b, err := p.reader.skipWhitespaceAndPeek()
	if err != nil {
		return err
	}

	switch b {
	case '"':
		_, _ = p.reader.ReadByte()
		return p.skipStringContent()
	case '{':
		_, _ = p.reader.ReadByte()
		return p.skipStructure('}')
	case '[':
		_, _ = p.reader.ReadByte()
		return p.skipStructure(']')
	default:
		// Number, boolean, null — read until delimiter
		for {
			c, err := p.reader.Peek()
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if c == ',' || c == '}' || c == ']' || isSpace(c) {
				return nil
			}
			_, _ = p.reader.ReadByte()
		}
	}
}

func decodeHexRune(hex []byte) (rune, bool) {
	var val rune
	for _, b := range hex {
		var digit rune
		switch {
		case b >= '0' && b <= '9':
			digit = rune(b - '0')
		case b >= 'a' && b <= 'f':
			digit = rune(b-'a') + 10
		case b >= 'A' && b <= 'F':
			digit = rune(b-'A') + 10
		default:
			return 0, false
		}
		val = (val << 4) | digit
	}
	return val, true
}
