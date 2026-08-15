package secrets

import "github.com/google/uuid"

// EntryID represents a unique identifier for a vault entry.
// It is a strong type to prevent confusion with other strings (e.g., names).
type EntryID string

// NewEntryID generates a new random EntryID (UUID v4).
func NewEntryID() EntryID {
	return EntryID(uuid.New().String())
}

// String returns the string representation of the EntryID.
func (id EntryID) String() string {
	return string(id)
}
