package lifecycle

import (
	"errors"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// ErrNotFound distinguishes an absent record from a failed read.
var ErrNotFound = errors.New("approval record not found")

// StoreEntry describes one stored record, including quarantined records whose
// encoded bytes still consume the admission budget.
type StoreEntry struct {
	Key         string
	EncodedSize int64
	Quarantined bool
}

// Store persists one record atomically. Implementations are safe for concurrent
// calls and never retain or return caller-owned mutable record data. The engine
// separately serializes load/apply/commit; these methods are not a transaction.
//
// Load returns ErrNotFound for absence and record_corrupt for quarantine.
// Commit validates the record and its key before replacing anything. A nil
// error confirms the whole replacement; an ordinary error leaves it unchanged.
// An uncertain durable write must be reported as such, never as success.
// List returns a key-sorted snapshot, including quarantined entries. Remove is
// idempotent for missing keys and must refuse quarantined entries.
type Store interface {
	Load(key string) (approvalplan.R1, error)
	Commit(key string, record approvalplan.R1) error
	List() ([]StoreEntry, error)
	Remove(key string) error
}
