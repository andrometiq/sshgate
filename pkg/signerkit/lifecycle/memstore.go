package lifecycle

import (
	"slices"
	"strings"
	"sync"

	"github.com/karthikeyan5/sshgate/src/approvalplan"
)

// MemStore is a volatile Store. Its zero value is ready for use. Keeping this
// instance across engine restarts preserves records, but no engine projections.
type MemStore struct {
	mu      sync.RWMutex
	records map[string][]byte
}

var _ Store = (*MemStore)(nil)

func validKey(key string) bool {
	if len(key) != 54 || !strings.HasPrefix(key, "r-") {
		return false
	}
	for _, c := range key[2:] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func keyError() error {
	return &approvalplan.CodeError{Code: approvalplan.CodeRecordCorrupt, Field: "record_key", Msg: "invalid or mismatched record key"}
}

func (s *MemStore) Load(key string) (approvalplan.R1, error) {
	if !validKey(key) {
		return approvalplan.R1{}, keyError()
	}
	s.mu.RLock()
	data, ok := s.records[key]
	s.mu.RUnlock()
	if !ok {
		return approvalplan.R1{}, ErrNotFound
	}
	return approvalplan.DecodeR1(data)
}

func (s *MemStore) Commit(key string, record approvalplan.R1) error {
	if !validKey(key) || key != approvalplan.RecordKey(record.Header.Principal, record.Header.RequestID) {
		return keyError()
	}
	data, err := approvalplan.EncodeR1(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string][]byte)
	}
	s.records[key] = data
	return nil
}

func (s *MemStore) List() ([]StoreEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries := make([]StoreEntry, 0, len(s.records))
	for key, data := range s.records {
		entries = append(entries, StoreEntry{Key: key, EncodedSize: int64(len(data))})
	}
	slices.SortFunc(entries, func(a, b StoreEntry) int { return strings.Compare(a.Key, b.Key) })
	return entries, nil
}

func (s *MemStore) Remove(key string) error {
	if !validKey(key) {
		return keyError()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, key)
	return nil
}
