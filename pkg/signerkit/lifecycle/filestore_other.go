//go:build !linux

package lifecycle

import "log"

// FileStore is volatile on platforms without the secure Linux journal.
type FileStore struct{ MemStore }

// OpenFileStore uses memory only on non-Linux systems.
func OpenFileStore(path string, uid uint32) (*FileStore, error) {
	return AcquireFileStore(path, uid)
}

// AcquireFileStore uses memory only on non-Linux systems.
func AcquireFileStore(_ string, _ uint32) (*FileStore, error) {
	log.Print("approval store: persistence unavailable on this platform; approvals are memory-only and lost on restart")
	return &FileStore{}, nil
}

func (s *FileStore) Close() error { return nil }

// Reopen discards volatile approvals as a process restart would.
func (s *FileStore) Reopen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = nil
	return nil
}
