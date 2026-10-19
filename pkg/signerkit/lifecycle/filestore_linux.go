//go:build linux

package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/karthikeyan5/sshgate/internal/securestate"
	ap "github.com/karthikeyan5/sshgate/src/approvalplan"
	"golang.org/x/sys/unix"
)

type fileRecord struct {
	entry  StoreEntry
	record ap.R1
}

// FileStore owns a journal directory until Close, including across Reopen.
// The lifecycle owner must stop and join its effects before Reopen or Close.
// Admission, retention and reservation accounting belong to Engine.
// After an uncertain update or failed reload, Commit, Remove, Load and List
// return *approvalplan.CodeError with CodeStorageUncertain until Reopen succeeds.
type FileStore struct {
	operation         sync.Mutex
	publication       *publishedState
	mu                sync.RWMutex
	holderFD          int
	uid               uint32
	disk              *securestate.Store
	records           map[string]fileRecord
	poisoned          bool
	closed            bool
	orphanTemps       int
	beforeStoreUpdate func() error
	afterStoreUpdate  func() error
}

var _ Store = (*FileStore)(nil)

// OpenFileStore acquires ownership and loads the journal. A load failure returns
// both the owned store and the error: the caller must retry Reopen or Close it.
// Only an ownership failure returns a nil store.
func OpenFileStore(path string, uid uint32) (*FileStore, error) {
	s, err := AcquireFileStore(path, uid)
	if err != nil {
		return nil, err
	}
	return s, s.Reopen()
}

// AcquireFileStore creates the final directory component if absent and acquires
// its ownership flock without loading records. Its parent must already exist.
// Call Reopen before use; until then all Store operations are storage_uncertain.
func AcquireFileStore(path string, uid uint32) (*FileStore, error) {
	path = filepath.Clean(path)
	parent, err := unix.Open(filepath.Dir(path), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	name := filepath.Base(path)
	if name == "." || name == "/" || name == ".." {
		return nil, errors.New("approval store: invalid directory")
	}
	if err := unix.Mkdirat(parent, name, 0700); err == nil {
		if err := unix.Fsync(parent); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("approval store %s is held by another signer process: %w", path, err)
		}
		return nil, fmt.Errorf("approval store %s requires a local filesystem with working flock: %w", path, err)
	}
	return &FileStore{holderFD: fd, uid: uid, poisoned: true}, nil
}

// Reopen reloads from the held inode, never from the original pathname. On
// failure ownership is retained and all operations remain storage_uncertain.
// A new Engine must run Startup after this succeeds; an old engine is invalid.
func (s *FileStore) Reopen() error {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return unavailable()
	}
	s.mu.Unlock()
	s.poison()
	if s.disk != nil {
		if err := s.disk.Close(); err != nil {
			return err
		}
		s.disk = nil
	}
	disk, err := securestate.OpenDirectory(s.holderFD, s.uid, true)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			disk.Close()
		}
	}()
	removed := 0
	if err := disk.Update(func(tx *securestate.Transaction) error {
		var err error
		removed, err = tx.RemoveOrphanTemps()
		return err
	}); err != nil {
		return err
	}
	records := make(map[string]fileRecord)
	err = disk.View(func(tx *securestate.Transaction) error {
		names, err := tx.ListNames(ap.LocalRecordsTotal)
		if err != nil {
			return err
		}
		for _, name := range names {
			if !validKey(name) {
				return fmt.Errorf("approval store: unexpected entry %q", name)
			}
			// DecodeR1 checks canonical JSON and the schema together. Keep I/O
			// failures distinct from corrupt bytes: only the latter quarantine.
			data, err := tx.ReadFile(name, ap.R1Max)
			if err != nil {
				return fmt.Errorf("approval store %s: %w", name, err)
			}
			rec, decodeErr := ap.DecodeR1(data)
			entry := StoreEntry{Key: name, EncodedSize: int64(len(data))}
			entry.Quarantined = decodeErr != nil || ap.RecordKey(rec.Header.Principal, rec.Header.RequestID) != name
			if entry.Quarantined {
				rec = ap.R1{}
			}
			records[name] = fileRecord{entry, rec}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.disk = disk
	s.mu.Lock()
	s.records, s.poisoned = records, false
	s.orphanTemps += removed
	s.mu.Unlock()
	success = true
	return nil
}

func storageUncertain() error { return &ap.CodeError{Code: ap.CodeStorageUncertain} }

func (s *FileStore) availableLocked() error {
	if s.closed {
		return unavailable()
	}
	if s.poisoned {
		return storageUncertain()
	}
	return nil
}

func (s *FileStore) Load(key string) (ap.R1, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.availableLocked(); err != nil {
		return ap.R1{}, err
	}
	if !validKey(key) {
		return ap.R1{}, keyError()
	}
	cached, ok := s.records[key]
	if !ok {
		return ap.R1{}, ErrNotFound
	}
	if cached.entry.Quarantined {
		return ap.R1{}, keyError()
	}
	data, err := ap.EncodeR1(cached.record)
	if err != nil {
		return ap.R1{}, err
	}
	var record ap.R1
	if err := json.Unmarshal(data, &record); err != nil {
		return ap.R1{}, err
	}
	return record, nil
}

func (s *FileStore) List() ([]StoreEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.availableLocked(); err != nil {
		return nil, err
	}
	entries := make([]StoreEntry, 0, len(s.records))
	for _, cached := range s.records {
		entries = append(entries, cached.entry)
	}
	slices.SortFunc(entries, func(a, b StoreEntry) int { return strings.Compare(a.Key, b.Key) })
	return entries, nil
}

// bindPublication is called before Startup, after the previous owner joined.
func (s *FileStore) bindPublication(p *publishedState) {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.publication = p
}

func (s *FileStore) poison() {
	p := s.publication
	if p != nil {
		p.mu.Lock()
	}
	s.mu.Lock()
	s.poisoned, s.records = true, nil
	if p != nil {
		p.poisonLocked(storageUncertain())
	}
	s.mu.Unlock()
	if p != nil {
		p.mu.Unlock()
		p.cancel()
	}
}

func (s *FileStore) update(fn func(*securestate.Transaction) error) error {
	var err error
	if s.beforeStoreUpdate != nil {
		err = s.beforeStoreUpdate()
	}
	if err == nil {
		err = s.disk.Update(fn)
		if err == nil && s.afterStoreUpdate != nil {
			if fault := s.afterStoreUpdate(); fault != nil {
				err = errors.Join(securestate.ErrCommitUncertain, fault)
			}
		}
	}
	if errors.Is(err, securestate.ErrCommitUncertain) {
		s.poison()
		return storageUncertain()
	}
	return err
}

func (s *FileStore) Commit(key string, record ap.R1) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.RLock()
	err := s.availableLocked()
	cached, exists := s.records[key]
	count := len(s.records)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if !validKey(key) || key != ap.RecordKey(record.Header.Principal, record.Header.RequestID) || cached.entry.Quarantined {
		return keyError()
	}
	data, err := ap.EncodeR1(record)
	if err != nil {
		return err
	}
	var owned ap.R1
	if err := json.Unmarshal(data, &owned); err != nil {
		return err
	}
	if !exists && count >= ap.LocalRecordsTotal {
		return &ap.CodeError{Code: ap.CodeQueueFull}
	}
	err = s.update(func(tx *securestate.Transaction) error {
		_, err := tx.WriteCanonicalJSON(key, owned, ap.R1Max)
		return err
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.records[key] = fileRecord{StoreEntry{Key: key, EncodedSize: int64(len(data))}, owned}
	s.mu.Unlock()
	return nil
}

func (s *FileStore) Remove(key string) error {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.RLock()
	err := s.availableLocked()
	cached, exists := s.records[key]
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if !validKey(key) || cached.entry.Quarantined {
		return keyError()
	}
	if !exists {
		return nil
	}
	if err := s.update(func(tx *securestate.Transaction) error { return tx.Remove(key) }); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.records, key)
	s.mu.Unlock()
	return nil
}

// Close releases ownership only after the lifecycle owner has joined its work.
func (s *FileStore) Close() error {
	s.operation.Lock()
	defer s.operation.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed, s.records = true, nil
	s.mu.Unlock()
	var err error
	if s.disk != nil {
		err = s.disk.Close()
	}
	return errors.Join(err, unix.Close(s.holderFD))
}
