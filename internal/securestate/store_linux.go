//go:build linux

// Package securestate provides a small FD-relative owner-only persistence
// primitive for local signer journals and CLI artifacts. It does not impose a
// schema or lifecycle; callers perform multi-object operations inside one
// inode-stable transaction and supply explicit per-object byte bounds.
package securestate

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	directoryMode = 0o700
	fileMode      = 0o600
	lockName      = ".securestate.lock"
	maxNameBytes  = 255
)

var (
	// ErrUnsafe marks an object that failed its descriptor-level owner, mode,
	// type, link-count, or pinned-inode checks.
	ErrUnsafe = errors.New("securestate: unsafe object")
	// ErrNotFound marks an absent directory or data file.
	ErrNotFound = errors.New("securestate: object not found")
	// ErrTooLarge marks an object outside its caller-supplied byte bound.
	ErrTooLarge = errors.New("securestate: object too large")
	// ErrClosed marks use after Store.Close.
	ErrClosed = errors.New("securestate: store closed")
	// ErrInactiveTransaction marks a retained Transaction used after its
	// callback returned.
	ErrInactiveTransaction = errors.New("securestate: inactive transaction")
)

// Store pins an already-open directory and one lock inode. All paths below it
// are resolved with *at syscalls; replacing any parent pathname cannot redirect
// an open Store. The process mutex and retained flock inode together serialize
// callers within and across processes.
type Store struct {
	mu          sync.Mutex
	dirFD       int
	lockFD      int
	expectedUID uint32
	closed      bool

	// beforeRename is an unexported failure-injection seam for package tests.
	// Production stores leave it nil.
	beforeRename func() error
}

// Transaction is valid only during a View or Update callback. View exposes
// read methods; mutating methods fail unless the transaction is an Update.
type Transaction struct {
	store    *Store
	writable bool
	active   bool
}

// OpenAt opens name relative to parentFD. With initialize=true it creates a
// missing 0700 directory and its 0600 lock, fsyncing parent and child metadata.
// name is exactly one path component and is never resolved through a symlink.
func OpenAt(parentFD int, name string, expectedUID uint32, initialize bool) (*Store, error) {
	if err := validateComponent(name); err != nil {
		return nil, err
	}
	if initialize {
		err := unix.Mkdirat(parentFD, name, directoryMode)
		switch {
		case err == nil:
			if err := unix.Fsync(parentFD); err != nil {
				return nil, fmt.Errorf("securestate: fsync parent after mkdir: %w", err)
			}
		case errors.Is(err, unix.EEXIST):
		default:
			return nil, fmt.Errorf("securestate: create directory %q: %w", name, err)
		}
	}
	dirFD, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: directory %q", ErrNotFound, name)
		}
		return nil, fmt.Errorf("%w: open directory %q: %v", ErrUnsafe, name, err)
	}
	defer unix.Close(dirFD)
	return OpenDirectory(dirFD, expectedUID, initialize)
}

// OpenDirectory duplicates dirFD with CLOEXEC, validates its exact 0700 owner
// posture, and pins the existing (or newly initialized) lock inode.
func OpenDirectory(dirFD int, expectedUID uint32, initialize bool) (*Store, error) {
	dupFD, err := unix.FcntlInt(uintptr(dirFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("securestate: duplicate directory fd: %w", err)
	}
	s := &Store{dirFD: dupFD, lockFD: -1, expectedUID: expectedUID}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = unix.Close(s.dirFD)
			if s.lockFD >= 0 {
				_ = unix.Close(s.lockFD)
			}
		}
	}()

	if err := s.validateDirectory(); err != nil {
		return nil, err
	}
	if initialize {
		if err := s.initializeLock(); err != nil {
			return nil, err
		}
	}
	lockFD, err := unix.Openat(s.dirFD, lockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, lockName)
		}
		return nil, fmt.Errorf("%w: open lock: %v", ErrUnsafe, err)
	}
	s.lockFD = lockFD
	if _, err := s.validateFileFD(lockFD, lockName); err != nil {
		return nil, err
	}
	if err := s.validatePinnedLock(); err != nil {
		return nil, err
	}
	closeOnError = false
	return s, nil
}

// Close releases the pinned directory and lock descriptors. It is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	if err := unix.Close(s.lockFD); err != nil {
		errs = append(errs, fmt.Errorf("close lock: %w", err))
	}
	if err := unix.Close(s.dirFD); err != nil {
		errs = append(errs, fmt.Errorf("close directory: %w", err))
	}
	return errors.Join(errs...)
}

// View runs fn under the process mutex and a shared inode-stable flock.
func (s *Store) View(fn func(*Transaction) error) error {
	return s.withLock(unix.LOCK_SH, false, fn)
}

// Update runs fn under the process mutex and an exclusive inode-stable flock.
// Multiple file replacements in one callback are serialized, though callers
// remain responsible for their higher-level crash/recovery state machine.
func (s *Store) Update(fn func(*Transaction) error) error {
	return s.withLock(unix.LOCK_EX, true, fn)
}

func (s *Store) withLock(operation int, writable bool, fn func(*Transaction) error) error {
	if fn == nil {
		return errors.New("securestate: nil transaction callback")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if err := s.validateDirectory(); err != nil {
		return err
	}
	if err := s.validatePinnedLock(); err != nil {
		return err
	}
	for {
		err := unix.Flock(s.lockFD, operation)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("securestate: flock: %w", err)
		}
		break
	}
	defer unix.Flock(s.lockFD, unix.LOCK_UN)
	// Recheck after acquiring the lock so replacing the directory entry during
	// a blocking flock cannot split cooperating processes across lock inodes.
	if err := s.validatePinnedLock(); err != nil {
		return err
	}
	tx := &Transaction{store: s, writable: writable, active: true}
	defer func() { tx.active = false }()
	return fn(tx)
}

// ReadFile reads one exact regular 0600 single-link owner file through the
// directory FD and enforces max before allocation and while reading.
func (tx *Transaction) ReadFile(name string, max int) ([]byte, error) {
	if err := tx.check(false); err != nil {
		return nil, err
	}
	if err := validateDataName(name); err != nil {
		return nil, err
	}
	if max <= 0 {
		return nil, fmt.Errorf("securestate: invalid maximum %d", max)
	}
	fd, err := unix.Openat(tx.store.dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return nil, fmt.Errorf("%w: open %s: %v", ErrUnsafe, name, err)
	}
	defer unix.Close(fd)
	opened, err := tx.store.validateFileFD(fd, name)
	if err != nil {
		return nil, err
	}
	if opened.Size < 0 || opened.Size > int64(max) {
		return nil, fmt.Errorf("%w: %s is %d bytes; maximum is %d", ErrTooLarge, name, opened.Size, max)
	}
	body := make([]byte, 0, int(opened.Size))
	chunk := make([]byte, min(32<<10, max))
	for {
		n, readErr := unix.Read(fd, chunk)
		if n > 0 {
			if len(body)+n > max {
				return nil, fmt.Errorf("%w: %s grew beyond %d bytes", ErrTooLarge, name, max)
			}
			body = append(body, chunk[:n]...)
		}
		switch {
		case readErr == nil && n > 0:
			continue
		case readErr == nil:
		case errors.Is(readErr, unix.EINTR):
			continue
		default:
			return nil, fmt.Errorf("securestate: read %s: %w", name, readErr)
		}
		break
	}
	closed, err := tx.store.validateFileFD(fd, name)
	if err != nil {
		return nil, err
	}
	path, err := tx.store.statPath(name)
	if err != nil {
		return nil, err
	}
	if !sameInode(opened, closed) || !sameInode(opened, path) || int64(len(body)) != closed.Size {
		return nil, fmt.Errorf("%w: %s changed during read", ErrUnsafe, name)
	}
	return body, nil
}

// ReadCanonicalJSON reads bounded bytes, decodes one typed JSON value with
// unknown fields rejected, and requires byte equality with json.Marshal(dst).
// This rejects duplicate keys, alternate field ordering/whitespace, trailing
// values, and non-canonical scalar encodings.
func (tx *Transaction) ReadCanonicalJSON(name string, max int, dst any) ([]byte, error) {
	if dst == nil {
		return nil, errors.New("securestate: nil JSON destination")
	}
	body, err := tx.ReadFile(name, max)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return nil, fmt.Errorf("securestate: decode %s: %w", name, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("securestate: decode %s: trailing JSON value", name)
		}
		return nil, fmt.Errorf("securestate: decode %s trailing data: %w", name, err)
	}
	canonical, err := json.Marshal(dst)
	if err != nil {
		return nil, fmt.Errorf("securestate: re-marshal %s: %w", name, err)
	}
	if !bytes.Equal(body, canonical) {
		return nil, fmt.Errorf("securestate: %s is not canonical typed JSON", name)
	}
	return body, nil
}

// WriteFile atomically replaces one bounded owner-only file using a
// same-directory exclusive temp, fsync, rename, and directory fsync. A crash
// can expose the old complete file or the new complete file, never a torn mix.
func (tx *Transaction) WriteFile(name string, body []byte, max int) error {
	if err := tx.check(true); err != nil {
		return err
	}
	if err := validateDataName(name); err != nil {
		return err
	}
	if max <= 0 {
		return fmt.Errorf("securestate: invalid maximum %d", max)
	}
	if len(body) > max {
		return fmt.Errorf("%w: %s body is %d bytes; maximum is %d", ErrTooLarge, name, len(body), max)
	}
	if _, err := tx.store.statPath(name); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return tx.atomicReplace(name, body)
}

// WriteCanonicalJSON marshals value once, enforces max, atomically persists
// those exact bytes, and returns a copy for hashing/audit use.
func (tx *Transaction) WriteCanonicalJSON(name string, value any, max int) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("securestate: marshal %s: %w", name, err)
	}
	if err := tx.WriteFile(name, body, max); err != nil {
		return nil, err
	}
	return append([]byte(nil), body...), nil
}

func (tx *Transaction) atomicReplace(name string, body []byte) error {
	var suffix [12]byte
	for attempt := 0; attempt < 16; attempt++ {
		if _, err := rand.Read(suffix[:]); err != nil {
			return fmt.Errorf("securestate: random temp suffix: %w", err)
		}
		tempName := ".tmp-" + hex.EncodeToString(suffix[:])
		fd, err := unix.Openat(tx.store.dirFD, tempName, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CREAT|unix.O_EXCL, fileMode)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("securestate: create temp: %w", err)
		}
		cleanup := true
		closeFD := true
		defer func() {
			if closeFD {
				_ = unix.Close(fd)
			}
			if cleanup {
				_ = unix.Unlinkat(tx.store.dirFD, tempName, 0)
			}
		}()
		if err := unix.Fchmod(fd, fileMode); err != nil {
			return fmt.Errorf("securestate: chmod temp: %w", err)
		}
		created, err := tx.store.validateFileFD(fd, tempName)
		if err != nil {
			return err
		}
		if err := writeAll(fd, body); err != nil {
			return fmt.Errorf("securestate: write temp: %w", err)
		}
		if err := unix.Fsync(fd); err != nil {
			return fmt.Errorf("securestate: fsync temp: %w", err)
		}
		if tx.store.beforeRename != nil {
			if err := tx.store.beforeRename(); err != nil {
				return err
			}
		}
		if err := unix.Close(fd); err != nil {
			closeFD = false
			return fmt.Errorf("securestate: close temp: %w", err)
		}
		closeFD = false
		if err := unix.Renameat(tx.store.dirFD, tempName, tx.store.dirFD, name); err != nil {
			return fmt.Errorf("securestate: rename temp: %w", err)
		}
		cleanup = false
		installed, err := tx.store.statPath(name)
		if err != nil {
			return err
		}
		if !sameInode(created, installed) {
			return fmt.Errorf("%w: installed %s is not the written inode", ErrUnsafe, name)
		}
		if err := unix.Fsync(tx.store.dirFD); err != nil {
			return fmt.Errorf("securestate: fsync directory: %w", err)
		}
		return nil
	}
	return errors.New("securestate: could not allocate unique temp file")
}

func (tx *Transaction) check(write bool) error {
	if tx == nil || !tx.active || tx.store == nil {
		return ErrInactiveTransaction
	}
	if write && !tx.writable {
		return errors.New("securestate: mutation attempted in read-only transaction")
	}
	return nil
}

func (s *Store) initializeLock() error {
	fd, err := unix.Openat(s.dirFD, lockName, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CREAT|unix.O_EXCL, fileMode)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("securestate: create lock: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, fileMode); err != nil {
		return fmt.Errorf("securestate: chmod lock: %w", err)
	}
	if _, err := s.validateFileFD(fd, lockName); err != nil {
		return err
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("securestate: fsync lock: %w", err)
	}
	if err := unix.Fsync(s.dirFD); err != nil {
		return fmt.Errorf("securestate: fsync directory after lock creation: %w", err)
	}
	return nil
}

func (s *Store) validateDirectory() error {
	flags, err := unix.FcntlInt(uintptr(s.dirFD), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("%w: inspect directory descriptor: %v", ErrUnsafe, err)
	}
	if flags&unix.O_PATH != 0 {
		return fmt.Errorf("%w: O_PATH directory cannot provide durable replacement", ErrUnsafe)
	}
	var st unix.Stat_t
	if err := unix.Fstat(s.dirFD, &st); err != nil {
		return fmt.Errorf("%w: fstat directory: %v", ErrUnsafe, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != s.expectedUID || st.Mode&0o7777 != directoryMode {
		return fmt.Errorf("%w: directory type/owner/mode is %o uid=%d; want directory %04o uid=%d", ErrUnsafe, st.Mode&0o7777, st.Uid, directoryMode, s.expectedUID)
	}
	return nil
}

func (s *Store) validateFileFD(fd int, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return st, fmt.Errorf("%w: fstat %s: %v", ErrUnsafe, name, err)
	}
	if err := s.validateFileStat(st, name); err != nil {
		return st, err
	}
	return st, nil
}

func (s *Store) statPath(name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(s.dirFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return st, fmt.Errorf("%w: %s", ErrNotFound, name)
		}
		return st, fmt.Errorf("%w: stat %s: %v", ErrUnsafe, name, err)
	}
	if err := s.validateFileStat(st, name); err != nil {
		return st, err
	}
	return st, nil
}

func (s *Store) validateFileStat(st unix.Stat_t, name string) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != s.expectedUID || st.Mode&0o7777 != fileMode {
		return fmt.Errorf("%w: %s type/links/owner/mode is mode=%o links=%d uid=%d; want regular single-link %04o uid=%d", ErrUnsafe, name, st.Mode&0o7777, st.Nlink, st.Uid, fileMode, s.expectedUID)
	}
	return nil
}

func (s *Store) validatePinnedLock() error {
	opened, err := s.validateFileFD(s.lockFD, lockName)
	if err != nil {
		return err
	}
	path, err := s.statPath(lockName)
	if err != nil {
		return err
	}
	if !sameInode(opened, path) {
		return fmt.Errorf("%w: lock path no longer names pinned inode", ErrUnsafe)
	}
	return nil
}

func sameInode(a, b unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }

func validateComponent(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > maxNameBytes || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("securestate: unsafe path component %q", name)
	}
	return nil
}

func validateDataName(name string) error {
	if err := validateComponent(name); err != nil {
		return err
	}
	if name == lockName || strings.HasPrefix(name, ".tmp-") {
		return fmt.Errorf("securestate: reserved data name %q", name)
	}
	return nil
}

func writeAll(fd int, body []byte) error {
	for len(body) > 0 {
		n, err := unix.Write(fd, body)
		if n > 0 {
			body = body[n:]
		}
		switch {
		case err == nil && n > 0:
			continue
		case err == nil:
			return io.ErrShortWrite
		case errors.Is(err, unix.EINTR):
			continue
		default:
			return err
		}
	}
	return nil
}
