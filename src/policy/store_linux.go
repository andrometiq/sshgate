//go:build linux

package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	manifestFile = "base.manifest"
	anchorFile   = "base.anchor"
	lockFile     = ".policy.lock"

	anchorDomain  = "SSHGATE_POLICY_ANCHOR_V1\x00"
	anchorSize    = len(anchorDomain) + 8 + 8 + sha256.Size
	maxAnchorSize = 256
)

var (
	// ErrPolicyNotFound means an authoritative policy file is absent. A
	// mode-aware Tier-2/3 gate must treat this as recovery-only, never auto.
	ErrPolicyNotFound = errors.New("policy: authoritative state not found")
	// ErrUnsafePolicyFile means a policy directory or file failed its
	// descriptor-level ownership, type, link-count, or permission checks.
	ErrUnsafePolicyFile = errors.New("policy: unsafe policy file")
	// ErrPolicyRollback means a signed manifest is older than the protected
	// high-water anchor.
	ErrPolicyRollback = errors.New("policy: manifest rollback")
	// ErrPolicyConflict means the same epoch/revision names different signed
	// bytes, or the protected files otherwise disagree.
	ErrPolicyConflict = errors.New("policy: authoritative state conflict")
	// ErrStoreClosed means an operation was attempted after Close.
	ErrStoreClosed = errors.New("policy: store closed")
)

// StoreConfig describes the root/admin-created high-assurance layout. Modes
// are exact permission bits rather than maxima: accepting a differently
// permissioned file would make an operator's ACL/group assumptions ambiguous.
// Group/other write permission is never accepted for either mode.
type StoreConfig struct {
	ExpectedUID   uint32
	DirectoryMode fs.FileMode
	FileMode      fs.FileMode
}

// RootOwnedStoreConfig is the recommended /var/lib/sshgate-policy/<uid>/
// posture. A private group or ACL may grant the target account read/traverse
// access; the target account must not own or be able to write these objects.
func RootOwnedStoreConfig() StoreConfig {
	return StoreConfig{
		ExpectedUID:   0,
		DirectoryMode: 0o750,
		FileMode:      0o640,
	}
}

// PolicyVersion is ordered lexicographically by Epoch then Revision. A new
// epoch may restart Revision at one.
type PolicyVersion struct {
	Epoch    uint64
	Revision uint64
}

// LoadedBase is one verified, host-bound policy snapshot.
type LoadedBase struct {
	Manifest BaseManifest
	Digest   [sha256.Size]byte
	Version  PolicyVersion
}

// Store owns a CLOEXEC duplicate of an already-open policy directory FD. It
// never resolves the directory by pathname, so renaming or replacing a parent
// path cannot redirect an existing Store.
type Store struct {
	mu     sync.RWMutex
	dirFD  int
	config StoreConfig
	pubKey ed25519.PublicKey
	host   string
	closed bool

	// afterAnchor is an unexported crash-injection seam used by package tests.
	// Production Stores leave it nil.
	afterAnchor func() error
}

type policyAnchor struct {
	Version PolicyVersion
	Digest  [sha256.Size]byte
}

// InitializeStore creates the inode-stable lock file if needed, fsyncs it and
// the directory, and returns an opened Store. This is an administrative
// provisioning operation; ordinary gate execution should call OpenStore.
func InitializeStore(dirFD int, config StoreConfig, publicKey ed25519.PublicKey, expectedHost string) (*Store, error) {
	s, err := openStore(dirFD, config, publicKey, expectedHost, true)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// OpenStore opens an existing administrative layout. It never creates policy
// state, preserving the high-assurance rule that a target account cannot turn
// missing policy into auto or initialize root-owned authority.
func OpenStore(dirFD int, config StoreConfig, publicKey ed25519.PublicKey, expectedHost string) (*Store, error) {
	return openStore(dirFD, config, publicKey, expectedHost, false)
}

func openStore(dirFD int, config StoreConfig, publicKey ed25519.PublicKey, expectedHost string, initialize bool) (*Store, error) {
	if err := validateStoreConfig(config); err != nil {
		return nil, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: Ed25519 public key is %d bytes; want %d", ErrBadSignature, len(publicKey), ed25519.PublicKeySize)
	}
	if err := validateHostFingerprint(expectedHost); err != nil {
		return nil, fmt.Errorf("policy: expected host: %w", err)
	}

	dupFD, err := unix.FcntlInt(uintptr(dirFD), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("policy: duplicate directory fd: %w", err)
	}
	s := &Store{
		dirFD:  dupFD,
		config: config,
		pubKey: append(ed25519.PublicKey(nil), publicKey...),
		host:   expectedHost,
	}
	if err := s.validateDirectory(); err != nil {
		_ = unix.Close(dupFD)
		return nil, err
	}
	if initialize {
		if err := s.initializeLock(); err != nil {
			_ = unix.Close(dupFD)
			return nil, err
		}
	}
	lockFD, err := s.openLock()
	if err != nil {
		_ = unix.Close(dupFD)
		return nil, err
	}
	_ = unix.Close(lockFD)
	return s, nil
}

// Close releases the Store's duplicate directory descriptor.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := unix.Close(s.dirFD); err != nil {
		return fmt.Errorf("policy: close directory fd: %w", err)
	}
	return nil
}

// LoadBase obtains a shared inter-process lock and returns one verified
// manifest+anchor snapshot. Missing or inconsistent state is an error for the
// caller to map to recovery-only.
func (s *Store) LoadBase() (LoadedBase, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return LoadedBase{}, ErrStoreClosed
	}
	if err := s.validateDirectory(); err != nil {
		return LoadedBase{}, err
	}
	lockFD, err := s.lock(unix.LOCK_SH)
	if err != nil {
		return LoadedBase{}, err
	}
	defer unlockAndClose(lockFD)
	return s.loadBaseLocked()
}

// ReplaceBase verifies candidate before taking the exclusive inter-process
// lock, then reloads authoritative state under that lock. A higher anchor is
// durably installed before its manifest. Therefore a crash may leave the gate
// recovery-only, but can never reactivate older authority. Replaying the exact
// candidate resumes an interrupted replacement.
func (s *Store) ReplaceBase(candidate []byte) (LoadedBase, error) {
	if len(candidate) == 0 || len(candidate) > MaxPolicyEnvelopeBytes {
		return LoadedBase{}, fmt.Errorf("%w: manifest envelope is %d bytes; maximum is %d", ErrTooLarge, len(candidate), MaxPolicyEnvelopeBytes)
	}
	candidate = append([]byte(nil), candidate...)
	verified, err := s.verifyEnvelope(candidate)
	if err != nil {
		return LoadedBase{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return LoadedBase{}, ErrStoreClosed
	}
	if err := s.validateDirectory(); err != nil {
		return LoadedBase{}, err
	}
	lockFD, err := s.lock(unix.LOCK_EX)
	if err != nil {
		return LoadedBase{}, err
	}
	defer unlockAndClose(lockFD)

	anchor, anchorErr := s.readAnchor()
	if anchorErr != nil && !errors.Is(anchorErr, ErrPolicyNotFound) {
		return LoadedBase{}, anchorErr
	}
	current, currentErr := s.readAndVerifyManifest()
	if currentErr != nil && !errors.Is(currentErr, ErrPolicyNotFound) {
		// A protected anchor plus a malformed/replayed manifest can be repaired
		// only by the pinned candidate or a strictly newer signed candidate.
		cmp := compareVersion(verified.Version, anchor.Version)
		if anchorErr != nil || cmp < 0 || (cmp == 0 && verified.Digest != anchor.Digest) {
			return LoadedBase{}, currentErr
		}
	}

	if anchorErr == nil {
		switch cmp := compareVersion(verified.Version, anchor.Version); {
		case cmp < 0:
			return LoadedBase{}, fmt.Errorf("%w: candidate %s is older than anchor %s", ErrPolicyRollback, formatVersion(verified.Version), formatVersion(anchor.Version))
		case cmp == 0 && verified.Digest != anchor.Digest:
			return LoadedBase{}, fmt.Errorf("%w: %s has a different manifest digest", ErrPolicyConflict, formatVersion(verified.Version))
		}
	}
	if currentErr == nil {
		cmp := compareVersion(verified.Version, current.Version)
		if cmp < 0 {
			return LoadedBase{}, fmt.Errorf("%w: candidate %s is older than current manifest %s", ErrPolicyRollback, formatVersion(verified.Version), formatVersion(current.Version))
		}
		if cmp == 0 && verified.Digest != current.Digest {
			return LoadedBase{}, fmt.Errorf("%w: current %s has a different manifest digest", ErrPolicyConflict, formatVersion(verified.Version))
		}
	}

	anchorMatches := anchorErr == nil && anchor.Version == verified.Version && anchor.Digest == verified.Digest
	manifestMatches := currentErr == nil && current.Version == verified.Version && current.Digest == verified.Digest
	if anchorMatches && manifestMatches {
		return verified, nil
	}
	if !anchorMatches {
		encoded := encodeAnchor(policyAnchor{Version: verified.Version, Digest: verified.Digest})
		if err := s.atomicReplace(anchorFile, encoded); err != nil {
			return LoadedBase{}, fmt.Errorf("policy: replace anchor: %w", err)
		}
	}
	if s.afterAnchor != nil {
		if err := s.afterAnchor(); err != nil {
			return LoadedBase{}, err
		}
	}
	if !manifestMatches {
		if err := s.atomicReplace(manifestFile, candidate); err != nil {
			return LoadedBase{}, fmt.Errorf("policy: replace manifest: %w", err)
		}
	}
	return verified, nil
}

func (s *Store) loadBaseLocked() (LoadedBase, error) {
	anchor, err := s.readAnchor()
	if err != nil {
		return LoadedBase{}, err
	}
	manifest, err := s.readAndVerifyManifest()
	if err != nil {
		return LoadedBase{}, err
	}
	cmp := compareVersion(manifest.Version, anchor.Version)
	if cmp < 0 {
		return LoadedBase{}, fmt.Errorf("%w: manifest %s is older than anchor %s", ErrPolicyRollback, formatVersion(manifest.Version), formatVersion(anchor.Version))
	}
	if cmp > 0 || manifest.Digest != anchor.Digest {
		return LoadedBase{}, fmt.Errorf("%w: manifest %s does not match protected anchor %s", ErrPolicyConflict, formatVersion(manifest.Version), formatVersion(anchor.Version))
	}
	return manifest, nil
}

func (s *Store) readAndVerifyManifest() (LoadedBase, error) {
	envelope, err := s.readSecureFile(manifestFile, MaxPolicyEnvelopeBytes)
	if err != nil {
		return LoadedBase{}, err
	}
	return s.verifyEnvelope(envelope)
}

func (s *Store) verifyEnvelope(envelope []byte) (LoadedBase, error) {
	manifest, err := VerifyBaseManifest(envelope, s.pubKey)
	if err != nil {
		return LoadedBase{}, fmt.Errorf("policy: verify base manifest: %w", err)
	}
	if manifest.Host != s.host {
		return LoadedBase{}, fmt.Errorf("policy: manifest host %q does not match expected host %q", manifest.Host, s.host)
	}
	payload, _, err := DecodeBaseManifestEnvelope(envelope)
	if err != nil {
		return LoadedBase{}, fmt.Errorf("policy: decode verified manifest: %w", err)
	}
	digest, err := BaseManifestPayloadDigest(payload)
	if err != nil {
		return LoadedBase{}, fmt.Errorf("policy: digest verified manifest: %w", err)
	}
	return LoadedBase{
		Manifest: manifest,
		Digest:   digest,
		Version:  PolicyVersion{Epoch: manifest.Epoch, Revision: manifest.Revision},
	}, nil
}

func (s *Store) readAnchor() (policyAnchor, error) {
	raw, err := s.readSecureFile(anchorFile, maxAnchorSize)
	if err != nil {
		return policyAnchor{}, err
	}
	anchor, err := decodeAnchor(raw)
	if err != nil {
		return policyAnchor{}, fmt.Errorf("%w: anchor: %v", ErrPolicyConflict, err)
	}
	return anchor, nil
}

func (s *Store) validateDirectory() error {
	flags, err := unix.FcntlInt(uintptr(s.dirFD), unix.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("%w: inspect directory descriptor: %v", ErrUnsafePolicyFile, err)
	}
	if flags&unix.O_PATH != 0 {
		return fmt.Errorf("%w: O_PATH directory descriptor cannot provide durable replacement", ErrUnsafePolicyFile)
	}
	var st unix.Stat_t
	if err := unix.Fstat(s.dirFD, &st); err != nil {
		return fmt.Errorf("%w: fstat directory: %v", ErrUnsafePolicyFile, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: supplied descriptor is not a directory", ErrUnsafePolicyFile)
	}
	if st.Uid != s.config.ExpectedUID {
		return fmt.Errorf("%w: directory owner uid %d; want %d", ErrUnsafePolicyFile, st.Uid, s.config.ExpectedUID)
	}
	if got, want := fs.FileMode(st.Mode)&fs.ModePerm, s.config.DirectoryMode.Perm(); got != want {
		return fmt.Errorf("%w: directory mode %04o; want %04o", ErrUnsafePolicyFile, got, want)
	}
	return nil
}

func (s *Store) readSecureFile(name string, max int) ([]byte, error) {
	fd, err := unix.Openat(s.dirFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, fmt.Errorf("%w: %s", ErrPolicyNotFound, name)
		}
		return nil, fmt.Errorf("%w: open %s: %v", ErrUnsafePolicyFile, name, err)
	}
	defer unix.Close(fd)
	if err := s.validateFileFD(fd, name); err != nil {
		return nil, err
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("%w: fstat %s: %v", ErrUnsafePolicyFile, name, err)
	}
	if st.Size < 0 || st.Size > int64(max) {
		return nil, fmt.Errorf("%w: %s is %d bytes; maximum is %d", ErrTooLarge, name, st.Size, max)
	}
	buf := make([]byte, 0, int(st.Size))
	chunk := make([]byte, 32*1024)
	for {
		n, readErr := unix.Read(fd, chunk)
		if n > 0 {
			if len(buf)+n > max {
				return nil, fmt.Errorf("%w: %s grew beyond %d bytes", ErrTooLarge, name, max)
			}
			buf = append(buf, chunk[:n]...)
		}
		if readErr == nil {
			if n == 0 {
				break
			}
			continue
		}
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		return nil, fmt.Errorf("policy: read %s: %w", name, readErr)
	}
	return buf, nil
}

func (s *Store) validateFileFD(fd int, name string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("%w: fstat %s: %v", ErrUnsafePolicyFile, name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafePolicyFile, name)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("%w: %s has link count %d; want 1", ErrUnsafePolicyFile, name, st.Nlink)
	}
	if st.Uid != s.config.ExpectedUID {
		return fmt.Errorf("%w: %s owner uid %d; want %d", ErrUnsafePolicyFile, name, st.Uid, s.config.ExpectedUID)
	}
	if got, want := fs.FileMode(st.Mode)&fs.ModePerm, s.config.FileMode.Perm(); got != want {
		return fmt.Errorf("%w: %s mode %04o; want %04o", ErrUnsafePolicyFile, name, got, want)
	}
	return nil
}

func (s *Store) initializeLock() error {
	fd, err := unix.Openat(s.dirFD, lockFile, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, uint32(s.config.FileMode.Perm()))
	if errors.Is(err, unix.EEXIST) {
		fd, err = s.openLock()
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	if err != nil {
		return fmt.Errorf("policy: create lock: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Fchmod(fd, uint32(s.config.FileMode.Perm())); err != nil {
		return fmt.Errorf("policy: chmod lock: %w", err)
	}
	if err := unix.Fsync(fd); err != nil {
		return fmt.Errorf("policy: fsync lock: %w", err)
	}
	if err := unix.Fsync(s.dirFD); err != nil {
		return fmt.Errorf("policy: fsync directory after lock creation: %w", err)
	}
	return s.validateFileFD(fd, lockFile)
}

func (s *Store) openLock() (int, error) {
	fd, err := unix.Openat(s.dirFD, lockFile, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return -1, fmt.Errorf("%w: %s", ErrPolicyNotFound, lockFile)
		}
		return -1, fmt.Errorf("%w: open lock: %v", ErrUnsafePolicyFile, err)
	}
	if err := s.validateFileFD(fd, lockFile); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (s *Store) lock(operation int) (int, error) {
	fd, err := s.openLock()
	if err != nil {
		return -1, err
	}
	for {
		err = unix.Flock(fd, operation)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("policy: flock: %w", err)
	}
	return fd, nil
}

func unlockAndClose(fd int) {
	_ = unix.Flock(fd, unix.LOCK_UN)
	_ = unix.Close(fd)
}

func (s *Store) atomicReplace(name string, body []byte) error {
	var random [12]byte
	for attempt := 0; attempt < 16; attempt++ {
		if _, err := rand.Read(random[:]); err != nil {
			return fmt.Errorf("random temp suffix: %w", err)
		}
		temp := ".tmp-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(s.dirFD, temp, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_CREAT|unix.O_EXCL, uint32(s.config.FileMode.Perm()))
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return fmt.Errorf("create temp: %w", err)
		}
		cleanup := true
		defer func() {
			_ = unix.Close(fd)
			if cleanup {
				_ = unix.Unlinkat(s.dirFD, temp, 0)
			}
		}()
		if err := unix.Fchmod(fd, uint32(s.config.FileMode.Perm())); err != nil {
			return fmt.Errorf("chmod temp: %w", err)
		}
		if err := s.validateFileFD(fd, temp); err != nil {
			return err
		}
		if err := writeAll(fd, body); err != nil {
			return fmt.Errorf("write temp: %w", err)
		}
		if err := unix.Fsync(fd); err != nil {
			return fmt.Errorf("fsync temp: %w", err)
		}
		if err := unix.Close(fd); err != nil {
			fd = -1
			return fmt.Errorf("close temp: %w", err)
		}
		fd = -1
		if err := unix.Renameat(s.dirFD, temp, s.dirFD, name); err != nil {
			return fmt.Errorf("rename temp: %w", err)
		}
		cleanup = false
		if err := unix.Fsync(s.dirFD); err != nil {
			return fmt.Errorf("fsync directory: %w", err)
		}
		return nil
	}
	return errors.New("policy: could not allocate unique temp file")
}

func writeAll(fd int, body []byte) error {
	for len(body) > 0 {
		n, err := unix.Write(fd, body)
		if n > 0 {
			body = body[n:]
		}
		if err == nil {
			if n == 0 {
				return io.ErrShortWrite
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
	return nil
}

func encodeAnchor(anchor policyAnchor) []byte {
	out := make([]byte, anchorSize)
	offset := copy(out, anchorDomain)
	binary.BigEndian.PutUint64(out[offset:offset+8], anchor.Version.Epoch)
	offset += 8
	binary.BigEndian.PutUint64(out[offset:offset+8], anchor.Version.Revision)
	offset += 8
	copy(out[offset:], anchor.Digest[:])
	return out
}

func decodeAnchor(raw []byte) (policyAnchor, error) {
	if len(raw) != anchorSize || !bytes.Equal(raw[:len(anchorDomain)], []byte(anchorDomain)) {
		return policyAnchor{}, errors.New("non-canonical anchor")
	}
	offset := len(anchorDomain)
	anchor := policyAnchor{}
	anchor.Version.Epoch = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	anchor.Version.Revision = binary.BigEndian.Uint64(raw[offset : offset+8])
	offset += 8
	copy(anchor.Digest[:], raw[offset:])
	if anchor.Version.Epoch == 0 || anchor.Version.Revision == 0 {
		return policyAnchor{}, errors.New("zero epoch or revision")
	}
	if anchor.Digest == ([sha256.Size]byte{}) {
		return policyAnchor{}, errors.New("zero digest")
	}
	return anchor, nil
}

func compareVersion(a, b PolicyVersion) int {
	if a.Epoch < b.Epoch {
		return -1
	}
	if a.Epoch > b.Epoch {
		return 1
	}
	if a.Revision < b.Revision {
		return -1
	}
	if a.Revision > b.Revision {
		return 1
	}
	return 0
}

func formatVersion(v PolicyVersion) string {
	return fmt.Sprintf("epoch=%d/revision=%d", v.Epoch, v.Revision)
}

func validateStoreConfig(config StoreConfig) error {
	for _, item := range []struct {
		name string
		mode fs.FileMode
	}{
		{name: "directory", mode: config.DirectoryMode},
		{name: "file", mode: config.FileMode},
	} {
		name, mode := item.name, item.mode
		if mode != mode.Perm() {
			return fmt.Errorf("policy: %s mode must contain permission bits only", name)
		}
		if mode&0o022 != 0 {
			return fmt.Errorf("policy: %s mode %04o permits group/other writes", name, mode)
		}
	}
	if config.DirectoryMode == 0 || config.FileMode == 0 {
		return errors.New("policy: directory and file modes are required")
	}
	if config.DirectoryMode&0o700 != 0o700 {
		return fmt.Errorf("policy: directory mode %04o must grant its administrative owner rwx", config.DirectoryMode)
	}
	if config.FileMode&0o600 != 0o600 {
		return fmt.Errorf("policy: file mode %04o must grant its administrative owner read/write", config.FileMode)
	}
	return nil
}
