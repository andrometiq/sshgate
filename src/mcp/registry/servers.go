package registry

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// warnw is the sink for non-fatal warnings (the deprecated-wrapper notice in
// Load and the best-effort reload-failure notices in reloadIfChanged). It
// defaults to os.Stderr; tests swap it for a buffer to assert warn-once
// behaviour. Unexported on purpose. Not safe to swap concurrently with code
// that writes to it — tests that swap it must not run in parallel with each
// other or with stderr-capturing tests.
var warnw io.Writer = os.Stderr

// Entry is the on-disk record for one server alias. AddedAt is
// persisted in JSON so the audit log can correlate "when was this
// alias registered" with the approval timeline.
type Entry struct {
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	User    string    `json:"user"`
	AddedAt time.Time `json:"added_at"`
	// ReadOnly records that the alias was added in tier-1 read-only
	// mode (no gate.pub pushed, no signer). Writes to a ReadOnly
	// server are denied at the gate, so the run/run_batch paths
	// short-circuit before soliciting a wasted Telegram approval.
	// To move a read-only server to signed-write a human revokes it
	// (/sshgate:revoke) and re-provisions with `sshgate add` (no
	// --read-only); an in-place upgrade was rejected for security
	// (roadmap #17, redefined) — re-tiering stays revoke + re-provision.
	ReadOnly bool `json:"read_only,omitempty"`
	// Fingerprint is the target's TOFU-pinned SSH host-key fingerprint
	// (OpenSSH "SHA256:..." form), recorded by provisioning. The MCP supplies
	// it — from HERE, the trusted registry, never an agent parameter — in the
	// sign request so the signed payload binds to this exact host; the gate
	// self-derives its own host fingerprint and rejects a signature whose
	// binding names a different server. omitempty so a registry written before
	// this field existed still round-trips.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Servers is the alias → Entry map backed by the file at Path. All
// methods are safe for concurrent calls. A missing file is treated as
// an empty registry; the first Add creates it with mode 0o600.
type Servers struct {
	path string

	mu   sync.Mutex
	data map[string]Entry
	// lastHash is the sha256 of the file BODY as it was last SEEN by a reload
	// — recorded whether the subsequent decode succeeded OR failed. Comparing
	// the current body's hash against it is the change signal: it catches an
	// equal-size, same-mtime-tick out-of-band edit that a (mtime,size) signal
	// would miss (a stale Host/Fingerprint is a trust-boundary leak), and it
	// suppresses re-warning on an unchanged bad version (warn once per distinct
	// file version). hasHash distinguishes "never observed" from "observed".
	// filePresent records whether the file existed at the last observation so a
	// disappear/appear is also treated as a change. All guarded by mu.
	lastHash    [sha256.Size]byte
	hasHash     bool
	filePresent bool
}

// New opens the registry at path. It performs the permission check
// (per daemon.md §5.2 — refuses any group- or world-write bit) and
// loads existing contents. A missing file is not an error; the data
// map is initialised empty.
func New(path string) (*Servers, error) {
	s := &Servers{path: path, data: make(map[string]Entry)}
	if err := s.Load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Load re-reads the file at Path into memory. Callers normally do not
// invoke this directly — New does it on construction — but tests rely
// on it.
//
// Load returns nil if the file does not exist (empty registry). It
// returns an error if the file is group- or world-writable, or if the
// JSON is malformed.
func (s *Servers) Load() error {
	info, err := os.Stat(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		s.mu.Lock()
		s.data = make(map[string]Entry)
		// File absent: remember that so reloadIfChanged treats a later
		// "file appeared" as a change worth reloading.
		s.recordHashLocked([sha256.Size]byte{}, false)
		s.mu.Unlock()
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", s.path, err)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("registry %s has insecure mode %#o (group/world writable)", s.path, perm)
	}
	body, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	bodyHash := sha256.Sum256(body)
	if len(body) == 0 {
		s.mu.Lock()
		s.data = make(map[string]Entry)
		s.recordHashLocked(bodyHash, true)
		s.mu.Unlock()
		return nil
	}
	var loaded map[string]Entry
	if err := json.Unmarshal(body, &loaded); err != nil {
		return fmt.Errorf("unmarshal %s: %w", s.path, err)
	}
	if loaded == nil {
		loaded = make(map[string]Entry)
	}

	// Legacy {"servers":...} wrapper detection.
	//
	// The registry is a BARE alias→Entry map: top-level JSON keys ARE the
	// aliases. Two older install snippets, however, seeded the file with a
	// WRAPPED shape — {"servers":{}} or {"servers":{<real servers>}}. Read as
	// a bare map that mismatch is silent and dangerous:
	//   - {"servers":{}} decodes to ONE alias literally named "servers" whose
	//     {} becomes a zero-value Entry — a PHANTOM server surfaced by
	//     list_servers/status (empty host, AddedAt 0001-01-01).
	//   - {"servers":{<real servers>}} decodes the inner object into a single
	//     Entry (its keys don't match Entry fields) and the real servers are
	//     SILENTLY DROPPED with no error — the fleet collapses.
	//
	// We trigger ONLY on the unambiguous wrapper signature: exactly one key,
	// it is "servers", and its Entry is the zero value. A REAL server aliased
	// "servers" has a non-empty Host (provisioning requires one), so it does
	// not match and loads normally.
	if len(loaded) == 1 {
		if e, ok := loaded["servers"]; ok && e == (Entry{}) {
			// Re-inspect the raw body to split empty-vs-populated wrappers
			// without re-deciding from the lossy bare-map decode above.
			var top map[string]json.RawMessage
			if err := json.Unmarshal(body, &top); err != nil {
				return fmt.Errorf("unmarshal %s: %w", s.path, err)
			}
			var inner map[string]json.RawMessage
			if err := json.Unmarshal(top["servers"], &inner); err != nil {
				return fmt.Errorf("unmarshal %s: %w", s.path, err)
			}
			if len(inner) == 0 {
				// Legacy EMPTY wrapper ({"servers":{}} or {"servers":null}) —
				// the common fresh-install case. Normalise to an empty
				// registry and warn; failing here would brick every Tier-1
				// setup that used the old seed snippet.
				fmt.Fprintf(warnw, "sshgate: registry %s uses the deprecated wrapped {\"servers\":...} format; treating as empty — convert it to a bare alias→server map (see docs/install-step-by-step.md)\n", s.path)
				loaded = make(map[string]Entry)
			} else {
				// Legacy POPULATED wrapper — a bare-map read would silently
				// drop these real servers. Refuse to start so the operator
				// converts the file instead of losing the fleet.
				sortedKeys := make([]string, 0, len(inner))
				for k := range inner {
					sortedKeys = append(sortedKeys, k)
				}
				sort.Strings(sortedKeys)
				return fmt.Errorf("registry %s uses the unsupported wrapped {\"servers\":...} format; %d server(s) (%s) would be silently dropped — convert it to a bare alias→server map (see docs/install-step-by-step.md)", s.path, len(inner), strings.Join(sortedKeys, ", "))
			}
		}
	}

	s.mu.Lock()
	s.data = loaded
	s.recordHashLocked(bodyHash, true)
	s.mu.Unlock()
	return nil
}

// recordHashLocked stamps the identity of the file version most recently SEEN:
// the sha256 of its body (zero value when the file is absent) and whether it
// was present. reloadIfChanged compares against this to decide whether to
// reload. It is recorded whether the decode succeeded OR failed, so an
// unchanged bad version is not reprocessed/re-warned (warn once per distinct
// file version). The caller must already hold s.mu.
func (s *Servers) recordHashLocked(hash [sha256.Size]byte, present bool) {
	s.lastHash = hash
	s.hasHash = true
	s.filePresent = present
}

// reloadIfChanged re-reads the file if its CONTENT has changed on disk since
// the last version we saw — covering a human `sshgate add` running in a
// separate process, which rewrites servers.json while this MCP is live. The
// change signal is a sha256 of the file body, NOT (mtime,size): an out-of-band
// edit that preserves byte length and lands in the same coarse mtime tick would
// be missed by (mtime,size) and serve a STALE Host/Fingerprint (a trust-boundary
// value), whereas a content hash always catches it. The registry is <1KB on a
// low-frequency interactive path, so read+hash per Get/List is cheap.
//
// It is BEST-EFFORT: a stat/read error or a Load error leaves the in-memory
// data untouched (the running MCP keeps serving the last good registry) and is
// reported to warnw only — never propagated, never panics. The hash of the body
// we just SAW is recorded whether Load succeeded or FAILED, so an unchanged bad
// version (corrupt JSON, perm-loosened file) is not reprocessed and the warning
// fires once per distinct file version, not on every Get/List. Callers (Get/List)
// invoke it WITHOUT holding s.mu, because Load acquires s.mu itself.
//
// The production writer (persist) uses tmp+rename, so a concurrent stat/read
// here always sees a complete old-or-new file, never a partial one.
func (s *Servers) reloadIfChanged() {
	s.mu.Lock()
	hasHash := s.hasHash
	wasPresent := s.filePresent
	curHash := s.lastHash
	s.mu.Unlock()

	body, err := os.ReadFile(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		// File absent. Only a transition present→absent is a change worth
		// reloading (Load reflects it as an empty registry). If it was already
		// known absent (same version), do nothing — and don't re-warn.
		if !hasHash || wasPresent {
			if lerr := s.Load(); lerr != nil {
				fmt.Fprintf(warnw, "sshgate: registry %s reload failed (%v); keeping last-known servers\n", s.path, lerr)
			}
		}
		return
	}
	if err != nil {
		// Transient read error (e.g. EACCES on the file itself, no body to
		// hash): keep last-known data, do not reload. No identity to dedupe on,
		// so this is not warn-once.
		fmt.Fprintf(warnw, "sshgate: registry %s read failed (%v); keeping last-known servers\n", s.path, err)
		return
	}

	// File present. Unchanged content (same hash, still present) → nothing to do.
	bodyHash := sha256.Sum256(body)
	if hasHash && wasPresent && bodyHash == curHash {
		return
	}

	// New version. Record its hash NOW (before Load) so that even if Load fails
	// to parse it we don't reprocess/re-warn until the bytes change again. On
	// Load success Load re-stamps the identical hash (harmless).
	s.mu.Lock()
	s.recordHashLocked(bodyHash, true)
	s.mu.Unlock()

	if lerr := s.Load(); lerr != nil {
		fmt.Fprintf(warnw, "sshgate: registry %s reload failed (%v); keeping last-known servers\n", s.path, lerr)
	}
}

// Get returns the entry for alias, or false if it is not registered.
func (s *Servers) Get(alias string) (Entry, bool) {
	// Pick up an out-of-band `sshgate add` before reading; best-effort.
	s.reloadIfChanged()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.data[alias]
	return e, ok
}

// List returns a copy of the registry. Mutating the returned map does
// not affect the Servers state.
func (s *Servers) List() map[string]Entry {
	// Pick up an out-of-band `sshgate add` before reading; best-effort.
	s.reloadIfChanged()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]Entry, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

// Add inserts or replaces alias with e and persists the registry
// atomically (tmp + fsync + rename + fsync(parent), per daemon.md
// §5.1). If the write fails the in-memory state is rolled back so
// callers observing Get see a consistent registry.
func (s *Servers) Add(alias string, e Entry) error {
	if alias == "" {
		return errors.New("registry: alias is empty")
	}
	s.mu.Lock()
	prev, hadPrev := s.data[alias]
	s.data[alias] = e
	snapshot := s.cloneLocked()
	s.mu.Unlock()

	if err := s.persist(snapshot); err != nil {
		s.mu.Lock()
		if hadPrev {
			s.data[alias] = prev
		} else {
			delete(s.data, alias)
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

// Remove deletes the entry for alias. It returns an error if alias is
// not registered (so callers can surface a clean "unknown alias"
// message to operators).
func (s *Servers) Remove(alias string) error {
	s.mu.Lock()
	prev, ok := s.data[alias]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("registry: unknown alias %q", alias)
	}
	delete(s.data, alias)
	snapshot := s.cloneLocked()
	s.mu.Unlock()

	if err := s.persist(snapshot); err != nil {
		s.mu.Lock()
		s.data[alias] = prev
		s.mu.Unlock()
		return err
	}
	return nil
}

// cloneLocked returns a copy of s.data; caller must already hold s.mu.
func (s *Servers) cloneLocked() map[string]Entry {
	out := make(map[string]Entry, len(s.data))
	for k, v := range s.data {
		out[k] = v
	}
	return out
}

// persist atomically rewrites Path with the contents of m. The write
// pattern is the standard "tmp + fsync + rename + fsync(parent)" so a
// crash mid-write never leaves a partial file at Path.
func (s *Servers) persist(m map[string]Entry) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".servers.*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	// On any subsequent error we want to clean up the tmp file.
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("rename: %w", err)
	}
	// Fsync the parent directory so the rename is durable.
	if dirF, err := os.Open(dir); err == nil {
		_ = dirF.Sync()
		_ = dirF.Close()
	}
	return nil
}
