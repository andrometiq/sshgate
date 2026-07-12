package signerkit

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/karthikeyan5/sshgate/src/xfer"
)

// XferRegistry is the signer's per-server box→box transfer key registry. It is
// the trust anchor for the whole feature: when the signer builds a transfer's
// two signed legs it sources the recipient's box public key and the sender's
// identity public key ONLY from here — NEVER from the MCP request. A rogue
// agent therefore cannot inject its own key: an unregistered fingerprint fails
// the lookup, and a registered fingerprint yields the key a HUMAN registered
// (registration is always-prompt, human-only — see daemon.handleRegisterXferKey).
//
// Because it is a trust anchor, a group/other-accessible registry file is a
// rogue-key-injection surface (MITM). LoadXferRegistry refuses any file with a
// group/other bit set (mask 0o077), exactly like LoadKey does for the master
// private key, and Register persists at mode 0600.
//
// Keyed by host-key fingerprint ("SHA256:…") — the same string every signed
// payload's Host already carries.
type XferRegistry struct {
	mu      sync.RWMutex
	path    string
	version int
	servers map[string]xferEntry
}

// xferEntry is one registered server's transfer material, stored in the
// canonical xfer.PublicText form so it round-trips through
// xfer.ParseBoxPublicText / ParseIDPublicText.
type xferEntry struct {
	label   string
	boxPub  string // canonical "sshgate-xfer-box-x25519 <stdb64>"
	idPub   string // canonical "sshgate-xfer-id-ed25519 <stdb64>"
	addedAt string
}

// xferRegistryFile is the on-disk JSON shape. version is for forward-compat;
// added_at is audit metadata.
type xferRegistryFile struct {
	Version int                        `json:"version"`
	Servers map[string]xferEntryOnDisk `json:"servers"`
}

type xferEntryOnDisk struct {
	Label   string `json:"label"`
	BoxPub  string `json:"box_pub"`
	IDPub   string `json:"id_pub"`
	AddedAt string `json:"added_at"`
}

const xferRegistryVersion = 1

// LoadXferRegistry loads the registry at path. A MISSING file is an EMPTY
// registry (mirrors registry.Servers' missing-file-is-empty), so a daemon whose
// operator has not registered any transfer peer still starts and simply refuses
// every transfer at the lookup step. If the file is present, its permission
// bits are checked BEFORE any read: a group/other bit (mask 0o077) is refused —
// the registry is a trust anchor and a group-writable registry is a rogue-key
// injection surface. The path is retained so Register can persist beside it.
func LoadXferRegistry(path string) (*XferRegistry, error) {
	reg := &XferRegistry{
		path:    path,
		version: xferRegistryVersion,
		servers: make(map[string]xferEntry),
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return reg, nil
		}
		return nil, fmt.Errorf("stat xfer registry: %w", err)
	}
	mode := info.Mode().Perm()
	if mode&0o077 != 0 {
		return nil, fmt.Errorf("xfer registry %s has insecure mode %#o (group/other bits must be off)", path, mode)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read xfer registry: %w", err)
	}
	var f xferRegistryFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse xfer registry: %w", err)
	}
	if f.Version != 0 {
		reg.version = f.Version
	}
	for fp, e := range f.Servers {
		// Validate stored key material on load: a corrupt/tampered entry is a
		// hard startup error rather than a silent bad trust anchor.
		if _, err := xfer.ParseBoxPublicText(e.BoxPub); err != nil {
			return nil, fmt.Errorf("xfer registry entry %s: box key: %w", fp, err)
		}
		if _, err := xfer.ParseIDPublicText(e.IDPub); err != nil {
			return nil, fmt.Errorf("xfer registry entry %s: id key: %w", fp, err)
		}
		reg.servers[fp] = xferEntry{label: e.Label, boxPub: e.BoxPub, idPub: e.IDPub, addedAt: e.AddedAt}
	}
	return reg, nil
}

// Lookup returns the registered box + id public keys and display label for the
// given host fingerprint. It parses the stored canonical text on read and fails
// CLOSED (ok=false) on a missing entry OR an unparseable stored key — a
// half-broken trust anchor never yields a usable key. Concurrency-safe.
func (r *XferRegistry) Lookup(fp string) (boxPub *[32]byte, idPub ed25519.PublicKey, label string, ok bool) {
	r.mu.RLock()
	e, exists := r.servers[fp]
	r.mu.RUnlock()
	if !exists {
		return nil, nil, "", false
	}
	bp, err := xfer.ParseBoxPublicText(e.boxPub)
	if err != nil {
		return nil, nil, "", false
	}
	ip, err := xfer.ParseIDPublicText(e.idPub)
	if err != nil {
		return nil, nil, "", false
	}
	return bp, ip, e.label, true
}

// Register inserts or overwrites the entry for fp and persists the whole
// registry atomically at mode 0600. Both keys are validated (canonical
// PublicText form) BEFORE any mutation, so a malformed key never lands.
// Overwrite is allowed — a re-provision / key rotation — because every Register
// is human-approved upstream (handleRegisterXferKey routes through an
// always-prompt backend and calls Register ONLY on StatusApproved), so an
// overwrite is an authorised rotation, not a silent takeover.
func (r *XferRegistry) Register(fp, label, boxText, idText string) error {
	if fp == "" {
		return errors.New("register: empty host fingerprint")
	}
	if _, err := xfer.ParseBoxPublicText(boxText); err != nil {
		return fmt.Errorf("register: box key: %w", err)
	}
	if _, err := xfer.ParseIDPublicText(idText); err != nil {
		return fmt.Errorf("register: id key: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.servers == nil {
		r.servers = make(map[string]xferEntry)
	}
	r.servers[fp] = xferEntry{
		label:   label,
		boxPub:  boxText,
		idPub:   idText,
		addedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return r.persistLocked()
}

// persistLocked serialises the registry and writes it atomically at 0600 via
// the same unexported atomicWrite the keystore uses (same package). Caller must
// hold r.mu.
func (r *XferRegistry) persistLocked() error {
	f := xferRegistryFile{
		Version: r.version,
		Servers: make(map[string]xferEntryOnDisk, len(r.servers)),
	}
	for fp, e := range r.servers {
		f.Servers[fp] = xferEntryOnDisk{
			Label:   e.label,
			BoxPub:  e.boxPub,
			IDPub:   e.idPub,
			AddedAt: e.addedAt,
		}
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal xfer registry: %w", err)
	}
	if err := atomicWrite(r.path, data, 0o600); err != nil {
		return fmt.Errorf("write xfer registry: %w", err)
	}
	return nil
}
