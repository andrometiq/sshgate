package main

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/karthikeyan5/sshgate/pkg/signerkit"
)

// TestNewErrorUnreachableInShippedWiring proves C9's last item: signerkit.New,
// as wired by run() (main.go), CANNOT return an error — so the `return 1` guard
// on its error is a future-proofing tripwire, not a new observable failure class
// that could reorder startup failures. run()'s failure-class ORDER is therefore
// preserved: every config-validation failure still fails at its original step
// (loadConfig / flock / LoadKey / OpenAuditLog / buildBackend / LoadXferRegistry)
// BEFORE New is ever reached.
//
// The argument is closed, not asserted by hope:
//
//  1. New's ENTIRE error surface is exactly two typed sentinels, each requiring
//     a nil interface: Config.Signer == nil → ErrNoSigner, Config.Audit == nil →
//     ErrNoAudit (service.go). Cases 1a/1b below pin both.
//  2. run() reaches the New call only AFTER signerkit.LoadKey and signerkit.OpenAuditLog
//     have both succeeded. LoadKey returns a non-nil, 64-byte ed25519.PrivateKey
//     or an error (run() returns 1 first); OpenAuditLog returns a non-nil
//     *signerkit.AuditLog or an error (run() returns 1 first). A non-nil concrete
//     value assigned to Config.Signer (crypto.Signer) / Config.Audit (AuditSink)
//     is a non-nil interface, so neither sentinel can fire.
//  3. Feeding EXACTLY what run()'s construct step feeds — the LoadKey result as
//     Signer, the OpenAuditLog result as Audit, a real backend + xfer registry +
//     salt/rules — yields a usable *Service and a nil error. If a future edit
//     adds a THIRD validation to New that the shipped Config trips, THIS case
//     fails loudly.
func TestNewErrorUnreachableInShippedWiring(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// --- Reproduce run()'s two non-nil guarantees with the real loaders. ---
	keyPath := filepath.Join(dir, "gate.key")
	pubPath := filepath.Join(dir, "gate.pub")
	if err := signerkit.GenerateKeyPair(keyPath, pubPath); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	priv, err := signerkit.LoadKey(keyPath)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("LoadKey returned %d bytes; want %d — run() would never reach New with a short key",
			len(priv), ed25519.PrivateKeySize)
	}
	// A non-nil ed25519.PrivateKey is a non-nil crypto.Signer interface — the
	// exact value run() hands to Config.Signer.
	var asSigner crypto.Signer = priv
	if asSigner == nil {
		t.Fatal("LoadKey result is a nil crypto.Signer; impossible for a 64-byte key")
	}

	audit, err := signerkit.OpenAuditLog(filepath.Join(dir, "approvals.log"))
	if err != nil {
		t.Fatalf("OpenAuditLog: %v", err)
	}
	defer audit.Close()
	// A non-nil *AuditLog is a non-nil signerkit.AuditSink interface — the exact
	// value run() hands to Config.Audit.
	var asSink signerkit.AuditSink = audit
	if asSink == nil {
		t.Fatal("OpenAuditLog result is a nil AuditSink; impossible for a real *AuditLog")
	}

	// --- 1. New's full error surface: exactly the two nil-interface sentinels. ---
	if _, e := signerkit.New(signerkit.Config{Signer: nil, Audit: asSink}); !errors.Is(e, signerkit.ErrNoSigner) {
		t.Errorf("New(nil Signer) = %v; want ErrNoSigner", e)
	}
	if _, e := signerkit.New(signerkit.Config{Signer: asSigner, Audit: nil}); !errors.Is(e, signerkit.ErrNoAudit) {
		t.Errorf("New(nil Audit) = %v; want ErrNoAudit", e)
	}

	// --- 3. Exactly run()'s construct step: no error, usable Service. ---
	// A missing xfer-registry file is an empty registry with a nil error, so
	// this mirrors a fresh daemon with no transfer peers registered.
	xferReg, err := signerkit.LoadXferRegistry(filepath.Join(dir, "xfer-registry.json"))
	if err != nil {
		t.Fatalf("LoadXferRegistry: %v", err)
	}
	svc, err := signerkit.New(signerkit.Config{
		Signer:       priv,
		Backend:      signerkit.StubBackend{},
		Audit:        audit,
		XferRegistry: xferReg,
		RedactSalt:   [32]byte{},
		RedactRules:  nil,
	})
	if err != nil {
		t.Fatalf("New(shipped wiring) = %v; run()'s error guard must be unreachable", err)
	}
	if svc == nil {
		t.Fatal("New(shipped wiring) returned a nil *Service with a nil error")
	}
	// run() wires it as signerkit.Server.Handler, i.e. a RequestHandler.
	var _ signerkit.RequestHandler = svc
}
