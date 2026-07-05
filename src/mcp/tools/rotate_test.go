package tools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
)

// seedServer writes a servers.json under cfg.ServersPath with one alias.
func seedServer(t *testing.T, cfg provisionCfg, alias, fp string, readOnly bool) {
	t.Helper()
	reg, err := registry.New(cfg.ServersPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Add(alias, registry.Entry{
		Host: "h.example.com", Port: 22, User: "u",
		AddedAt: time.Now(), Fingerprint: fp, ReadOnly: readOnly,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRotateXferKeys_HappyPath: on a re-opened plain window (no gate answers),
// RotateXferKeys re-locks, runs genkeys --rotate, verifies, and returns the new
// public lines under the SAME fingerprint.
func TestRotateXferKeys_HappyPath(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	seedServer(t, cfg, "prod", "SHA256:rot", false)
	block, wantBox, wantID := genKeysReadbackBlock(t)
	sess := &fakeBootstrapSession{
		catAuthKeys: plainPastedLine(t, pub),
		probeOut:    []byte("SSHGATE_OK\n"),
		genkeysOut:  block,
		// versionProbeOut empty => no gate answers => plain shell (rotate proceeds).
	}
	installFakeBootstrapSession(t, sess, "SHA256:rot")

	out, err := RotateXferKeys(context.Background(), cfg, RotateInput{Alias: "prod"})
	if err != nil {
		t.Fatalf("RotateXferKeys: %v", err)
	}
	if out.Fingerprint != "SHA256:rot" {
		t.Errorf("Fingerprint = %q; want the unchanged servers.json fp", out.Fingerprint)
	}
	if out.XferBoxPub != wantBox || out.XferIDPub != wantID {
		t.Error("rotate did not return the parsed genkeys public lines")
	}
	if !sess.ranContaining(remoteGateBin + " genkeys --rotate") {
		t.Error("genkeys --rotate did not run on the plain shell")
	}
}

// TestRotateXferKeys_StillLockedRefused: if a gate still answers (forced command
// active), rotate refuses with a remediation and runs no genkeys.
func TestRotateXferKeys_StillLockedRefused(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	seedServer(t, cfg, "prod", "SHA256:rot", false)
	sess := &fakeBootstrapSession{
		catAuthKeys:     plainPastedLine(t, pub),
		versionProbeOut: []byte("SSHGATE_VERSION rev=abc123\n"), // a gate answers
	}
	installFakeBootstrapSession(t, sess, "SHA256:rot")

	_, err := RotateXferKeys(context.Background(), cfg, RotateInput{Alias: "prod"})
	if err == nil {
		t.Fatal("RotateXferKeys = nil; want a still-locked refusal")
	}
	if !strings.Contains(err.Error(), "still locked") {
		t.Errorf("err = %v; want a 'still locked' remediation", err)
	}
	if sess.ranContaining("genkeys") {
		t.Error("genkeys ran despite the gate still being locked")
	}
}

// TestRotateXferKeys_Tier1Rejected: a read-only alias has no transfer keys.
func TestRotateXferKeys_Tier1Rejected(t *testing.T) {
	cfg, _ := provisionMaterials(t)
	seedServer(t, cfg, "edge", "SHA256:ro", true)
	_, err := RotateXferKeys(context.Background(), cfg, RotateInput{Alias: "edge"})
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("err = %v; want a Tier-1 read-only refusal", err)
	}
}

// TestRotateXferKeys_FingerprintMismatchAborts: a host whose captured fp differs
// from the stored one aborts (never rotate against a new identity).
func TestRotateXferKeys_FingerprintMismatchAborts(t *testing.T) {
	cfg, pub := provisionMaterials(t)
	seedServer(t, cfg, "prod", "SHA256:expected", false)
	sess := &fakeBootstrapSession{catAuthKeys: plainPastedLine(t, pub)}
	installFakeBootstrapSession(t, sess, "SHA256:different") // dialed fp != stored

	_, err := RotateXferKeys(context.Background(), cfg, RotateInput{Alias: "prod"})
	if err == nil {
		t.Fatal("RotateXferKeys = nil; want a host-key-change abort")
	}
	if !strings.Contains(err.Error(), "changed") {
		t.Errorf("err = %v; want a host-key-changed abort", err)
	}
	if sess.ranContaining("genkeys") {
		t.Error("genkeys ran despite a fingerprint mismatch")
	}
}

// TestRotateXferKeys_UnknownAlias errors cleanly.
func TestRotateXferKeys_UnknownAlias(t *testing.T) {
	cfg, _ := provisionMaterials(t)
	seedServer(t, cfg, "prod", "SHA256:rot", false)
	_, err := RotateXferKeys(context.Background(), cfg, RotateInput{Alias: "ghost"})
	if err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("err = %v; want a not-registered error", err)
	}
}
