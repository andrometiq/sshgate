package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	"github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/xfer"
)

// These tests drive the human-only transfer CLI verbs with the registerXferKey /
// xferKeysOnHost seams faked, so no real signer socket or SSH dial is touched. A
// temp config root ($XDG_CONFIG_HOME/sshgate) holds a seeded servers.json.

// seedConfigRoot points $XDG_CONFIG_HOME at a temp dir and writes a servers.json
// with the given entries. Returns the config root.
func seedConfigRoot(t *testing.T, entries map[string]registry.Entry) string {
	t.Helper()
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	root := filepath.Join(base, "sshgate")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.New(filepath.Join(root, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	for alias, e := range entries {
		if err := reg.Add(alias, e); err != nil {
			t.Fatalf("seed %s: %v", alias, err)
		}
	}
	return root
}

// freshXferLines returns a valid (box, id) canonical PublicText pair.
func freshXferLines(t *testing.T) (boxLine, idLine string) {
	t.Helper()
	bk, err := xfer.GenerateBoxKey()
	if err != nil {
		t.Fatal(err)
	}
	ik, err := xfer.GenerateIDKey()
	if err != nil {
		t.Fatal(err)
	}
	return bk.PublicText(), ik.PublicText()
}

// installFakeRegister swaps the registerXferKey seam and records the last call.
func installFakeRegister(t *testing.T, retErr error) *capturedRegister {
	t.Helper()
	cap := &capturedRegister{}
	orig := registerXferKey
	t.Cleanup(func() { registerXferKey = orig })
	registerXferKey = func(_ context.Context, sockPath, reqID string, req sign.RegisterXferKeyReq) error {
		cap.called++
		cap.sockPath = sockPath
		cap.reqID = reqID
		cap.req = req
		return retErr
	}
	return cap
}

type capturedRegister struct {
	called   int
	sockPath string
	reqID    string
	req      sign.RegisterXferKeyReq
}

// TestXferRegister_HappyPath: alias→fp lookup, valid lines, the seam is called
// with the fp from servers.json and label defaulting to the alias.
func TestXferRegister_HappyPath(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
	})
	box, id := freshXferLines(t)
	cap := installFakeRegister(t, nil)

	code := run([]string{"xfer-register", "prod", "--box-pub", box, "--id-pub", id})
	if code != 0 {
		t.Fatalf("run = %d; want 0", code)
	}
	if cap.called != 1 {
		t.Fatalf("register seam called %d times; want 1", cap.called)
	}
	if cap.req.HostFP != "SHA256:prodfp" {
		t.Errorf("registered under fp %q; want the servers.json fingerprint", cap.req.HostFP)
	}
	if cap.req.Label != "prod" {
		t.Errorf("label = %q; want the alias default", cap.req.Label)
	}
	if cap.req.BoxPub != box || cap.req.IDPub != id {
		t.Error("box/id lines not passed through to the signer verbatim")
	}
}

// TestXferRegister_Tier1Rejected: a read-only alias is refused before any dial.
func TestXferRegister_Tier1Rejected(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"edge": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:edgefp", ReadOnly: true},
	})
	box, id := freshXferLines(t)
	cap := installFakeRegister(t, nil)

	code := run([]string{"xfer-register", "edge", "--box-pub", box, "--id-pub", id})
	if code == 0 {
		t.Fatal("run = 0; want non-zero for a Tier-1 alias")
	}
	if cap.called != 0 {
		t.Error("register seam was called for a Tier-1 alias; must be refused before dialing")
	}
}

// TestXferRegister_MalformedBoxRejectedBeforeDial: a bad --box-pub line never
// spends a human tap.
func TestXferRegister_MalformedBoxRejectedBeforeDial(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
	})
	_, id := freshXferLines(t)
	cap := installFakeRegister(t, nil)

	code := run([]string{"xfer-register", "prod", "--box-pub", "not-a-valid-line", "--id-pub", id})
	if code != 2 {
		t.Fatalf("run = %d; want 2 (usage/validation error)", code)
	}
	if cap.called != 0 {
		t.Error("register seam called despite a malformed box line")
	}
}

// TestXferRegister_OverLongLabelRejected: a >64-byte label is rejected CLI-side
// before dialing.
func TestXferRegister_OverLongLabelRejected(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
	})
	box, id := freshXferLines(t)
	cap := installFakeRegister(t, nil)
	longLabel := strings.Repeat("x", 65)

	code := run([]string{"xfer-register", "prod", "--box-pub", box, "--id-pub", id, "--label", longLabel})
	if code != 2 {
		t.Fatalf("run = %d; want 2 (label too long)", code)
	}
	if cap.called != 0 {
		t.Error("register seam called despite an over-long label")
	}
}

// TestXferRegister_UnknownAlias: an alias not in servers.json is an error.
func TestXferRegister_UnknownAlias(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{})
	box, id := freshXferLines(t)
	installFakeRegister(t, nil)
	code := run([]string{"xfer-register", "ghost", "--box-pub", box, "--id-pub", id})
	if code == 0 {
		t.Fatal("run = 0; want non-zero for an unknown alias")
	}
}

// TestXferRegister_DeniedReported: a denied verdict surfaces a non-zero exit and
// does NOT claim success.
func TestXferRegister_DeniedReported(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
	})
	box, id := freshXferLines(t)
	installFakeRegister(t, sign.ErrDenied)
	code := run([]string{"xfer-register", "prod", "--box-pub", box, "--id-pub", id})
	if code == 0 {
		t.Fatal("run = 0; want non-zero when registration is denied")
	}
}

// TestXferStatus_RendersTierAndFingerprint: xfer-status lists each server's tier
// + fingerprint without touching the signer. The host probe is faked so no real
// dial happens; the Tier-1 server is reported n/a and never probed.
func TestXferStatus_RendersTierAndFingerprint(t *testing.T) {
	seedConfigRoot(t, map[string]registry.Entry{
		"prod": {Host: "h", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:prodfp"},
		"edge": {Host: "h2", Port: 22, User: "u", AddedAt: time.Now(), Fingerprint: "SHA256:edgefp", ReadOnly: true},
	})
	origProbe := xferKeysOnHost
	t.Cleanup(func() { xferKeysOnHost = origProbe })
	var probedTier1 bool
	xferKeysOnHost = func(_ context.Context, cfg tools.ProvisionConfig, alias string) (bool, bool) {
		if alias == "edge" {
			probedTier1 = true
		}
		return true, true
	}

	out := captureStdout(t, func() {
		if code := run([]string{"xfer-status"}); code != 0 {
			t.Fatalf("run = %d; want 0", code)
		}
	})
	if probedTier1 {
		t.Error("xfer-status probed a Tier-1 server for keys; it must not")
	}
	if !strings.Contains(out, "prod") || !strings.Contains(out, "SHA256:prodfp") {
		t.Errorf("status output missing tier-2 row:\n%s", out)
	}
	if !strings.Contains(out, "tier-1") || !strings.Contains(out, "SHA256:edgefp") {
		t.Errorf("status output missing tier-1 row:\n%s", out)
	}
	if !strings.Contains(out, "yes") {
		t.Errorf("status output missing keys-on-host=yes for the probed tier-2 server:\n%s", out)
	}
}

// captureStdout swaps os.Stdout for a pipe, runs fn, and returns everything
// written (the CLI writes its status table to stdout).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan struct{})
	var sb strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if rerr != nil {
				break
			}
		}
		close(done)
	}()
	fn()
	_ = w.Close()
	<-done
	os.Stdout = orig
	_ = r.Close()
	return sb.String()
}
