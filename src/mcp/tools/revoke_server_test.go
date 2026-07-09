package tools_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

func TestRevokeServer_HappyPath(t *testing.T) {
	t.Parallel()
	const revFP = "SHA256:revokeHostKeyFingerprintAAAAAAAAAAAAAAAAAAA"
	r := newRegistryWith(t, "to-revoke", registry.Entry{
		Host: "host.example.com", Port: 22, User: "ops", AddedAt: time.Now(), Fingerprint: revFP,
	})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_REVOKE", Sig: "SSHGATE_SIG:fake-sig:fake-payload"}}}
	ssh := &fakeSSH{stdout: []byte("SSHGATE_REVOKED lines=1 dir=removed\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "to-revoke"})
	if err != nil {
		t.Fatalf("RevokeServer: %v", err)
	}
	if !out.RemoteCleaned {
		t.Error("RemoteCleaned = false; want true")
	}
	if !out.RegistryRemoved {
		t.Error("RegistryRemoved = false; want true")
	}
	if out.Alias != "to-revoke" {
		t.Errorf("Alias = %q; want to-revoke", out.Alias)
	}
	if !sign.signCalled {
		t.Error("Sign was not called")
	}
	if len(sign.gotCmds) != 1 || sign.gotCmds[0].Cmd != "SSHGATE_REVOKE" {
		t.Errorf("sign got %+v; want one cmd SSHGATE_REVOKE", sign.gotCmds)
	}
	// SSHGATE_REVOKE is a signed admin command, so it must carry the host
	// binding read from the registry or the gate would reject it.
	if sign.gotCmds[0].Host != revFP {
		t.Errorf("revoke sign CmdReq.Host = %q; want registry fingerprint %q", sign.gotCmds[0].Host, revFP)
	}
	if !strings.HasPrefix(ssh.gotCmd, "SSHGATE_SIG:") || !strings.HasSuffix(ssh.gotCmd, " SSHGATE_REVOKE") {
		t.Errorf("ssh.gotCmd = %q; want SSHGATE_SIG:... SSHGATE_REVOKE", ssh.gotCmd)
	}
	// Registry must no longer have the alias.
	if _, ok := r.Get("to-revoke"); ok {
		t.Error("registry still has the alias after a successful revoke")
	}
}

// TestRevokeServer_Tier1ShortCircuit asserts that revoking a read-only (Tier-1)
// server is refused BEFORE any sign request: the gate has no signer pubkey, so a
// signed SSHGATE_REVOKE can never be verified — soliciting the signature first
// would burn a real human Telegram tap on a guaranteed no-op. The registry must
// be left intact, Sign must never be called, and the message must NOT tell the
// user to run /sshgate:revoke (circular).
func TestRevokeServer_Tier1ShortCircuit(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "ro-box", registry.Entry{
		Host: "1.2.3.4", Port: 22, User: "ops", AddedAt: time.Now(), ReadOnly: true,
	})
	sign := &fakeSign{}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	out, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "ro-box"})
	if err == nil {
		t.Fatal("expected error revoking a read-only (Tier-1) server, got nil")
	}
	if sign.signCalled {
		t.Error("Sign was called for a Tier-1 revoke; must short-circuit before signing (a wasted Telegram tap)")
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called for a Tier-1 revoke; nothing should reach the host")
	}
	if out.RemoteCleaned || out.RegistryRemoved {
		t.Errorf("out reports cleanup on a refused Tier-1 revoke: %+v", out)
	}
	// Registry must be untouched.
	if _, ok := r.Get("ro-box"); !ok {
		t.Error("registry alias removed despite the Tier-1 short-circuit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "read-only") || !strings.Contains(msg, "ro-box") {
		t.Errorf("error %q is not the actionable read-only guidance naming the alias", msg)
	}
	if strings.Contains(msg, "/sshgate:revoke") {
		t.Errorf("error %q gives circular /sshgate:revoke advice", msg)
	}
	if !strings.Contains(msg, "sshgate add") {
		t.Errorf("error %q does not describe the manual re-add path", msg)
	}
}

func TestRevokeServer_UnknownAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "exists", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}

	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "nope"})
	if err == nil {
		t.Fatal("expected error for unknown alias")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("err=%v; want mention of alias", err)
	}
}

func TestRevokeServer_SignDenied(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrDenied}
	ssh := &fakeSSH{}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if err == nil {
		t.Fatal("expected error on denial")
	}
	if !errors.Is(err, signpkg.ErrDenied) {
		t.Errorf("err=%v; want wrap of ErrDenied", err)
	}
	if len(ssh.callHistory) != 0 {
		t.Error("SSH was called after denial")
	}
	// Registry must NOT have been touched.
	if _, ok := r.Get("a"); !ok {
		t.Error("registry alias removed despite denial")
	}
}

func TestRevokeServer_SignTimeout(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrTimeout}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if !errors.Is(err, signpkg.ErrTimeout) {
		t.Errorf("err=%v; want wrap of ErrTimeout", err)
	}
}

func TestRevokeServer_SignUnreachable(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{err: signpkg.ErrUnreachable}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: &fakeSSH{}}
	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if !errors.Is(err, signpkg.ErrUnreachable) {
		t.Errorf("err=%v; want wrap of ErrUnreachable", err)
	}
}

func TestRevokeServer_NoConfirmationMarker(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_REVOKE", Sig: "SSHGATE_SIG:x:y"}}}
	ssh := &fakeSSH{stdout: []byte("nothing interesting\n"), exit: 0}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if err == nil {
		t.Fatal("expected error when stdout missing SSHGATE_REVOKED marker")
	}
	// Registry should remain intact — we cannot prove the remote cleaned itself.
	if _, ok := r.Get("a"); !ok {
		t.Error("registry alias removed despite missing confirmation marker")
	}
}

func TestRevokeServer_SSHErrorReturnsError(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "a", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	sign := &fakeSign{signed: []signpkg.Signed{{Cmd: "SSHGATE_REVOKE", Sig: "SSHGATE_SIG:x:y"}}}
	ssh := &fakeSSH{err: errors.New("dial: connection refused")}
	runner := &tools.Runner{Servers: r, Sign: sign, SSH: ssh}

	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "a"})
	if err == nil {
		t.Fatal("expected error on SSH failure")
	}
	if _, ok := r.Get("a"); !ok {
		t.Error("registry alias removed despite SSH failure")
	}
}

func TestRevokeServer_NilRegistryRejected(t *testing.T) {
	t.Parallel()
	runner := &tools.Runner{Sign: &fakeSign{}, SSH: &fakeSSH{}}
	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: "x"})
	if err == nil {
		t.Fatal("expected error for nil Servers")
	}
}

func TestRevokeServer_EmptyAlias(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r, _ := registry.New(filepath.Join(dir, "servers.json"))
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	_, err := runner.RevokeServer(context.Background(), tools.RevokeServerInput{Alias: ""})
	if err == nil {
		t.Fatal("expected error for empty alias")
	}
}
