package tools

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// White-box bootstrap-flow test infrastructure. This file holds the
// in-memory fakeBootstrapSession / khSSH fakes and the install*BootstrapSession
// seams (a package-level var, mirroring src/mcp/sign's dialWithCtx) that the
// Provision tests in provision_test.go drive, plus the bootstrapAuthMethod
// seam tests (agent path, parse-private-key) for the credential resolver
// Provision shares. The production seam constructs the SAME real ssh session
// it always did; tests swap in the in-memory fake so the dial-upload-rollback
// flow is reachable without a live sshd.

// ---------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------

// fakeBootstrapSession is an in-memory bootstrapSession. It records every
// Run/Upload/Close call in order and can be scripted to fail a specific
// command substring or upload remotePath. It also models the remote
// authorized_keys / gate-dir state just enough to let the idempotency
// "cat authorized_keys" probe and rollback assertions be meaningful.
type fakeBootstrapSession struct {
	// runs/uploads record the ordered call log.
	runs    []string // commands passed to Run
	uploads []uploadCall
	closed  int

	// catReturns is the stdout returned for the "cat authorized_keys"
	// idempotency probe (and any other Run). Empty => no existing keys.
	catAuthKeys []byte

	// failRunSub: if a Run command contains this non-empty substring,
	// Run returns an error (and records the attempt).
	failRunSub string
	// failUploadPath: if an Upload remotePath equals this non-empty
	// value, Upload returns an error (and records the attempt).
	failUploadPath string

	// uploadedAuthKeys captures the bytes written to remoteAuthKeys (the
	// rewritten file) so tests can assert the forced-command rewrite.
	uploadedAuthKeys []byte

	// probeOut is the stdout returned for the empty-command SSHGATE_OK
	// verify probe (Provision re-dials and runs ""). Set to "SSHGATE_OK\n"
	// for the success paths; left empty to drive the verify-failure rollback
	// path.
	probeOut []byte

	// versionProbeOut is the stdout returned for the unsigned SSHGATE_VERSION
	// idempotency probe Provision sends FIRST on the dedicated-key dial. Set
	// to "SSHGATE_VERSION rev=<rev>\n" to model an already-gated host (the
	// probe-first idempotent path); leave empty to model a fresh/plain-shell
	// host so Provision falls through to the authorized_keys detection. To
	// model a plain shell's hard failure ("command not found", exit 127) use
	// failRunSub: "SSHGATE_VERSION" instead.
	versionProbeOut []byte

	// genkeysOut is the stdout returned for the `gate genkeys` (or
	// `gate genkeys --rotate`) readback the Tier-2 fresh add / rotate runs over
	// the plain shell. Set to a valid SSHGATE_XFER_PUBKEYS_BEGIN/END block (see
	// genKeysReadbackBlock) for the write happy paths; leave empty to model an
	// older gate that returns no block (drives the readback-parse failure).
	genkeysOut []byte
}

type uploadCall struct {
	remotePath string
	mode       string
	body       []byte
}

func (f *fakeBootstrapSession) Run(_ context.Context, cmd string) ([]byte, []byte, error) {
	f.runs = append(f.runs, cmd)
	if f.failRunSub != "" && strings.Contains(cmd, f.failRunSub) {
		return nil, []byte("scripted-stderr"), errors.New("scripted run failure")
	}
	// The probe-first idempotency check sends the unsigned SSHGATE_VERSION
	// verb. Return the modelled gate answer (empty => no gate answered).
	if cmd == "SSHGATE_VERSION" {
		return f.versionProbeOut, nil, nil
	}
	// The Tier-2 fresh add / rotate runs `gate genkeys[ --rotate]` over the plain
	// shell. Return the modelled readback block.
	if strings.Contains(cmd, "genkeys") {
		return f.genkeysOut, nil, nil
	}
	// The fallback idempotency detection is "cat ~/.ssh/authorized_keys ...".
	// Return the modelled existing keys for any cat-of-authorized_keys command.
	if strings.Contains(cmd, "cat "+remoteAuthKeys) {
		return f.catAuthKeys, nil, nil
	}
	// The Provision verify probe re-dials and runs the empty command, which
	// triggers gate's SSHGATE_OK path. Model that as probeOut.
	if cmd == "" {
		return f.probeOut, nil, nil
	}
	return nil, nil, nil
}

func (f *fakeBootstrapSession) Upload(_ context.Context, body []byte, remotePath, mode string) error {
	f.uploads = append(f.uploads, uploadCall{remotePath: remotePath, mode: mode, body: append([]byte(nil), body...)})
	if f.failUploadPath != "" && remotePath == f.failUploadPath {
		return errors.New("scripted upload failure")
	}
	if remotePath == remoteAuthKeys {
		f.uploadedAuthKeys = append([]byte(nil), body...)
	}
	return nil
}

func (f *fakeBootstrapSession) Close() error {
	f.closed++
	return nil
}

func (f *fakeBootstrapSession) ranContaining(sub string) bool {
	for _, c := range f.runs {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func (f *fakeBootstrapSession) uploadedTo(remotePath string) (uploadCall, bool) {
	for _, u := range f.uploads {
		if u.remotePath == remotePath {
			return u, true
		}
	}
	return uploadCall{}, false
}

// khSSH is an SSHRunner that ALSO exposes a known_hosts path (so
// Runner.knownHostsPath() returns non-empty and buildBootstrapClientConfig
// succeeds) and records the verify-probe Run calls. The probe stdout /
// err are scriptable to drive the post-verify rollback path.
type khSSH struct {
	kh       string
	probeOut []byte
	probeErr error
	calls    int
}

func (s *khSSH) Run(_ context.Context, _, _ string, _ int, _ string) ([]byte, []byte, int, error) {
	s.calls++
	return s.probeOut, nil, 0, s.probeErr
}

func (s *khSSH) KnownHosts() string { return s.kh }

// ---------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------

// installFakeBootstrapSession points the newBootstrapSession seam at sess
// (returning fingerprint fp) and restores the original via t.Cleanup. It
// records the cfg the production code built so tests can assert the dial
// args were threaded correctly.
func installFakeBootstrapSession(t *testing.T, sess bootstrapSession, fp string) *capturedDial {
	t.Helper()
	cap := &capturedDial{}
	orig := newBootstrapSession
	t.Cleanup(func() { newBootstrapSession = orig })
	newBootstrapSession = func(_ context.Context, host string, port int, cfg *ssh.ClientConfig) (bootstrapSession, string, error) {
		cap.host = host
		cap.port = port
		cap.cfg = cfg
		return sess, fp, nil
	}
	return cap
}

type capturedDial struct {
	host string
	port int
	cfg  *ssh.ClientConfig
}

// installFailingBootstrapDial points the seam at a dialer that fails with
// the given error (e.g. an "unable to authenticate" handshake error).
func installFailingBootstrapDial(t *testing.T, dialErr error) {
	t.Helper()
	orig := newBootstrapSession
	t.Cleanup(func() { newBootstrapSession = orig })
	newBootstrapSession = func(_ context.Context, _ string, _ int, _ *ssh.ClientConfig) (bootstrapSession, string, error) {
		return nil, "", dialErr
	}
}

// writeBootstrapKey writes a valid 0600 OpenSSH ed25519 private key and
// returns its path, so bootstrapAuthMethod's key-file branch succeeds
// naturally (no seam needed for the common case).
func writeBootstrapKey(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// canonicalAuthKeysLine builds the exact restricted authorized_keys line
// AddServer would write for sshgatePub, used to seed the idempotent
// re-add case.
func canonicalAuthKeysLine(t *testing.T, sshgatePub ssh.PublicKey) []byte {
	t.Helper()
	line, err := rewriteAuthorizedKeys(nil, sshgatePub, remoteGateBin)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

// ---------------------------------------------------------------------
// bootstrapAuthMethod seams: agent path and parse-private-key success
// ---------------------------------------------------------------------

// TestBootstrapAuthMethod_AgentPathViaFakeSocket exercises the
// ssh-agent branch with a fake $SSH_AUTH_SOCK: the dialAgentSock seam
// returns a controlled net.Conn (one half of a socketpair) so the branch
// reaches agent.NewClient and returns a PublicKeysCallback auth method —
// no live ssh-agent required.
func TestBootstrapAuthMethod_AgentPathViaFakeSocket(t *testing.T) {
	// Not parallel: mutates SSH_AUTH_SOCK and the dialAgentSock seam.
	t.Setenv("SSH_AUTH_SOCK", "/fake/agent/sock")

	// A connected pipe stands in for the agent socket. We never speak
	// the agent protocol here — bootstrapAuthMethod only needs a live
	// conn to hand to agent.NewClient; the Signers RPC is deferred until
	// dial time, which these tests never reach.
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	orig := dialAgentSock
	t.Cleanup(func() { dialAgentSock = orig })
	dialAgentSock = func(sock string) (net.Conn, error) {
		if sock != "/fake/agent/sock" {
			t.Errorf("dialAgentSock got sock=%q; want the env value", sock)
		}
		return clientConn, nil
	}

	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapAgent: true})
	if err != nil {
		t.Fatalf("bootstrapAuthMethod(agent) = %v; want nil", err)
	}
	if auth == nil {
		t.Fatal("bootstrapAuthMethod(agent) returned a nil AuthMethod")
	}
}

// TestBootstrapAuthMethod_AgentDialFailure: when the (seamed) agent dial
// fails, the error is wrapped as "dial ssh-agent".
func TestBootstrapAuthMethod_AgentDialFailure(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "/fake/agent/sock")
	orig := dialAgentSock
	t.Cleanup(func() { dialAgentSock = orig })
	dialAgentSock = func(string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapAgent: true})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(agent, dial fails) = nil; want error")
	}
	if !strings.Contains(err.Error(), "dial ssh-agent") {
		t.Errorf("err = %v; want a 'dial ssh-agent' wrap", err)
	}
}

// TestBootstrapAuthMethod_ParsePrivateKeySuccess covers the key-file
// parse-success branch end to end: a real 0600 key is written, the real
// parsePrivateKey parses it, and a PublicKeys auth method is returned.
// This proves the seam's default (ssh.ParsePrivateKey) is wired and the
// success path is reachable.
func TestBootstrapAuthMethod_ParsePrivateKeySuccess(t *testing.T) {
	t.Parallel()
	keyPath := writeBootstrapKey(t)
	auth, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: keyPath})
	if err != nil {
		t.Fatalf("bootstrapAuthMethod(valid key) = %v; want nil", err)
	}
	if auth == nil {
		t.Fatal("bootstrapAuthMethod(valid key) returned a nil AuthMethod")
	}
}

// TestBootstrapAuthMethod_ParsePrivateKeyFailureViaSeam drives the
// parse-FAILURE branch deterministically by swapping the parsePrivateKey
// seam for one that always errors (so we don't depend on crafting a
// malformed-but-stat-clean key file).
func TestBootstrapAuthMethod_ParsePrivateKeyFailureViaSeam(t *testing.T) {
	keyPath := writeBootstrapKey(t) // valid file; the seam forces the failure
	orig := parsePrivateKey
	t.Cleanup(func() { parsePrivateKey = orig })
	parsePrivateKey = func([]byte) (ssh.Signer, error) {
		return nil, errors.New("scripted parse failure")
	}
	_, err := bootstrapAuthMethod(AddServerInput{BootstrapKeyPath: keyPath})
	if err == nil {
		t.Fatal("bootstrapAuthMethod(parse fails) = nil; want error")
	}
	if !strings.Contains(err.Error(), "parse bootstrap key") {
		t.Errorf("err = %v; want a 'parse bootstrap key' wrap", err)
	}
}
