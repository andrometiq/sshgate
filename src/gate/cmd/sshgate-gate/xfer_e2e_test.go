package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp"
	"github.com/karthikeyan5/sshgate/src/mcp/livelog"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// TestXferE2E_GrepTheLogs is the PHASE ACCEPTANCE GATE (P3 spec §5.3). It wires
// two local "gate hosts" (temp dirs) with NO real SSH/daemon, an in-test signer
// (signs both host-bound legs with the shared signer key), and a real
// mcp.Server + tools.Runner whose SSH/SSHStdin invoke the REAL gate run() for
// each host. Driving the real `transfer` MCP tool runs the full chain:
//
//	tool → signer legs → gate A SEND (real seal, real audit) → envelope →
//	gate B RECV (real open, real atomic write, real audit) → marker → tool result
//
// then it greps a UNIQUE sentinel plaintext against EVERY surface and requires
// it ABSENT, and confirms the envelope (ciphertext) is absent from every surface
// it must not transit. The dest file must equal the sentinel (positive control).
//
// It is SERIAL — no t.Parallel — because it swaps process-global state
// (os.Stdin/os.Stdout/os.Stderr, SSH_ORIGINAL_COMMAND, and the
// gateDirFn/hostKeyFPsFn package vars) between the two legs.
func TestXferE2E_GrepTheLogs(t *testing.T) {
	const sentinel = "XFERSECRET-e2e-a1b2c3d4e5f6g7h8"

	signerPub, signerPriv := genKey(t)

	// --- Gate A (sender): id key attests. ---
	dirA := t.TempDir()
	seedPub(t, dirA, signerPub, 0o644)
	boxA, idA := genXferKeys(t)
	seedXferKeyFiles(t, dirA, boxA, idA)
	seedAuditAllFull(t, dirA)

	// --- Gate B (recipient): box key opens. ---
	dirB := t.TempDir()
	seedPub(t, dirB, signerPub, 0o644)
	boxB, idB := genXferKeys(t)
	seedXferKeyFiles(t, dirB, boxB, idB)
	seedAuditAllFull(t, dirB)

	const aFP = "SHA256:hostA-fingerprint-eeeeeeeeeeeeeeeeeeeeeeee"
	const bFP = "SHA256:hostB-fingerprint-ffffffffffffffffffffffff"

	// Source file holding the sentinel; dest path the gate B RECV writes.
	srcPath := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(srcPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	destPath := filepath.Join(t.TempDir(), "delivered.env")

	// In-test signer: signs both legs with the shared signer key and writes a
	// metadata-only "signer audit" line (representing P2's auditTransfer).
	signerAudit := filepath.Join(t.TempDir(), "signer-audit.log")
	signer := &e2eSigner{
		t: t, priv: signerPriv,
		destBoxPub: boxB.Public(), srcIDPub: idA.Public(),
		auditPath: signerAudit,
	}

	// Registry: src→hostA, dst→hostB (fingerprints the signer binds each leg to).
	r := newE2ERegistry(t, aFP, bFP)

	gateSSH := &e2eGateSSH{
		t:         t,
		hosts:     map[string]e2eHost{"hostA": {dirA, aFP}, "hostB": {dirB, bFP}},
		stderrBuf: &bytes.Buffer{},
	}

	// Real MCP-side live log on disk + a captured operator logger.
	liveLogPath := filepath.Join(t.TempDir(), "audit-live.log")
	liveLog := livelog.New(liveLogPath, 5<<20)
	var loggerBuf bytes.Buffer
	logger := log.New(&loggerBuf, "", 0)

	runner := &tools.Runner{Servers: r, Xfer: signer, SSH: gateSSH, SSHStdin: gateSSH}
	srv := &mcp.Server{Runner: runner, Logger: logger, LiveLog: liveLog}

	// Drive the REAL Serve over a pipe pair and call the transfer tool.
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, c2sR, s2cW) }()

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "e2e-client", Version: "0.0.1"}, nil)
	cs, err := client.Connect(ctx, &mcpsdk.IOTransport{Reader: s2cR, Writer: c2sW}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}

	res, err := cs.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: mcp.ToolNameTransfer,
		Arguments: map[string]any{
			"src_alias": "src", "src_path": srcPath,
			"dest_alias": "dst", "dest_path": destPath,
		},
	})
	if err != nil {
		t.Fatalf("CallTool transfer: %v", err)
	}
	if res.IsError {
		t.Fatalf("transfer tool returned IsError; content=%+v", res.Content)
	}

	// Positive control: the transfer really delivered the sentinel.
	got, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != sentinel {
		t.Fatalf("dest file = %q; want the sentinel %q", got, sentinel)
	}

	// The full tool result (StructuredContent + TextContent) as JSON.
	resJSON, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	// --- The grep-the-logs acceptance gate ---
	surfaces := map[string]string{
		"MCP tool result (JSON)": string(resJSON),
		"MCP live-log file":      readFileOrEmpty(liveLogPath),
		"gate A audit log":       readFileOrEmpty(filepath.Join(dirA, "audit.log")),
		"gate B audit log":       readFileOrEmpty(filepath.Join(dirB, "audit.log")),
		"signer audit file":      readFileOrEmpty(signerAudit),
		"captured gate stderr":   gateSSH.stderrBuf.String(),
		"MCP s.Logger buffer":    loggerBuf.String(),
	}
	for name, body := range surfaces {
		if strings.Contains(body, sentinel) {
			t.Errorf("CONFIDENTIALITY: sentinel plaintext leaked into %s:\n%s", name, body)
		}
	}

	// The envelope (ciphertext) must be ABSENT from every surface EXCEPT the
	// in-memory SEND-stdout→RECV-stdin relay (which the fake gate performed).
	envelope := gateSSH.lastEnvelope
	if len(envelope) == 0 {
		t.Fatal("no envelope was captured — the SEND leg did not run")
	}
	envStr := string(envelope)
	for _, name := range []string{
		"MCP tool result (JSON)", "MCP live-log file", "signer audit file",
		"captured gate stderr", "MCP s.Logger buffer",
	} {
		if strings.Contains(surfaces[name], envStr) {
			t.Errorf("CONFIDENTIALITY: envelope (ciphertext) leaked into %s", name)
		}
	}

	// Sanity: the marker's xferID rode into the metadata result.
	if !strings.Contains(string(resJSON), signer.lastXferID) {
		t.Errorf("tool result did not carry the xferID metadata %q", signer.lastXferID)
	}

	// Clean shutdown.
	_ = cs.Close()
	_ = c2sW.CloseWithError(io.EOF)
	_ = s2cR.Close()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("Serve returned: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Serve did not return after client close")
	}
}

// ---------------------------------------------------------------------------
// e2e doubles
// ---------------------------------------------------------------------------

// e2eSigner is the in-test signer: it signs both host-bound legs with the shared
// signer key (whose pub is gate.pub on both hosts) and sources the recipient box
// pub + sender id pub from its own fields (standing in for the P2 registry).
type e2eSigner struct {
	t          *testing.T
	priv       ed25519.PrivateKey
	destBoxPub *[32]byte
	srcIDPub   ed25519.PublicKey
	auditPath  string
	lastXferID string
}

func (s *e2eSigner) Transfer(_ context.Context, _ string, req signpkg.TransferReq) (signpkg.TransferResult, error) {
	xferID := "E2Exferid1234567890AB"
	s.lastXferID = xferID
	sendCmd, err := xferwire.EncodeSend(s.destBoxPub, xferID, req.DestFP, req.SrcPath)
	if err != nil {
		return signpkg.TransferResult{}, err
	}
	recvCmd, err := xferwire.EncodeRecv(s.srcIDPub, xferID, req.SrcFP, req.DestFP, req.Mode, req.DestPath)
	if err != nil {
		return signpkg.TransferResult{}, err
	}
	// Each leg is signed with its OWN host binding: SEND=srcFP, RECV=destFP.
	sendSig := signedLine(s.t, s.priv, payloadHost(sendCmd, req.SrcFP))
	recvSig := signedLine(s.t, s.priv, payloadHost(recvCmd, req.DestFP))
	// Metadata-only signer audit (never the plaintext).
	appendFile(s.t, s.auditPath, "transfer src="+req.SrcFP+" dest="+req.DestFP+" xfer="+xferID+" mode="+req.Mode+"\n")
	return signpkg.TransferResult{
		XferID:   xferID,
		Send:     signpkg.Signed{Cmd: sendCmd, Sig: sendSig},
		Recv:     signpkg.Signed{Cmd: recvCmd, Sig: recvSig},
		AuthMode: "human",
	}, nil
}

type e2eHost struct{ dir, fp string }

// e2eGateSSH is both SSHRunner and StdinRunner. Each call invokes the REAL gate
// run() for the targeted host, capturing its stdout/stderr/exit.
type e2eGateSSH struct {
	t            *testing.T
	hosts        map[string]e2eHost
	mu           sync.Mutex
	stderrBuf    *bytes.Buffer
	lastEnvelope []byte
}

func (g *e2eGateSSH) record(stderr string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stderrBuf.WriteString(stderr)
}

func (g *e2eGateSSH) Run(_ context.Context, host, _ string, _ int, cmd string) ([]byte, []byte, int, error) {
	h, ok := g.hosts[host]
	if !ok {
		g.t.Fatalf("unknown host %q", host)
	}
	out, errOut, code := driveGate(g.t, h.dir, h.fp, cmd, nil)
	g.record(errOut)
	g.mu.Lock()
	g.lastEnvelope = []byte(out)
	g.mu.Unlock()
	return []byte(out), []byte(errOut), code, nil
}

func (g *e2eGateSSH) RunWithStdin(_ context.Context, host, _ string, _ int, cmd string, stdin io.Reader) ([]byte, []byte, int, error) {
	h, ok := g.hosts[host]
	if !ok {
		g.t.Fatalf("unknown host %q", host)
	}
	body, _ := io.ReadAll(stdin)
	out, errOut, code := driveGate(g.t, h.dir, h.fp, cmd, body)
	g.record(errOut)
	return []byte(out), []byte(errOut), code, nil
}

// driveGate runs the REAL gate run() for one host, pointing the gateDirFn /
// hostKeyFPsFn seams at (dir, fp), setting SSH_ORIGINAL_COMMAND, feeding stdin
// (RECV), and capturing stdout + stderr. All process-global state is restored on
// return, so consecutive legs do not corrupt one another (the SERIAL contract).
func driveGate(t *testing.T, dir, fp, cmd string, stdin []byte) (stdout, stderr string, exit int) {
	t.Helper()
	prevDir, prevFP := gateDirFn, hostKeyFPsFn
	binPath := filepath.Join(dir, "gate")
	gateDirFn = func() (string, string, error) { return dir, binPath, nil }
	hostKeyFPsFn = func() ([]string, error) { return []string{fp}, nil }
	prevEnv, hadEnv := os.LookupEnv("SSH_ORIGINAL_COMMAND")
	_ = os.Setenv("SSH_ORIGINAL_COMMAND", cmd)

	prevIn, prevOut, prevErr := os.Stdin, os.Stdout, os.Stderr
	var inR *os.File
	if stdin != nil {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("stdin pipe: %v", err)
		}
		inR = r
		os.Stdin = r
		go func() { _, _ = w.Write(stdin); _ = w.Close() }()
	}
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	os.Stdout = outW
	os.Stderr = errW

	var obuf, ebuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&obuf, outR) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&ebuf, errR) }()

	exit = run()

	_ = outW.Close()
	_ = errW.Close()
	wg.Wait()
	_ = outR.Close()
	_ = errR.Close()

	os.Stdin, os.Stdout, os.Stderr = prevIn, prevOut, prevErr
	if inR != nil {
		_ = inR.Close()
	}
	gateDirFn, hostKeyFPsFn = prevDir, prevFP
	if hadEnv {
		_ = os.Setenv("SSH_ORIGINAL_COMMAND", prevEnv)
	} else {
		_ = os.Unsetenv("SSH_ORIGINAL_COMMAND")
	}
	return obuf.String(), ebuf.String(), exit
}

func newE2ERegistry(t *testing.T, aFP, bFP string) *registry.Servers {
	t.Helper()
	r, err := registry.New(filepath.Join(t.TempDir(), "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add("src", registry.Entry{Host: "hostA", Port: 22, User: "ops", AddedAt: time.Now(), Fingerprint: aFP}); err != nil {
		t.Fatal(err)
	}
	if err := r.Add("dst", registry.Entry{Host: "hostB", Port: 22, User: "ops", AddedAt: time.Now(), Fingerprint: bFP}); err != nil {
		t.Fatal(err)
	}
	return r
}

func appendFile(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		t.Fatalf("write audit: %v", err)
	}
}

func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
