package mcp_test

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.uber.org/goleak"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// TestMain runs goleak for the mcp package tests. The Server spawns
// goroutines via the SDK; each subtest closes its session so the
// counts settle before goleak's snapshot.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// fakeSign returns canned signatures.
type fakeSign struct {
	signed   []signpkg.Signed
	authMode string
	err      error

	grantID         string
	grantExpiryUnix int64
	grantErr        error
	revokeGrantErr  error

	listGrantsResult []signpkg.GrantInfo
	listGrantsErr    error
}

func (f *fakeSign) Sign(_ context.Context, _ string, _ []signpkg.CmdReq) (signpkg.SignResult, error) {
	return signpkg.SignResult{Signed: f.signed, AuthMode: f.authMode}, f.err
}

// RequestGrant / RevokeGrant satisfy SignClient. The grant* fields let a
// test drive the request_grant / revoke_grant tool handlers.
func (f *fakeSign) RequestGrant(_ context.Context, _, _, _ string, _ []string, _ int64) (string, int64, error) {
	return f.grantID, f.grantExpiryUnix, f.grantErr
}
func (f *fakeSign) RevokeGrant(_ context.Context, _, _ string) error { return f.revokeGrantErr }
func (f *fakeSign) ListGrants(_ context.Context, _, _ string) ([]signpkg.GrantInfo, error) {
	return f.listGrantsResult, f.listGrantsErr
}

// fakeSSH returns canned output.
type fakeSSH struct {
	stdout []byte
	stderr []byte
	exit   int
	err    error
}

func (f *fakeSSH) Run(_ context.Context, _, _ string, _ int, _ string) ([]byte, []byte, int, error) {
	return f.stdout, f.stderr, f.exit, f.err
}

func buildServer(t *testing.T, runner *tools.Runner) *mcp.Server {
	t.Helper()
	logger := log.New(io.Discard, "", 0)
	return &mcp.Server{Runner: runner, Logger: logger}
}

func connectInProcess(t *testing.T, server *mcp.Server) (*mcpsdk.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcpsdk.NewInMemoryTransports()

	sdkServer := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    mcp.ServerName,
		Version: mcp.Version,
	}, nil)
	// Mirror the run-tool registration that Serve does, but use the
	// in-memory transport so we don't fight with stdin EOF.
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolName,
		Description: "Run a shell command on a registered server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunInput) (*mcpsdk.CallToolResult, tools.RunOutput, error) {
		out, err := server.Runner.Run(ctx, in)
		if err != nil {
			return nil, tools.RunOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameRunBatch,
		Description: "Run a batch of shell commands on a registered server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RunBatchInput) (*mcpsdk.CallToolResult, tools.RunBatchOutput, error) {
		out, err := server.Runner.RunBatch(ctx, in)
		if err != nil {
			return nil, tools.RunBatchOutput{}, err
		}
		return nil, out, nil
	})
	if _, err := sdkServer.Connect(ctx, serverT, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	return cs, func() {
		_ = cs.Close()
	}
}

func newRegistryWith(t *testing.T, alias string, e registry.Entry) *registry.Servers {
	t.Helper()
	dir := t.TempDir()
	r, err := registry.New(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Add(alias, e); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServer_InitializeReportsName(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)

	cs, stop := connectInProcess(t, srv)
	defer stop()

	info := cs.InitializeResult()
	if info == nil {
		t.Fatal("InitializeResult is nil")
	}
	if info.ServerInfo == nil {
		t.Fatal("ServerInfo is nil")
	}
	if info.ServerInfo.Name != mcp.ServerName {
		t.Errorf("ServerInfo.Name = %q; want %q", info.ServerInfo.Name, mcp.ServerName)
	}
}

func TestServer_ListToolsReturnsBothTools(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectInProcess(t, srv)
	defer stop()

	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(res.Tools) != 2 {
		t.Fatalf("got %d tools; want 2", len(res.Tools))
	}
	byName := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		if tool.Description == "" {
			t.Errorf("tool %q: Description is empty", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q: InputSchema is nil", tool.Name)
		}
		byName[tool.Name] = true
	}
	if !byName[mcp.ToolName] {
		t.Errorf("missing tool %q", mcp.ToolName)
	}
	if !byName[mcp.ToolNameRunBatch] {
		t.Errorf("missing tool %q", mcp.ToolNameRunBatch)
	}
}

func TestServer_CallToolReadPath(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte("hello\n")}}
	srv := buildServer(t, runner)
	cs, stop := connectInProcess(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolName,
		Arguments: map[string]any{"alias": "h1", "command": "df -h"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Errorf("IsError = true; expected success. Content: %+v", res.Content)
	}
	// StructuredContent is `any` over the wire — the SDK delivers it
	// as a json.RawMessage on the client side.
	raw, ok := res.StructuredContent.(json.RawMessage)
	if !ok {
		// Fallback: marshal whatever was delivered and re-parse.
		b, mErr := json.Marshal(res.StructuredContent)
		if mErr != nil {
			t.Fatalf("structured content: %T (%v)", res.StructuredContent, res.StructuredContent)
		}
		raw = b
	}
	var out tools.RunOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal structured content: %v (raw=%s)", err, string(raw))
	}
	if out.Stdout != "hello\n" {
		t.Errorf("Stdout = %q", out.Stdout)
	}
	if out.Kind != "read" {
		t.Errorf("Kind = %q; want read", out.Kind)
	}
}

func TestServer_CallToolUnknownAliasReturnsToolError(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectInProcess(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolName,
		Arguments: map[string]any{"alias": "nope", "command": "df -h"},
	})
	if err != nil {
		t.Fatalf("CallTool returned protocol err: %v", err)
	}
	if !res.IsError {
		t.Error("IsError = false; want true for unknown alias")
	}
}

// TestServe_RegistersExactlyAgentTools drives the REAL Serve() over a
// pair of pipes and asserts the production tool registration is exactly
// the agent-facing set {run, run_batch, list_servers, status, ping,
// revoke_server, request_grant, revoke_grant, list_grants, update_gate,
// transfer} — and, critically, that add_server is NOT among them.
// Provisioning was removed from the agent surface (it is now the
// human-only `sshgate` CLI); this test is the regression guard that the
// MCP server never re-exposes it.
//
// Unlike the connectInProcess / connectAllTools helpers, which mirror
// registration locally, this test exercises Serve itself, so it catches
// a stray AddTool(add_server) being re-added to server.go.
func TestServe_RegistersExactlyAgentTools(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := &mcp.Server{Runner: runner, Logger: log.New(io.Discard, "", 0)}

	// Two pipes: client→server and server→client. Serve reads from
	// c2sR and writes to s2cW; the client reads from s2cR and writes to
	// c2sW.
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, c2sR, s2cW) }()

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	clientT := &mcpsdk.IOTransport{Reader: s2cR, Writer: c2sW}
	cs, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}

	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	want := map[string]bool{
		mcp.ToolName:             true, // run
		mcp.ToolNameRunBatch:     true,
		mcp.ToolNameListServers:  true,
		mcp.ToolNameStatus:       true,
		mcp.ToolNamePing:         true,
		mcp.ToolNameRevokeServer: true,
		mcp.ToolNameRequestGrant: true,
		mcp.ToolNameRevokeGrant:  true,
		mcp.ToolNameListGrants:   true,
		mcp.ToolNameUpdateGate:   true,
		mcp.ToolNameTransfer:     true,
	}
	if len(res.Tools) != len(want) {
		t.Errorf("registered %d tools; want %d (%v)", len(res.Tools), len(want), got)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing expected tool %q", name)
		}
	}
	// The whole point: add_server must NOT be exposed to the agent.
	if got["add_server"] {
		t.Error("add_server is registered as an MCP tool; provisioning must be human-only (sshgate CLI)")
	}

	// Clean shutdown: close the client session, then the client→server
	// pipe so Serve sees EOF and returns.
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

func TestServe_StdioEOFShutsDown(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := &mcp.Server{Runner: runner, Logger: log.New(io.Discard, "", 0)}

	// Empty reader → immediate EOF. Serve should return promptly.
	in := bytesReader(nil)
	var out devNull
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, in, &out) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve on EOF: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Serve did not return within 2s on EOF")
	}
}

func TestServe_RejectsNilRunner(t *testing.T) {
	t.Parallel()
	srv := &mcp.Server{Logger: log.New(io.Discard, "", 0)}
	err := srv.Serve(context.Background(), bytesReader(nil), &devNull{})
	if err == nil {
		t.Error("Serve with nil Runner returned nil; want error")
	}
}

func TestServe_RejectsNilLogger(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := &mcp.Server{Runner: runner}
	err := srv.Serve(context.Background(), bytesReader(nil), &devNull{})
	if err == nil {
		t.Error("Serve with nil Logger returned nil; want error")
	}
}

// bytesReader returns an io.Reader over a static byte slice that
// reports io.EOF after the slice is exhausted (which io.Reader of
// nil/empty does by default — bytes.Reader is fine here, but we
// want a tiny dependency-free helper to keep the file portable
// across the goleak-protected test run).
type byteReader struct {
	buf []byte
	off int
}

func bytesReader(b []byte) *byteReader { return &byteReader{buf: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

type devNull struct{}

func (*devNull) Write(p []byte) (int, error) { return len(p), nil }

// Ensure imports stay referenced even when adjusting tests.
var _ = os.Stdin
