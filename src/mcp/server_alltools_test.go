package mcp_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/karthikeyan5/sshgate/src/mcp"
	"github.com/karthikeyan5/sshgate/src/mcp/registry"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
	"github.com/karthikeyan5/sshgate/src/mcp/tools"
)

// connectAllTools mirrors Server.Serve's agent-facing tool registration
// (the eight tools the agent can call) over the SDK's in-memory
// transport. The existing connectInProcess helper wires only
// run/run_batch; this one closes the gap so list_servers, status, ping,
// revoke_server, request_grant, revoke_grant, and list_grants are also
// exercised at the SDK boundary (request → handler → structured result).
// add_server is intentionally absent: it is no longer an MCP tool —
// provisioning is the human-only `sshgate` CLI.
//
// Handlers here are thin shims that call the same Runner methods the
// production handlers in server.go call — no production behavior is
// altered. We use shims (rather than reaching into server.go's
// unexported handlers) because those handlers are methods bound at
// registration time inside Serve, which we cannot drive without real
// stdio.
func connectAllTools(t *testing.T, server *mcp.Server) (*mcpsdk.ClientSession, func()) {
	t.Helper()
	ctx := context.Background()
	clientT, serverT := mcpsdk.NewInMemoryTransports()

	sdkServer := mcpsdk.NewServer(&mcpsdk.Implementation{
		Name:    mcp.ServerName,
		Version: mcp.Version,
	}, nil)

	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameListServers,
		Description: "List every registered SSHGate server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.ListServersInput) (*mcpsdk.CallToolResult, tools.ListServersOutput, error) {
		out, err := server.Runner.ListServers(ctx, in)
		if err != nil {
			return nil, tools.ListServersOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameStatus,
		Description: "Report signer-socket and per-server reachability.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.StatusInput) (*mcpsdk.CallToolResult, tools.StatusOutput, error) {
		out, err := server.Runner.Status(ctx, in)
		if err != nil {
			return nil, tools.StatusOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNamePing,
		Description: "Probe reachability of one named server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.PingInput) (*mcpsdk.CallToolResult, tools.PingOutput, error) {
		out, err := server.Runner.Ping(ctx, in)
		if err != nil {
			return nil, tools.PingOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameRevokeServer,
		Description: "Revoke a registered server.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RevokeServerInput) (*mcpsdk.CallToolResult, tools.RevokeServerOutput, error) {
		out, err := server.Runner.RevokeServer(ctx, in)
		if err != nil {
			return nil, tools.RevokeServerOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameRequestGrant,
		Description: "Request a standing grant.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RequestGrantInput) (*mcpsdk.CallToolResult, tools.RequestGrantOutput, error) {
		out, err := server.Runner.RequestGrant(ctx, in)
		if err != nil {
			return nil, tools.RequestGrantOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameRevokeGrant,
		Description: "Revoke a standing grant.",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.RevokeGrantInput) (*mcpsdk.CallToolResult, tools.RevokeGrantOutput, error) {
		out, err := server.Runner.RevokeGrant(ctx, in)
		if err != nil {
			return nil, tools.RevokeGrantOutput{}, err
		}
		return nil, out, nil
	})
	mcpsdk.AddTool(sdkServer, &mcpsdk.Tool{
		Name:        mcp.ToolNameListGrants,
		Description: "List live standing grants (read-only).",
	}, func(ctx context.Context, _ *mcpsdk.CallToolRequest, in tools.ListGrantsInput) (*mcpsdk.CallToolResult, tools.ListGrantsOutput, error) {
		out, err := server.Runner.ListGrants(ctx, in)
		if err != nil {
			return nil, tools.ListGrantsOutput{}, err
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
	return cs, func() { _ = cs.Close() }
}

// decodeStructured unmarshals an SDK CallTool result's structured
// content into v. It tolerates both the json.RawMessage delivery (the
// common case over the in-memory transport) and a pre-decoded any.
func decodeStructured(t *testing.T, res *mcpsdk.CallToolResult, v any) {
	t.Helper()
	raw, ok := res.StructuredContent.(json.RawMessage)
	if !ok {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			t.Fatalf("structured content: %T (%v)", res.StructuredContent, res.StructuredContent)
		}
		raw = b
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal structured content: %v (raw=%s)", err, string(raw))
	}
}

func TestServer_ListServers_SDKBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "alpha", registry.Entry{Host: "10.0.0.1", Port: 22, User: "operator", AddedAt: time.Now()})
	if err := r.Add("bravo", registry.Entry{Host: "10.0.0.2", Port: 2222, User: "ops", AddedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameListServers,
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError=true: %+v", res.Content)
	}
	var out tools.ListServersOutput
	decodeStructured(t, res, &out)
	if out.Total != 2 {
		t.Errorf("Total = %d; want 2", out.Total)
	}
	// Output is alphabetically sorted by alias.
	if len(out.Servers) != 2 || out.Servers[0].Alias != "alpha" || out.Servers[1].Alias != "bravo" {
		t.Errorf("servers not sorted alpha-first: %+v", out.Servers)
	}
	if out.Servers[1].Port != 2222 || out.Servers[1].User != "ops" {
		t.Errorf("bravo row wrong: %+v", out.Servers[1])
	}
}

func TestServer_Status_SDKBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	// fakeSSH returns SSHGATE_OK so the per-server probe reports reachable.
	runner := &tools.Runner{
		Servers:        r,
		Sign:           &fakeSign{},
		SSH:            &fakeSSH{stdout: []byte("SSHGATE_OK\n")},
		SignerSockPath: filepath.Join(t.TempDir(), "absent.sock"),
	}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameStatus,
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError=true: %+v", res.Content)
	}
	var out tools.StatusOutput
	decodeStructured(t, res, &out)
	// Socket file is absent → Tier-1 not-configured, not reachable.
	if out.SignerSocket.Reachable || out.SignerSocket.Configured {
		t.Errorf("signer status = %+v; want unreachable + not configured", out.SignerSocket)
	}
	if len(out.Servers) != 1 || !out.Servers[0].Reachable {
		t.Errorf("server probe = %+v; want one reachable row", out.Servers)
	}
}

func TestServer_Ping_SDKBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	// fakeSSH returns SSHGATE_OK so the single-server probe reports reachable.
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{stdout: []byte("SSHGATE_OK\n")}}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNamePing,
		Arguments: map[string]any{"alias": "h1"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError=true: %+v", res.Content)
	}
	var out tools.PingOutput
	decodeStructured(t, res, &out)
	if out.Alias != "h1" || !out.Reachable {
		t.Errorf("out = %+v; want alias h1 reachable", out)
	}
}

func TestServer_RevokeServer_SDKBoundaryUnknownAlias(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameRevokeServer,
		Arguments: map[string]any{"alias": "ghost"},
	})
	if err != nil {
		t.Fatalf("CallTool returned protocol err: %v", err)
	}
	if !res.IsError {
		t.Error("IsError = false; want true for unknown alias revoke")
	}
}

func TestServer_RequestGrant_SDKBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "throwaway", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{
		Servers: r,
		Sign:    &fakeSign{grantID: "g_sdk", grantExpiryUnix: 1700000000},
		SSH:     &fakeSSH{},
	}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameRequestGrant,
		Arguments: map[string]any{"alias": "throwaway", "scope": "all", "duration_hours": 8},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError=true: %+v", res.Content)
	}
	var out tools.RequestGrantOutput
	decodeStructured(t, res, &out)
	if out.GrantID != "g_sdk" || out.ExpiryUnix != 1700000000 {
		t.Errorf("out = %+v; want grant_id g_sdk expiry 1700000000", out)
	}
}

func TestServer_RequestGrant_SDKBoundaryBadDuration(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "h1", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameRequestGrant,
		Arguments: map[string]any{"alias": "h1", "scope": "all", "duration_hours": 99},
	})
	if err != nil {
		t.Fatalf("CallTool returned protocol err: %v", err)
	}
	if !res.IsError {
		t.Error("IsError = false; want true for out-of-range duration")
	}
}

func TestServer_RevokeGrant_SDKBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{Servers: r, Sign: &fakeSign{}, SSH: &fakeSSH{}}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameRevokeGrant,
		Arguments: map[string]any{"alias": "prod"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError=true: %+v", res.Content)
	}
	var out tools.RevokeGrantOutput
	decodeStructured(t, res, &out)
	if !out.Revoked {
		t.Error("Revoked = false; want true")
	}
}

func TestServer_ListGrants_SDKBoundary(t *testing.T) {
	t.Parallel()
	r := newRegistryWith(t, "prod", registry.Entry{Host: "h", Port: 22, User: "u", AddedAt: time.Now()})
	runner := &tools.Runner{
		Servers: r,
		Sign: &fakeSign{listGrantsResult: []signpkg.GrantInfo{
			{Alias: "prod", Scope: "commands", Commands: []string{"systemctl restart nginx"}, GrantID: "g_sdk", ExpiryUnix: 1700000000},
		}},
		SSH: &fakeSSH{},
	}
	srv := buildServer(t, runner)
	cs, stop := connectAllTools(t, srv)
	defer stop()

	res, err := cs.CallTool(context.Background(), &mcpsdk.CallToolParams{
		Name:      mcp.ToolNameListGrants,
		Arguments: map[string]any{"alias": "prod"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("IsError=true: %+v", res.Content)
	}
	var out tools.ListGrantsOutput
	decodeStructured(t, res, &out)
	if len(out.Grants) != 1 || out.Grants[0].GrantID != "g_sdk" {
		t.Errorf("out = %+v; want one grant g_sdk", out)
	}
}
