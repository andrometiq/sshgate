//go:build journey

package journey

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type journeyMCP struct {
	session                 *mcp.ClientSession
	command                 *exec.Cmd
	processDone             <-chan error
	reader                  *io.PipeReader
	stdin                   io.WriteCloser
	protocol, input, stderr *journeyCapture
}

func (r *journeyRig) mcp(t *testing.T) *journeyMCP {
	t.Helper()
	command := exec.Command("docker", "exec", "-i", r.controller, "runuser", "-l", "sgop", "-c", "exec sshgate-mcp")
	protocol, input, stderr := &journeyCapture{}, &journeyCapture{}, &journeyCapture{}
	reader, writer := io.Pipe()
	command.Stdout = journeyForward{protocol, writer}
	command.Stderr = stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { err := command.Wait(); _ = writer.Close(); done <- err }()
	result := &journeyMCP{command: command, processDone: done, reader: reader, stdin: stdin, protocol: protocol, input: input, stderr: stderr}
	t.Cleanup(func() { result.close(t) })
	client := mcp.NewClient(&mcp.Implementation{Name: "journey", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: reader, Writer: journeyInput{stdin, input}}, nil)
	if err != nil {
		t.Fatalf("MCP initialize: %v", err)
	}
	result.session = session
	return result
}

func (c *journeyMCP) close(t *testing.T) {
	t.Helper()
	if c.session != nil {
		if err := c.session.Close(); err != nil {
			t.Errorf("close MCP: %v", err)
		}
		c.session = nil
	}
	if c.command != nil {
		_ = c.reader.Close()
		_ = c.stdin.Close()
		command := c.command
		timer := time.AfterFunc(5*time.Second, func() { _ = command.Process.Kill() })
		err := <-c.processDone
		timer.Stop()
		if err != nil {
			t.Errorf("MCP process shutdown failed: %v", err)
		}
		c.command = nil
	}
	if c.protocol != nil {
		c.protocol.check(t)
		c.input.check(t)
		c.stderr.check(t)
	}
}

func (c *journeyMCP) assertTools(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var names []string
	cursor := ""
	for {
		result, err := c.session.ListTools(ctx, &mcp.ListToolsParams{Cursor: cursor})
		if err != nil {
			t.Fatalf("tools/list: %v", err)
		}
		for _, tool := range result.Tools {
			names = append(names, tool.Name)
		}
		cursor = result.NextCursor
		if cursor == "" {
			break
		}
	}
	sort.Strings(names)
	expected := []string{"list_grants", "list_servers", "ping", "request_grant", "revoke_grant", "revoke_server", "run", "run_batch", "status", "transfer", "update_gate"}
	if !reflect.DeepEqual(names, expected) {
		t.Fatalf("tool surface = %v, want %v", names, expected)
	}
}

func (c *journeyMCP) call(t *testing.T, name string, arguments map[string]any, output any) *mcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	defer cancel()
	result, err := c.session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: arguments})
	if err != nil {
		t.Fatalf("tools/call %s: %v", name, err)
	}
	if output != nil {
		if result.StructuredContent == nil {
			t.Fatalf("tools/call %s has no structured content", name)
		}
		data, err := json.Marshal(result.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, output); err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
	}
	return result
}

func TestMCPCallToolError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server := mcp.NewServer(&mcp.Implementation{Name: "fixture", Version: "1"}, nil)
	server.AddTool(&mcp.Tool{Name: "refuse", InputSchema: map[string]any{"type": "object"}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{IsError: true, StructuredContent: map[string]any{"error_class": "read_only_server"}}, nil
		})
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	connection := &journeyMCP{session: session}
	defer connection.close(t)
	var output struct {
		ErrorClass string `json:"error_class"`
	}
	result := connection.call(t, "refuse", map[string]any{}, &output)
	if !result.IsError || output.ErrorClass != "read_only_server" {
		t.Fatalf("refusal not preserved: isError=%v, output=%+v", result.IsError, output)
	}
}
