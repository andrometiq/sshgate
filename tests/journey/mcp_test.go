//go:build journey

package journey

import (
	"context"
	"encoding/json"
	"os/exec"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type journeyMCP struct{ session *mcp.ClientSession }

func (r *journeyRig) mcp(t *testing.T) *journeyMCP {
	t.Helper()
	command := exec.Command("docker", "exec", "-i", r.controller, "runuser", "-l", "sgop", "-c", "exec sshgate-mcp")
	// CommandTransport keeps protocol stdout separate. Stderr is deliberately not
	// persisted here: scenarios own redacted/bounded artifact collection.
	client := mcp.NewClient(&mcp.Implementation{Name: "journey", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command, TerminateDuration: 5 * time.Second}, nil)
	if err != nil {
		t.Fatalf("MCP initialize: %v", err)
	}
	result := &journeyMCP{session: session}
	t.Cleanup(func() { result.close(t) })
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
	if result.IsError {
		t.Fatalf("tools/call %s returned an MCP error", name)
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
