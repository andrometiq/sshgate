package sign

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func withPipeResponse(t *testing.T, response []byte) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	original := dialWithCtx
	t.Cleanup(func() { dialWithCtx = original })
	dialWithCtx = func(context.Context, string) (net.Conn, error) { return clientConn, nil }
	go func() {
		defer serverConn.Close()
		_, _ = bufio.NewReader(serverConn).ReadBytes('\n')
		_, _ = serverConn.Write(response)
	}()
}

func TestSignAcceptsCompleteNewlineLessJSONAtEOF(t *testing.T) {
	withPipeResponse(t, []byte(`{"request_id":"r1","status":"approved","signatures":[{"cmd":"x","sig":"SSHGATE_SIG:a:b"}]}`))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	result, err := client.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Signed) != 1 || result.Signed[0].Cmd != "x" {
		t.Fatalf("result = %#v", result)
	}
}

func TestSignTreatsNonemptyEOFWithInvalidJSONAsMalformed(t *testing.T) {
	withPipeResponse(t, []byte(`{"request_id":"r1","status":"appr`))
	client := &Client{SocketPath: "/unused", Timeout: time.Second}
	_, err := client.Sign(context.Background(), "r1", []CmdReq{{Server: "s", Cmd: "x", TTLSec: 60}})
	if err == nil || !strings.Contains(err.Error(), "malformed response") {
		t.Fatalf("error = %v; want malformed response", err)
	}
	if errors.Is(err, ErrVerdictUnknown) {
		t.Fatalf("nonempty malformed response was classified verdict-unknown: %v", err)
	}
}
