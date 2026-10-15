package sign_test

import (
	"bufio"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// wantSignRequestNoNet is the exact request line the client at ad7407a (before
// the net field) writes for netWireCommands. A request without network must
// stay byte-identical to it.
const wantSignRequestNoNet = `{"kind":"sign","request_id":"r_net_wire","commands":[` +
	`{"server":"prod","cmd":"uptime","ttl_seconds":60,"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA"},` +
	`{"server":"prod","cmd":"cat /etc/app.env","ttl_seconds":120,"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA","reveal":true,"reason":"debug the deploy"}` +
	`],"proto_version":1}` + "\n"

func netWireCommands() []sign.CmdReq {
	const host = "SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA"
	return []sign.CmdReq{
		{Server: "prod", Cmd: "uptime", TTLSec: 60, Host: host},
		{Server: "prod", Cmd: "cat /etc/app.env", TTLSec: 120, Host: host, Reveal: true, Reason: "debug the deploy"},
	}
}

func TestSignRequestWireNoNetGolden(t *testing.T) {
	if got := captureSignRequest(t, netWireCommands()); got != wantSignRequestNoNet {
		t.Errorf("request without network drifted from the pre-network wire:\n got  %q\n want %q", got, wantSignRequestNoNet)
	}

	cmds := netWireCommands()
	cmds[0].Net = true
	want := strings.Replace(wantSignRequestNoNet,
		`"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA"},`,
		`"host":"SHA256:netWireHostFingerprintAAAAAAAAAAAAAAAAAAAAAA","net":true},`, 1)
	if got := captureSignRequest(t, cmds); got != want {
		t.Errorf("request with network:\n got  %q\n want %q", got, want)
	}
}

// captureSignRequest runs the real client against a socket that records the
// raw request line and answers denied.
func captureSignRequest(t *testing.T, cmds []sign.CmdReq) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	lineCh := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			lineCh <- ""
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(conn).ReadString('\n')
		lineCh <- line
		_, _ = conn.Write([]byte(`{"request_id":"r_net_wire","status":"denied","proto_version":1}` + "\n"))
	}()

	client := &sign.Client{SocketPath: path, Timeout: 5 * time.Second}
	if _, err := client.Sign(context.Background(), "r_net_wire", cmds); !errors.Is(err, sign.ErrDenied) {
		t.Fatalf("Sign err = %v; want ErrDenied", err)
	}
	return <-lineCh
}
