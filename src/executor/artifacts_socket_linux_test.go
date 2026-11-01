//go:build linux

package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	gatessh "github.com/karthikeyan5/sshgate/src/mcp/ssh"
	sshlib "golang.org/x/crypto/ssh"
)

func TestCommandJobSocketArtifactsContainNoAuthority(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	signer, err := sshlib.NewSignerFromKey(key)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	root := t.TempDir()
	keyPath := filepath.Join(root, "key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	done := make(chan struct{})
	var execs atomic.Int32
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		config := &sshlib.ServerConfig{NoClientAuth: true}
		config.AddHostKey(signer)
		server, channels, requests, err := sshlib.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go sshlib.DiscardRequests(requests)
		for incoming := range channels {
			channel, requests, err := incoming.Accept()
			if err != nil {
				return
			}
			for request := range requests {
				if request.Type == "exec" {
					execs.Add(1)
					request.Reply(false, nil)
					channel.Close()
					return
				}
				request.Reply(false, nil)
			}
			channel.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	client := &gatessh.Client{KeyPath: keyPath, KnownHostsPath: filepath.Join(root, "known_hosts"), Timeout: time.Second}
	port := listener.Addr().(*net.TCPAddr).Port
	commandArtifacts(t, commandSSHFunc(func(ctx context.Context, wire string, guard func() error, out, stderr io.Writer) (int, error) {
		return client.RunPhasedTo(ctx, "127.0.0.1", "test", port, wire, nil, guard, out, stderr)
	}))
	if execs.Load() != 1 {
		t.Fatal("exec rejection boundary was not reached", execs.Load())
	}
}
