package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
)

// Client dials user@host:port with an Ed25519 key from KeyPath and
// runs a single command per connection. It is safe for concurrent
// calls; each Run uses a fresh session.
type Client struct {
	// KeyPath is the absolute path to the Ed25519 private key (no
	// passphrase). The file must be mode 0o600.
	KeyPath string
	// KnownHostsPath is the TOFU known_hosts file. Created with mode
	// 0o600 on first contact.
	KnownHostsPath string
	// Timeout bounds the dial + SSH handshake only (TCP connect plus
	// auth/key-exchange). The connection deadline is CLEARED right
	// after the handshake (see Run, conn.SetDeadline(time.Time{})), so
	// Timeout does NOT bound command execution: a command that runs
	// longer than Timeout still completes normally. Execution duration
	// is bounded by the caller's ctx, not by Timeout. Zero means 30
	// seconds.
	Timeout time.Duration
}

// Run dials user@host:port and executes cmd in a single SSH session.
// The remote command's stdout and stderr are returned independently;
// exit is the remote exit status (0 on success, the remote's reported
// exit code on failure, or -1 if the remote terminated by signal).
//
// Run honours ctx cancellation: the dial + handshake are bounded by
// Timeout (the deadline is cleared once the handshake completes, so
// command execution is NOT bounded by Timeout — only by ctx), and a
// cancelled ctx forcibly closes the connection so a stuck session
// returns promptly.
func (c *Client) Run(ctx context.Context, host, user string, port int, cmd string) ([]byte, []byte, int, error) {
	return c.run(ctx, host, user, port, cmd, nil)
}

// RunWithStdin is Run plus a single, gated exception: it wires stdin as the
// SSH session's channel stdin, so a caller can stream bytes to the remote
// command. It is used ONLY by update_gate, which streams the new gate binary
// on stdin (SSHGATE_UPDATE) — data the gate authenticates by hash before it
// installs it, never a program fed to a shell. A nil stdin makes RunWithStdin
// byte-for-byte identical to Run. All of Run's ctx/deadline/exit-code
// semantics are preserved (both delegate to the same run).
func (c *Client) RunWithStdin(ctx context.Context, host, user string, port int, cmd string, stdin io.Reader) ([]byte, []byte, int, error) {
	return c.run(ctx, host, user, port, cmd, stdin)
}

// run is the shared implementation behind Run (stdin nil) and RunWithStdin
// (stdin non-nil). When stdin != nil it is set as the session's channel
// stdin before sess.Run, which copies it as the command's stdin; when nil the
// session carries no stdin, exactly as Run always has.
func (c *Client) run(ctx context.Context, host, user string, port int, cmd string, stdin io.Reader) ([]byte, []byte, int, error) {
	if c.KeyPath == "" {
		return nil, nil, 0, errors.New("ssh: KeyPath is empty")
	}
	if c.KnownHostsPath == "" {
		return nil, nil, 0, errors.New("ssh: KnownHostsPath is empty")
	}
	if host == "" {
		return nil, nil, 0, errors.New("ssh: host is empty")
	}
	if user == "" {
		return nil, nil, 0, errors.New("ssh: user is empty")
	}
	if port == 0 {
		port = 22
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	signer, err := loadKey(c.KeyPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ssh: load key: %w", err)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: TOFU(c.KnownHostsPath),
		Timeout:         timeout,
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}
	// Apply the overall deadline to the TCP conn so the SSH handshake
	// cannot block past it.
	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, nil, 0, fmt.Errorf("ssh: handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	// Clear the deadline once the handshake is done — the per-session
	// I/O is bounded by the ctx watcher below. NOTE: this is what makes
	// Client.Timeout cover only dial + handshake, not exec. Do NOT
	// re-apply a Timeout-derived deadline here: long-running commands
	// (e.g. a build) are meant to outlive Timeout and are bounded only
	// by the caller's ctx. See TestRun_CommandLongerThanTimeoutCompletes.
	_ = conn.SetDeadline(time.Time{})

	// Propagate ctx cancellation: close the client to abort a stuck
	// session.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-stopWatch:
		}
	}()

	sess, err := client.NewSession()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ssh: new session: %w", err)
	}
	defer sess.Close()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	// Only update_gate uses this: stream the new gate binary on the session's
	// channel stdin. sess.Run copies stdin into the channel for us, so a plain
	// bytes.Reader is sufficient — no StdinPipe/goroutine needed. A nil stdin
	// leaves the session with no stdin, exactly as Run has always behaved.
	if stdin != nil {
		sess.Stdin = stdin
	}

	runErr := sess.Run(cmd)
	exit := 0
	if runErr != nil {
		var ee *ssh.ExitError
		if errors.As(runErr, &ee) {
			exit = ee.ExitStatus()
			runErr = nil
		} else {
			var em *ssh.ExitMissingError
			if errors.As(runErr, &em) {
				// Remote terminated by signal; surface as -1 plus the
				// error (caller may decide to retry).
				exit = -1
				runErr = nil
			}
		}
	}

	if runErr != nil {
		return stdout.Bytes(), stderr.Bytes(), exit, fmt.Errorf("ssh: run: %w", runErr)
	}
	// If ctx fired between dial and sess.Run completing, surface it
	// so callers can distinguish "we cancelled this" from "remote
	// finished successfully."
	if ctxErr := ctx.Err(); ctxErr != nil {
		return stdout.Bytes(), stderr.Bytes(), exit, fmt.Errorf("ssh: %w", ctxErr)
	}
	return stdout.Bytes(), stderr.Bytes(), exit, nil
}

// loadKey reads a PEM-encoded Ed25519 private key from path and
// returns an ssh.Signer for it. The file is required to be 0o600 to
// match SSH's own client expectations.
func loadKey(path string) (ssh.Signer, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("key file %s does not exist", path)
	}
	if err != nil {
		return nil, err
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("key file %s has insecure mode %#o (must be 0600)", path, perm)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(body)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return signer, nil
}
