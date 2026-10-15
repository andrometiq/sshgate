package ssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// PhasedError describes execution certainty without retaining a raw SSH error.
type PhasedError struct {
	Class  string
	Phase  string
	Detail string
}

func (e *PhasedError) Error() string {
	return "ssh: " + e.Class + " (" + e.Phase + "): " + e.Detail
}

// RunPhased separates pre-dispatch failures from uncertain execution.
// Signed commands require a guard, called immediately before the exec request.
// Known exits win over cancellation. Timeout bounds only dial and handshake.
func (c *Client) RunPhased(ctx context.Context, host, user string, port int, cmd string, stdin io.Reader, preStart func() error) ([]byte, []byte, int, error) {
	var stdout, stderr bytes.Buffer
	exit, err := c.RunPhasedTo(ctx, host, user, port, cmd, stdin, preStart, &stdout, &stderr)
	return stdout.Bytes(), stderr.Bytes(), exit, err
}

// RunPhasedTo streams output to caller-owned writers, allowing bounded capture.
// Writers must drain excess output and must not block indefinitely.
func (c *Client) RunPhasedTo(ctx context.Context, host, user string, port int, cmd string, stdin io.Reader, preStart func() error, stdout, stderr io.Writer) (int, error) {
	if strings.HasPrefix(cmd, "SSHGATE_SIG:") && preStart == nil {
		return 0, &PhasedError{"failed_not_started", "pre_dial", "missing pre-start guard"}
	}
	if c.KeyPath == "" || c.KnownHostsPath == "" || host == "" || user == "" {
		return 0, &PhasedError{"failed_not_started", "pre_dial", "invalid configuration"}
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
		return 0, &PhasedError{"failed_not_started", "pre_dial", "key load failed"}
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
		return 0, &PhasedError{"failed_not_started", "dial", "dial failed"}
	}
	deadline, _ := dialCtx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		_ = conn.Close()
		return 0, &PhasedError{"failed_not_started", "handshake", "handshake failed"}
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	_ = conn.SetDeadline(time.Time{})

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
		return 0, &PhasedError{"failed_not_started", "new_session", "new session failed"}
	}
	defer sess.Close()

	sess.Stdout = stdout
	sess.Stderr = stderr
	if stdin != nil {
		sess.Stdin = stdin
	}

	if preStart != nil {
		if preStart() != nil {
			return 0, &PhasedError{"guard_refused", "pre_start", "pre-start guard refused"}
		}
	}
	if err := sess.Start(cmd); err != nil {
		// x/crypto exposes exec rejection only as this exact string.
		if err.Error() == "ssh: command "+cmd+" failed" {
			return 0, &PhasedError{"failed_not_started", "start", "exec request rejected"}
		}
		return 0, &PhasedError{"indeterminate", "start", "start i/o error"}
	}
	err = sess.Wait()
	var exitError *ssh.ExitError
	if err == nil {
		return 0, nil
	}
	if errors.As(err, &exitError) {
		return exitError.ExitStatus(), nil
	}
	detail := "transport error after start"
	var missing *ssh.ExitMissingError
	if ctx.Err() != nil {
		detail = "context canceled"
	} else if errors.As(err, &missing) {
		detail = "channel closed without exit status"
	}
	return -1, &PhasedError{"indeterminate", "wait", detail}
}
