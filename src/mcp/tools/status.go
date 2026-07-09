package tools

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// StatusInput is the JSON input to sshgate.status. The tool takes no
// parameters; the empty struct is here so the SDK derives an empty
// object schema.
type StatusInput struct{}

// SignerStatus captures the signer-socket health probe. Path is
// the configured socket path so operators can see what the MCP is
// pointed at. Reachable is true iff a TCP-style dial succeeded;
// Error is set on failure and carries the dial error string.
type SignerStatus struct {
	Path      string `json:"path"`
	Reachable bool   `json:"reachable"`
	// Configured is true when the socket file EXISTS (a signer daemon
	// is installed), regardless of whether the dial succeeded. On Tier 1
	// (read-only, no signer) the socket file is absent, so Configured is
	// false and an unreachable signer is the NORMAL, expected state —
	// not something to debug. Audit M4.
	Configured bool   `json:"configured"`
	// Permission is true when the socket file EXISTS but the dial was
	// refused with a permission error — the MCP process is not in the
	// sshgatesigner group (membership inactive until a fresh login + Claude
	// Code relaunch). This is NOT a dead daemon; it has a different fix.
	Permission bool   `json:"permission,omitempty"`
	Error      string `json:"error,omitempty"`
}

// ServerStatus is one row in StatusOutput.Servers. PingMS is the
// round-trip in milliseconds on success and omitted on failure;
// Error carries a short failure summary suitable for surfacing to
// Claude. ReadOnly surfaces the server's TIER from the registry
// (true = Tier-1 read-only, writes denied at the gate; false/absent =
// signed-write). It is set from the trusted registry entry regardless
// of reachability — the tier is a property of how the server was
// provisioned, not of whether it currently answers a probe (W3-7).
type ServerStatus struct {
	Alias     string `json:"alias"`
	Reachable bool   `json:"reachable"`
	PingMS    int64  `json:"ping_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	ReadOnly  bool   `json:"read_only,omitempty"`
}

// StatusOutput is the structured result of sshgate.status. The
// signer block stands on its own (always present); Servers is the
// alphabetically-sorted per-registered-server health view.
type StatusOutput struct {
	SignerSocket SignerStatus   `json:"signer_socket"`
	Servers      []ServerStatus `json:"servers"`
}

const (
	// statusSignerDialTimeout bounds the signer-socket probe. It
	// is intentionally short: we are checking that the socket file is
	// connectable, not initiating an approval round-trip.
	statusSignerDialTimeout = 2 * time.Second
	// statusServerDialTimeout bounds a single server's SSH dial + the
	// SSHGATE_OK probe. 5s matches the spec's "short timeout" budget.
	statusServerDialTimeout = 5 * time.Second
	// statusServerProbeWorkers caps the parallel SSH probe pool so
	// status against many servers does not fan out unboundedly
	// (go.md §3.11).
	statusServerProbeWorkers = 4
)

// Status concurrently probes the signer socket and every registered
// server. Servers are dialled in parallel, capped at
// statusServerProbeWorkers. Each per-server probe sends the empty
// SSH_ORIGINAL_COMMAND (gate replies SSHGATE_OK) and records the
// round-trip duration.
//
// Status returns an error only on a configuration problem (nil
// dependencies). Per-target failures are recorded in the output, never
// surfaced as a Go error — the tool's job is to report.
func (r *Runner) Status(ctx context.Context, _ StatusInput) (StatusOutput, error) {
	if r.Servers == nil {
		return StatusOutput{}, errors.New("tools: Servers is nil")
	}
	if r.SSH == nil {
		return StatusOutput{}, errors.New("tools: SSH is nil")
	}

	out := StatusOutput{
		SignerSocket: SignerStatus{Path: r.SignerSockPath},
	}

	// Signer socket probe and server probes run concurrently. The
	// signer side is one dial; the server side is N probes through
	// a bounded worker pool.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		out.SignerSocket = probeSignerSocket(ctx, r.SignerSockPath)
	}()

	servers := r.snapshotRegistry()
	statuses := make([]ServerStatus, len(servers))

	jobs := make(chan int, len(servers))
	workers := statusServerProbeWorkers
	if workers > len(servers) {
		workers = len(servers)
	}
	var workerWG sync.WaitGroup
	for w := 0; w < workers; w++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for i := range jobs {
				statuses[i] = r.probeServer(ctx, servers[i])
			}
		}()
	}
	for i := range servers {
		jobs <- i
	}
	close(jobs)
	workerWG.Wait()
	wg.Wait()

	out.Servers = statuses
	return out, nil
}

// registryRow pairs an alias with its registry entry — used internally
// so the status workers do not need to take r.Servers's lock per probe.
type registryRow struct {
	alias    string
	host     string
	user     string
	port     int
	readOnly bool
}

// snapshotRegistry returns the registry contents sorted alphabetically
// by alias, decoupling the worker pool from the registry's lock.
func (r *Runner) snapshotRegistry() []registryRow {
	raw := r.Servers.List()
	rows := make([]registryRow, 0, len(raw))
	for alias, e := range raw {
		rows = append(rows, registryRow{alias: alias, host: e.Host, user: e.User, port: e.Port, readOnly: e.ReadOnly})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].alias < rows[j].alias })
	return rows
}

// probeServer runs the SSHGATE_OK probe against row's host and returns
// a populated ServerStatus. Errors and non-SSHGATE_OK bodies both
// surface as Reachable=false with a descriptive Error string.
func (r *Runner) probeServer(ctx context.Context, row registryRow) ServerStatus {
	probeCtx, cancel := context.WithTimeout(ctx, statusServerDialTimeout)
	defer cancel()

	start := time.Now()
	stdout, _, _, err := r.SSH.Run(probeCtx, row.host, row.user, row.port, "")
	elapsed := time.Since(start)

	// Tier is a registry property, so it is reported regardless of
	// reachability (an unreachable server still has a known tier).
	s := ServerStatus{Alias: row.alias, ReadOnly: row.readOnly}
	if err != nil {
		s.Error = err.Error()
		return s
	}
	if !strings.Contains(string(stdout), "SSHGATE_OK") {
		s.Error = "probe response did not contain SSHGATE_OK"
		return s
	}
	s.Reachable = true
	s.PingMS = elapsed.Milliseconds()
	return s
}

// probeSignerSocket dials path with a short timeout and immediately
// closes the connection. Reachable is true iff the dial succeeded.
// An empty path produces a clear "not configured" Error.
func probeSignerSocket(ctx context.Context, path string) SignerStatus {
	s := SignerStatus{Path: path}
	if path == "" {
		s.Error = "signer socket path not configured"
		return s
	}
	// Configured iff the socket file exists. Absent = Tier 1 (no signer
	// daemon installed); that is normal, not a failure. Audit M4.
	if _, err := os.Stat(path); err == nil {
		s.Configured = true
	}
	dialCtx, cancel := context.WithTimeout(ctx, statusSignerDialTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", path)
	if err != nil {
		s.Error = err.Error()
		// EACCES/EPERM on a socket that EXISTS means the process is not in
		// the sshgatesigner group (membership inactive until re-login +
		// relaunch), not a dead daemon — flag it so status gives the right
		// remediation instead of "unreachable, debug systemd".
		if s.Configured && errors.Is(err, fs.ErrPermission) {
			s.Permission = true
		}
		return s
	}
	_ = conn.Close()
	s.Reachable = true
	return s
}
