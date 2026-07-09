package tools

import (
	"context"
	"errors"
	"fmt"
)

// PingInput is the JSON input to the sshgate.ping tool. It names the
// single registered alias to probe for reachability.
type PingInput struct {
	Alias string `json:"alias" jsonschema:"registered server alias to probe for reachability (run sshgate.list_servers to see options)"`
}

// PingOutput mirrors one ServerStatus row: the reachability of the named
// server via the SSHGATE_OK probe. PingMS is the round-trip in
// milliseconds on success (omitted on failure); Error carries a short
// failure summary. ReadOnly surfaces the server's tier from the registry
// (W3-7), reported regardless of reachability.
type PingOutput struct {
	Alias     string `json:"alias"`
	Reachable bool   `json:"reachable"`
	PingMS    int64  `json:"ping_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	ReadOnly  bool   `json:"read_only,omitempty"`
}

// Ping probes the reachability of exactly ONE registered server via the
// same SSHGATE_OK probe status uses (empty SSH_ORIGINAL_COMMAND, 5s
// timeout). It is READ-class by construction: the empty command makes the
// gate reply SSHGATE_OK without ever engaging the signer, so ping never
// creates a sign request, never solicits a Telegram approval, and never
// touches the read-only gate — unlike status, it does not fan out across
// every registered server.
//
// Ping returns a Go error only for a configuration problem (nil
// dependencies) or an unknown alias. A reachable/unreachable verdict for a
// known alias is always reported in the output, never as an error — the
// tool's job is to report.
func (r *Runner) Ping(ctx context.Context, in PingInput) (PingOutput, error) {
	if r.Servers == nil {
		return PingOutput{}, errors.New("tools: Servers is nil")
	}
	if r.SSH == nil {
		return PingOutput{}, errors.New("tools: SSH is nil")
	}
	if in.Alias == "" {
		return PingOutput{}, errors.New("tools: alias is empty")
	}

	e, ok := r.Servers.Get(in.Alias)
	if !ok {
		return PingOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	// Reuse the battle-tested single-server probe (5s timeout, SSHGATE_OK
	// check). The tier rides along from the trusted registry entry.
	row := registryRow{alias: in.Alias, host: e.Host, user: e.User, port: e.Port, readOnly: e.ReadOnly}
	s := r.probeServer(ctx, row)
	return PingOutput{
		Alias:     s.Alias,
		Reachable: s.Reachable,
		PingMS:    s.PingMS,
		Error:     s.Error,
		ReadOnly:  s.ReadOnly,
	}, nil
}
