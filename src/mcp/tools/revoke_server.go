package tools

import (
	"context"
	"errors"
	"fmt"
	"strings"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// RevokeServerInput is the JSON input to sshgate.revoke_server. The
// tool tears down the remote gate install behind alias and removes
// the alias from the local registry. Spec §"Revocation → From our end
// (remote)".
type RevokeServerInput struct {
	Alias string `json:"alias" jsonschema:"alias of the server to revoke (must already be registered)"`
}

// RevokeServerOutput is the structured result. RemoteCleaned and
// RegistryRemoved are reported independently so partial-failure cases
// (e.g. SSH succeeded but registry write failed) are visible to the
// caller; a fully-successful revoke has both true.
type RevokeServerOutput struct {
	Alias           string `json:"alias"`
	RemoteCleaned   bool   `json:"remote_cleaned"`
	RegistryRemoved bool   `json:"registry_removed"`
	Message         string `json:"message"`
}

// RevokeTTLSec is the validity window we request when signing the
// SSHGATE_REVOKE command. Spec calls for 60s — long enough to cover
// dial+exec, well under sigwire.MaxSigValidity.
const RevokeTTLSec = 60

// revokeStdoutMarker is the prefix gate prints on successful revoke
// (see gate.FormatRevokeStdout). The MCP side requires the marker
// before removing the alias from the registry.
const revokeStdoutMarker = "SSHGATE_REVOKED"

// RevokeServer signs SSHGATE_REVOKE, runs it on the remote, and on
// confirmation removes the alias from the registry.
//
// Flow:
//
//  1. Look up alias → unknown → return error.
//  2. Sign SSHGATE_REVOKE through the signer backend (one-cmd
//     sign request, TTL = RevokeTTLSec).
//  3. SSH the signed line. gate's main.go routes it to doRevoke,
//     which strips the SSHGate-restricted authorized_keys line and
//     removes ~/.sshgate-gate/.
//  4. Verify stdout contains SSHGATE_REVOKED; remove alias from the
//     registry. Registry write failures keep RemoteCleaned=true so the
//     operator can re-run revoke or hand-clean the registry.
//
// Sign-side errors (ErrDenied, ErrTimeout, ErrUnreachable) are wrapped
// so callers can match with errors.Is.
func (r *Runner) RevokeServer(ctx context.Context, in RevokeServerInput) (RevokeServerOutput, error) {
	if r.Servers == nil {
		return RevokeServerOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return RevokeServerOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return RevokeServerOutput{}, errors.New("tools: SSH is nil")
	}
	if in.Alias == "" {
		return RevokeServerOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return RevokeServerOutput{}, fmt.Errorf("tools: unknown server alias %q", in.Alias)
	}

	// Tier-1 (read-only) short-circuit: a read-only gate has NO signer pubkey, so
	// it cannot verify the signed SSHGATE_REVOKE below — the gate denies it (exit
	// 77) and the alias is never removed, yet Sign would first burn a real human
	// Telegram tap on a guaranteed no-op. Refuse BEFORE newRequestID/Sign and
	// point at the manual de-provision that actually works. Mirrors runWrite's
	// readOnlyWriteErr placement.
	if entry.ReadOnly {
		return RevokeServerOutput{Alias: in.Alias}, tier1RevokeErr(in.Alias)
	}

	reqID, err := newRequestID()
	if err != nil {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: request id: %w", err)
	}
	// Spec defines CmdReq.Server as the registered alias (recorded
	// in the signer audit log), not the underlying hostname.
	//
	// SSHGATE_REVOKE is a SIGNED admin command, so the gate enforces the
	// per-server host-key binding on it too — bind it to this server's
	// registry fingerprint (read in code, never from the agent) or the gate
	// rejects the revoke with ErrHostMismatch.
	res, err := r.Sign.Sign(ctx, reqID, []signpkg.CmdReq{{
		Server: in.Alias,
		Cmd:    "SSHGATE_REVOKE",
		TTLSec: RevokeTTLSec,
		Host:   entry.Fingerprint,
	}})
	if err != nil {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: sign revoke: %w", err)
	}
	if len(res.Signed) != 1 {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: expected 1 signature; got %d", len(res.Signed))
	}
	wireCmd := res.Signed[0].Sig + " SSHGATE_REVOKE"

	stdout, stderr, exit, err := r.SSH.Run(ctx, entry.Host, entry.User, entry.Port, wireCmd)
	if err != nil {
		return RevokeServerOutput{Alias: in.Alias}, fmt.Errorf("tools: ssh revoke: %w (stderr=%q exit=%d)",
			err, strings.TrimSpace(string(stderr)), exit)
	}
	if !strings.Contains(string(stdout), revokeStdoutMarker) {
		return RevokeServerOutput{Alias: in.Alias},
			fmt.Errorf("tools: gate did not confirm revoke (stdout=%q stderr=%q exit=%d)",
				strings.TrimSpace(string(stdout)), strings.TrimSpace(string(stderr)), exit)
	}

	out := RevokeServerOutput{
		Alias:         in.Alias,
		RemoteCleaned: true,
		Message:       strings.TrimSpace(string(stdout)),
	}

	if err := r.Servers.Remove(in.Alias); err != nil {
		// Remote is already clean. Surface the registry error but keep
		// RemoteCleaned=true so the operator can recover by hand-editing
		// servers.json.
		return out, fmt.Errorf("tools: remote cleaned but registry remove failed: %w", err)
	}
	out.RegistryRemoved = true
	return out, nil
}
