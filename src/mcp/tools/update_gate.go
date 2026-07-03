package tools

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gatever"
	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// UpdateGateInput is the JSON input to sshgate.update_gate. The agent supplies
// ONLY the alias — never the binary bytes, never a hash (R5). The MCP reads the
// operator's locally-staged gate binary, hashes it, and requests a signature
// that commits to that exact hash; the operator approves a distinct, scary
// Telegram banner bound to it.
type UpdateGateInput struct {
	Alias string `json:"alias" jsonschema:"alias of an already-registered server whose gate binary to update in place (must already be registered; read-only/Tier-1 servers are refused)"`
}

// UpdateGateOutput is the structured result of a successful update. NewHash is
// the SHA-256 the operator approved and the gate confirmed it installed; Size
// and Revision echo the gate's success marker; VerifiedAlive reports whether a
// post-update liveness re-probe saw the new gate answer (best-effort — the
// update already succeeded and was confirmed by the marker either way).
type UpdateGateOutput struct {
	Alias         string `json:"alias"`
	NewHash       string `json:"new_hash"`
	Size          int64  `json:"size"`
	Revision      string `json:"revision"`
	VerifiedAlive bool   `json:"verified_alive"`
}

// UpdateTTLSec is the signature validity window requested for an
// SSHGATE_UPDATE. It is set to the sigwire.MaxSigValidity cap (300s) for ample
// post-tap transfer margin on a multi-MB binary; a longer window is harmless
// here because an update replay re-installs the identical approved binary (an
// idempotent no-op — the gate re-hashes and only ever installs the approved
// bytes).
const UpdateTTLSec = 300

// updatedMarkerPrefix is the token the gate prints on a successful update. The
// MCP requires it (and a matching hash) before trusting that the install took.
const updatedMarkerPrefix = "SSHGATE_UPDATED"

// UpdateGate requests a SIGNED, in-place update of the gate binary on an
// already-registered server. The agent supplies only the alias; the MCP reads
// the operator's locally-staged gate binary, hashes it, shows that hash + build
// revision to the operator for a human tap (a standing grant can NEVER
// auto-sign it — the signer's matchGrant carve-out forces a prompt), then
// streams the exact approved bytes on the SSH session's stdin. The gate
// re-hashes what it receives and refuses on mismatch, so an approved update
// authorizes exactly that one binary.
//
// Flow (spec §5.1):
//
//  1. Nil-checks + empty-alias check.
//  2. Resolve alias; unknown → friendly error.
//  3. Read-only alias → short-circuit before any tap (a Tier-1 box refuses all
//     signed commands locally). Then the /sshgate:setup key pre-flight.
//  4. Read the staged binary ONCE (bytes + hash from the same buffer, R5 /
//     Finding 5); absent → actionable "run `make install-local` first".
//  5. Hash → cmd = "SSHGATE_UPDATE <sha256hex>".
//  6. Scan the staged build's version marker (best-effort) for the banner.
//  7. Probe the running gate's version (best-effort; an old gate won't answer).
//  8. Build the Build-line reason (rides in CmdReq.Reason → telegram banner).
//  9. Sign (ordinary sign path; matchGrant forces a human tap).
//  10. Stream the exact approved buffer on stdin.
//  11. Parse + verify the success marker's hash equals the approved hash.
//  12. Re-probe liveness (best-effort) → VerifiedAlive.
func (r *Runner) UpdateGate(ctx context.Context, in UpdateGateInput) (UpdateGateOutput, error) {
	if r.Servers == nil {
		return UpdateGateOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Sign == nil {
		return UpdateGateOutput{}, errors.New("tools: Sign is nil")
	}
	if r.SSH == nil {
		return UpdateGateOutput{}, errors.New("tools: SSH is nil")
	}
	if r.SSHStdin == nil {
		return UpdateGateOutput{}, errors.New("tools: SSHStdin is nil")
	}
	if in.Alias == "" {
		return UpdateGateOutput{}, errors.New("tools: alias is empty")
	}

	entry, ok := r.Servers.Get(in.Alias)
	if !ok {
		return UpdateGateOutput{}, fmt.Errorf("tools: unknown server alias %q (check sshgate.list_servers)", in.Alias)
	}

	// A read-only (Tier-1) box has no signer pubkey, so it denies every signed
	// command locally (exit 77). Short-circuit BEFORE any Telegram tap so a
	// guaranteed no-op never wastes a human approval — mirrors runWrite.
	if entry.ReadOnly {
		return UpdateGateOutput{Alias: in.Alias}, readOnlyWriteErr(in.Alias)
	}
	// A write before /sshgate:setup cannot succeed (no key, no signer): surface
	// the same actionable guidance the read/write paths use.
	if err := r.checkKeyReady(); err != nil {
		return UpdateGateOutput{Alias: in.Alias}, err
	}

	if r.StagedGatePath == "" {
		return UpdateGateOutput{Alias: in.Alias}, errors.New(
			"tools: no staged gate binary configured — run `make install-local` first (it stages the gate binary the MCP hashes and pushes)")
	}
	// READ ONCE (R5 / Finding 5): hash THIS buffer and stream THIS buffer.
	// Re-opening the path would open a window in which a concurrent overwrite
	// could send bytes the operator never approved; the gate's re-hash would
	// catch it, but "what was approved == what was streamed" must hold by
	// construction, not by the gate's backstop.
	body, err := os.ReadFile(r.StagedGatePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
				"tools: staged gate binary %s does not exist — run `make install-local` first: %w", r.StagedGatePath, err)
		}
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf("tools: read staged gate binary %s: %w", r.StagedGatePath, err)
	}
	if len(body) == 0 {
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
			"tools: staged gate binary %s is empty — run `make install-local` first", r.StagedGatePath)
	}

	sum := sha256.Sum256(body)
	hexHash := hex.EncodeToString(sum[:])
	cmd := "SSHGATE_UPDATE " + hexHash

	// Build identity for the approval banner, scanned from the SAME buffer via
	// the safe marker scan (gatever.Scan: runtime-built prefix + all-occurrences
	// acceptance rule, spec §11.2 HIGH-1 — the identical logic the gate uses in
	// binaryRevision). Best-effort: a non-gate / marker-stripped binary yields
	// "unknown". This is the build-injected version marker, NOT debug/buildinfo
	// vcs stamping (empty under the release recipe's -buildvcs=false).
	stagedVer := gatever.Scan(body)

	// Probe the running gate's version so the operator sees the staged and
	// running versions side by side (downgrade visibility, Finding 4). This is
	// BEST-EFFORT: an old gate predating SSHGATE_VERSION classifies it as an
	// unknown write and returns exit 77 — never fail the tool on a probe.
	runningVer := probeRunningRev(ctx, r.SSH, entry.Host, entry.User, entry.Port)

	// The reason rides in CmdReq.Reason → the telegram "Build:" line. It is
	// display-only/unsigned (downgrade visibility), so keep it a single clean
	// line. Always non-empty and always carries the running version, so a
	// marker-stripped staged binary can never hide the downgrade cue (Finding 4).
	// The arch-bearing staged basename is included so a future multi-arch
	// operator checks the right .sha256 (LOW-5).
	reason := updateReason(filepath.Base(r.StagedGatePath), stagedVer, runningVer)

	reqID, err := newRequestID()
	if err != nil {
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf("tools: request id: %w", err)
	}
	// Host binds the signature to THIS server's TOFU-pinned host key, read from
	// the trusted registry entry (never an agent parameter). matchGrant's
	// admin-verb carve-out forces a human tap for the SSHGATE_-prefixed command.
	res, err := r.Sign.Sign(ctx, reqID, []signpkg.CmdReq{{
		Server: in.Alias,
		Cmd:    cmd,
		TTLSec: UpdateTTLSec,
		Host:   entry.Fingerprint,
		Reason: reason,
	}})
	if err != nil {
		return UpdateGateOutput{Alias: in.Alias}, r.remediateSignErr(err)
	}
	if len(res.Signed) != 1 {
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf("tools: expected 1 signature; got %d", len(res.Signed))
	}
	wireCmd := res.Signed[0].Sig + " " + cmd

	// Stream the EXACT approved buffer on the session's stdin (bytes.NewReader
	// over the same body we hashed — no re-open).
	stdout, stderr, exit, err := r.SSHStdin.RunWithStdin(ctx, entry.Host, entry.User, entry.Port, wireCmd, bytes.NewReader(body))
	if err != nil {
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf("tools: ssh update: %w (stderr=%q exit=%d)",
			err, strings.TrimSpace(string(stderr)), exit)
	}
	// A gate deny comes back as err=nil with a raw non-zero exit. The update
	// path does NOT route through gateDenyNote: the gate reuses exit 65 for a
	// DETERMINISTIC binary-check refusal (hash mismatch / non-ELF / wrong-arch /
	// size), so gateDenyNote's "expired signature… retry" advice would be
	// actively wrong here — re-firing the scary approval for a request that will
	// fail identically. Annotate the update-specific exit codes instead.
	if exit != 0 {
		outStr := strings.TrimSpace(string(stdout))
		errStr := strings.TrimSpace(string(stderr))
		switch exit {
		case 65:
			return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
				"tools: gate refused the update — the streamed binary failed a gate check (hash mismatch / not an ELF / wrong architecture / size violation); the old gate is unchanged. Do NOT re-run without first fixing the staged binary (re-run `make install-local`). (exit=%d stdout=%q stderr=%q)",
				exit, outStr, errStr)
		case 70:
			return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
				"tools: gate could not replace its binary (filesystem error) — the old gate is still in place; check ~/.sshgate-gate on the server (disk space / permissions). (exit=%d stdout=%q stderr=%q)",
				exit, outStr, errStr)
		case 77:
			return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
				"tools: the server denied the signed update (read-only / no signer pubkey / missing signature) — check sshgate.status. (exit=%d stdout=%q stderr=%q)",
				exit, outStr, errStr)
		default:
			return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
				"tools: gate refused the update (exit=%d stdout=%q stderr=%q)",
				exit, outStr, errStr)
		}
	}

	gotHash, size, rev, ok := parseUpdatedMarker(string(stdout))
	if !ok {
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
			"tools: gate did not confirm the update (missing %s marker; stdout=%q stderr=%q exit=%d)",
			updatedMarkerPrefix, strings.TrimSpace(string(stdout)), strings.TrimSpace(string(stderr)), exit)
	}
	// Defense-in-depth: the gate already refuses on a hash mismatch, so this
	// should never trip — but confirm the gate installed EXACTLY the approved
	// binary before we report success.
	if gotHash != hexHash {
		return UpdateGateOutput{Alias: in.Alias}, fmt.Errorf(
			"tools: gate confirmed a DIFFERENT hash than approved (approved=%s confirmed=%s) — refusing to report success", hexHash, gotHash)
	}

	// Best-effort liveness re-probe: an empty command makes the gate print
	// SSHGATE_OK (mirrors status/verifyProvision). The update already succeeded
	// and was confirmed by the marker, so do NOT fail the tool if this probe
	// fails — just report VerifiedAlive=false.
	verifiedAlive := probeAlive(ctx, r.SSH, entry.Host, entry.User, entry.Port)

	return UpdateGateOutput{
		Alias:         in.Alias,
		NewHash:       hexHash,
		Size:          size,
		Revision:      rev,
		VerifiedAlive: verifiedAlive,
	}, nil
}

// updateReason builds the operator-facing Build line carried in CmdReq.Reason
// (→ the telegram banner's "Build:" line). It ALWAYS presents the staged build
// version and the running build version side by side so a downgrade is
// spottable — critically, it shows the running version even when the staged
// version is unknown, because a hostile stager that strips the marker would
// otherwise hide BOTH versions and defeat the downgrade cue (Finding 4) exactly
// when it matters. Shape (spec §5.2, §11.8 task 4):
//
//	"<staged-basename> · version <staged> · running version <running>"
//
// There is NO "(time)" component — vcs stamping is off under the release recipe
// (-buildvcs=false, §11.1), so no build time exists. Always non-empty (the
// basename is always present); an unknown staged/running version renders
// "version unknown". The basename carries the arch (sshgate-gate-linux-amd64) so
// a future multi-arch operator checks the right .sha256 (LOW-5).
func updateReason(basename, stagedVer, runningVer string) string {
	if stagedVer == "" {
		stagedVer = gatever.Unknown
	}
	if runningVer == "" {
		runningVer = gatever.Unknown
	}
	return fmt.Sprintf("%s · version %s · running version %s", basename, stagedVer, runningVer)
}

// probeRunningRev best-effort reads the running gate's build revision via the
// unsigned SSHGATE_VERSION verb. An old gate that predates the verb classifies
// it as an unknown write (exit 77) and never prints "rev=", so this returns
// "unknown" rather than failing — the caller must NEVER fail on a probe error.
func probeRunningRev(ctx context.Context, sshRunner SSHRunner, host, user string, port int) string {
	stdout, _, exit, err := sshRunner.Run(ctx, host, user, port, "SSHGATE_VERSION")
	if err != nil || exit != 0 {
		return "unknown"
	}
	s := string(stdout)
	i := strings.Index(s, "rev=")
	if i < 0 {
		return "unknown"
	}
	tok := strings.TrimSpace(s[i+len("rev="):])
	if tok == "" {
		return "unknown"
	}
	// Take the first whitespace-delimited token after rev=.
	if fields := strings.Fields(tok); len(fields) > 0 {
		return fields[0]
	}
	return "unknown"
}

// probeAlive best-effort re-probes the server with an empty command (the gate
// prints SSHGATE_OK) to confirm the NEW gate answers after an update. Any
// error or a missing marker reports false — the update already succeeded and
// was confirmed by the SSHGATE_UPDATED marker, so this is informational only.
func probeAlive(ctx context.Context, sshRunner SSHRunner, host, user string, port int) bool {
	stdout, _, _, err := sshRunner.Run(ctx, host, user, port, "")
	if err != nil {
		return false
	}
	return strings.Contains(string(stdout), "SSHGATE_OK")
}

// parseUpdatedMarker extracts the sha256, size, and rev from the gate's success
// marker "SSHGATE_UPDATED sha256=<hex> size=<n> rev=<version-or-unknown>". The
// rev= KEY is frozen (spec §11.2 HIGH-2); only its value changed from a git sha
// to the injected version. ok is false when the marker is absent or the required
// sha256/size tokens cannot be parsed. rev defaults to "unknown" when absent.
func parseUpdatedMarker(stdout string) (hash string, size int64, rev string, ok bool) {
	if !strings.Contains(stdout, updatedMarkerPrefix) {
		return "", 0, "", false
	}
	rev = "unknown"
	haveHash, haveSize := false, false
	for _, f := range strings.Fields(stdout) {
		switch {
		case strings.HasPrefix(f, "sha256="):
			hash = strings.TrimPrefix(f, "sha256=")
			haveHash = true
		case strings.HasPrefix(f, "size="):
			n, err := strconv.ParseInt(strings.TrimPrefix(f, "size="), 10, 64)
			if err == nil {
				size = n
				haveSize = true
			}
		case strings.HasPrefix(f, "rev="):
			rev = strings.TrimPrefix(f, "rev=")
		}
	}
	if !haveHash || !haveSize {
		return "", 0, "", false
	}
	return hash, size, rev, true
}
