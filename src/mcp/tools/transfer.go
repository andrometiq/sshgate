package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	signpkg "github.com/karthikeyan5/sshgate/src/mcp/sign"
)

// TransferInput is the JSON input to sshgate.transfer. The agent supplies ONLY
// display aliases + paths (+ optional mode). It NEVER supplies pubkeys, host
// fingerprints, or an xferID: the MCP sources the fingerprints from its TRUSTED
// registry and the signer sources the pubkeys + mints the xferID from ITS
// registry — the whole anti-MITM guarantee.
type TransferInput struct {
	SrcAlias  string `json:"src_alias" jsonschema:"registered alias of the SOURCE server (holds the secret file)"`
	SrcPath   string `json:"src_path" jsonschema:"absolute path of the secret file on the source server to read"`
	DestAlias string `json:"dest_alias" jsonschema:"registered alias of the DESTINATION server (receives the secret file)"`
	DestPath  string `json:"dest_path" jsonschema:"absolute path on the destination server to write the secret file"`
	Mode      string `json:"mode,omitempty" jsonschema:"octal file mode for the written file (default 0600; only 0600 is accepted today)"`
}

// TransferOutput is METADATA ONLY. It carries NO stdout, NO envelope, NO
// plaintext — the transferred secret value never appears in the tool result.
type TransferOutput struct {
	SrcAlias  string `json:"src_alias"`
	SrcPath   string `json:"src_path"`
	DestAlias string `json:"dest_alias"`
	DestPath  string `json:"dest_path"`
	Mode      string `json:"mode"`
	XferID    string `json:"xfer_id"`
	Bytes     int64  `json:"bytes"`     // length only (from the RECV marker); never the value
	AuthMode  string `json:"auth_mode"` // always "human" on a transfer approval
}

// TransferTTLSec is the sig-validity window for both legs — set to the
// sigwire.MaxSigValidity cap (300s) for ample margin across two SSH round-trips
// after one human tap. A longer window is harmless: re-presenting a SEND leg
// re-seals identical ciphertext, a RECV leg re-writes identical plaintext (both
// idempotent), exactly like update_gate's replay reasoning.
const TransferTTLSec = 300

// xferReceivedMarkerPrefix is the token the destination gate prints on a
// successful RECV. The MCP requires it (and a matching xferID) before trusting
// that the write took.
const xferReceivedMarkerPrefix = "SSHGATE_XFER_RECEIVED"

// Transfer moves a secret file from one registered server to another,
// end-to-end encrypted through the gate. The agent supplies only display
// aliases + paths; the MCP sources the two host fingerprints from its TRUSTED
// registry and the signer sources the recipient box key + sender identity key
// from ITS registry (and mints the xferID), so a rogue agent can neither
// substitute a recipient key nor correlate a stale leg. The value is sealed on
// the source gate, RELAYED by the MCP as opaque ciphertext (SEND stdout → RECV
// stdin), and opened on the destination gate — it NEVER reaches the agent, the
// tool result, or any log.
//
// Flow (P3 spec §2.2):
//
//  1. Nil-checks + empty-field checks.
//  2. Resolve BOTH aliases via r.Servers.Get; unknown ⇒ friendly error.
//  3. Read-only short-circuit BEFORE any tap: a signed leg to a Tier-1 box is
//     denied 77 locally, so short-circuit whichever side is read-only.
//  4. r.checkKeyReady() (MCP SSH key present).
//  5. Default mode to 0600.
//  6. One human approval → two signed host-bound legs (fps from the registry).
//  7. Run SEND on the source gate, CAPTURING stdout (the envelope).
//  8. Relay: run RECV on the dest gate feeding the envelope on stdin.
//  9. Parse + verify the RECV marker (present AND xfer == the approved id).
//  10. Return METADATA ONLY — no stdout, no envelope, no plaintext.
func (r *Runner) Transfer(ctx context.Context, in TransferInput) (TransferOutput, error) {
	if r.Servers == nil {
		return TransferOutput{}, errors.New("tools: Servers is nil")
	}
	if r.Xfer == nil {
		return TransferOutput{}, errors.New("tools: Xfer is nil")
	}
	if r.SSH == nil {
		return TransferOutput{}, errors.New("tools: SSH is nil")
	}
	if r.SSHStdin == nil {
		return TransferOutput{}, errors.New("tools: SSHStdin is nil")
	}
	if in.SrcAlias == "" {
		return TransferOutput{}, errors.New("tools: src_alias is empty")
	}
	if strings.TrimSpace(in.SrcPath) == "" {
		return TransferOutput{}, errors.New("tools: src_path is empty")
	}
	if in.DestAlias == "" {
		return TransferOutput{}, errors.New("tools: dest_alias is empty")
	}
	if strings.TrimSpace(in.DestPath) == "" {
		return TransferOutput{}, errors.New("tools: dest_path is empty")
	}

	srcEntry, ok := r.Servers.Get(in.SrcAlias)
	if !ok {
		return TransferOutput{}, fmt.Errorf("tools: unknown source server alias %q (check sshgate.list_servers)", in.SrcAlias)
	}
	destEntry, ok := r.Servers.Get(in.DestAlias)
	if !ok {
		return TransferOutput{}, fmt.Errorf("tools: unknown destination server alias %q (check sshgate.list_servers)", in.DestAlias)
	}

	// A read-only (Tier-1) box has no signer pubkey, so it denies every signed
	// command locally (exit 77). Short-circuit BEFORE any Telegram tap so a
	// guaranteed no-op never wastes a human approval — mirrors runWrite /
	// update_gate. SEND lands on the source; RECV lands on the destination.
	if srcEntry.ReadOnly {
		return TransferOutput{}, readOnlyWriteErr(in.SrcAlias, "")
	}
	if destEntry.ReadOnly {
		return TransferOutput{}, readOnlyWriteErr(in.DestAlias, "")
	}

	// A transfer before /sshgate:setup cannot succeed (no key, no signer):
	// surface the same actionable guidance the read/write paths use.
	if err := r.checkKeyReady(); err != nil {
		return TransferOutput{}, err
	}

	mode := in.Mode
	if mode == "" {
		mode = "0600"
	}

	reqID, err := newRequestID()
	if err != nil {
		return TransferOutput{}, fmt.Errorf("tools: request id: %w", err)
	}

	// One human approval → two host-bound signed legs. The fingerprints come
	// from the TRUSTED registry entries (never an agent parameter); the signer
	// sources the pubkeys + mints the xferID from ITS own registry.
	res, err := r.Xfer.Transfer(ctx, reqID, signpkg.TransferReq{
		SrcAlias:  in.SrcAlias,
		SrcFP:     srcEntry.Fingerprint,
		SrcPath:   in.SrcPath,
		DestAlias: in.DestAlias,
		DestFP:    destEntry.Fingerprint,
		DestPath:  in.DestPath,
		Mode:      mode,
		TTLSec:    TransferTTLSec,
	})
	if err != nil {
		// Preserve the shared sentinels (denied/timeout/permission/unreachable/
		// verdict-unknown) so the MCP layer maps the outcome correctly.
		return TransferOutput{}, r.remediateSignErr(err)
	}

	wireSend := res.Send.Sig + " " + res.Send.Cmd
	wireRecv := res.Recv.Sig + " " + res.Recv.Cmd

	// Run the SEND leg on the SOURCE gate, capturing stdout (the envelope). The
	// envelope lives ONLY in this local variable — it is relayed to the RECV
	// leg's stdin, never logged, never returned. On any error we surface
	// metadata only (exit code) — NEVER sendOut/sendErr, which could carry the
	// envelope.
	sendOut, _, sendExit, err := r.SSH.Run(ctx, srcEntry.Host, srcEntry.User, srcEntry.Port, wireSend)
	if err != nil {
		return TransferOutput{}, fmt.Errorf("tools: ssh transfer send: %w (exit=%d)", err, sendExit)
	}
	if sendExit != 0 {
		return TransferOutput{}, fmt.Errorf("tools: %s", xferSendExitNote(sendExit))
	}

	// Relay: run the RECV leg on the DEST gate, feeding the envelope on stdin.
	recvOut, recvErr, recvExit, err := r.SSHStdin.RunWithStdin(ctx, destEntry.Host, destEntry.User, destEntry.Port, wireRecv, bytes.NewReader(sendOut))
	if err != nil {
		return TransferOutput{}, fmt.Errorf("tools: ssh transfer recv: %w (exit=%d)", err, recvExit)
	}
	if recvExit != 0 {
		// recvErr is a generic gate stderr line (never plaintext/envelope), so
		// it is safe to include for diagnosis; the envelope/stdin are never
		// echoed. Trim to a single clean line.
		return TransferOutput{}, fmt.Errorf("tools: %s (gate: %q)", xferRecvExitNote(recvExit), strings.TrimSpace(string(recvErr)))
	}

	// The dest gate confirms with a metadata-only marker; require it present
	// AND that the confirmed xferID equals the approved one.
	gotXferID, nbytes, ok := parseXferReceivedMarker(string(recvOut))
	if !ok {
		return TransferOutput{}, fmt.Errorf(
			"tools: destination gate did not confirm the transfer (missing %s marker; exit=%d)", xferReceivedMarkerPrefix, recvExit)
	}
	if gotXferID != res.XferID {
		return TransferOutput{}, fmt.Errorf(
			"tools: destination confirmed a DIFFERENT transfer id than approved (approved=%s confirmed=%s) — refusing to report success", res.XferID, gotXferID)
	}

	return TransferOutput{
		SrcAlias:  in.SrcAlias,
		SrcPath:   in.SrcPath,
		DestAlias: in.DestAlias,
		DestPath:  in.DestPath,
		Mode:      mode,
		XferID:    res.XferID,
		Bytes:     nbytes,
		AuthMode:  res.AuthMode,
	}, nil
}

// xferSendExitNote maps a non-zero SEND-leg gate exit to remediation. It NEVER
// echoes the gate's stdout (the envelope) or stderr. Codes per P3 spec §1.7:
// 65 = data/crypto refusal, 70 = fs/key error, 77 = read-only/unsigned.
func xferSendExitNote(exit int) string {
	switch exit {
	case 65:
		return "the source gate refused the transfer send (exit 65): the signed leg failed to parse, or the source file was empty or over the size cap; nothing was sealed."
	case 70:
		return "the source gate could not read the source file or its transfer keys (exit 70): check src_path and that the source gate holds its xfer keys."
	case 77:
		return "the source gate denied the signed send (exit 77): read-only / no signer pubkey / missing signature — check sshgate.status."
	default:
		return fmt.Sprintf("the source gate refused the transfer send (exit %d).", exit)
	}
}

// xferRecvExitNote maps a non-zero RECV-leg gate exit to remediation. Codes per
// P3 spec §1.7: 65 = data/crypto refusal (parse / binding / attestation / cap),
// 70 = fs/key error, 77 = read-only/unsigned.
func xferRecvExitNote(exit int) string {
	switch exit {
	case 65:
		return "the destination gate refused the transfer receive (exit 65): the signed leg failed to parse, the envelope was empty/oversize/malformed, or the crypto binding/attestation failed; nothing was written."
	case 70:
		return "the destination gate could not load its transfer keys or write the destination file (exit 70): check dest_path is writable and that the destination gate holds its xfer keys."
	case 77:
		return "the destination gate denied the signed receive (exit 77): read-only / no signer pubkey / missing signature — check sshgate.status."
	default:
		return fmt.Sprintf("the destination gate refused the transfer receive (exit %d).", exit)
	}
}

// parseXferReceivedMarker extracts the xferID + byte length from the dest
// gate's success marker "SSHGATE_XFER_RECEIVED xfer=<id> bytes=<n>". It mirrors
// parseUpdatedMarker. ok is false when the marker is absent or the xfer/bytes
// tokens cannot be parsed. bytes is a LENGTH, never the secret value.
func parseXferReceivedMarker(stdout string) (xferID string, nbytes int64, ok bool) {
	if !strings.Contains(stdout, xferReceivedMarkerPrefix) {
		return "", 0, false
	}
	haveXfer, haveBytes := false, false
	for _, f := range strings.Fields(stdout) {
		switch {
		case strings.HasPrefix(f, "xfer="):
			xferID = strings.TrimPrefix(f, "xfer=")
			haveXfer = true
		case strings.HasPrefix(f, "bytes="):
			n, err := strconv.ParseInt(strings.TrimPrefix(f, "bytes="), 10, 64)
			if err == nil {
				nbytes = n
				haveBytes = true
			}
		}
	}
	if !haveXfer || !haveBytes {
		return "", 0, false
	}
	return xferID, nbytes, true
}
