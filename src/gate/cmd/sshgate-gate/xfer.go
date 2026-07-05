package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/xfer"
	"github.com/karthikeyan5/sshgate/src/xferwire"
)

// This file isolates all gate-side box→box transfer logic, mirroring how
// update.go isolates SSHGATE_UPDATE. It is reached ONLY from the signed-admin
// dispatch in main.go (after VerifySigned, before classify/exec), so a
// SSHGATE_XFER_* line is never handed to /bin/sh. It reuses the package-scope
// seams (gateDirFn, auditNoExec, logf, the exit-code consts) and consumes the
// committed P1 crypto (src/xfer) + P2 wire codec (src/xferwire) — it adds no
// new crypto and no new wire grammar.
//
// SECURITY — the load-bearing invariants this file enforces:
//   - Keys come ONLY from the signer-signed leg (which the signer sourced from
//     ITS registry): SEND seals to leg.BoxPub, RECV verifies leg.IDPub. The gate
//     never reads a transfer key from argv, env, or stdin.
//   - Host binding is already enforced by gate.VerifySigned BEFORE dispatch
//     (SEND verifies only on the src host, RECV only on the dest host); this
//     file does not re-implement or weaken it.
//   - BOUNDED reads everywhere: io.LimitReader on the SEND source-file read and
//     on the RECV stdin envelope read, applied BEFORE xfer.Unmarshal (the P1
//     carry-over — Open's cap protects the AEAD, not the JSON-decode allocation).
//   - CONFIDENTIALITY: plaintext NEVER reaches stdout, the audit string, or any
//     log/error. SEND emits only ciphertext to stdout; RECV writes plaintext
//     ONLY to the dest file, then scrubs its buffer, and prints a metadata-only
//     marker. Every audit row is metadata-only auditNoExec over the wrapped leg.
//   - Fail closed: missing/mis-permissioned keys, oversize inputs, parse/crypto
//     failures — all generic errors, correct exit codes (§1.7 of the P3 spec).

// maxXferPlaintextBytes bounds a transferred secret. Real payloads are a
// botToken / KB-scale configs; 8 MiB is generous headroom while capping a
// hostile/huge source so an unbounded read can never exhaust gate memory. var,
// not const, only so a test can shrink it; production never reassigns it.
var maxXferPlaintextBytes int64 = 8 << 20

// maxXferEnvelopeBytes bounds the RECV stdin read BEFORE xfer.Unmarshal (the P1
// carry-over: Open's cap protects the AEAD, not the JSON-decode allocation).
// An envelope base64-expands the sealed plaintext (+box.AnonymousOverhead) ~4/3
// plus the attestation + JSON scaffolding; 2x the plaintext cap is ample. var,
// not const, only so a test can shrink it; production never reassigns it.
var maxXferEnvelopeBytes int64 = maxXferPlaintextBytes*2 + (64 << 10)

// xferBoxKeyPath resolves this gate's recipient X25519 private key (RECV path:
// xfer.Open). It lives beside gate.pub in the gate dir, resolved via the
// gateDirFn seam — NEVER an env var (same forgery-surface rationale as
// gate.pub, main.go). The file is written on the host by `gate genkeys` /
// `gate genkeys --rotate` during provisioning (see genkeys.go).
func xferBoxKeyPath() (string, error) {
	dir, _, err := gateDirFn()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "xfer-box.key"), nil
}

// xferIDKeyPath resolves this gate's sender ed25519 private key (SEND path:
// xfer.Seal attestation). Same gate-dir, non-env resolution as xferBoxKeyPath.
func xferIDKeyPath() (string, error) {
	dir, _, err := gateDirFn()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "xfer-id.key"), nil
}

// handleXfer dispatches a verified SSHGATE_XFER_* leg to the SEND or RECV
// handler. It is reached only on the signed path after VerifySigned succeeded
// (authentic, unexpired, host-bound) on a Tier-2 gate. It runs NO /bin/sh child
// and ALWAYS returns an exit code. An unknown XFER verb fails closed (exit 65),
// never falling through to classify/exec.
func handleXfer(audit *gate.AuditLogger, innerCmd string) int {
	switch {
	case strings.HasPrefix(innerCmd, xferwire.VerbSend+" "):
		return handleXferSend(audit, innerCmd)
	case strings.HasPrefix(innerCmd, xferwire.VerbRecv+" "):
		return handleXferRecv(audit, innerCmd)
	default:
		logf("xfer: unknown transfer verb")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
}

// handleXferSend runs on gate A (Host=A_fp already verified). It parses the
// signed SEND leg, reads the source file (bounded), seals the plaintext to the
// recipient box key FROM THE SIGNED LEG (attesting with THIS gate's id key),
// and writes the opaque envelope to stdout. Plaintext never touches stdout, the
// audit string, or any log.
func handleXferSend(audit *gate.AuditLogger, innerCmd string) int {
	leg, err := xferwire.ParseSend(innerCmd) // anchored, injection-safe (P2)
	if err != nil {
		logf("xfer send: leg parse failed")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	idPath, err := xferIDKeyPath()
	if err != nil {
		logf("xfer send: locate id key")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}
	idKey, err := xfer.LoadIDKey(idPath) // 0o077-reject; missing ⇒ error
	if err != nil {
		logf("xfer send: id key unavailable")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}

	// Bounded read of the source file (never bare os.ReadFile — a huge file
	// must not exhaust gate memory). The +1 lets us detect an over-cap file.
	f, err := os.Open(leg.SrcPath)
	if err != nil {
		logf("xfer send: open source")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}
	plaintext, err := io.ReadAll(io.LimitReader(f, maxXferPlaintextBytes+1))
	_ = f.Close()
	// Best-effort scrub of the in-memory plaintext on every exit path after the
	// read — mirrors handleXferRecv's deferred scrub (defense-in-depth; Go GC
	// makes this non-guaranteeing, but it shrinks the window symmetrically).
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()
	if err != nil {
		logf("xfer send: read source")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}
	switch {
	case len(plaintext) == 0:
		logf("xfer send: empty source")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	case int64(len(plaintext)) > maxXferPlaintextBytes:
		logf("xfer send: source exceeds cap")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// Seal to the recipient box pub FROM THE SIGNED LEG, attest with THIS gate's
	// id key, bind xferID+destID from the signed leg (all crypto in P1).
	env, err := xfer.Seal(plaintext, leg.BoxPub, idKey.Private(), leg.XferID, leg.DestID)
	if err != nil {
		logf("xfer send: seal failed")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
	out, err := env.Marshal()
	if err != nil {
		logf("xfer send: marshal failed")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// Envelope (CIPHERTEXT) to stdout, verbatim, no trailing newline — the MCP
	// relays these exact bytes to the RECV leg's stdin. Gate logs go to stderr
	// only. The plaintext NEVER touches stdout (env.Marshal base64-encodes the
	// sealed bytes, so stdout is opaque ciphertext).
	if _, err := os.Stdout.Write(out); err != nil {
		logf("xfer send: write stdout")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}
	auditNoExec(audit, innerCmd, "write", "signed", exitOK)
	return exitOK
}

// handleXferRecv runs on gate B (Host=B_fp already verified). It reads the
// envelope from the gate's OWN stdin (bounded, BEFORE xfer.Unmarshal), opens it
// against THIS gate's box key while verifying the sender id + xferID/destID
// binding FROM THE SIGNED LEG, and atomically writes the recovered plaintext to
// the dest path. The plaintext goes ONLY to the dest file — never stdout (only
// a metadata marker), never the audit string — and its buffer is scrubbed after
// the write.
func handleXferRecv(audit *gate.AuditLogger, innerCmd string) int {
	leg, err := xferwire.ParseRecv(innerCmd)
	if err != nil {
		logf("xfer recv: leg parse failed")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// BOUNDED read of the envelope from the gate's OWN stdin, at the transport
	// boundary, BEFORE xfer.Unmarshal (the P1 carry-over). Mirrors update.go's
	// bounded stdin read. The +1 lets us detect an over-cap envelope.
	body, err := io.ReadAll(io.LimitReader(os.Stdin, maxXferEnvelopeBytes+1))
	if err != nil {
		logf("xfer recv: read stdin")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
	switch {
	case len(body) == 0:
		logf("xfer recv: empty envelope")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	case int64(len(body)) > maxXferEnvelopeBytes:
		logf("xfer recv: envelope exceeds cap")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	boxPath, err := xferBoxKeyPath()
	if err != nil {
		logf("xfer recv: locate box key")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}
	boxKey, err := xfer.LoadBoxKey(boxPath) // 0o077-reject; missing ⇒ error
	if err != nil {
		logf("xfer recv: box key unavailable")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}

	env, err := xfer.Unmarshal(body) // input now bounded
	if err != nil {
		logf("xfer recv: malformed envelope")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// Open: verify sender id pub FROM THE SIGNED LEG + xferID/destID binding +
	// AEAD + plaintext cap. Any failure ⇒ generic error, nothing written.
	plaintext, err := xfer.Open(env, boxKey.Public(), boxKey.Private(), leg.IDPub, leg.XferID, leg.DestID, maxXferPlaintextBytes)
	if err != nil {
		logf("xfer recv: open failed")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}
	// Best-effort scrub of the in-memory plaintext on EVERY exit path after a
	// successful Open — including the AtomicReplace-failure return below
	// (defense-in-depth; Go GC makes this non-guaranteeing, but it shrinks the
	// window). Deferred so no future early return can skip it.
	defer func() {
		for i := range plaintext {
			plaintext[i] = 0
		}
	}()

	mode64, err := strconv.ParseUint(leg.Mode, 8, 32) // leg.Mode is allowlisted ("0600")
	if err != nil {
		logf("xfer recv: bad mode")
		auditNoExec(audit, innerCmd, "write", "signed", exitDataErr)
		return exitDataErr
	}

	// Atomic plaintext write to the dest path with the leg's mode. Plaintext
	// goes ONLY to the dest file — never stdout, never the audit string.
	if err := gate.AtomicReplace(leg.DestPath, plaintext, os.FileMode(mode64)); err != nil {
		logf("xfer recv: write failed")
		auditNoExec(audit, innerCmd, "write", "signed", exitSoftware)
		return exitSoftware
	}
	nbytes := len(plaintext)

	auditNoExec(audit, innerCmd, "write", "signed", exitOK)
	// Status marker to stdout — metadata only (xferID is a random id; bytes is a
	// length, NOT the secret value). The MCP confirms xfer= matches.
	fmt.Printf("SSHGATE_XFER_RECEIVED xfer=%s bytes=%d\n", leg.XferID, nbytes)
	return exitOK
}
