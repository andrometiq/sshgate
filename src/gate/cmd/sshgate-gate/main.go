// Command gate is the remote-side gate of SSHGate. OpenSSH invokes
// it through a forced `command="~/.sshgate-gate/gate"` entry on the
// SSHGate dedicated key; the forwarded command from the client arrives
// in $SSH_ORIGINAL_COMMAND.
//
// Exit codes (BSD sysexits where applicable):
//
//	0  — success (also: empty SSH_ORIGINAL_COMMAND, the post-install
//	     verification probe, prints SSHGATE_OK; the unsigned SSHGATE_VERSION
//	     probe, prints the running gate's build revision; and a completed
//	     SSHGATE_UPDATE, prints SSHGATE_UPDATED)
//	1  — generic runtime failure or non-zero from /bin/sh -c on the
//	     non-pass-through paths
//	65 — EX_DATAERR: bad signature, bad envelope format, expired sig,
//	     validity window too long; also a SSHGATE_UPDATE refusal (malformed
//	     hash, empty/oversized/undersized stdin, hash mismatch, or a
//	     non-ELF/wrong-arch binary — nothing is written)
//	70 — EX_SOFTWARE: pubkey file unreadable, corrupt, or has insecure
//	     mode; also a SSHGATE_UPDATE filesystem/replace failure (old gate
//	     left intact)
//	77 — EX_NOPERM: write command without a verified SSHGATE_SIG prefix
//
// Exit codes from the executed inner command are passed through
// directly (so /bin/sh -c 'exit 42' makes gate exit 42).
//
// Stdio discipline: gate's own log lines go to stderr only,
// prefixed with "gate: ". Stdout is reserved for the executed
// inner command's stdout. The post-install probe is the one
// exception — it prints exactly "SSHGATE_OK" to stdout because the
// installer reads that line over SSH to confirm the gate is alive.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/karthikeyan5/sshgate/src/classify"
	"github.com/karthikeyan5/sshgate/src/gate"
	"github.com/karthikeyan5/sshgate/src/hostkey"
	"github.com/karthikeyan5/sshgate/src/redact"
	redactrules "github.com/karthikeyan5/sshgate/src/redact/rules"
	"github.com/karthikeyan5/sshgate/src/sigwire"
)

// sessionSalt is the per-process 32 random bytes the redactor uses to
// derive HMAC marker keys. Populated by run() at startup, never
// persisted, never transmitted. Per-process equals per-session because
// OpenSSH spawns a fresh gate for every SSH_ORIGINAL_COMMAND
// invocation. Stored at package scope so execChild can read it without
// threading it through every call site.
var sessionSalt [32]byte

// redactRules, when non-nil, is a test-injected redaction ruleset.
// Production leaves it nil and compiles the real v1.2 ruleset
// (redactrules.Combined() — sshgate-native + gitleaks-vendored)
// LAZILY in execChild: only the execute path needs it, so a per-command
// gate spawn that denies a write, fails signature verification, or
// answers the install probe never pays the ~1 MB regex-compile cost.
// Kept out of init() (daemon guideline 1.6) so test imports don't pay
// it either.
var redactRules []redact.Rule

// Exit codes (BSD sysexits subset).
const (
	exitOK        = 0
	exitGeneric   = 1
	exitDataErr   = 65 // EX_DATAERR
	exitSoftware  = 70 // EX_SOFTWARE
	exitNoPermVal = 77 // EX_NOPERM
)

func main() {
	os.Exit(run())
}

// run is the testable entry point; main exits on its return value.
func run() int {
	// Per-process redactor state: fresh 32-byte salt + compiled-in
	// ruleset. Failures here are fatal — we cannot serve traffic
	// without a fresh salt for HMAC marker keys.
	if _, err := rand.Read(sessionSalt[:]); err != nil {
		logf("crypto/rand: %v", err)
		return exitSoftware
	}

	raw := os.Getenv("SSH_ORIGINAL_COMMAND")
	if raw == "" {
		// Post-install probe. Stdout only (the installer reads this).
		// The probe is gate machinery, not a command the operator ran, so
		// it is intentionally NOT audited.
		fmt.Println("SSHGATE_OK")
		return exitOK
	}

	if raw == "SSHGATE_VERSION" {
		// Unsigned build-identity probe: report THIS running gate's build
		// revision so the MCP can tell which gate is on a box and confirm a
		// prior SSHGATE_UPDATE took effect. Version info only, no secrets and
		// no filesystem/exec — treated like the empty-cmd probe (not audited,
		// works on both tiers). Recognised BEFORE the pubkey load so a Tier-1
		// read-only gate can answer it too.
		fmt.Println(runningGateVersion())
		return exitOK
	}

	// Tier 6a — resolve the gate-side authoritative audit logger from the
	// gate dir. The level/path config files live there (owner/admin-edited
	// only; the agent cannot reach them), and resolution NEVER fails the
	// gate: a missing/unreadable config falls to the default (all+meta /
	// gateDir/audit.log). When the gate dir cannot be resolved at all
	// (os.Executable failure), we degrade to a nil logger — auditing is a
	// side effect, never a gate, so the command still runs.
	audit := newAuditLogger()

	// Locate gate.pub alongside the binary.
	pubPath, err := pubKeyPath()
	if err != nil {
		logf("locate pubkey: %v", err)
		return exitSoftware
	}
	pubkey, err := gate.LoadPubKey(pubPath)
	if err != nil {
		logf("load pubkey: %v", err)
		return exitSoftware
	}

	// Decide whether the inbound line is signed.
	signed := sigwire.IsSigned(raw)

	// Tier-1 read-only mode: pubkey is nil when gate.pub is absent.
	// Reads still execute (no signature check required); writes and
	// signed commands are denied — there is no anchor to verify them
	// against, and silently exec'ing them would be a privilege
	// escalation against the operator's expectation that "no signer
	// means no writes."
	if pubkey == nil {
		if signed {
			logf("no signing key configured; signed commands cannot be verified")
			// A signed command on a read-only host is a denial: classify it
			// as a write (it was elevated) so it is logged from `writes` up.
			auditNoExec(audit, raw, "write", "denied", exitNoPermVal)
			return exitNoPermVal
		}
		kind := classify.Classify(raw)
		if kind == classify.KindRead {
			// Tier-1 read-only: unsigned read, never revealed.
			return execAndAudit(audit, raw, "read", "unsigned", false)
		}
		// KindWrite or KindUnknown (empty/whitespace already handled
		// upstream — anything else unknown falls through as write).
		logf("no signing key configured (read-only install — re-run /sshgate:setup to add a signer)")
		auditNoExec(audit, raw, "write", "denied", exitNoPermVal)
		return exitNoPermVal
	}

	innerCmd := raw
	// reveal is the verified SECRET-REVEAL capability. It can ONLY become true
	// on the signed path below, from the authenticated payload — the unsigned
	// read path leaves it false, so a read is never revealed (it is redacted
	// like any other output). The agent cannot set this; only a human approval
	// turned into a signature can.
	reveal := false
	if signed {
		// Self-derive THIS gate's host-key fingerprints so VerifySigned can
		// enforce the per-server binding: a signature approved for server X
		// must name X's pinned host key, so it cannot be replayed on server Y.
		// Reading the world-readable static /etc/ssh/ssh_host_*.pub files at
		// process start is identity, not decision state — the gate stays
		// stateless. An empty set fails closed inside VerifySigned
		// (ErrHostMismatch), which is the correct outcome when the gate cannot
		// identify itself; we surface a clearer error here when the glob itself
		// errored.
		selfHostFPs, herr := hostKeyFPsFn()
		if herr != nil {
			logf("derive host-key fingerprints: %v", herr)
			return exitSoftware
		}
		ic, rev, err := gate.VerifySigned(raw, pubkey, time.Now(), selfHostFPs)
		if err != nil {
			logf("%v", err)
			// A signature that failed to verify (bad/expired/wrong-host) is a
			// denial. We log the OUTER raw line (the verified inner command is
			// not trustworthy here) and classify it as a write — it carried a
			// SIG prefix, so it was an elevation attempt — so it is recorded
			// from `writes` up.
			auditNoExec(audit, raw, "write", "denied", exitDataErr)
			return exitDataErr
		}
		innerCmd = ic
		reveal = rev
	}

	// Administrative commands. Only valid when signed.
	if signed {
		if innerCmd == "SSHGATE_REVOKE" {
			// A verified admin verb runs no /bin/sh child, so there is no
			// output metadata — record it as a signed write with the actual
			// exit code. doRevoke owns the teardown + its own exit code.
			rc := doRevoke()
			auditNoExec(audit, innerCmd, "write", "signed", rc)
			return rc
		}
		if strings.HasPrefix(innerCmd, "SSHGATE_UPDATE ") {
			// Signed in-place gate self-update. The verified inner cmd commits
			// to the SHA-256 of the new binary; handleUpdate reads the bytes
			// from the gate's OWN stdin, refuses on any hash mismatch, and
			// atomically replaces this binary. It ALWAYS returns — never falls
			// through to classify/exec.
			return handleUpdate(audit, innerCmd)
		}
	}

	kind := classify.Classify(innerCmd)
	switch kind {
	case classify.KindRead:
		// A signed READ may carry reveal=true (e.g. `cat secret.env`
		// approved as a reveal): the verified flag flows through. An
		// UNSIGNED read can never reach here (reveal stays false above).
		status := "unsigned"
		if signed {
			status = "signed"
		}
		return execAndAudit(audit, innerCmd, "read", status, reveal)
	case classify.KindWrite, classify.KindUnknown:
		// Fail-safe: unknown is treated as write (classify.Classify
		// already returns KindWrite for the truly-unknown cases; an
		// empty/whitespace cmd is the only KindUnknown that can reach
		// here, and we treat that as denied too).
		if !signed {
			logf("write commands require a SSHGATE_SIG prefix")
			auditNoExec(audit, innerCmd, "write", "denied", exitNoPermVal)
			return exitNoPermVal
		}
		return execAndAudit(audit, innerCmd, "write", "signed", reveal)
	default:
		logf("unexpected classification: %v", kind)
		auditNoExec(audit, innerCmd, "write", "denied", exitGeneric)
		return exitGeneric
	}
}

// execChild runs cmd under a signal-aware context. SIGTERM/SIGINT
// received by gate are propagated to the child process group via
// the context cancellation wired through Exec. The child's
// stdout/stderr are wrapped in redact.Writer instances so every byte
// the child emits passes Layer-1 redaction (v1.2 R1) — UNLESS reveal is
// true, the signed SECRET-REVEAL path, where the verified payload
// authorised raw (un-redacted) output. reveal can only be true on the
// signed path (see run()); it is never set for an unsigned read.
//
// It returns the gate exit code AND the ExecResult (output metadata) so
// the caller can feed the Tier-6a audit log. captureLimit (>0 only at the
// audit all+full level) makes the executor tee a capped copy of the
// output into the result. On an exec start-failure (exit<0) the gate exit
// code is normalised to exitGeneric (1).
func execChild(cmd string, reveal bool, captureLimit int) (int, gate.ExecResult) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	// Resolve the redaction ruleset lazily via auditRules() — only this
	// execute path (and the command-string audit redaction) needs it; a
	// deny/verify-fail/probe path that never reaches here pays nothing.
	rules := auditRules()
	res, err := gate.ExecWithRedaction(ctx, cmd, gate.ExecOpts{
		SessionSalt:  sessionSalt,
		Rules:        rules,
		Reveal:       reveal,
		CaptureLimit: captureLimit,
	})
	if err != nil {
		logf("%v", err)
	}
	if res.ExitCode < 0 {
		return exitGeneric, res
	}
	return res.ExitCode, res
}

// auditRulesOnce + cachedAuditRules MEMOIZE the production ruleset compile so
// redactrules.Combined() (the ~1 MB regex compile) runs at most ONCE per gate
// process. This is distinct from the redactRules test-injection seam: when
// that seam is nil (production) the two consumers of auditRules() within one
// gate invocation — output redaction (execChild) and command-string redaction
// (redactAuditCommand) — would otherwise each trigger a fresh Combined(),
// paying the compile twice per executed write. The cache collapses them to one.
var (
	auditRulesOnce   sync.Once
	cachedAuditRules []redact.Rule
)

// auditRules resolves the redaction ruleset the gate scrubs with. It is the
// single compile point shared by output redaction (execChild) and
// command-string redaction (redactAuditCommand): a test may inject the
// redactRules package-var seam (the explicit override — returned verbatim,
// uncached), otherwise the real v1.2 ruleset (redactrules.Combined() —
// sshgate-native + gitleaks-vendored) is compiled ONCE via auditRulesOnce and
// cached for the rest of the process. Compiling lazily keeps the
// deny/verify-fail/probe paths free of the ~1 MB regex-compile cost, and the
// once-cache guarantees the two consumers within a single executed write share
// ONE compile rather than triggering it twice.
func auditRules() []redact.Rule {
	if redactRules != nil {
		return redactRules
	}
	auditRulesOnce.Do(func() {
		cachedAuditRules = redactrules.Combined()
	})
	return cachedAuditRules
}

// redactAuditCommand scrubs a command string about to be persisted to the
// Tier-6a audit log, reusing the gate's per-process sessionSalt + the same
// ruleset used for output redaction. It is FAIL-OPEN: if RedactString
// reports an internal error, the raw command is logged rather than the audit
// line being dropped — observability of "what ran" must never be blocked by
// the redactor. A benign command (no secret pattern) is returned unchanged.
func redactAuditCommand(cmd string) string {
	red, ok := redact.RedactString(cmd, sessionSalt, auditRules())
	if !ok {
		return cmd
	}
	return red
}

// auditFullCaptureLimit bounds the per-stream bytes the gate buffers for
// the all+full audit level. 256 KiB is generous for a captured command
// transcript while keeping a runaway command from ballooning gate memory;
// beyond it the record carries a truncation marker.
const auditFullCaptureLimit = 256 * 1024

// newAuditLogger builds the Tier-6a gate-side authoritative logger from
// the gate dir. Level + path come from the gate-dir config files
// (audit-level / audit-path), each failing to a safe default. If the
// gate dir itself cannot be resolved (os.Executable failure), it returns
// nil — auditing is a side effect, never a gate, so a nil logger simply
// means "no audit this invocation" and the command still runs. A nil
// *gate.AuditLogger.Record is a documented no-op.
func newAuditLogger() *gate.AuditLogger {
	gateDir, _, err := gateDirFn()
	if err != nil {
		// Cannot locate the gate dir → no audit, but never block the gate.
		return nil
	}
	return gate.NewAuditLogger(gate.LoadAuditLevel(gateDir), gate.AuditPath(gateDir))
}

// execAndAudit runs cmd, records ONE Tier-6a audit line with output
// metadata (and raw output only at all+full), and returns the gate exit
// code. It is the single exec+audit chokepoint for reads and signed
// writes. The audit write is fail-open inside Record — a logging failure
// never affects the returned exit code.
func execAndAudit(audit *gate.AuditLogger, cmd, classification, approval string, reveal bool) int {
	// Only buffer output when the audit level actually wants raw output
	// (all+full). At every other level captureLimit stays 0 and the
	// executor streams without buffering — zero added cost on the hot path.
	//
	// REVEAL EXCLUSION: a SECRET-REVEAL bypasses the redactor, so the child's
	// output is the RAW secret. The audit log is accountability, not a secret
	// store, and reveal's threat model never accepted persisting the secret to
	// disk. So we DON'T EVEN CAPTURE it: captureLimit stays 0 for a revealed
	// command regardless of level, meaning the raw secret is never buffered in
	// the gate in the first place (defence in depth — there is nothing to
	// accidentally serialise). The record still gets full metadata + revealed:true.
	captureLimit := 0
	if audit != nil && audit.Level() >= gate.AuditAllFull && !reveal {
		captureLimit = auditFullCaptureLimit
	}
	rc, res := execChild(cmd, reveal, captureLimit)
	audit.Record(gate.AuditRecord{
		TS: time.Now().UTC().Unix(),
		// Redact a secret embedded in the command STRING before persisting it
		// to the system-of-record. The redactor already scrubs output; the
		// command string is the symmetric at-rest sink (F5). Fail-open.
		Command:        redactAuditCommand(cmd),
		Classification: classification,
		ApprovalStatus: approval,
		ExitCode:       rc,
		Meta: &gate.AuditMeta{
			StdoutBytes: res.StdoutBytes,
			StderrBytes: res.StderrBytes,
			Lines:       res.Lines,
			DurationMS:  res.Duration.Milliseconds(),
		},
		// Revealed marks a SECRET-REVEAL so the record shows revealed:true with
		// metadata but no output — accountability without storing the secret.
		Revealed: reveal,
		// res.Stdout/Stderr are populated ONLY when captureLimit>0, i.e. at
		// all+full AND not a reveal. For a reveal captureLimit is 0 (above), so
		// these are empty — the raw secret is never even buffered, let alone
		// persisted. AuditLogger.Record additionally blanks them below all+full,
		// so all+meta provably cannot leak raw output either.
		Stdout: res.Stdout,
		Stderr: res.Stderr,
	})
	return rc
}

// auditNoExec records a Tier-6a line for a command that ran NO /bin/sh
// child: a rejection (approval="denied", exit is the deny code) or a
// signed admin verb handled internally (approval="signed"). Meta is nil
// because there is no output metadata. The write is fail-open.
func auditNoExec(audit *gate.AuditLogger, cmd, classification, approval string, exit int) {
	audit.Record(gate.AuditRecord{
		TS: time.Now().UTC().Unix(),
		// Redact a secret embedded in the command string even on the no-exec
		// (denial / admin-verb) path — a denied command can still carry a
		// secret in its text (F5). Fail-open.
		Command:        redactAuditCommand(cmd),
		Classification: classification,
		ApprovalStatus: approval,
		ExitCode:       exit,
		Meta:           nil,
	})
}

// gateDirFn resolves the gate install directory and the absolute path
// to the running gate binary inside it. It is a package-level var so
// in-package tests can point the resolution at a t.TempDir without
// re-exec'ing the test binary; production code always uses
// defaultGateDir, which derives both from os.Executable(). This is NOT
// driven by any environment variable on purpose — letting the
// environment redirect where gate.pub is read would be a signature
// forgery surface, since gate.pub is the trust anchor for every
// verified command.
var gateDirFn = defaultGateDir

// homeDirFn resolves the operator's home directory. Same test-seam
// rationale as gateDirFn; defaults to os.UserHomeDir.
var homeDirFn = os.UserHomeDir

// hostKeyFPsFn returns THIS gate's own SSH host-key fingerprints, used to
// enforce the per-server host-key binding on the signed-write path. It is a
// package-level var so in-package tests can inject a controlled set without an
// /etc/ssh on the test box; production reads the real host keys from
// hostkey.DefaultHostKeyGlob (/etc/ssh/ssh_host_*.pub). Like gateDirFn this is
// deliberately NOT driven by any environment variable: letting the environment
// redirect which host keys the gate trusts would be a binding-forgery surface.
var hostKeyFPsFn = hostkey.LoadHostFingerprints

// defaultGateDir returns the directory holding the gate binary and the
// binary's own absolute path, both derived from os.Executable().
func defaultGateDir() (gateDir, binaryPath string, err error) {
	exe, err := os.Executable()
	if err != nil {
		return "", "", fmt.Errorf("os.Executable: %w", err)
	}
	return filepath.Dir(exe), exe, nil
}

// pubKeyPath returns the path to gate.pub, expected to live in the
// same directory as the gate binary itself.
func pubKeyPath() (string, error) {
	dir, _, err := gateDirFn()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "gate.pub"), nil
}

// doRevoke performs the on-host teardown half of a revoke. It locates
// the gate install directory relative to os.Executable() (so the
// SSHGate dedicated key, which is the only one routed here, controls
// exactly its own line in authorized_keys), runs gate.Revoke, and
// prints a single SSHGATE_REVOKED status line to stdout on success.
// The MCP side detects that prefix as confirmation.
//
// Exit codes:
//
//	0  — revoke succeeded (lines may or may not have matched; both are
//	     legitimate, the dir is gone either way)
//	1  — could not resolve paths or rewrite authorized_keys
func doRevoke() int {
	gateDir, binaryPath, err := gateDirFn()
	if err != nil {
		logf("revoke: %v", err)
		return exitGeneric
	}

	home, err := homeDirFn()
	if err != nil {
		logf("revoke: home dir: %v", err)
		return exitGeneric
	}

	res, err := gate.Revoke(home, gateDir, binaryPath)
	if err != nil {
		logf("revoke: %v", err)
		return exitGeneric
	}
	fmt.Println(gate.FormatRevokeStdout(res))
	return exitOK
}

// logf writes a single line to stderr with the "gate: " prefix.
// Errors from the write are intentionally ignored — there is no
// recovery path for "could not write to stderr."
func logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	// Unwrap-friendly sentinels render through %v as expected. Keep
	// only one final newline.
	msg = strings.TrimRight(msg, "\n")
	fmt.Fprintf(os.Stderr, "gate: %s\n", msg)
}
