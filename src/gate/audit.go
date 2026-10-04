package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// ── Tier 6a: gate-side authoritative audit log ──────────────────────────
//
// This is the tamper-resistant record that matters. It is written BY THE
// GATE, on the target host, for every command the gate sees (reads,
// writes, and rejections). The agent can never reach it: the agent only
// ever speaks THROUGH the gate, so it cannot rewrite or delete what the
// gate logs about it.
//
// STATELESSNESS: this is a pure SIDE EFFECT. The gate never READS this
// log to make a decision — it only appends. open→append→fsync→close per
// invocation (a fresh gate process is spawned per SSH_ORIGINAL_COMMAND,
// so "per invocation" == "per command"). The gate stays a pure
// (payload, command) → (allow/deny, exec) function.
//
// FAIL-OPEN: a logging failure must NEVER block the command. The audit
// is a side effect, not a gate. Record swallows all errors after a
// best-effort attempt (it cannot even log them — the gate's only log
// sink is stderr, which is the SSH stream; writing there would corrupt
// the command's own output). This is a deliberate, documented choice:
// we would rather lose an audit line than fail a command because the
// audit disk filled up.
//
// TAMPER-RESISTANCE POSTURE (documented, NOT automated here):
//   - The log is opened append-only (O_APPEND|O_CREATE|O_WRONLY) + fsync.
//   - The PATH is configurable (see AuditPath) so an admin can point it
//     at a directory owned by a SEPARATE user with an append-only
//     attribute (`chattr +a`), so the gate's run-as user can append but
//     not rewrite or delete. TRUE tamper-resistance requires that
//     root-time setup (a dedicated `sshgate-audit` user owning the dir);
//     SSHGate does NOT automate that provisioning. Absent it, the gate
//     degrades to gate-user-owned best-effort append-only — defense in
//     depth, not perfection (a full host compromise can still nuke the
//     folder; "if they're in, the logs are the least of our problems").
//
// CONFIG-CHANGE PROTECTION: the level (audit-level) and path
// (audit-path) config files live in the GATE DIR (~/.sshgate-gate/).
// Changing them via a gate command is itself a WRITE — it must be signed
// and human-approved — and an admin with box access edits them directly.
// The agent therefore cannot silently quiet its own audit.

// AuditLevel selects which records the gate-side log emits and whether
// raw output is captured. Defined low→high so a simple >= comparison
// answers "does this level emit at least writes?".
type AuditLevel int

const (
	// AuditOff logs nothing.
	AuditOff AuditLevel = iota
	// AuditWrites logs write commands only (rejections always logged
	// from this level up).
	AuditWrites
	// AuditAll logs reads + writes (+ rejections).
	AuditAll
	// AuditAllMeta logs all commands + rejections + output metadata
	// (bytes/lines/duration/exit), but NO raw output. This is the
	// DEFAULT.
	AuditAllMeta
	// AuditAllFull logs everything, including raw output (verbose).
	AuditAllFull
)

// DefaultAuditLevel is what the gate uses when the audit-level config
// file is absent or unreadable — it fails to the safe, informative
// default rather than going dark or crashing.
const DefaultAuditLevel = AuditAllMeta

func (l AuditLevel) String() string {
	switch l {
	case AuditOff:
		return "off"
	case AuditWrites:
		return "writes"
	case AuditAll:
		return "all"
	case AuditAllMeta:
		return "all+meta"
	case AuditAllFull:
		return "all+full"
	default:
		return "all+meta"
	}
}

// ParseAuditLevel parses a level token. Unknown, empty, or malformed
// input returns DefaultAuditLevel — the gate NEVER crashes on a bad
// config; it falls to the safe default. Parsing is case-insensitive and
// trims surrounding whitespace.
func ParseAuditLevel(s string) AuditLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off":
		return AuditOff
	case "writes":
		return AuditWrites
	case "all":
		return AuditAll
	case "all+meta":
		return AuditAllMeta
	case "all+full":
		return AuditAllFull
	default:
		return DefaultAuditLevel
	}
}

// auditLevelFile / auditPathFile are the config file names inside the
// gate dir. They are deliberately separate small files (not a parsed
// config blob) so an admin can `echo writes > ~/.sshgate-gate/audit-level`
// by hand, and so a malformed one fails to its own default without
// affecting the other.
const (
	auditLevelFile   = "audit-level"
	auditPathFile    = "audit-path"
	defaultAuditFile = "audit.log"
)

// LoadAuditLevel reads gateDir/audit-level and parses it. A missing or
// unreadable file yields DefaultAuditLevel (fail to default, never
// crash). The level config lives in the gate dir on purpose — changing
// it is a privileged, out-of-band action, not something the agent can do
// through a tool (see the config-change protection note above).
func LoadAuditLevel(gateDir string) AuditLevel {
	b, err := os.ReadFile(filepath.Join(gateDir, auditLevelFile))
	if err != nil {
		return DefaultAuditLevel
	}
	return ParseAuditLevel(string(b))
}

// AuditPath returns the gate-side audit log path. If gateDir/audit-path
// exists and names a non-empty path, that path is used (so an admin can
// redirect the log to a separate-user-owned, append-only location for
// real tamper-resistance). Otherwise it defaults to
// gateDir/audit.log. The override file is read once per invocation; like
// the level it lives in the gate dir and is human/owner-edited only.
func AuditPath(gateDir string) string {
	if b, err := os.ReadFile(filepath.Join(gateDir, auditPathFile)); err == nil {
		if p := strings.TrimSpace(string(b)); p != "" {
			return p
		}
	}
	return filepath.Join(gateDir, defaultAuditFile)
}

// AuditMeta is the output metadata captured for a command (no raw
// output). It is populated from ExecResult on the exec paths and left
// nil for rejections that never ran a child.
type AuditMeta struct {
	StdoutBytes int64 `json:"stdout_bytes"`
	StderrBytes int64 `json:"stderr_bytes"`
	Lines       int64 `json:"lines"`
	DurationMS  int64 `json:"duration_ms"`
}

// AuditRecord is one gate-side authoritative log line. The shape is flat
// and string-y so a plain `grep` over the file stays useful without JSON
// tooling, mirroring the signer's audit format (src/signer/audit.go).
//
// Stdout/Stderr hold raw output and are ONLY serialised at AuditAllFull —
// the json tags carry omitempty AND the logger blanks them below
// AuditAllFull, so `all+meta` provably cannot leak raw output (belt and
// braces).
type AuditRecord struct {
	// TS is the UTC epoch seconds at which the gate processed the command.
	TS int64 `json:"ts"`
	// Command is the literal inner command the gate dispatched (the
	// signed/verified command on the signed path; the raw command on the
	// unsigned read path). This is metadata about WHAT ran, not its
	// output — always logged from AuditWrites up.
	Command string `json:"command"`
	// Classification is "read" or "write" (the classifier's verdict).
	Classification string `json:"classification"`
	// ApprovalStatus records the authorisation that let (or would have let)
	// the command run:
	//   "signed"   — a verified signature accompanied the command (writes,
	//                and reveal reads).
	//   "unsigned" — an unsigned read (Tier-1 or signed-server read path).
	//   "denied"   — the gate refused the command (see ExitCode for why:
	//                77 = missing sig / read-only, 65 = bad/expired sig).
	//
	// NOTE (F4): the gate cannot and MUST NOT distinguish a standing-grant
	// auto-sign from a real-time human Telegram tap — both arrive as a
	// byte-identical "signed" signature by design (the gate is stateless and
	// never learns grants exist). The human-vs-grant "auth_mode" lives only in
	// the signer audit (src/signer/audit.go) and the MCP live-log
	// (src/mcp/livelog), never here.
	ApprovalStatus string `json:"approval_status"`
	// ExitCode is the gate's exit code for the command (the child's code,
	// or the deny code on a rejection).
	ExitCode int `json:"exit_code"`
	// CleanupError records post-execution cleanup failure; ExitCode stays unchanged.
	CleanupError string `json:"cleanup_error,omitempty"`
	// Meta is output metadata (bytes/lines/duration). nil for rejections
	// that never executed a child.
	Meta *AuditMeta `json:"meta,omitempty"`
	// Revealed is true when the command ran as a SECRET-REVEAL (its output
	// bypassed the gate redactor). The audit log is accountability, NOT a
	// secret store: a revealed command is recorded with revealed:true and full
	// metadata, but its raw output is NEVER captured (the gate does not even
	// buffer it — see execAndAudit), so Stdout/Stderr stay empty here even at
	// all+full. Reveal's accepted exposure is the agent + transcript + approval
	// chat, not this on-disk record.
	Revealed bool `json:"revealed,omitempty"`
	// Rung is the kernel-confinement tier a READ ran under: "full" | "landlock"
	// | "unconfined" | "lane2" (the shell-free daemon-read allowlist). Empty
	// (omitted) on records that ran no read child — denials, admin verbs and
	// signed writes — so those records are unchanged.
	Rung string `json:"rung,omitempty"`
	// Stdout/Stderr hold raw output, serialised ONLY at AuditAllFull — and
	// never for a revealed command (see Revealed).
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

// AuditLogger is the gate-side authoritative logger. It is configured
// with a level and a path; Record applies the leveling policy and, for
// records that pass, appends one JSON line (open→append→fsync→close).
//
// It holds NO open file handle between Record calls — a fresh gate
// process is spawned per command, so a per-Record open/close keeps the
// gate stateless and the log append-only without a long-lived FD. The
// zero value is not usable; call NewAuditLogger.
type AuditLogger struct {
	level AuditLevel
	path  string
}

// NewAuditLogger returns a logger for the given level and path. Pass the
// values resolved via LoadAuditLevel(gateDir) and AuditPath(gateDir).
func NewAuditLogger(level AuditLevel, path string) *AuditLogger {
	return &AuditLogger{level: level, path: path}
}

// Level reports the logger's configured level (for the gate to decide
// whether to bother gathering raw output before calling Record).
func (a *AuditLogger) Level() AuditLevel { return a.level }

// shouldEmit applies the leveling policy to a record.
//
//   - off    → nothing.
//   - writes → write commands + any rejection (ApprovalStatus=="denied").
//   - all+   → everything.
//
// Rejections are always logged from AuditWrites up (a denied read is
// still a security-relevant event the operator wants to see).
func (a *AuditLogger) shouldEmit(r AuditRecord) bool {
	switch a.level {
	case AuditOff:
		return false
	case AuditWrites:
		return r.Classification == "write" || r.ApprovalStatus == "denied"
	default: // AuditAll, AuditAllMeta, AuditAllFull
		return true
	}
}

// Record applies the leveling policy and, if the record passes, appends
// it as one JSON line. ALL errors are swallowed (fail-open): the audit
// is a side effect, never a gate, and the gate has no safe out-of-band
// error sink (stderr is the SSH stream). A record that does not pass the
// level is silently dropped.
//
// Below AuditAllFull, raw Stdout/Stderr are blanked before marshaling so
// `all+meta` cannot leak raw output even if a caller populated them.
func (a *AuditLogger) Record(r AuditRecord) {
	if a == nil || !a.shouldEmit(r) {
		return
	}
	// Strip metadata below AuditAllMeta (writes/all carry the command +
	// classification + exit + approval, but not output metrics).
	if a.level < AuditAllMeta {
		r.Meta = nil
	}
	// Strip raw output below AuditAllFull — belt-and-braces against a raw
	// leak at any lower level.
	if a.level < AuditAllFull {
		r.Stdout = ""
		r.Stderr = ""
	}

	b, err := json.Marshal(r)
	if err != nil {
		return // fail-open
	}
	b = append(b, '\n')

	// Append-only + fsync for tamper-resistance / durability. Mode 0600:
	// owner-only. The log carries command text always and raw output at
	// all+full, so it must not be group- or world-readable. Open failures
	// (e.g. an append-only dir the gate user truly cannot write, or a full
	// disk) are swallowed.
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return // fail-open
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return // fail-open
	}
	_ = f.Sync() // best-effort durability; ignore (fail-open)
}
