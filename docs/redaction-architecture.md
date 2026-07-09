# SSHGate output redactor — unified architecture

> Integrates findings from [`secrets-redaction-research.md`](secrets-redaction-research.md). This is the durable design reference for the gate-side output redactor.

> **Changelog — 2026-07 default-deny widening (P1-B).** A production
> multi-server run showed real secrets passing raw (JSON/camelCase-named
> values, `*_API_HASH`/`*_SESSION`, Telegram bot tokens, fine-grained GitHub
> PATs, and unknown-named high-entropy values). `standard` now carries a
> **bounded generic default-deny net** — an O(n) linear pass
> (`scanGenericRuns`) emitting telegram-bot-token stitches and generic
> high-entropy runs behind a shared gate (3-class content + ssh-line veto +
> Shannon entropy ≥ 3.5, ≥ 32 chars) — plus a live `Rule.Entropy` gate on
> broad-prefix rules (`sk-<base62>`), a widened `sshgate-sensitive-assignment`
> rule, and new `sshgate-openai-broad` / `-github-fine-pat` / `-zoho-token`
> rules. A regex net was measured and rejected (+66–73%/MB vs ~+2% for the
> linear pass). See spec `docs/proposed/redaction-widening-2026-07.md`.

> **Implementation status (as of v1.3.0).** Shipped and live in the gate:
> **Layer 1** (named-format rules + the 2026-07 generic default-deny net), the
> PEM accumulator, per-session HMAC markers, and the signed **secret-reveal**
> bypass (`reveal=true` on `run`). Designed below but **not yet shipped**:
> Layer 2 (file-mode heuristic), Layer 3 (`redactlist`/`unredactlist`), the
> recursive decode pass, the `SSHGATE_CMD` wire-command namespace
> (`redact.*` / `unredact.*`), and the `thorough` mode (`standard` is the only
> live behaviour; there is no per-host mode config yet). `src/redact` carries
> scaffolding for the unshipped layers (e.g. `FormatFileMarker`) by design —
> see `src/redact/doc.go`.

## Summary

This document specifies the v1.2 output redactor inside the `gate` binary on every SSHGate-managed host. Bytes flow `child process stdout/stderr → redact.Writer → SSH pipe → MCP → agent`. The redactor runs three detection layers — Layer 1 named-format regex (built-in + vendored gitleaks rules + SSHGate-native rules), Layer 2 file-mode heuristic over the inbound command, Layer 3 operator-curated `redactlist.append-only` — plus a recursive base64/hex/URL decode pass. A sibling `unredactlist.append-only` file holds signed false-positive overrides for the heuristics.

There are exactly two modes: **`standard` (default)** and **`thorough`**. The earlier `fast` and `verified` modes are dropped; `fast`'s features fold into `standard`, and `verified` is parked as future work. Redaction markers carry no source/reason inline — operators retrieve provenance via a signed `redact.why <key>` command.

The honesty framing is sharper: redaction is **defense-in-depth, not a perimeter**. SSHGate's pattern + file-mode + redactlist layers catch a meaningful fraction of plausibly leaked secrets in typical workloads. The right long-term answer is kernel-level read enforcement (Linux Landlock), tracked for v1.2.1+.

## What changed from the prior proposal

| Topic | Prior proposal | Unified architecture | Driver |
|---|---|---|---|
| Detection modes | One | **Two** — `standard` (default), `thorough` | Locked. `fast` merged into `standard`; `verified` parked |
| Rule library | Imported from gitleaks at runtime | **Vendored** under `src/redact/rules/gitleaks/` + SSHGate-native rules under `src/redact/rules/sshgate/`; combined file is committed | Locked. Reviewable diffs, deterministic builds |
| Recursive decode | Not in design | base64/hex/URL views; depth 1 (`standard`), depth 3 (`thorough`) | Research §"Notable evasions" |
| Safe-prefix invariant | 256 bytes | 4 KiB + PEM-boundary special case | Research §"Streaming regex" |
| Layer 2 scope | Single-file `cat` only | **Registry of predicates** — multi-arg cat, pipelines whose first stage reads 0600, grep/head/tail/less/bat/nl/more, `<` redirects | Locked. Treat as rat race; structured for easy appends |
| Verification | Not in design | **Parked for future work** (TruffleHog-style) | Locked. v1.2 ships without it |
| Markers | `key=` + optional `via=` | `key=<8hex>` only; provenance via signed `redact.why` | Locked. No source info inline |
| Sign-requirement | Implicit | **Explicit matrix** — REDUCING redaction needs sign, INCREASING does not | Locked |
| Unredactlist | Single `unmask:` line type in redactlist | **Sibling `unredactlist.append-only`** with parallel signed semantics | Locked |
| Removal | Manual root + `chattr -a` | **Signed tombstone** appended to file; loader walks adds + tombstones | Locked. No manual chattr in normal ops |
| Wire-command envelope | Per-feature command names | **`SSHGATE_CMD:<sig>:<payload>`** JSON-envelope namespace; `revoke`/`update` migrate as aliases | Locked |
| Validation of new patterns | Not specified | **6-step auto-validation pipeline** before append | Locked |
| Provenance per entry | None | **Per-entry JSON metadata** — rule_id, kind, signed, session_fp, agent_hint, supersedes | Locked |
| Bulk-cleanup admin | None | **`redact.remove-by-session <session_fp>`** signed admin command | Locked |

## Industry alignment (retained)

The research synthesised four industry-consensus mechanisms. SSHGate continues to adopt each:

1. **Hybrid detection (regex + keyword + entropy/BPE)** — research §"Industry consensus", §Gitleaks. SSHGate ships regex + keyword pre-filter as the floor in `standard`. Entropy is gated to `thorough`.
2. **Streaming with overlap window** — research §"Streaming regex / buffer-boundary handling". Same chunk-N + tail-of-N-1 idiom as gitleaks PR #1760 (`StreamDetectReader`), `replacestream`, and `stream-snitch`.
3. **HMAC-SHA256 with per-session salt for stable IDs** — research §"Stable-identifier mapping". The Vault audit-log model is the industry default. SSHGate's `[SSHGATE_REDACTED key=<8hex>]` is exactly this, truncated to 32 bits.
4. **Defence in depth: redact before the LLM/agent sees the bytes** — research §"LLM/agent-context-window redaction". SSHGate enforces at the gate boundary on the remote host. Anthropic Claude Code issue #29434 explicitly punts in-context redaction to middleware.

## Architecture

### Where it lives

**Inside the gate binary on the remote host**, between the child process's stdout/stderr pipes and the SSH stream back to the MCP. Trust concentrates at the gate boundary — the MCP runs as the operator's user on the laptop and is bypassable by any alternate SSH client; the gate is the only place bytes physically exit Claude's reach.

Integration point: `src/gate/executor.go` lines 39–40 (`c.Stdout = os.Stdout; c.Stderr = os.Stderr`) become `c.Stdout = redact.NewWriter(os.Stdout, sessionKey, ruleset)` and similarly for stderr. `src/gate/cmd/sshgate-gate/main.go` plumbs the per-process session key (32 random bytes from `crypto/rand` at startup, never persisted) and the loaded ruleset into the executor. Because OpenSSH spawns a fresh `gate` process per command-with-forced-command, "per-process" is precisely "per-session" — no daemon state to manage, no cross-command key reuse.

**Rejected — MCP-side redaction.** Any path that lets the agent read SSH bytes pre-redaction (parallel `ssh` invocation, patched MCP binary, shell injection reading `/dev/pts/*`) defeats the redactor. Remote-side gate is the only choke point.

**Rejected — separate redactor process between gate and SSH.** Signal propagation, pipe-close handling, exit-code loss. Still rules it out.

### Detection modes — two only

- **`standard` (default)** — Layer 1 named-format regex (built-in + vendored gitleaks + SSHGate-native) + the **bounded generic default-deny net** (2026-07: an O(n) linear pass emitting telegram-bot-token stitches and generic high-entropy runs ≥ 32 chars that clear a 3-class + ssh-line-veto + entropy ≥ 3.5 gate — the same gate broad-prefix rules opt into via `Rule.Entropy`) + Layer 2 file-mode heuristic + Layer 3 redactlist + recursive decode pass to depth 1. No API verification. This is the "common case works out of the box" envelope.
- **`thorough`** — `standard` + **looser generic gates** (1-/2-class candidates and lower length/entropy floors than the standard net's 3-class ≥ 32 ≥ 3.5) + the *unguarded* gitleaks entropy rules + recursive decode to depth 3. Higher false-positive rate; appropriate for one-off audits or hosts where over-redaction is preferable.

Because there is no `fast` fallback, **`standard` is optimised aggressively**: tight loops, no allocations in the hot path, benchmark with `go test -bench`, profile with `pprof`. The performance budget is the same as the prior `fast` mode's was — `standard` must hit it.

Mode is set per host at install time and stored in `~/.sshgate-gate/config` (a tiny JSON file, schema-versioned per daemon guideline 5.5). Changing the mode requires a **signed** `SSHGATE_CMD:<sig>:{"cmd":"redact.mode","args":{"mode":"thorough"}}` envelope. Mode-change is recorded in the redactlist append-only log.

### Rule library — vendored, not imported

The redactor uses **no runtime import of gitleaks**. The relevant rules are extracted from the upstream gitleaks TOML and vendored as Go source under `src/redact/rules/`.

Layout:

```
src/redact/rules/
├── gen.go                 # go:generate hook
├── rules_combined.go      # generated; committed to repo; the gate compiles this in
├── gitleaks/
│   ├── PROVENANCE.md      # upstream sha + date + curation notes
│   └── rules.go           # // pulled from github.com/gitleaks/gitleaks@<sha> on 2026-05-19;
│                          # // to update, diff against upstream and merge selected rules
└── sshgate/
    └── rules.go           # SSHGate-native named-format rules; our floor
```

Rule struct (single struct shared across both source dirs):

```go
type Rule struct {
    ID           string
    Description  string
    Regex        *regexp.Regexp
    Keywords     []string  // cheap substring pre-filter
    SecretGroup  int       // which regex group is the secret (for entropy gating)
    Entropy      float64   // shared-gate threshold (bits/byte); >0 = live in standard, 0 = ungated
    MinLen, MaxLen int
}
```

`go generate ./src/redact/rules/...` reads every source dir and emits a single `rules_combined.go`. **The combined file is committed** so PR reviewers see the final, in-binary ruleset. The gate binary compiles `rules_combined.go` directly; no runtime file I/O for rule loading.

The SSHGate-native list is **our floor** — we add named-format patterns there that gitleaks doesn't cover. This list will grow as we discover new leak patterns in real workloads.

**Re-pulling from gitleaks upstream is a manual workflow**: diff against the upstream sha recorded in `PROVENANCE.md`, review proposed rule additions one at a time, append to `gitleaks/rules.go`, regenerate, commit. There is no automated upstream sync.

### Layer 1 — named-format pattern matching

Compiled into the gate binary at build time via the combined-rule generator above.

Scope (the `standard`-mode ruleset):

- Provider-issued tokens with structural prefixes: AWS access/secret/session, GitHub PAT (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`), GitLab tokens (`glpat-`, `glptt-`), Stripe (`sk_live_`, `pk_live_`, `rk_live_`), Slack (`xox[bpa]-`), JWT (`eyJ...`), Google OAuth (`ya29.`), Azure (`AccountKey=`), Twilio (`SK`), SendGrid (`SG.`), Twitter (`AAAA...`), Square (`sq0atp-`).
- Generic structural formats: PEM blocks (`-----BEGIN .* PRIVATE KEY-----`), SSH keys, certificate-with-secret bundles.
- Keyword-anchored bearer tokens: `Authorization: Bearer <token>`, `token=...`, `password=...` — keyword-anchored. Free-floating high-entropy runs are **also** caught as of 2026-07, but only through the bounded generic net (3-class + ssh-line veto + entropy ≥ 3.5, ≥ 32 chars — see Conflict resolution step 3), never by unguarded entropy on an arbitrary capture group.

Explicitly **excluded from `standard`**: gitleaks's `Generic API Key` / `Hashicorp Token` heuristics and any rule that redacts on Shannon entropy **without the three-guard gate** (3-class + ssh-line veto + ≥ 3.5). The bounded, gated net shipped 2026-07 after a live missed-secret report; the *unguarded* entropy rules still reappear only in `thorough`.

### Layer 2 — file-mode heuristic (registry of predicates)

This remains SSHGate's own innovation. Research §"File-mode-based heuristics" surveyed no prior art.

**Top-of-file comment names the pattern this is fighting and links to a v1.2.1 issue tracker. Treat as rat race; new bypasses get new predicates.**

Mechanism: a registry of predicates, each implementing one bypass-class. The parser first tokenises the inbound command argv; on any shell metacharacter (`$`, backtick, `;`, `>`, `&`, `*`, `?`, `~`, `(`, `)`, `{`, `}`) the heuristic **bails out to Layer 1 only** — we do not parse shell.

```go
type ParsedCmd struct {
    Argv     []string
    Pipeline [][]string   // each stage's argv; len==1 for non-pipelines
    Redirects []Redirect  // `<` redirects
}

type SensitiveFileMatch struct {
    Path   string
    Mode   uint32
    SHA256 [8]byte  // truncated
    Reason string   // which predicate fired
}

var predicates = []func(cmd ParsedCmd) []SensitiveFileMatch{
    catSingleFile,           // cat <one-file>
    catMultiFile,            // cat file1 file2 file3 — per-file checks
    pipelineFirstStageReads, // cat /etc/shadow | head -1, tail -f /etc/shadow | grep root
    readerOverFile,          // grep/head/tail/less/bat/nl/more <file>
    inputRedirect,           // command < /etc/shadow
}
```

Required predicates for v1.2 (the floor):

1. **`catSingleFile`** — `cat <one-file>`, mode `& 0o077 == 0` → whole-file redaction marker.
2. **`catMultiFile`** — `cat file1 file2 file3`, per-file mode check; one marker per 0600 file in the argv.
3. **`pipelineFirstStageReads`** — pipelines where the first stage reads a 0600 file: `cat /etc/shadow | head -1`, `tail -f /etc/shadow | grep root`. Whole-output redaction.
4. **`readerOverFile`** — `grep`, `head`, `tail`, `less`, `bat`, `nl`, `more` over a 0600 file as a positional arg. Whole-output redaction.
5. **`inputRedirect`** — `command < /etc/shadow`, `read x < /etc/shadow`-style. Whole-output redaction.

Each match consults `unredactlist.append-only` for a matching `unmask:` entry; if found, the heuristic mark is suppressed for this command only (it does not delete the rule from the predicate registry).

**Known unhandled bypasses** (documented honestly — file-mode is not a perimeter):

- 0644 config files with embedded secrets (e.g. `/etc/nginx/sites-enabled/foo` with a DB password). File mode says "world-readable, treat as non-sensitive." Layer 1 + Layer 3 must catch.
- Complex shell patterns: command substitution (`$(cat /etc/shadow)`), backtick reads, eval-wrapped reads. The metacharacter-guard bails out by design.
- Network-mediated reads: `curl file:///etc/shadow`, `nc -l < /etc/shadow`, anything that reads the file via a non-argv-positional path.
- Tools we haven't enumerated yet: `xxd`, `od`, `hexdump`, `strings`, `awk -f` over the file, `sed -n p` reads, `python -c "open('/etc/shadow').read()"`.
- File-mode-clean files reachable via `sudo cat /etc/shadow` where the SSH user happens to have NOPASSWD sudo.

Each new bypass discovered in production gets a new predicate appended to the registry. This is the rat race; we lose ground until kernel-level read enforcement (Landlock) lands.

### Layer 3 — operator redactlist + unredactlist

Two sibling files under `~/.sshgate-gate/`:

- **`redactlist.append-only`** — positive entries (redact more). Line types: `pattern:`, `anchor:` (HMAC of literal), `file:` (whole-file).
- **`unredactlist.append-only`** — negative entries (redact less; override heuristics). Line types: `pattern:`, `anchor:`, `file:`, `unmask:` (a file-mode-heuristic override; was previously a single line type inside redactlist).

Both files use the same signed-line format with parallel semantics. `chattr +a` best-effort; signed-only enforcement is the fallback when `chattr` is unsupported. Loader validates each sig with the master pubkey gate already loads (`src/gate/keystore.go`). Failed sigs → reject load, fail closed → all reads downgrade to opaque whole-output markers as a safety degraded mode (symmetric mirror of `src/gate/verify.go`).

Soft cap: **500 entries** per file with a warning at 250 — HMAC-per-anchor cost on streaming output is real. Beyond 500 the install warns and refuses new anchors (patterns and files have no cap).

### Recursive decode pass

Research §"Notable evasions" lists base64/hex/URL-encoded secrets as the #1 evasion vector across all surveyed tools.

Mechanism: before running Layer 1 regexes, the scanner produces 1–3 decoded *views* of the current window:

- **Plaintext** (always).
- **Base64-decoded segments** — any contiguous run of `[A-Za-z0-9+/]{20,}={0,2}` and the URL-safe variant `[A-Za-z0-9_-]{20,}={0,2}`; if the decoded bytes are >75% printable ASCII, scan them.
- **Hex-decoded segments** — runs of `[0-9a-fA-F]{32,}` with even length, decoded.
- **URL-decoded** — any `%[0-9a-fA-F]{2}` triples expanded inline.

Depth: `standard` mode does 1 level, `thorough` does 3.

A match in a decoded view causes redaction of the **original encoded substring** in the output — the agent sees `[SSHGATE_REDACTED key=abc12345]` where the base64 blob was, not the decoded plaintext. The decoder produces `(decoded_view, byte_range_in_original)` tuples per decoded segment; matches map back via the recorded range.

### PEM-boundary detection

Research §"Streaming regex / buffer-boundary handling" calls out PEM-encoded private keys (~1600 bytes for RSA 2048, up to 3400+ for RSA 4096) as the longest plausible single secret.

Two complementary mitigations:

1. **Boundary-aware special case**: when the scanner sees a literal `-----BEGIN ` prefix, it switches into "PEM accumulate" mode — buffers verbatim until it sees the matching `-----END .*-----\n`, then redacts the entire span. Abort at 8 KiB if END doesn't appear (false BEGIN).
2. **Default safe-prefix raised to 4 KiB** (from 256 bytes), ring buffer 8 KiB initial, 64 KiB cap.

## Conflict resolution

Order of operations on each chunk. Layers run sequentially; each layer's marks are subject to the unredactlist filter at its own step.

1. **Layer 1 named regex** (built-in + sshgate-native + gitleaks-vendored). Matches are **sticky** — only a signed `redact.remove` of that rule can un-stick. Unredactlist entries do NOT cancel Layer 1 named hits.
2. **Layer 2 file-mode heuristic.** Check unredactlist for matching `unmask:` entries on the file path; remove matching marks.
3. **Layer 1 entropy + generic default-deny net** (`Rule.Entropy`-gated rules and the linear `scanGenericRuns` pass — live in `standard` as of 2026-07; `thorough` only adds looser gates). Check unredactlist patterns/anchors; remove matching marks.
4. **Recursive decode pass.** Check unredactlist; remove matching marks.
5. **Layer 3 redactlist** (user-curated patterns / anchors / files). Sticky — only signed `redact.remove` un-sticks.
6. **Emit remaining flagged spans as redactions.**

**Net effect**: named-format hits and user-curated redactlist hits are immutable except via signed removal. Heuristic hits (file-mode, entropy, decode pass) are overridable via signed unredact entries.

### Bias toward over-redaction is intentional

The first few sessions per server will have approval churn — the operator will be approving unredact entries for false positives on heuristic-driven hits. Each unredact entry is sticky (signed, append-only).

This is an acceptable trade. The alternative is leaking secrets. The operator-facing UX flow is designed around this expectation; the install banner and README say so plainly.

## Marker format

- **Inline match**: `[SSHGATE_REDACTED key=<8hex>]`
- **Whole-file**: `[SSHGATE_REDACTED_FILE path=<p> mode=<oct> sha256=<8hex>]`

`key` is the first 32 bits of `HMAC-SHA256(per-session-32-byte-salt, matched-bytes)`. Same secret in the same session → same key. New session → fresh salt → different key for the same secret. No reversibility, no cross-session linkability.

`sha256` on the file marker is over the *file contents* (truncated to 8 hex chars), so the agent can recognise "same file as before" across reads within the session without learning what's in it.

**No `via=` field. No source/reason inline.** Provenance is exposed ONLY via the signed `redact.why <key>` command. This is a deliberate departure from the prior proposal's `via=` debug field — leaking "rule X fired" tells the agent which rule to study and craft evasions against.

HMAC key per session: 32 random bytes from `crypto/rand`, never persisted, one per gate-process-invocation. Because OpenSSH spawns a fresh gate per forced-command, per-process == per-session.

## Wire-command architecture

The gate accepts two command-envelope namespaces.

### `SSHGATE_SIG:<sig>:<payload> <shell-cmd>` — unchanged from v1

Existing v1 signed shell command execution. Untouched.

### `SSHGATE_CMD:<sig>:<payload>` — new in v1.2

Meta-commands. Payload is JSON:

```json
{
  "cmd": "redact.add" | "redact.remove" | "redact.mode" | "redact.why" | "redact.list" |
         "redact.remove-by-session" |
         "unredact.add" | "unredact.remove" |
         "revoke" | "update" | "service-probe",
  "args": { ... }
}
```

Sig is present for signed ops, absent for unsigned (envelope becomes `SSHGATE_CMD::<payload>` — sig field empty). The gate dispatches on `cmd`.

`SSHGATE_REVOKE` and `SSHGATE_UPDATE` (v1.0) become aliases for `SSHGATE_CMD:<sig>:{"cmd":"revoke"}` and `{"cmd":"update"}` respectively. **Both old and new forms are accepted for one release** to preserve backwards compatibility; the old forms log a deprecation warning.

### Sign-requirement matrix

The principle: **REDUCING redaction needs sign; INCREASING does not.**

| Command | Signed? | Why |
|---|---|---|
| `redact.add` | unsigned | More redaction = safe. Audit-logged for rogue-agent forensics. |
| `redact.remove` | **signed** | Reduces redaction. |
| `unredact.add` | **signed** | Reveals data — most dangerous direction. |
| `unredact.remove` | unsigned | Re-enables redaction. |
| `redact.mode` (standard ↔ thorough) | **signed** | Changes coverage. |
| `redact.why <key>` | **signed** | Leaks source info. |
| `redact.list` | **signed** | Enumerates rules. |
| `redact.remove-by-session <session_fp>` | **signed** | Rogue-agent cleanup; bulk reduction of redaction. |
| `revoke` | **signed** | Already v1. |
| `update` | **signed** | Already stubbed. |
| `service-probe` | unsigned | Read-only. |

Even unsigned ops are recorded in the per-file append-only log with full provenance (see "Per-entry provenance metadata" below) so a rogue agent's bulk `redact.add` spam is forensically traceable.

## Auto-validation of new patterns

Every `redact.add pattern=...` and `unredact.add pattern=...` runs the following checks **in order before append**. Any failure → reject with error returned to caller AND audit-log entry.

1. **Length ≤ 256 chars.**
2. **`regexp.Compile`** (RE2 — no catastrophic backtracking is structurally possible in Go, but pathologically large patterns can still compile slowly).
3. **Compile-time wall-clock budget: 50 ms.**
4. **Runtime torture test**: execute the freshly-compiled regex against a 16 KB fixed synthetic torture corpus (mixed ASCII, base64, hex, UUIDs, common log noise); wall-clock budget **100 ms**. The corpus bytes live in `testdata/torture-corpus.txt` and ship in the gate binary as an embedded resource.
5. **Over-broad check**: run against three benign strings — `"hello world"`, `"the quick brown fox"`, `"abc123"`. Reject if the pattern matches any in full, OR matches more than 50% of the torture corpus.
6. **Empty-match check**: reject if `re.MatchString("")` is true.

A failed validation never appends to the file. The caller (signer / Telegram-approval UI) receives a structured error citing the failed check; the gate also writes an audit-log entry with the rejected pattern and the failure reason for forensic review.

## Removal via signed tombstones

`redact.remove <rule-id>` (signed) appends a tombstone entry to the same file. The loader walks adds + tombstones in file order; tombstones supersede prior adds by `rule_id`. The loader returns the net set after applying all tombstones.

**No manual `chattr -a` in normal operations.** The append-only-file invariant holds because tombstones are also appends. Manual root access is required only if the file itself becomes corrupted (a daemon-level recovery scenario, not part of redaction UX).

## Per-entry provenance metadata

Every append (positive add, negative add, or tombstone) carries:

```json
{
  "rule_id":    "ab12cd34",
  "kind":       "pattern" | "anchor" | "file" | "unmask" | "tombstone",
  "value":      "...",
  "added_at":   "2026-05-19T14:23:01Z",
  "added_via":  "redact.add" | "unredact.add" | "redact.remove" | "unredact.remove" | "redact.remove-by-session",
  "signed":     true | false,
  "session_fp": "8hex",
  "agent_hint": "claude-mcp v0.1.0",
  "supersedes": "ab12cd34"
}
```

- `rule_id` is deterministic at append time: `hex(sha256({cmd, args, added_at, nonce}))[:8]`. Tombstones reference the superseded `rule_id` in `supersedes`.
- `session_fp` is derived from the SSH session of the originating connection (short hash of session ID + key fingerprint). It is **not** a stable identity across sessions, but is stable within one session — enough to bulk-clean a rogue agent's adds.
- `agent_hint` is best-effort metadata supplied by the MCP-side caller. Don't trust it for security decisions; do log it for forensics.
- `signed` records whether the original envelope carried a signature. Unsigned adds (`redact.add`, `unredact.remove`) are still authenticated as having come through the gate's stdin (which is reachable only via the signed-forced-command channel) — but they did not require an explicit Telegram tap. The audit log preserves this distinction.

The `unmask:` line type (an entry in `unredactlist.append-only`) uses `kind: "unmask"` and `value: <path>`.

### `redact.remove-by-session <session_fp>`

A signed admin command. The gate iterates the redactlist + unredactlist, finds every entry with the matching `session_fp`, and appends a tombstone for each. One Telegram tap cleans up a rogue agent's bulk additions.

## Operator-facing UX

### At install time

Provisioning a host with the `sshgate` CLI (`sshgate add <alias> <user@host>`) does the existing setup, then:

1. Runs `gate --service-probe` (read-only, classified as read by `classify`).
2. Shows the detected services + mode selector:

   ```
   On host prod-db, I detected these services:
     - nginx     → redact /etc/nginx/* (mode-sensitive)
     - postgres  → redact /etc/postgresql/*/pg_hba.conf, ~postgres/.pgpass

   Choose redaction mode (default: standard):
     standard  = regex + file-mode + redactlist + 1-level decode  [default]
     thorough  = standard + entropy + 3-level recursive decode (higher FPR)
   ```

3. On confirm, bulk-signs all proposed `redact.add` entries plus a single `redact.mode` command. One Telegram tap approves all.
4. Prints the honesty banner:

   ```
   Redaction is defense-in-depth, NOT a perimeter. The model is assumed not
   rogue. A truly hostile LLM can bypass this. SSHGate's pattern + file-mode +
   redactlist layers catch ~50%+ of plausibly leaked secrets in typical
   workloads; we add rules as new bypasses are reported. The right long-term
   answer is kernel-level read-enforcement (Linux Landlock — planned for
   v1.2.1+).

   Expect approval churn in the first few sessions per host: heuristic-driven
   false positives surface as Telegram prompts to add unredact entries. Each
   entry is signed and append-only — biased toward over-redaction by design.
   ```

### During use

- **Redacted inline match** → `[SSHGATE_REDACTED key=abc12345]`. Same secret in the same session → same key. New session → fresh salt → different key.
- **Redacted file** → `[SSHGATE_REDACTED_FILE path=/etc/ssh/ssh_host_ed25519_key mode=0600 sha256=def67890]`.
- **stderr is treated identically to stdout.** Both streams pass through their own `redact.Writer`.
- **The agent never sees pre-redaction bytes.** No debug mode, no `--no-redact` flag, no environment override. A signed `redact.why <key>` is the only way to learn what a marker references — and it returns only the *source* (which rule/anchor fired, with provenance metadata), never the plaintext.
- **Cross-session correlation is intentionally lost.** If the operator needs the audit log out-of-band, the master key path is the only route.

### Adding a new positive pattern (more redaction)

1. Agent (or the operator) drafts a regex.
2. MCP issues `sshgate.add_redact_pattern(server, pattern)` → wraps as **unsigned** `SSHGATE_CMD::{"cmd":"redact.add","args":{"kind":"pattern","value":"..."}}`.
3. Gate runs the 6-step auto-validation pipeline.
4. On pass: gate appends the entry with full provenance metadata to `redactlist.append-only` and returns success.
5. On fail: gate returns the structured error and writes an audit-log entry.

Note: `redact.add` is **unsigned** because more redaction is safe. No Telegram tap required. The audit log is the forensic backstop if an agent goes rogue and floods the redactlist.

### Adding an unredact entry (less redaction; false-positive recovery)

1. Agent encounters `[SSHGATE_REDACTED key=...]` on a value the operator confirms is benign.
2. MCP issues `sshgate.add_unredact_pattern(server, pattern|anchor|file|unmask)` → wraps as **signed** `SSHGATE_CMD:<sig>:{"cmd":"unredact.add","args":{...}}`.
3. The operator gets a Telegram DM:

   ```
   Unredact (reveal) on prod-db?
     kind:     unmask
     value:    /var/log/myapp/access.log
     proposer: claude (session 7f3a...)
     context:  saw [SSHGATE_REDACTED_FILE path=/var/log/myapp/access.log ...]
               in `tail -n 50` and confirmed it is access logs, not secrets
   [Approve] [Deny]
   ```

4. On approve → signed → SSH → gate validates → appends to `unredactlist.append-only`.

### Removing a positive pattern (signed)

`redact.remove <rule-id>` issues a signed tombstone. Telegram approval required. The tombstone is appended; the loader treats the original entry as superseded on next load (gate process restart, which happens per session anyway).

### Bulk cleanup after a rogue agent

`redact.remove-by-session <session_fp>` (signed) — one Telegram tap appends tombstones for every entry from that session_fp.

### Mode change

`redact.mode <standard|thorough>` (signed). Recorded in the redactlist append-only log.

### Looking up what a marker meant

`redact.why <key>` (signed). Returns the source rule, line type, and provenance metadata for the marker. Never returns plaintext.

## Threat model

**In-scope threats**:

1. **Accidental secret exfiltration via read commands.** Agent runs `cat /etc/myapp/config.yml`, file contains `db_password: hunter2`, agent's context now holds plaintext.
2. **Pattern-bypass via encoding.** k8s `kubectl get secret -o yaml`, Docker env JSON, JWT payload. Mitigated by recursive decode.
3. **Pattern-bypass via chunk boundary.** PEM keys or long tokens straddling 4 KiB reads. Mitigated by safe-prefix + PEM accumulator.
4. **Pattern-bypass via custom-format secrets.** `MYCO_v3_<32hex>`. Mitigated by Layer 3 redactlist + the "flag unredacted credentials" skill prompt.
5. **Pattern-bypass via mode-mismatch.** A 0644 config file with embedded secret. Layer 1 + Layer 3 are the catch.
6. **Rogue-agent flooding the redactlist with broad patterns to break workflows.** Mitigated by 6-step auto-validation, audit log, and `redact.remove-by-session` admin command.

**Explicitly out-of-scope**:

1. **Malicious gate binary.** Same trust boundary as signed-write verification.
2. **Compromised MCP / laptop / operator.** The signer key is uncompromised by assumption.
3. **Side-channel exfiltration via timing or output structure.** A 4096-byte response → PEM-RSA-2048 length inference. Not defended.
4. **Cross-session correlation via the redacted output text.** 32-bit HMAC collides at scale. Intentional.
5. **A truly hostile LLM that crafts evasions.** Bypass is structurally possible. The honesty banner says so.

## Limitations to document honestly

Surfaced in the README, install banner, and skill.

1. **Detection has substantial false-positive surface on log-shaped content in `thorough` mode.** Independent benchmarks put gitleaks-class rules at ~46% precision on broad corpora; SSHGate's named-only `standard` mode improves on that but does not eliminate it. Use per-host `unmask:` and unredact entries.
2. **Multi-line secrets can straddle buffer boundaries.** 4 KiB safe-prefix + PEM accumulator + 64 KiB ring cap. A 6 KB+ non-PEM secret (rare) could in theory split.
3. **The file-mode heuristic has no published prior art.** It is a SSHGate-original mechanism. The predicate registry will grow; the "Known unhandled bypasses" list above is the honest floor.
4. **The recursive decode pass is not yet shipped** (designed depth: 1 in `standard`, 3 in `thorough`). Today an encoded secret is caught only when the encoded run itself trips a named rule or the generic high-entropy net; even once shipped, a secret wrapped beyond the depth limit will not be caught.
5. **Per-session HMAC key never persists.** The redactor cannot recover plaintext for debugging. `redact.why` returns source rule, not plaintext.
6. **The gate binary is the trust anchor.** A compromised gate (replaced via non-SSHGate channel) defeats redaction.
7. **No prior benchmark exists for streaming scanners on command output specifically.** Real-world FPR/FNR on `journalctl`, `env`, `docker inspect` is unknown until shipped and measured.
8. **Custom-format secrets are invisible to defaults.** Add via `redact.add pattern=`.
9. **Removing a pattern requires a signed envelope.** Intentional friction.
10. **ReDoS is mitigated but not impossible.** Go's `regexp` is RE2 (no backreferences, no catastrophic backtracking by design). The 6-step validation pipeline catches the bulk of bad regexes. A per-chunk wall-clock budget (default 50 ms) is a v1.2.1 backlog item.
11. **The honest framing — rat race**: redaction is defense-in-depth, not a perimeter. The model is assumed not rogue. The right long-term answer is kernel-level read enforcement (Linux Landlock), tracked under "Future work" below.
12. **A public-PEM body is scanned named-only — a non-named high-entropy secret smuggled inside a valid-looking certificate armor is NOT redacted (accepted risk).** To keep `cat server.crt` intact, a *completed* PEM block whose BEGIN label is a public type (`CERTIFICATE`, public keys, CSRs — the `pemPublicTypes` allowlist) is routed through the **named-only** scan (`scanNamedAndEmit` → `findNamedMatches`), which deliberately skips the generic high-entropy net. Named secrets embedded in that body (AWS keys, PATs, `password=` lines) still redact; **only** an arbitrary, unnamed high-entropy blob wrapped under a public BEGIN label passes through verbatim. The same bytes raw (no armor) *would* be caught by the generic `scanGenericRuns` net, so the cert armor genuinely narrows the default-deny mandate for this one shape. This is a deliberate tradeoff, not a defect: private-key blocks and unrecognized BEGIN labels still fail closed (whole-block redaction), the case requires a secret pre-wrapped in a *public* label (not a natural accidental-leak shape), and the content redactor is defense-in-depth (item 11), not a boundary against an adversarial child — which could evade any content filter trivially. Optional V1.1 hardening (out of scope for V1): DER-decode the allowlisted block and confirm it actually parses as a certificate/public-key/CSR before trusting the BEGIN label; unparseable ⇒ redact wholesale (fail closed).

## Implementation plan

Sequenced tasks; each maps to a feature branch + PR.

### R1 — Streaming scrubber with vendored rules and PEM-aware safe-prefix

Files: `src/redact/{scanner,writer,markers}.go` + tests; modify `src/gate/executor.go`.

- Vendor gitleaks named-format rules into `src/redact/rules/gitleaks/`.
- SSHGate-native rules in `src/redact/rules/sshgate/`.
- `go generate` produces `src/redact/rules/rules_combined.go`; committed.
- PEM-boundary special-case handling.
- Safe-prefix invariant 4 KiB; ring buffer 8 KiB initial, 64 KiB cap.
- Mode dispatch (`standard`/`thorough`); only `standard` paths implemented in R1.
- HMAC key per session; marker emission with no `via=`.

LOC ~600 production + ~750 test.

### R2 — Append-only redactlist + unredactlist + wire-command envelope

Files: `src/redact/{store,validate,envelope}.go` + tests.

- `redactlist.append-only` and `unredactlist.append-only` with parallel signed semantics.
- 6-step auto-validation pipeline.
- Tombstone-based removal + loader walking adds + tombstones.
- Per-entry JSON provenance metadata.
- `SSHGATE_CMD:<sig>:<payload>` envelope namespace; dispatch by `cmd`.
- Backwards-compat alias for `SSHGATE_REVOKE` and `SSHGATE_UPDATE`.

LOC ~500 + ~650 test.

### R3 — File-mode heuristic with predicate registry

Files: `src/redact/filemode/{parse,predicates}.go` + tests.

- Five required predicates: `catSingleFile`, `catMultiFile`, `pipelineFirstStageReads`, `readerOverFile`, `inputRedirect`.
- Shell-metacharacter guard → bail to Layer 1.
- Consults `unredactlist` `unmask:` entries.

LOC ~300 + ~450 test.

### R4 — Recursive decode pass

Files: `src/redact/decode.go` + tests.

- `decode.Views(buf, depth)` returning `[]{Bytes, OrigRange}`.
- base64, base64-url, hex, URL-percent decoders.
- Match-in-decoded-view → redact original encoded substring.

LOC ~300 + ~400 test. Benchmark-gated — must not regress per-chunk throughput on a 100 MB `journalctl` dump by more than 30% in `standard` mode.

### R5 — Wire commands (the meta-command set)

Files: `src/gate/cmd/sshgate-gate/cmds_redact.go` + tests.

- `redact.add`, `redact.remove`, `redact.mode`, `redact.why`, `redact.list`, `redact.remove-by-session`.
- `unredact.add`, `unredact.remove`.
- Sign-requirement enforced per the matrix.
- Audit log for every command (signed or not).

LOC ~400 + ~500 test.

### R6 — First-run UX (service probe + mode selection + honesty banner)

Files: MCP-side provisioning flow + signer-side bulk-approval UI.

LOC ~280 + ~280 test.

### R7 — E2E + golden fixtures + benchmarks

Files: `testdata/redact/`, `testdata/torture-corpus.txt`, e2e harness extensions.

- Per-rule golden tests.
- Buffer-boundary tests with deliberately small chunk sizes.
- Decode-pass tests including nested base64-of-base64.
- File-mode tests with temp files (0600/0644/0640) across all predicates.
- Tombstone-walk tests.
- Auto-validation pipeline tests.
- `httptest.NewServer` mocks — though no verifiers ship in v1.2, the harness is in place.
- Benchmark suite via `go test -bench` over 100 MB synthetic log corpus; track per-chunk allocation count, per-chunk wall-clock, p99 latency. Gate the benchmark in CI with a max-allowed regression of 30% vs the prior commit.

LOC ~250 + ~40 fixture files.

**Total: ~2,400 LOC production + ~3,200 LOC test ≈ 5,600 LOC.** 9–12 day project.

## Rollout and migration

1. **v1.2.0 ships with `standard` as the default** for both fresh installs and upgrades. There is no `fast` mode to inherit; aggressive optimisation in `standard` should make it acceptable as the universal default.
2. **`SSHGATE_UPDATE`** (shipped in v1.3.0 as the signed `update_gate` verb — orthogonal to redaction) is the deployment vehicle. Operators can roll back to a previous binary by signing an `SSHGATE_UPDATE` to it (the approval banner's hash cross-check makes a downgrade an explicit, deliberate act).
3. **Backwards compatibility of the redactlist/unredactlist files**: a v1.2 gate refuses to start if either file exists with a schema version it doesn't recognise (daemon guideline 5.5). For v1.2.0 the schema is "v1".
4. **There is no opt-out flag.** If an operator wants no redaction, they uninstall the v1.2 binary and roll back. Vault's anti-`log_raw` discipline drives this — a redaction-off flag inevitably ships to production by mistake.
5. **Backwards-compat for `SSHGATE_REVOKE` / `SSHGATE_UPDATE`**: both old wire forms accepted for one release alongside the `SSHGATE_CMD:` envelope; deprecation warning logged.

## Testing strategy

1. **Per-rule golden tests** under `testdata/redact/` — one fixture per built-in rule, each with a positive instance and a negative-but-plausible instance (UUID, hash). Table-driven Go tests.
2. **Buffer-boundary tests** — feed inputs through the writer with chunk sizes 8, 16, 32, 256 bytes and verify safe-prefix invariant. PEM-block-spanning-boundaries fixture (3 KB key delivered as 16-byte writes).
3. **Decode-pass tests** — base64-wrapped AWS key, hex-wrapped GitHub PAT, URL-encoded `?token=ghp_...`, nested base64-of-base64 (depth 2). Verify original encoded substring is what gets redacted.
4. **Mode-dispatch tests** — same fixture through `standard` and `thorough`.
5. **File-mode tests** — temp files with 0600/0644/0640 modes; every predicate (single-arg cat, multi-arg cat, pipeline-first-stage, reader-over-file, input-redirect); shell-metacharacter bail-out.
6. **Predicate registry tests** — adding a new predicate must not regress existing ones; predicates run in registry order; first match wins per file path.
7. **Redactlist + unredactlist signature tests** — append signed and tampered lines, assert fail-closed on tampered.
8. **Tombstone walk tests** — verify loader applies adds + tombstones in file order; verify `redact.remove-by-session` produces correct tombstone set.
9. **Auto-validation pipeline tests** — every reject path: length, compile-budget, runtime-budget, over-broad, empty-match.
10. **Wire-envelope tests** — `SSHGATE_CMD::<payload>` (unsigned), `SSHGATE_CMD:<sig>:<payload>` (signed), backwards-compat aliases for revoke/update.
11. **End-to-end** — Dockerised openssh-server, deploy gate, copy fixture file containing a secret, run `cat fixture` over SSHGate, assert the marker appears. Same harness as existing phase-5 e2e tests.
12. **Benchmark suite** — `go test -bench` over 100 MB synthetic log corpus; per-chunk allocation count, per-chunk wall-clock, p99 latency.

## Future work / deferred items

Captured here so a later contributor can pick each up with full context.

1. **`verified` mode (TruffleHog-style API verification).** Design intent: for the rules that support it (AWS STS `GetCallerIdentity`, GitHub `/user`, Slack `auth.test`, Stripe charges-list-with-limit-0), do a live API confirmation on candidate matches; on any verifier failure (timeout, non-200, network), **redact anyway** (fail safe — inverts TruffleHog's default of "silently drop on rate-limit"). Per-rule 2-second timeout, plain `http.Client` with explicit timeouts, no `DefaultClient` per daemon guideline 11.1, no retries on 401/403 per daemon guideline 11.5, per-host 10 req/sec rate limit, per-session in-memory cache. Recall regression (~25 points per research §TruffleHog) is intentional — `verified` is for audit workflows where the operator manually reviews. **Not shipped in v1.2.**

2. **BPE token-efficiency scoring (Betterleaks).** Research §Betterleaks reports 98.6% recall vs 70.4% entropy-only on CredData (F1 0.8922 best-config). Tokenizer-library dependency (cl100k_base, several MB embedded) and per-token cost in the hot path are the trade. Benchmark in v1.2.1.

3. **Linux Landlock kernel-level read enforcement.** The proper long-term answer to the rat race. Today's gate is best-effort byte-level filtering after read; Landlock prevents the read from happening at all. Requires per-command sandbox setup; non-trivial integration with the executor; needs a Linux kernel 5.13+ floor. Schedule alongside v1.2.1+.

4. **Cross-session HMAC-key recovery for legitimate audit needs.** Per-session keys are non-persistent by design, which means even legitimate audit needs can't reverse-correlate redacted spans across sessions. A signed admin command that derives a deterministic per-host audit key (separate from the per-session key) and writes audit-only logs under a master-key-only-readable path could unlock this without breaking the threat model. Defer.

5. **`redact.list` UI/CLI on the operator side.** A signed-read of the full ruleset, with pagination, filtering by `kind` / `signed` / `session_fp` / `added_at`. The wire command is part of the unshipped `SSHGATE_CMD` namespace (see status note at top); the operator-side UX (a MCP tool plus a Telegram-rendered list view) is deferred with it.

6. **Open empirical questions**:
   - Real-world FPR/FNR on command output (no public benchmark exists for streaming scanners on `journalctl`, `env`, `docker inspect`, `kubectl describe` outputs). SSHGate will be the first publishable measurement once shipped. Plan to collect anonymised aggregate stats (count of redactions per mode per host) via the existing telemetry channel — never the redacted plaintext itself.
   - Performance under `thorough` mode with entropy enabled on 10 GB+ `journalctl --no-pager` dumps. May warrant a runtime auto-downgrade ("output exceeds 100 MB → drop to standard for this command only"); deferred to avoid v1.2 scope creep.
   - HMAC redaction's effect on agent reasoning quality (does Claude debug effectively when secrets are HMAC tokens?). Empirical question only real operator usage answers.
   - Whether to expose the redactlist as a Claude tool (`sshgate.list_redact_patterns`). Risk: agent learns patterns by name and crafts evasions. Defer to v1.2.1 user feedback.
   - Per-chunk wall-clock budget (default 50 ms; configurable) as a ReDoS safety net for pathological regexes that pass auto-validation but degrade on adversarial input.
   - Whether to expose the redactlist as machine-readable audit output (SARIF, CycloneDX) for enterprise consumers.
