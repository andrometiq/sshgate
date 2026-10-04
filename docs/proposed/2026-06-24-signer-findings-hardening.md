# Signer/MCP hardening: six findings from a multi-server test run

> **Status: BUILT** (merged 2026-06-24, before the first versioned release line; part of the
> v0.1.3 baseline and every later version). This file is the design record for fixes F1–F6.
> Where the code lives today:
> `src/sigwire/protocol.go` (`ProtoVersion`), `src/sigwire/timeouts.go` (`ResponseWriteGrace`),
> `pkg/signerkit/socket.go` and `pkg/signerkit/daemon.go` (the signer daemon: write-grace,
> request-id echo, `list_grants` kind), `src/mcp/sign/client.go` and `src/mcp/sign/grant_client.go`
> (`ErrVerdictUnknown`, request-id handling), `src/mcp/tools/list_grants.go`,
> `src/redact/scrub.go` (`RedactString`), `src/signer/backend/telegram.go` (redacted approval
> messages). File names below that predate the move of the daemon into `pkg/signerkit/` refer to
> the same code there.

A multi-server test run on 2026-06-23 surfaced six findings (F1–F6). Each was checked against the
code. This record keeps the confirmed verdicts and the design decisions.

## The unifying root cause

The multi-hour difficulty diagnosing the 2026-06-23 failure traces to **one thing**: the daemon emits error
responses with an **empty `request_id`** (`respondError(conn, "", …)`), which the MCP client masked as
an opaque `request_id "" != r_…`. Two fixes kill that masking at both ends:
- **F3** — the client surfaces `resp.Error` when `request_id==""` (already done for `Sign`; mirror to
  the grant client).
- **F6** — the daemon **echoes the request_id from the lenient peek**, so even a malformed/version
  error carries a correlatable id instead of `""`.

## Key invariants every fix respects

- **The gate stays STATELESS.** New state lives in the signer daemon. The gate never learns about
  grants; an auto-signed grant signature is **byte-identical** to a human-approved one by design.
- **No change to the signed payload (`sigwire.SigPayload`).** All protocol evolution rides the
  **MCP↔signer Unix-socket RPC** (gate-invisible), never the gate-bound signature. So no deployed
  gate is affected by any fix here.
- **`omitempty` preserves legacy wire shape** (the discipline already used for `Host`/`Reveal`).
- **Telegram is input-only for the agent.** Provisioning stays human-only.

---

## Decisions (locked)

| Fork | Decision |
|------|----------|
| **F2** grant re-query | **Add an MCP tool `list_grants`** (read-only, no approval). It is one of the eleven tools today. |
| **F5** gate forensic audit | **Redact command strings everywhere, including the gate-side `audit.log`.** Never persist a secret; operator sees a correlatable marker. |
| **F1** fail-safe direction | **Strict**: a lost verdict = possible-deny → stop, do NOT auto-retry, surface to the human. Matches "if denied, don't resubmit." |
| **F4** live-log vocabulary | Full `auth_mode: "human" \| "grant:<id>"` (the agent already gets its own grant_id from `request_grant`). Add a first-class `auth_mode` to the signer audit too (decouple from the `approved_by` prefix). |
| **F6** version semantics | **Exact-match** single int `sigwire.ProtoVersion` (not a negotiated range). Decoupled from the human-facing semver. |

---

## Per-finding spec

### F1 — Verdict-undelivered race [HIGH] — no wire change
A single absolute conn deadline covers read + approval-wait + response-write (`socket.go` serveOne),
so a verdict resolving near the deadline has zero budget to write → the agent sees EOF/`i/o timeout`
with no `ErrDenied`/`ErrTimeout` sentinel → classified as a generic retryable error. A denied write
can be silently re-attempted. (The repo's own `socket_handlertimeout_test.go` documents this.)

Fix:
1. `sigwire.ResponseWriteGrace = 5 * time.Second`. In `serveOne`, set the initial conn deadline +
   `connCtx` to a **wait budget** = `SignerHandlerTimeout - ResponseWriteGrace`; pass a
   `resetWriteDeadline func()` into the handler that sets `conn.SetDeadline(now + ResponseWriteGrace)`.
   The daemon calls it **immediately before each `writeJSONLine`** (verdict + error paths), so the
   write always has a fresh, non-racing budget. Max conn lifetime stays ≤ `SignerHandlerTimeout`;
   `ClientSignTimeout` still dominates. (No timeout-value changes — the grace is carved from the
   existing 30s slack; assert `ApprovalWindow + ResponseWriteGrace ≤ SignerHandlerTimeout <
   ClientSignTimeout` by construction.)
2. New sentinel `sign.ErrVerdictUnknown`. In `client.go` (Sign) **and** `grant_client.go` (roundtrip):
   after the request was fully written, if the read fails with `io.EOF` or a net timeout AND
   `ctx.Err()==nil`, return `ErrVerdictUnknown` instead of the bare wrapped error.
3. `run.go`/`run_batch.go`: classify `ErrVerdictUnknown` explicitly → fail-safe agent guidance
   ("the signer decided but the response didn't arrive — a human may have DENIED this; do NOT
   auto-retry; check `sshgate.status` / `list_grants` and the Telegram thread before resubmitting").
4. Daemon audit: record `denied-undelivered` / `timeout-undelivered` (mirror the existing
   `approved-undelivered`) so the asymmetry is logged for ALL verdicts.

### F2 — Phantom-live grant [HIGH] — new `list_grants` tool
`request_grant` stores the grant LIVE under lock **before** the response write; a write failure leaves
a live standing grant the agent believes failed (no grant_id/expiry/scope). No verb to learn true
state.

Fix: new **read-only** socket kind `list_grants` (no backend, no approval, like `revoke_grant`):
RLock `d.grants`, filter live (`expiry > now`), optional alias filter, return
`[]{alias, scope, commands, grant_id, expiry_unix}`. Mirror in `grant_client.ListGrants`, a new
`tools/list_grants.go` (`Runner.ListGrants`), register the tool in `server.go` (read-only), extend
the `SignClient` interface. Old daemon → `unsupported kind` → MCP surfaces gracefully ("daemon too old
to list grants"). Do **not** persist grants (in-memory-only is deliberate). An idempotent re-request
(asking for the same grant twice returns the live one) was **not built** and is not scheduled.

### F3 — grant_client masks `resp.Error` [MED] — 16 LOC
Mirror the merged `client.go` 2b carve-out into `RequestGrant` and `RevokeGrant`: an
`if resp.RequestID=="" && resp.Status=="error"` block surfacing `resp.Error` **before** the strict id
compare.

### F4 — Audit auth-mode [LOW, downgraded] — socket-response field, gate untouched
The signer already distinguishes human vs grant (`approved_by="grant:<id>"` vs the approver name,
test-pinned). Gaps: the live-log's `approved:true` is ambiguous and its comment falsely says "a human
approved."

Fix:
- **Part A (bug):** fix the `livelog.go` `Approved` comment.
- **Part B:** add `auth_mode` (`omitempty`) to the `signResponse` socket struct (client uses plain
  `json.Unmarshal` → backward-compatible). Derive from `result.ApprovedBy` (`grant:` prefix → that
  value; else approved → `"human"`; else empty) via a shared helper (`authMode` in `pkg/signerkit/daemon.go`). Thread
  through `client.go` (return a `SignResult{Signed, AuthMode}`), `run.go` (`RunOutput.AuthMode`),
  `server.go` → `livelog.Entry.AuthMode` (run + run_batch).
- **Part B4:** first-class `auth_mode` on the signer `AuditEvent` (set via the same helper).
- **Gate:** no field; add a one-line comment near `ApprovalStatus` noting the gate cannot/must not
  distinguish grant from human.

### F5 — Redact command strings [LOW] — redact everywhere
The redactor only runs over command OUTPUT. A secret embedded in the command string lands verbatim in
the gate audit, signer audit, MCP live-log, and the Telegram approval message.

Fix: new `redact.RedactString(s, salt, rules) (string, bool)` reusing the streaming Writer + `Combined()`
ruleset (fail-open: on error return input + `false`). Apply at every command-string sink (all four
shipped):
- gate `execAndAudit` + `auditNoExec` (reuse the gate's existing salt + lazily-compiled `auditRules`);
- MCP live-log run + run_batch (new per-process salt + `Combined()` on `Server`);
- signer `audit()` (new per-process salt + `Combined()` on `Daemon`);
- Telegram approval **and** grant-approval message (`formatApprovalMessage` /
  `formatGrantApprovalMessage`), the fourth sink, shipped the same day.
  Redaction is **secret-only**: only the matched secret substring is replaced by the per-session marker,
  the command SHAPE stays visible, so the human approver still sees WHAT runs (and that a secret is
  present) — just not the literal secret, which therefore never reaches Telegram's servers. It is
  **display-only**: the signed/executed command is the RAW request command, untouched (the format
  functions only read `req.Commands`). The backend reuses the SAME per-process salt + already-compiled
  `Combined()` slice as the `Daemon` (wired once in `src/signer/cmd/sshgate-signer-telegram/main.go`); a backend
  with no ruleset wired (nil) renders verbatim via `RedactString`'s nil-rules fast-path.
Documented residual gap (still open): `mysql -p<secret>` (password as a CLI flag) has no covering
rule. `TestRedactStringMysqlFlagGapXFAIL` in `src/redact/scrub_test.go` pins it so it is not
silently assumed fixed.

### F6 — Wire/protocol version stamp [MED] — lenient peek, daemon-first
A naive version field **re-creates the outage**: an old daemon's `DisallowUnknownFields` rejects the
new `proto_version` field itself. Solve by checking the version in the **lenient `kindPeek` pre-pass**,
before any strict decode.

Fix:
- `sigwire/protocol.go`: `const ProtoVersion = 1`.
- `kindPeek` gains `ProtoVersion int` **and** `RequestID string` (both lenient). After the peek
  unmarshal: if `peek.ProtoVersion != 0 && peek.ProtoVersion != sigwire.ProtoVersion` →
  `respondError(conn, peek.RequestID, "proto_version mismatch: client vN vs daemon vM — signer and MCP
  are different builds; rebuild and restart both")`.
- The daemon **echoes `peek.RequestID`** on the malformed-peek and version-mismatch errors (was `""`)
  — closing the empty-id masking at the source.
- Add `proto_version` (`omitempty`) to the sign/grant/revoke **request** structs (daemon + client);
  the client SETS it = `sigwire.ProtoVersion`. Add to the response structs too (daemon sets it).
- `omitempty` + absent-⇒-accept-as-legacy keeps the legacy shape byte-identical, so a transitional
  peer is safe. Single-operator deploy order (restart signer, then relaunch sessions) satisfies
  daemon-first automatically; the field protects the **next** skew, not retroactively this one.

---

## Build order

The fixes shared files, so they were built in three groups on one branch: diagnosability (F3, F6),
then the two races (F1, F2), then forensics (F4, F5). Each group passed `make vet`,
`go test -race ./...` and a review before the next started.
