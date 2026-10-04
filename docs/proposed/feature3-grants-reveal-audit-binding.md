# Design record: Standing Grants, Secret-Read, Server-Binding, Audit Trail, Window Tightening

> **Status: BUILT** (merged 2026-06-23; part of v0.1.3 and every later version). Kept as the design
> record; §6c carries the as-built notes. Where the code lives: host binding in
> `src/sigwire/payload.go` and `src/hostkey/`; the gate-side audit log in `src/gate/audit.go`; the
> MCP-side live log in `src/mcp/livelog/`; standing grants in the signer (`pkg/signerkit/daemon.go`)
> and the `request_grant` / `revoke_grant` / `list_grants` tools in `src/mcp/tools/`; reveal in
> `src/gate/executor.go` (`ExecOpts.Reveal`) and `src/mcp/tools/run.go`; the 60 s default window
> in `src/mcp/tools/run.go` (`DefaultWriteTTLSec`).

**Date:** 2026-06-22
**Driver:** long unattended write windows (for example an overnight server migration) needed writes without a tap each; designing that surfaced several related gate and signer changes.

This bundles features that all touch the **signed payload** (`sigwire.SigPayload`), so they ship as one coherent wire change (gate + signer redeployed in lockstep — `DecodeSigned` uses `DisallowUnknownFields`, so old gates fail closed on a new payload, which is the safe degrade).

---

## 0. Invariants we preserve

- **The gate stays stateless.** No runtime state, no nonce store, no job table — no state the gate *reads back* to make a decision. The only files the gate reads for decisions are its binary, `gate.pub`, and (new) the host's own SSH host public key; the audit log (§6) is append-**only** write, never read for a decision. Reveal is a flag inside the per-command signed payload; **grants are signer-side state** (§4 — never on the wire, never gate-side) that auto-mint *normal* per-command signatures, so the gate never sees a grant at all. Long-running job state lives in the **OS process table + files on the target**, not in the gate.
- **Every elevated capability is encoded in the SIGNED payload** that the human approves. The agent can *request*; only the signer (on the human approver's tap) *grants*; the gate *enforces* against the verified signature. The agent can never self-elevate, and the gate can never self-grant.
- **The gate is the authoritative enforcement point** (independent of the signer), as today.

---

## 1. Long-running commands, concurrency, and "is the agent blind?" (grounding + answer)

**How it works (as of this design, still true):**
- `run`/`run_batch` are **synchronous and buffered**: `ssh.Client.Run` (`src/mcp/ssh/client.go`) blocks until the remote command exits and returns stdout/stderr all at once. There is **no streaming**.
- **No execution-duration cap.** The SSH client `Timeout` (30 s) bounds **dial + handshake only** — the connection deadline is *cleared* after the handshake; execution is bounded only by the caller's context, which has no deadline. So a 30-minute command runs to completion. The gate likewise runs under a signal-only context — unbounded. Long single commands already work. (The `Timeout` comment in `client.go` once claimed otherwise; it was corrected, with a regression test that a command longer than `Timeout` still completes.)
- **The real limitation is real:** because `run` is synchronous, a naive `run("mysqldump … 30 min")` **blocks the agent's turn** for 30 minutes with no visibility and no way to query/kill. That is a blind state.
- `run_batch` runs each command as a **separate SSH session, sequentially**, but all write sigs are minted at **one** approval with a 60s TTL each — so if an early command runs long, later commands' sigs expire (exit 65) before their turn.

**Answer (no gate state needed): detached-launch + poll-by-PID.** For any long op, the agent launches it detached and polls:
1. `run("nohup <cmd> >job.log 2>&1 & echo $!")` → returns the **PID** immediately (the shell backgrounds + exits; the gate process exits; the detached child survives).
2. Poll with cheap **reads**: `tail job.log`, `ps -p <pid>`, `ls -l <output>`, `cat done.flag`.
3. Control with **writes**: `kill <pid>`.
4. Completion signal: launch as `nohup sh -c '<cmd>; echo $? >done.flag' &`.

The **"executor ID" asked for is simply the OS PID** (or a per-job dir with a flag file). State lives in the OS + filesystem on the target — the gate stays stateless. Response correlation is 1:1 per `run` call (each poll is its own request/response); nothing is fire-and-forget. This pattern is the documented idiom for long operations (see `skills/debugging-remote-servers/SKILL.md`), and means **no executor-ID/job-table is added to the gate**.

**Gate control verbs stay minimal.** The gate interprets only a small set of verbs (the empty probe → `SSHGATE_OK`, `SSHGATE_VERSION`, and the signed admin verbs `SSHGATE_REVOKE`, `SSHGATE_UPDATE` and `SSHGATE_XFER_*`; see [design.md](../design.md)); everything else is an ordinary command. Monitoring needs **no new verbs** (`ps`/`kill`/`tail` are ordinary shell). We keep the gate-verb namespace tiny — good for statelessness and attack surface.

**Clarifications (checked against the code, 2026-06-22):**
- **No persistent connection.** Each `run` dials a fresh TCP+SSH, runs ONE command, tears down (`src/mcp/ssh/client.go`); `run_batch` re-dials per command. No pool, no keepalive, no reconnect. Every `run` is its own synchronous request→response, so reply-correlation is 1:1 by construction — there's no "whose reply is this?" ambiguity.
- **The agent gets back exactly what the command printed** (redacted stdout+stderr+exit, `src/mcp/tools/run.go`) — nothing else. So `nohup … & echo $!` returns just the PID; a normal command returns its output. PID vs output is purely a function of what you run; the gate has **no custom wire format** for ordinary commands (only the `SSHGATE_SIG:` prefix on writes + control verbs).
- **Yes, the agent polls** (by design): a detached job + cheap read-polls keeps the gate stateless, doesn't block the agent's turn, and — crucially — **survives pipe-breaks** (the `nohup` job lives on; only the current poll fails, the next re-dials). A synchronous long `run` instead dies on pipe-break (SIGHUP) and blocks the agent. Server-push/streaming would need gate state + a held connection. So poll-a-detached-job is the robust choice, not a compromise.
- **Regular-terminal login:** there is **no interactive shell today** — the gate key is locked to `command=`; `ssh <box>` (even `-t`) returns `SSHGATE_OK` and closes (the forced command in `src/mcp/tools/authorizedkeys.go`, the probe handling in `src/gate/cmd/sshgate-gate/main.go`). Humans reach these boxes out-of-band with their own admin creds (how the gate key got pasted). A **gated interactive shell** is future roadmap (§9).

---

## 2. Signature window: ts vs exp, one-field, timezone, 1-minute default

**The two checks (`src/gate/verify.go`):**
- `now < exp` — has it expired? (`exp` is the **"valid till"** time.)
- `exp − ts ≤ 5 min` (`sigwire.MaxSigValidity`) — caps the **maximum validity window** so a buggy/hostile signer can't mint a long-lived token. `exp` = `ts + ttl` (signer-set); the gate independently re-caps.

**Timezone:** `ts`/`exp` are **Unix epoch seconds (int64, UTC)** — timezone is irrelevant (`now.Unix()`). Only **clock skew** between signer host and target matters (a skewed clock breaks the app *and* the gate's `now < exp`).

**One-field simplification:** feasible — drop `ts`, keep only `exp`, and have the gate check `now < exp` AND `exp − now ≤ Max`. **Trade-off to decide:** the current `exp − ts` caps the *issued* window using the signer's clock (skew-immune for the cap); `exp − now` caps the *remaining* window using the gate's clock (skew-**sensitive**). With a tight 1-min default, skew tolerance matters, so **recommendation: keep `ts`** (it's free, keeps the window-cap skew-robust, and feeds the audit log's "signed-at"). The existing "valid till" field is `exp`. *(Open: drop `ts` anyway for minimalism? Recommend no.)*

**Default window → 60s (decided):** change `DefaultWriteTTLSec` 120→60 and keep `BatchWriteTTLSec` 60. Because the gate checks `now < exp` only at **receipt** (then runs unbounded), 60s is plenty for any single command (it's received instantly after signing, then runs as long as it needs). Longer windows are only needed for *sequential batches of long commands* — which the agent requests explicitly (5/10-min, with a reason) or covers via a standing grant. Shrinks the replay window 2×.

**Replay protection is intentionally NOT enforced (an accepted residual, also stated in [THREAT-MODEL.md](../THREAT-MODEL.md)).** The signed payload mints a `Nonce`, but the gate **never checks it** — enforcing single-use would require the gate to remember spent nonces, i.e. gate state, which violates the hard stateless invariant (§0). So replay of an already-approved write is possible **within its validity window** (60s default, 300s ceiling); the tight default window is the bound on that exposure (and host-binding, §3, keeps a replay from crossing machines). True single-use enforcement would live in the Tier-3 hosted (stateful) signer, not here.

---

## 3. Per-server identity & spoof-resistance (the "robust" requirement)

**Problem:** the same `gate.pub` is on every Tier-2 server and the signed payload carries no server identity, so a signature approved for server X verifies on any Tier-2 box (replay bounded only by the window). A 24h grant makes this unacceptable.

**Design — bind to the target's SSH host key:**
- Add a `host` field to the signed payload = the target's SSH **host-key fingerprint** (the one the MCP TOFU-pinned at provision, already in `known_hosts`).
- The **signer** puts the target's fingerprint into the payload when signing for that alias (the MCP supplies it from `known_hosts`).
- The **gate** reads its *own* host public key (`/etc/ssh/ssh_host_*.pub`, world-readable) and rejects unless `payload.host` matches one of its own host keys.
- **Spoof-resistance:** a captured signature for X cannot run on Y (Y's gate computes Y's fingerprint ≠ X's). Forging a payload for Y needs the master signing key. Binding is to the **machine's real identity**, not a writable label.
- **Stateless:** the gate reads an existing OS file; nothing new is synced (both sides derive from the host key). If the host key rotates (rebuild), the binding breaks → re-provision (a desirable property: a replaced machine must be re-trusted).
- Applies to **every** signature (per-command and grants), closing cross-server replay generally.
- *Alternative considered:* a provision-written `~/.sshgate-gate/server_id` file — simpler but a writable label and needs a new provision write; **host-key binding preferred.**
- **Residual (inherent to host-key binding, not a defect):** two machines that genuinely **share** their `/etc/ssh` host keys (a cloned VM / golden image) are **one identity** to this mechanism — a signature bound to one verifies on the other. This is the standard property of host-key binding. **Operational implication:** make sure servers have *distinct* host keys (they will, unless cloned from the same image); if any were cloned, regenerate their host keys before relying on per-server binding to separate them.

---

## 4. Standing grants (the keystone — replaces the original design's "Time-Scoped Tokens")

**Architecture: signer-side standing grant (auto-sign), NOT a gate-side grant blob.** (Decided 2026-06-22; this *revises* the section's earlier "grant presented on the wire" framing — rationale below.)

A **standing grant** is state the *signer* holds after one human approval; it never appears on the wire, and the **gate is completely unchanged and unaware of grants**. On the human approver's one Telegram approval, the signer records `{alias, scope, expiry ≤ 24h}` in memory. During the window, when the MCP requests a signature for a matching `(alias, command)`, the signer **auto-approves** (no tap) and emits a **normal per-command `SigPayload`** — host-bound (§3), `ts`/`exp` ≤ 60s/5min, exactly as today. The gate just verifies normal signatures, unchanged.

- **Scope = `all`** → any command on that alias auto-signs (meant for a fresh, throwaway box being built up).
- **Scope = exact command-set** → only the pre-shown exact command strings auto-sign; everything else still prompts (meant for boxes that hold anything that matters). *Exact-string match, no patterns.*
- **Server-bound:** the auto-signed per-command sig still carries `Host = fp(alias)` (§3), so the gate's host-binding makes a grant for one server physically unusable on another.
- **Window ≤ 24h** hard ceiling, enforced by the **signer** (it won't auto-sign past the grant's expiry). Each auto-signed sig is still independently capped at ≤ 5 min by the gate (unchanged), so the gate's replay window is unchanged.
- **Revocable — "stop the signer kills grants":** the grant lives in the signer, kept **in-memory**, so a signer restart also drops every grant. An explicit revoke drops a standing grant. There is nothing for the agent to hold or replay — it never sees a grant, only normal per-command sigs minted on demand.
- **Audited:** grant issuance + every command auto-signed under it are logged (the signer's approval log + the gate-side audit §6 records *every* command, grant or not).
- **Self-elevation impossible:** the agent can *request* a grant (the **`request_grant`** MCP tool; with `revoke_grant` and `list_grants`, three of today's eleven tools), but only the human approver *creates* one by approving a distinct, scary grant message (showing alias + scope + duration). The agent can never self-grant; the gate can never self-grant.

### Why signer-side (model I) over a gate-side grant blob (model II)
- **The gate stays stateless AND untouched** — the hard invariant, maximally preserved; zero new gate code = zero new gate attack surface; the wire is unchanged.
- **"Stop the signer → grants die" is natural** (the grant is signer state) — exactly the revocability asked for, for free.
- **Every command under a grant is still host-bound, ≤ 5 min, and audited** — no weakening of per-command enforcement.
- *Trade-off accepted:* the gate can't independently cap the 24h (it never sees a grant, only ≤ 5 min sigs); the 24h is signer-enforced. Fine — a rogue signer holds the key anyway, so a gate-side grant cap adds little; against a *buggy* signer the in-memory expiry + the gate's per-sig 5-min cap bound the blast radius.
- *Model II — a signed grant blob presented with each command, gate verifies scope/window/host — was rejected:* it adds grant-parsing to the gate (new attack surface) and makes "stop signer kills grants" awkward, because the issued blob is already in the agent's hands until expiry.

**Replay posture:** within the window a grant authorizes its scope by design; the mitigations are **server-binding** (a grant can't cross machines) + **exact-command-set scope** on sensitive boxes (only the approved strings auto-sign). `all` is reserved for throwaway boxes. A grant never auto-signs a reveal or an admin verb (`update_gate`, `revoke_server`, `transfer`); those always need a fresh tap.

"Extended-TTL" (the agent asking for a longer single-command window) is the degenerate case — a one-command, slightly-longer grant — same primitive.

---

## 5. Secret-read / reveal (orthogonal, agreed)

- Add `reveal bool` (omitempty) to the signed payload. Single seam in the gate executor (`ExecOpts.Reveal` in `src/gate/executor.go`): when it is set, that one command's output is **not** redacted.
- **Single command only** (never in `run_batch`, no bulk reveal). Mandatory agent **reason**, shown to the human approver.
- **Distinct, scary approval UX** ("⚠️ SECRET-REVEAL — output will NOT be redacted; raw values go to the agent + AI provider + this chat").
- **Accepted exposure (eyes open):** an approved reveal pushes the raw secret into the agent context → the model provider → the session transcript → possibly Telegram. Prefer moving secret *files* box-to-box without reading them (the `transfer` tool, built later); reveal is for the rare case a value must be *seen*.

---

## 6. Audit trail — TWO TIERS (the authoritative log MUST be gate-side)

An earlier "MCP-side only" plan was wrong: the agent shares the MCP's trust domain, so an MCP-side log is erasable by the very actor it audits. Split into two logs with different jobs:

### 6a. Gate-side authoritative log (tamper-resistant — the record that matters)
- **Written by the gate, on the target host**, for every command it sees (reads + writes + rejections) — classification, approval status, exit code, output **metadata** (bytes/lines/duration), NOT raw output by default.
- **Tamper-resistance:** the log is owned by a **separate user** (not the gate's run-as user), so the agent — which only ever speaks *through* the gate — cannot rewrite or delete it. Mechanism, strongest-available-by-privilege: if provisioning has root → a dedicated `sshgate-audit` user + append-only (`chattr +a` / syslog-journald which the gate's user can't rewrite); if only the unprivileged target user → best-effort restrictive perms + separate group. **Accepted limit:** an attacker who fully bypasses the gate and deletes the folder already has the host; the log is defense in depth, not perfection.
- **Does NOT break statelessness:** append-only logging is a *side effect*; the gate never *reads* the log to make a decision. It stays a pure (payload, command) → (allow/deny, exec) function.
- **Leveled + configurable, write-gated:** levels below; the level is set via the human `sshgate` control plane, never an agent tool — the agent can't quiet its own audit.

### 6b. MCP-side live/convenience log (rolling, full-output — powers the live view)
- **Size-capped rolling buffer** (terminal-scrollback style — older lines auto-dropped; a bit larger since it's on disk). Holds the **whole** command + full output. Auto-rolls/clears, so it's transient by design.
- This is what `tail -f` watches for a **live operator view** — it **subsumes "Live Command View"** (§7). It is a convenience/observability surface, NOT the system of record (that's 6a).

### Levels (apply to the gate-side authoritative log; default in bold)
- `off`
- `writes` — write commands only
- `all` — read + write commands
- **`all+meta`** (default) — all commands + rejections + output metadata (size/lines/duration/exit), **no raw output**
- `all+full` — everything incl. full output (verbose)
- Rejections/denials always logged from `writes` up.

### 6c. As-built notes (TDD landing, 2026-06-22)

**Tier 6a — gate-side authoritative log** (`src/gate/audit.go`, wired in `src/gate/cmd/sshgate-gate/main.go`):
- One append-only JSON-Lines record per command at the gate dispatch chokepoint — read, write, AND rejection. Fields: `ts` (UTC epoch), `command`, `classification` (read/write), `approval_status` (`signed` / `unsigned` / `denied`), `exit_code`, and `meta` (`stdout_bytes`/`stderr_bytes`/`lines`/`duration_ms`) at `all+meta`+. Raw `stdout`/`stderr` only at `all+full`.
- **Leveling** read from `~/.sshgate-gate/audit-level` (one token per the list above); **default `all+meta`** when the file is absent/unreadable/garbage — `ParseAuditLevel` fails to the default, the gate never crashes on bad config. `Record` additionally blanks raw output below `all+full` (belt-and-braces: `all+meta` provably cannot leak raw output).
- **Output metadata** comes from the widened executor (below). Counts are measured **post-redaction** — what the agent actually receives. `all+full` makes the executor tee a **capped** copy (256 KiB/stream, truncation-marked) so the level is meaningful without unbounded gate memory.
- **Append-only + fsync**, opened `O_APPEND|O_CREATE|O_WRONLY` mode 0640, **open→append→fsync→close per invocation** (a fresh gate per `SSH_ORIGINAL_COMMAND`, so per-invocation == per-command). The gate never holds an FD between commands and **never reads the log back** — statelessness preserved.
- **Path is configurable** via `~/.sshgate-gate/audit-path` (default `~/.sshgate-gate/audit.log`) so an admin can point it at a separate-user-owned append-only location.
- **Fail-open:** every audit error (open/write/fsync/marshal) is swallowed — a logging failure NEVER blocks the command (the audit is a side effect, not a gate; the gate also has no safe out-of-band error sink, since stderr is the SSH stream). Tested with an unwritable path.
- **Config-change protection:** the level/path files live in the gate dir. Changing them through a gate command is itself a WRITE (signed + approved); an admin with box access edits them directly. The agent cannot silently quiet its own audit.

**Tamper-resistance posture — what is built vs deferred (IMPORTANT):**
- The gate writes **append-only + fsync** regardless of who owns the directory — that is the best-effort baseline and it always holds.
- **TRUE tamper-resistance requires a root-time setup that SSHGate does NOT automate:** a dedicated `sshgate-audit` user owning an append-only directory (`chattr +a`, or a journald/syslog sink the gate's run-as user cannot rewrite), with the gate's run-as user granted append-but-not-rewrite/delete. An admin provisions that out-of-band and points `audit-path` at it. **We deliberately do NOT build root provisioning automation here** (out of scope, and root-time host policy is the admin's call).
- Absent that setup, the log degrades to **gate-user-owned best-effort append-only** — defense in depth, not perfection. A full host compromise that deletes the folder is an accepted limit.

**Executor widening** (`src/gate/executor.go`): `ExecWithRedaction` now returns `(ExecResult, error)` instead of `(int, error)`. `ExecResult` carries `ExitCode` plus `StdoutBytes`/`StderrBytes`/`Lines`/`Duration` (and, only when `CaptureLimit>0`, a capped `Stdout`/`Stderr`). Counting writers sit **below** the redactor so byte/line counts reflect the post-redaction stream. Existing redaction + reveal behaviour is unchanged (the redactor wiring and the `Reveal`/`Rules` seam are untouched; only the destination is wrapped in a counting writer).

**Tier 6b — MCP-side rolling live log** (`src/mcp/livelog/`, wired in `src/mcp/server.go` `runHandler`/`runBatchHandler`, configured in `src/mcp/cmd/sshgate-mcp/main.go`):
- Size-capped **rolling** JSON-Lines at `~/.config/sshgate/audit-live.log`, holding the **whole** command + **full** output per command (one entry per `run`, one per non-skipped `run_batch` result). When the file exceeds the cap it is rewritten keeping only the newest suffix of complete lines (oldest dropped, terminal-scrollback style) via a temp-file + atomic rename.
- **On by default**, cap = **5 MiB**, configurable via `~/.config/sshgate/audit-live-cap` (byte count; `0` disables — a nil log, a silent no-op). Fail-open like 6a.
- This is the `tail -f` operator view and **subsumes "Live Command View"**; it is the convenience surface, **NOT** the system of record (that's 6a).

---

## 7. Minor / deferred

- **`servers.json` perms:** the registry is written mode 0600 (`tmp.Chmod(0o600)` in the temp-file + fsync + rename path of `src/mcp/registry/servers.go`); this build added tests asserting the mode on all three write paths (create, rewrite, remove). Encryption at rest was dropped as over-spec for non-secret metadata.
- **Auto-update (`SSHGATE_UPDATE`)** — deferred here; since built as `update_gate` (see [sshgate-update-verb-2026-07.md](sshgate-update-verb-2026-07.md)).
- **Live Command View** — delivered by the **MCP-side rolling log (§6b)**: a real-time operator stream via `tail -f`. No dedicated UI.

---

## 8. Decisions

1. **`ts`:** kept (no one-field change).
2. **Per-server binding:** host-key fingerprint (§3).
3. **Audit:** two tiers (§6) — gate-side authoritative (append-only, ideally separate-user-owned)
   plus an MCP-side rolling full-output live view. `all+meta` is the default.

**Not in this build:**
- **Gated interactive shell** ("log in from a regular terminal" *through* SSHGate, every command
  classified, approved and audited): #25 in [ROADMAP.md](../ROADMAP.md), now scheduled as the
  signature terminal, work item 3 of [BUILD-PLAN.md](../BUILD-PLAN.md). Today the gate gives no
  interactive shell to anyone (the forced command answers `SSHGATE_OK` and closes); humans reach
  the boxes out of band with their own admin credentials.
- **Auto-update (`SSHGATE_UPDATE`)**: built later as `update_gate` (§7).
