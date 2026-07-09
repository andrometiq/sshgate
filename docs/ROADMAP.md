# SSHGate Roadmap

The forward-looking work for SSHGate, in priority order. This is the single
canonical roadmap; design rationale for individual items lives in the design and
decision docs referenced inline.

For the security model these items extend, see [design.md](design.md) and
[approval-architecture.md](approval-architecture.md).

---

## Already shipped

- **Human-only provisioning CLI.** Onboarding a server is a control-plane action
  done with the `sshgate` CLI (`pubkey` → paste → `add [--read-only]`), not an
  agent tool. The agent surface is exactly eleven tools (`run`, `run_batch`,
  `list_servers`, `status`, `ping`, `revoke_server`, `request_grant`, `revoke_grant`,
  `list_grants`, `update_gate`, `transfer`); there is deliberately no `add_server`
  tool, so the agent can never expand its own reach.
- **Read-only (Tier-1) and signed-write (Tier-2) provisioning**, selectable at
  `sshgate add` time.
- **Inline secret redaction of command output** in the gate (all commands,
  reads and writes; bypassed only by an approved secret-reveal).
- **Local Telegram signer** with separate-Unix-user key isolation, one-tap
  approval, and bulk (single-tap, N-command) approval.
- **Standing grants, secret-reveal, per-server binding, leveled audit trail
  (v1.3.0).** One signed-payload wire change: signer-issued **standing grants**
  (scope `all` or an exact command-set, ≤24h, server-bound, revocable) for
  unattended write windows; an approved **secret-reveal** that bypasses output
  redaction for a single signed command; **per-server identity** binding each
  signature to the target's SSH host-key fingerprint (closes cross-server
  replay); a **two-tier audit trail** — a gate-side append-only authoritative
  log plus an MCP-side rolling live view; a 60s default signature window; and
  `servers.json` 0600. Design:
  [docs/proposed/feature3-grants-reveal-audit-binding.md](proposed/feature3-grants-reveal-audit-binding.md).
- **Gate auto-update (`update_gate` / `SSHGATE_UPDATE`) + verified release
  channel (v1.3.0, deployed).** A signed control verb that updates the gate
  binary in place on an already-registered server — **signed** (through the
  master key like any other write), **versioned** (returns the installed
  SHA-256 + build revision), **fail-closed** (hash mismatch / wrong-arch
  binary / Tier-1 all refuse and write nothing), and **audited**. The agent
  supplies only the alias; the MCP hashes the operator's locally-staged gate
  binary and the human approves a distinct "GATE BINARY UPDATE" Telegram
  banner bound to that exact SHA-256; a standing grant never auto-signs it.
  The committed `dist/gate/` artifact + the `verify-gate` reproducible-build
  CI check anchor the approved hash off the machine. Replaces the old
  revoke + re-add redeploy for gate changes; the operator rollout to
  existing servers completed 2026-07-04. Design:
  `docs/proposed/sshgate-update-verb-2026-07.md`.

---

## Next

These are the highest-priority forward items.

- **Route approvals through the shared messaging layer (strategic anchor).** The
  signer currently embeds its own chat-channel integration — long-poll, backoff,
  update ingestion, message formatting. A separate in-house messaging system
  already solves that surface robustly (durable inbound queue, connectivity
  notifications, delivery retries). The direction is to make SSHGate *consume*
  that layer — as a plugin or a narrow call/API surface — rather than
  re-implement it. This deletes the signer's bespoke poller, which is the source
  of several verdict-delivery and concurrency gaps in the operational-hardening
  set below; those are marked "(subsumed)" because they resolve for free once
  approvals ride the shared layer. Evaluate and decide this **before** investing
  further in the signer's own chat integration — it is the anchoring decision for
  the next SSHGate pass.

- **Final product shape — component decomposition & packaging (owner direction,
  filed 2026-07-10).** Before the public release push, pin down the parts a user
  actually installs and where each management surface lives. The parts as
  understood today: (a) the **gate** (+ the SSH key line) installed on target
  servers; (b) the **MCP server** — the agent tool surface that talks to gated
  servers; (c) **provisioning & key management** — SSH keypair generation,
  `pubkey`/`add`, transfer enrollment — today the MCP and the `sshgate` CLI ship
  merged, and the open question is what is managed *inside* the MCP vs *outside*
  it (the CLI possibly becoming a separate tool); (d) the **Telegram signer** —
  candidate for refactoring to ride the shared messaging layer (the anchor item
  above); (e) the **hosted signer as an embeddable library/service** — installable
  on a customer's server, shipping a default web UI but wireable to their own UI,
  with a first-class audit surface (every incoming call, every approval, logged
  for the integrator). Sequencing: settle the shape → verify the stack works with
  **other agents (Codex, Gemini, …)** → only then decide which artifact is
  published to which **marketplace** (the shape decision gates the uploads).

- **Bundle DevOps skills with the plugin (owner ask, filed 2026-07-10).**
  Observed in real use: an agent driving the gate sometimes finds the problem
  fast, and sometimes just keeps reading — no method. Bootload the plugin with
  curated skills the agent can freely use — Linux server **debugging**, server
  **setup**, **installation** — alongside the existing
  `debugging-remote-servers` skill, so any agent using SSHGate has an efficient,
  opinionated playbook out of the box.

- **Argv-exec structural classifier fix (#22).** Replace the fail-closed shell
  heuristic on the read path with direct execution from a parsed `argv`
  (`execve`, no intervening `/bin/sh`), so the classifier's view of a command is
  exactly the view that executes. This eliminates the entire shell-parse-mismatch
  class (escapes, quoting, separators, substitution, redirects) and ends the
  per-tool flag arms race. Read *pipelines* are handled by a safe mini-executor
  that verifies each stage's binary against the read allowlist and wires the
  stages without a shell, or are routed through approval. Likely combined with
  kernel-level confinement (read-only mounts + seccomp denying write/exec
  syscalls) for defense in depth.

- **Interactive prompt / confirmation / password forwarding (Feature 1).** A
  remote command can trigger an interactive prompt mid-run — a `sudo`/password
  prompt, a `[Y/n]` confirmation, an "are you sure?". The gate currently execs
  non-interactively, which would force the operator to SSH in by hand just to
  answer. Allocate a PTY for the remote command, detect a prompt or input stall,
  surface it to the operator (Telegram and/or a web UI), capture the response,
  and write it to the command's stdin. Passwords must be handled securely — never
  logged or echoed. Reuses the existing approval channel. A design proposal exists
  at [docs/proposed/feature1-interactive-prompt-forwarding.md](proposed/feature1-interactive-prompt-forwarding.md)
  to start from.

- **Read-only SQL via per-service adapters (Feature 2).** Full SQL access over
  SSH is effectively all-or-nothing today. Support **read-only** SQL queries
  against common engines (PostgreSQL, MariaDB, SQLite, …), with **write** SQL
  requiring a signature — the same read/write-plus-sign model the gate applies to
  shell, but applied to SQL. The architecture is a customized per-service
  whitelist **adapter** (a SQL adapter, a shell adapter, …) built one engine at a
  time. This pairs naturally with #22: explicit per-service argv/grammar-based
  adapters can *be* the structural replacement for the single heuristic shell
  classifier. Design the adapter framework and the argv-exec fix together. A design
  proposal exists at [docs/proposed/feature2-service-adapters-argv-exec.md](proposed/feature2-service-adapters-argv-exec.md)
  to start from.

---

## Planned

- **Multi-key gates + provisioning exposure window (#17, redefined).** The old
  "in-place Tier-1 → Tier-2 upgrade" here is **rejected**: any unsigned
  tier-flip path the CLI could exercise is a path the agent could emulate —
  read-only is read-only, full stop; re-tiering stays out-of-band re-provision.
  In its place, two captured directions: (a) **multiple signer keys per gate**
  (per-agent identity — each agent its own keypair, no shared-key trust),
  version-aware `sshgate add` (upgrade an older installed gate, defer to a
  newer one, notify either way), single-vs-multiple gate binaries and signer
  topology as open design questions; (b) **shrink the plain-key exposure
  window in `add`** (run add first, it retries while the operator pastes the
  key out-of-band, gate swap lands within milliseconds; fully-manual install
  stays available for absolute security). 2026-07-04 additions: combined
  paste-&&-add one-liner (docs-only, available today); a self-contained
  provisioning command embedding the pubkey, runnable from any admin machine;
  a one-shot server-side install that never writes a plain key line at all;
  and programmatic/web-app-driven enterprise provisioning (pubkey exposed on
  the agent surface, install stays behind the application's own auth). Full
  capture with all constraints:
  [docs/proposed/multi-key-gates-and-add-exposure-2026-07.md](proposed/multi-key-gates-and-add-exposure-2026-07.md).
  Direction recorded 2026-07 — not scheduled; design questions go through the
  full pipeline before any build.

- **Reconcile tier on the probe-idempotent re-add path.** When `sshgate add`
  re-runs against an already-gated host (the probe-first idempotency that
  recovers a lost `servers.json`), it registers the **caller-supplied** tier
  flag without checking the remote's actual tier — the `SSHGATE_VERSION` probe
  is deliberately tier-blind, and `gate.pub` is only ever uploaded by the full
  provisioning flow. A mismatched flag records wrong state silently: a
  read-only host re-added without `--read-only` registers as writable, and
  every write then burns a human approval tap before failing exit 77 at the
  gate; the inverse direction under-reports a signed-write host as read-only.
  **Every mismatch direction fails closed** (the gate, not the registry, is
  the enforcement point), so this is a state-hygiene/UX defect, not a
  boundary break — reviewed and deliberately deferred rather than blocking
  the release-channel ship. Likely fix: extend the gate's version reply with
  a tier token (e.g. `SSHGATE_VERSION rev=<v> tier=ro|rw` — additive after
  the frozen `rev=` key, so it needs a small §11.2 spec amendment and a
  dist/gate republish) so the probe path can verify the flag it registers;
  until then the tier on that path is taken on faith.

- **Asynchronous approval lifecycle — dispatch-and-continue (owner direction
  2026-07-04).** Today a write's tool call BLOCKS from request to verdict: one
  approval in flight, the human must be watching the channel, and the client's
  wait budget bounds the whole exchange (the known verdict-undelivered /75s
  issue is a symptom). The end goal: the agent **dispatches N approval
  requests and goes on with its own work**; the human approves them
  asynchronously — Telegram today, a web approval surface later (longer
  cycles, several pending items answered in one sitting) — and the agent
  collects/gets notified of verdicts when they land, executing only then.
  Workflow shape identified so far (design questions, not commitments):
  an async dispatch variant returning a `request_id` immediately;
  **sign-at-approval, not sign-at-request** (the signer signs when the human
  decides, so signature TTLs stay short while the *pending request* gets its
  own longer validity window — a pre-signed long-TTL blob must never sit in a
  queue); collection via `await_approvals([ids])`/`list_pending_approvals`
  tools plus an optional local watcher to wake an idle agent (harness-specific;
  the polling tools stay the portable core); an operator-visible pending
  queue with cancel/deny-all and single-use nonce-bound verdicts; and batch
  approval UX that still renders each item for scrutiny (approve-all is a
  gesture over N displayed items, never a blind blanket). This converges
  deliberately with the Tier-3 hosted signer (its backend already models a
  pending approval queue + web auth) and with channel-relay approvals —
  design once, serve both surfaces. Not scheduled; full design pipeline
  before any build.

- **LLM approval-assist at the signing surface (owner direction, filed
  2026-07-10).** The agent requesting a signature supplies the *reason* it wants
  these commands; the approval surface then runs an LLM pass over
  (reason, command list) that (a) checks the commands actually match the stated
  reason, (b) flags anything inappropriate or out of scope, and (c) renders a
  plain-language summary of what approving would really do — so a human can
  scrutinize an N-command batch without hand-parsing shell. Native in the hosted
  signer's web UI (a first-class part of its integration story); the Telegram
  surface can carry a condensed form. Requires the MCP sign path to carry an
  agent-supplied reason (`run`/`run_batch` have none today; `request_grant`'s
  `reason` field is the precedent). Design together with the async approval
  lifecycle above and the hosted signer, so it is built once for every approval
  surface. The assist is advisory — the human tap remains the boundary, and a
  wrong LLM summary must never widen what was actually signed.

- **Per-gate memory subsystem (owner direction, filed 2026-07-10).** Alongside
  the gate install, give each target server a first-class, centrally-maintained
  **memory**: an indexed filesystem of markdown/instruction files that an agent
  can read and update natively through a gate verb (a clean file
  read/write/edit interface), so operational memory lives *per gate install on
  the machine itself* and any agent that logs in inherits it instead of
  carrying its own. Tiering is the open design question: a general memory area
  writable at Tier-1 (no signature) vs a **sensitive** area updatable only via
  a signed request; a third read-gated "confidential" level was floated but
  probably collapses into those two (owner's lean). Whether updates should be
  gated at all — freely written vs approval-routed — needs deep thought before
  any build; and the design interacts with multi-key gates / multi-login (#17):
  per-agent identity may shape per-area permissions.

- **Gated interactive session mode (#25).** A shell-*like* interactive prompt
  (history, `cd`/env that feel normal) where **every** command is still gated.
  The safe form is *not* wrapping a live `/bin/sh` — that is the read-only arms
  race on hard mode (persistent shell state, `eval`, history, interactive-program
  escapes like `:!sh`). Instead the gate *is* the shell: it reads a line, parses
  it into `argv` itself, classifies it, runs it via argv-exec (no `/bin/sh`),
  prints output, and loops, tracking cwd/env itself. Interactive sub-programs
  (`vim`, `mysql`, …) are handled by the per-service adapters (Feature 2) or
  blocked. **Depends on the #22 argv-exec foundation; build after it.**

- **Background-job verb (launch / poll / kill).** A first-class long-job
  capability so the agent can start a long command detached and poll it, instead
  of hand-rolling `nohup … & echo $!` (which trips the write classifier on the
  redirect/`&`). The gate owns the `nohup`/logfile/PID-dir plumbing (trusted)
  and classifies/approves **only the inner command**; `status`/`output` are
  reads, `kill` of an own-job is a low-risk control op. State lives in OS
  processes + a job dir on the target, so the gate stays stateless. Proposed
  agent tools: `job_run` (→ job handle + PID), `job_status` (→ running/exited +
  exit code + log tail), `job_kill` — with matching gate verbs `SSHGATE_JOB_RUN`
  / `SSHGATE_JOB_STATUS` / `SSHGATE_JOB_KILL` (the `SSHGATE_` prefix keeps them
  from colliding with a real command on the gate's command parse; the MCP tools
  are already namespaced under the `sshgate` server, so they stay unprefixed and
  consistent with `run`/`status`/`revoke_server`). **Recommended right after the
  grants/reveal/audit set, but NOT blocking the migration:** with a standing
  grant on the target box the manual `nohup` launch already auto-signs, so this
  is a UX upgrade rather than a prerequisite. A multi-server production run
  reinforced this and refined the shape: a `run_async` launcher plus **read-class**
  `job_status` / `job_tail` / `job_wait`, which also removes the brittle
  exact-string `nohup` launcher a `commands`-scoped grant must match verbatim.
  **Prerequisite before any foreground multi-GB transfer:** verify against the
  gate source whether an approved `run` execution is actually unbounded or has a
  client read-deadline / exec wall-clock cap — an unverified cap would kill a
  large `rsync` mid-transfer on the single most irreversible step.
  - *Context (settles three related questions):* multi-**connection**
    concurrency already works natively — sshd forks a separate gate process per
    connection and the gate is stateless per-connection, so multiple
    users/sessions are handled independently (cap = sshd `MaxStartups`/
    `MaxSessions`); there is no multiplexer to build. The only "a single agent
    shouldn't block on a long job" gap is closed by this async job handle, not by
    SSH multiplexing (the agent's turn is single-threaded). Live-output streaming
    to a **human** (progress bars, %) needs the tier-6b *streaming* enhancement
    — teeing the gate's already-redacted output to the live log as it arrives
    (the basic rolling log only captures each command's final output *after* it
    completes, so it is NOT a live intra-command view on its own); then
    `tail -f` shows real-time progress; full interactive Ctrl-C / PTY / "normal SSH terminal" is the
    gated interactive session (#25) — this job verb is the non-interactive
    fire-and-poll complement to it, not a duplicate.

- **Friendlier gate responses (#26).** When the gate denies a write (or any
  command needing a signature), return a clear, structured, agent-friendly
  message stating *what* is needed and *how* to get it ("this is a write — it
  needs an approved signature; request approval, then resubmit with the
  `SSHGATE_SIG` envelope") instead of a bare reject/kill. In an agent-driven flow
  this is the handshake that tells the agent to go get approval and resubmit.
  Applies to current single-command mode now and to the gated session (#25)
  later, where a write could optionally trigger inline approval.

- **Signed-at-rest redactor (deferred).** Strengthen the redaction path's signing
  posture and merge the deferred redactor work.

---

## Operational hardening (surfaced by a multi-server production run)

Driving a real multi-server operational workload through the gate surfaced a set
of reliability, safety, and ergonomics gaps. Ranked by impact. Several are
resolved for free by the "route approvals through the shared messaging layer"
anchor above and are marked *(subsumed)*.

- **Client sign-budget must outlast the approval window (fixed).** The MCP sign
  client's per-request budget was a hardcoded value far shorter than the human
  approval window, so the client abandoned the socket minutes before a human
  could be expected to approve — stranding an approved *or* denied verdict as an
  opaque "verdict undelivered" timeout on *every* verdict, not just a
  last-second deny. Now sourced from the single sigwire source of truth
  (`ClientSignTimeout > SignerHandlerTimeout > ApprovalWindow`) with a
  regression test, so it can never silently drift again. Follow-on: confirm the
  MCP host imposes no shorter per-tool-call deadline of its own.

- **Output-value redaction must be default-deny, not allowlist-by-name
  (security). — SHIPPED 2026-07-03 (P1-B).** The read path no longer relies on
  known field *names* alone: `standard` now carries a bounded generic
  default-deny net (the O(n) `scanGenericRuns` linear pass — telegram-token
  stitches + generic high-entropy runs behind a 3-class + ssh-line-veto +
  entropy-≥-3.5 gate), a live `Rule.Entropy` gate on broad-prefix rules, a
  widened `sshgate-sensitive-assignment` (JSON/camelCase/`*_HASH`/`*_SESSION`/
  `*_COOKIE`), and new openai-broad / github-fine-pat / zoho rules. All four
  sinks (agent output, MCP live log, approval display, gate audit) get it via
  `redactrules.Combined()`. Spec: `docs/proposed/redaction-widening-2026-07.md`.
  *Residual (all reviewed + accepted):* bare lowercase-hex secrets and
  unanchored tokens < 32 chars are still missed by design (see FUTURE.md
  limitation #8 / `thorough`'s looser gates); standard-base64 (`+`/`/`) and
  dot-/ANSI-split tokens are not reliably covered because the net's run
  alphabet is base64url (security-review F3 — documented in the spec §6). The
  keyword-dense scan cost (~+19% median) plus the generic pass's per-candidate
  1 KiB ssh-line back-scan (security-review F4 — a streaming-amplification
  concern only on remote-side newline-free candidate-dense output, e.g.
  `base64 -w0 bigfile`; the operator MCP does not re-scan received output) are
  the standing motivation for the Aho-Corasick / single-pass line-index item
  below — fold the per-`findMatches` line-position precompute into it.

- **Distinguish DENY from TIMEOUT at the agent surface; persist verdicts.** When
  a verdict is not delivered, the agent cannot tell "human denied" from "network
  hiccup" — the worst ambiguity for a near-irreversible write. Persist each
  resolved verdict server-side keyed by request id and add a read-only verb so
  the client can re-read the true outcome (approved/denied/timeout) after a lost
  response, mirroring the existing grant-list reconcile path. *(Largely subsumed
  — reliable delivery removes most of the ambiguity.)*

- **Per-command re-sign within an approved batch.** A single approval mints one
  short signature window for a whole multi-command batch, so slow early commands
  can expire the window and already-approved later commands then fail as
  expired. Re-sign each command at its own start, or return a structured
  expired/ran/skipped result instead of opaque per-command failures. A standing
  grant already mitigates this (granted commands re-sign fresh).

- **Targeted single-server reachability check (`ping`). _(shipped — W5-10)_**
  The `ping` tool is a cheap, short-timeout, single-server up/down check
  (READ-class, no approval, no signer), so probing one box does not cost a
  fan-out across every server. Still open: an optional **background monitor**
  that watches reachability continuously and surfaces a notification when a
  threshold is crossed (consecutive drops / latency spike) — the
  push-notification path is a natural fit for the shared-messaging anchor above.

- **Per-command output cap. _(shipped — W5-11)_** run/run_batch cap each
  command's structured stdout and stderr (independently) with an explicit
  truncation marker, so a single large read (a deep directory walk) cannot
  exhaust the agent's context. Default-on at 256 KiB per stream, overridable per
  call via `max_output_bytes` (0 = unlimited). The cap lives in the tools layer
  only — it never touches the update_gate readback or the box→box transfer
  envelope.

- **`stop_on_error` default for read batches. _(shipped — W5-12)_** run_batch now
  defaults to continue-on-error for an all-read batch (reads legitimately exit
  non-zero — an absent file, an empty crontab — so aborting on the first is the
  wrong default) and keeps stop-on-error for any batch containing a write (where
  ordering matters). An explicit `stop_on_error` always wins.

- **Concurrent gated approvals *(subsumed)*.** Firing several gated calls at once
  can cross-reject when the local tool-permission prompt and the approval channel
  assume a single pending request. Queue concurrent gated calls or key multiple
  in-flight approvals by request id. Routing approvals through the shared layer,
  with per-request delivery, is the clean fix.

---

## Deferred

- **Tier-3 hosted signer (the real boundary).** The headless backend exists — a
  signing engine, N-of-M approval, WebAuthn/TOTP auth, and a plane-separated API.
  What remains to ship it as a product: the rendered web UI (the backend serves
  JSON only), the Telegram channel on the hosted signer, a stable HTTPS hostname
  (passkeys are origin-bound), and deployment. This is the larger, recommended
  investment for anyone who needs an approval boundary that holds against a
  privileged rogue agent on the operating machine. See
  [approval-architecture.md](approval-architecture.md).

- **Redaction scanner performance work.** An Aho-Corasick / keyword-prefilter
  rewrite of the redaction scanner for large outputs. Security-sensitive, so
  deprioritized behind correctness work.

- **Sign-wire struct consolidation.** Internal cleanup of the signed-command
  request structures shared between the signer and the MCP, best done alongside
  the signed-at-rest envelope work.

---

Deferred / longer-term directions and the honest limitations of the shipped
surface: see [FUTURE.md](FUTURE.md).
