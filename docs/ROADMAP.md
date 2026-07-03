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
  agent tool. The agent surface is exactly eight tools (`run`, `run_batch`,
  `list_servers`, `status`, `revoke_server`, `request_grant`, `revoke_grant`,
  `list_grants`); there is deliberately no `add_server` tool, so the agent can
  never expand its own reach.
- **Read-only (Tier-1) and signed-write (Tier-2) provisioning**, selectable at
  `sshgate add` time.
- **Inline secret redaction on the read path** in the gate.
- **Local Telegram signer** with separate-Unix-user key isolation, one-tap
  approval, and bulk (single-tap, N-command) approval.

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

- **Standing grants, secret-reveal, per-server binding, audit trail (in progress).**
  A bundle that all touches the signed payload, so it ships as one wire change:
  signer-issued **standing grants** (scope `all` or an exact command-set, ≤24h,
  server-bound, revocable) for unattended write windows; an approved
  **secret-reveal** that bypasses output redaction for a single signed command;
  **per-server identity** binding each signature to the target's SSH host-key
  fingerprint (closes cross-server replay); a **two-tier audit trail** — a
  gate-side, separate-user, append-only authoritative log plus an MCP-side
  rolling full-output live view; plus a tighter 60s default signature window and
  `servers.json` 0600. Design at
  [docs/proposed/feature3-grants-reveal-audit-binding.md](proposed/feature3-grants-reveal-audit-binding.md).

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

- **In-place Tier-1 → Tier-2 upgrade (#17).** Today, changing a server from
  read-only to signed-write means revoking and re-provisioning it. Provide a
  smoother in-place upgrade, including how the upgrade is surfaced and wired in
  the setup flow.

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

- **Gate auto-update (`SSHGATE_UPDATE`).** A signed control verb to update the
  gate binary in place (a stub handler already exists in the gate). Deferred
  until its security is designed separately: an update path is a code-execution
  path, so it must be at least as strict as the signing model — signed,
  versioned, fail-closed, and audited. Until then, a changed gate is redeployed
  via the `sshgate` CLI (revoke + re-add).

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

- **Targeted single-server reachability check (`ping`).** A cheap, short-timeout,
  single-server up/down check (READ-class, no approval), so probing one box does
  not cost a full SSH dial timeout or a fan-out across every server. Optionally a
  **background monitor** that watches reachability continuously and surfaces a
  notification when a threshold is crossed (consecutive drops / latency spike) —
  the push-notification path is a natural fit for the shared-messaging anchor
  above.

- **Per-command output cap.** An optional output byte cap with an explicit
  truncation marker, so a single large read (a deep directory walk) cannot
  exhaust the agent's context. Reads should be safe-by-default against
  multi-megabyte output.

- **`stop_on_error` default for read batches.** Read/inventory batches
  legitimately contain commands that exit non-zero (absent file, empty crontab);
  aborting the whole batch on the first is the wrong default for reads. Default
  to continue-on-error for read-classified batches; keep stop-on-error for write
  batches where ordering matters.

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
