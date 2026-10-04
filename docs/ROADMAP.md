# SSHGate Roadmap

> **What to build next is in [BUILD-PLAN.md](BUILD-PLAN.md).** That file is the
> committed build order, with steps and definitions of done. This roadmap holds
> the release status and the features that are planned or possible but **not yet
> scheduled**. When an item here is scheduled, its definition moves to the build
> plan and the entry here becomes a pointer.

Entries are grouped, not strictly ordered. Design rationale for individual items
lives in the docs linked inline. For the security model these items extend, see
[THREAT-MODEL.md](THREAT-MODEL.md), [design.md](design.md) and
[approval-architecture.md](approval-architecture.md). Known limitations and
parked directions are in [FUTURE.md](FUTURE.md).

Numbers such as #22 are the project's stable item numbers; they are kept so that
other docs and commit messages can refer to an item.

---

## Release status & versioning

**SSHGate is pre-1.0 on purpose.** Version `1.0` is reserved for the point where
SSHGate is a fully stable, productized tool that anyone can drop into production
and rely on continuously — the bar is "as unremarkable to run in production as
the OS itself," not "it works for us." Until then every version is `v0.x`, and
the version number must never imply the product is finished.

**The current code line is v0.1.5** (the `VERSION` file). There are no git tags
or GitHub releases yet; install from a clone (see [INSTALL.md](../INSTALL.md)).
v0.1.5 contains the shipped baseline listed under *Already shipped* below, and
**phase 1 of the kernel read jail (#22)** — see
[CHANGELOG.md](../CHANGELOG.md).

**The next milestone is v0.2, the "daily-usable" release. It is not cut.** v0.2
is tagged only when its release gates pass:

- **#22 read jail** — the remaining phases (network as a permission, the host
  pin, labels, daemon-read verbs inside the jail) are work item 1 of
  [BUILD-PLAN.md](BUILD-PLAN.md).
- **#76 approval-assist and #65 async approval** — work item 2 of
  [BUILD-PLAN.md](BUILD-PLAN.md).
- **The hosted signer's policy authority (Tier 3)** — the hosted signer is a
  foundation today; its policy authority still needs design and implementation
  work before it is a release-ready approval boundary (see *Deferred* below).
- **The rest of the declared v0.2 queue.** The maintainers' 2026-07-11 ruling
  keeps v0.2's original scope: product shape and packaging (#74), including the
  hosted signer as an embeddable library and a simple reference web app; bundled
  DevOps skills (#75); friendlier gate responses (#26); multiple gate modes
  (#80); the background-job verb; the SQL service adapter (#24); transparent
  gated SSH (#81, work item 3); and the gated interactive session (#25). Items
  not yet in [BUILD-PLAN.md](BUILD-PLAN.md) are described under
  *Next (unscheduled)*.
- **The combined release checks** — cross-review and integration of the
  outstanding fixes, `make preflight`, `make e2e`, the jail test lanes, and a
  public-hygiene review, followed by one coordinated version, changelog and
  distribution cut.

No interim release is cut before that. Everything not listed here is post-v0.2
unless the maintainers schedule it into [BUILD-PLAN.md](BUILD-PLAN.md) first.

---

## Scheduled (see the build plan)

- **Read jail (#22).** The kernel jail is the read-only wall for reads, and it
  replaced the earlier plan to execute reads from a parsed `argv` without a
  shell. Phase 1 is built and in v0.1.5; phases 2–7 are work item 1 of
  [BUILD-PLAN.md](BUILD-PLAN.md).
- **Asynchronous approval lifecycle (#65) and LLM approval-assist (#76)** —
  work item 2: a reason on every write, durable approval records,
  sign-at-approval, an advisory AI assessment of each request, async dispatch
  with `await_approvals`/`list_pending_approvals`, and operator queue controls.
  Still unscheduled: an optional local watcher that wakes an idle agent when a
  verdict lands (harness-specific; the polling tools stay the portable core).
- **Transparent gated SSH from a normal terminal (#81)** — work item 3, the
  signature terminal.
- **Hosted signer as a remote MCP server** — work item 4.
- **Secret injection** — work item 5.

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
- **Kernel read jail, phase 1 (#22).** On hosts with unprivileged user
  namespaces and Landlock, every read runs in the `ro-v1` jail; see
  [THREAT-MODEL.md](THREAT-MODEL.md).
- **Inline secret redaction of command output** in the gate (all commands,
  reads and writes; bypassed only by an approved secret-reveal).
- **Local Telegram signer** with separate-Unix-user key isolation, one-tap
  approval, and bulk (single-tap, N-command) approval.
- **Standing grants, secret-reveal, per-server binding, leveled audit trail.**
  Signer-issued **standing grants** (scope `all` or an exact command-set, ≤24h,
  server-bound, revocable) for unattended write windows; an approved
  **secret-reveal** that bypasses output redaction for a single signed command;
  **per-server identity** binding each signature to the target's SSH host-key
  fingerprint (closes cross-server replay); a **two-tier audit trail** — a
  gate-side append-only authoritative log plus an MCP-side rolling live view; a
  60s default signature window; and `servers.json` 0600. Design:
  [docs/proposed/feature3-grants-reveal-audit-binding.md](proposed/feature3-grants-reveal-audit-binding.md).
- **Gate auto-update (`update_gate` / `SSHGATE_UPDATE`) + verified release
  channel.** A signed control verb that updates the gate binary in place on an
  already-registered server — **signed** (through the master key like any other
  write), **versioned** (returns the installed SHA-256 + build revision),
  **fail-closed** (hash mismatch / wrong-arch binary / Tier-1 all refuse and
  write nothing), and **audited**. The agent supplies only the alias; the MCP
  hashes the operator's locally staged gate binary and the human approves a
  distinct "GATE BINARY UPDATE" banner bound to that exact SHA-256; a standing
  grant never auto-signs it. The committed `dist/gate/` artifact and the
  reproducible-build CI check anchor the approved hash off the machine. Design:
  [docs/proposed/sshgate-update-verb-2026-07.md](proposed/sshgate-update-verb-2026-07.md).
- **Encrypted box-to-box `transfer`** of secret files between two registered
  servers under one approval, with the MCP relaying only ciphertext.
- **Forced-command hardening.** The `authorized_keys` line leads with
  `restrict` and pins `no-pty`, no forwarding and no `~/.ssh/rc`
  (golden-tested; see [THREAT-MODEL.md](THREAT-MODEL.md)).
- **`ping`, per-command output cap, `stop_on_error` default** — see
  *Operational hardening* below.

---

## Decided directions

These are maintainer decisions that shape future work; they are recorded here so
they are not reopened by accident.

- **Approvals stay on the signer's own channel.** Routing approvals through a
  shared messaging layer or an agent harness's permission prompt was considered
  and rejected: the approval allowlist, delivery credentials and reload control of
  such a layer live in the agent's own user account, so a compromised on-machine
  agent could edit the allowlist or bind a fake delivery endpoint and approve
  itself. The local signer keeps its own, isolated Telegram poller. The poller
  was reviewed afterwards; its one real gap (an unbounded Telegram HTTP client that
  could hang the poll loop on a black-holed connection) is fixed. A harness or
  channel verdict may never replace the signature: the gate verifies the
  signature itself.
- **Product shape.** One repository, six installable parts with unchanged names
  and binaries: the Claude Code plugin; the MCP server binary (also published on
  its own, which is what makes the tool usable from Codex, Gemini CLI, Cursor and
  other MCP clients); the `sshgate` CLI (the human-only control plane: `pubkey`,
  `add`, `revoke`, `xfer-*`); the local Telegram signer (the default, stronger
  Tier-2 channel); the hosted signer as the embeddable `pkg/signerkit` library
  plus a small reference web app; and the gate (never installed by the user
  directly; provisioning pushes it). The install story is three roles: agent kit
  (Tier 1) → plus local signer (Tier 2) → plus hosted signer (Tier 3). The local
  and hosted signers are two thin front-ends over one shared signer core
  (`signerkit`), not a fork; key custody is behind `crypto.Signer` so it can be
  backed by a KMS or HSM.
- **No in-place tier flip** (see #17 below): read-only stays read-only;
  re-tiering is an out-of-band re-provision.

---

## Next (unscheduled)

- **Bundle DevOps skills with the plugin (#75).** In real use an agent driving
  the gate sometimes finds the problem fast and sometimes just keeps reading
  without a method. Ship curated skills for Linux server **debugging**, server
  **setup** and **installation** alongside the existing
  `debugging-remote-servers` skill, so any agent using SSHGate has an efficient,
  opinionated playbook out of the box.

- **Multiple gate enforcement modes (#80).** The gate today has one behaviour:
  allow or deny driven by the read/write classifier. Add selectable per-host
  modes, an analogue to a coding agent's permission modes:
  (1) **strict allowlist** for high-threat hosts — only an explicit exact command
  set runs, everything else needs approval; (2) **auto** — today's classifier
  routing (recognized reads run unsigned, writes and unknowns route to approval);
  (3) **ask** — every command routes to approval, with an "always allow this exact
  command" setting that allowlists that one command and nothing else.
  Deliberately **no allow-everything mode** (it would make the gate pointless);
  time-limited standing grants stay the escape hatch. Allowlist growth has two
  selectable sub-paths: **sign-to-add** (an approved command joins the allowlist)
  or **out-of-band only** (the gate can never widen its own allowlist; new
  entries need an edit over a separate full-access SSH key — the highest-assurance
  posture). A strict mode could pin resolved IP addresses rather than names. A
  declarative permit/forbid policy layer is a possible later direction. Design
  first.

- **Friendlier gate responses (#26).** When the gate denies a write (or any
  command needing a signature), return a clear, structured, agent-friendly
  message stating *what* is needed and *how* to get it ("this is a write — it
  needs an approved signature; request approval, then resubmit with the
  `SSHGATE_SIG` envelope") instead of a bare refusal. In an agent-driven flow
  this is the handshake that tells the agent to go get approval and resubmit.
  A later extension is an `explain` dry-run ("why would this auto-approve / why
  did it need a tap") that renders the classifier's reasoning.

- **Interactive prompt / confirmation / password forwarding (#23, Feature 1).**
  A remote command can trigger an interactive prompt mid-run — a `sudo` password
  prompt, a `[Y/n]` confirmation. The gate runs commands non-interactively, so
  today the operator has to SSH in by hand to answer. Detect a prompt or input
  stall, surface it to the operator, capture the response and write it to the
  command's stdin; passwords are never logged or echoed. This needs a PTY, which
  the forced-command key line forbids today (`no-pty`), so it must be designed
  together with the signature terminal (BUILD-PLAN work item 3, step T0). A
  design proposal exists at
  [docs/proposed/feature1-interactive-prompt-forwarding.md](proposed/feature1-interactive-prompt-forwarding.md).

- **Read-only SQL via per-service adapters (#24, Feature 2).** Full SQL access
  over SSH is all-or-nothing today. Support **read-only** SQL queries against
  common engines (PostgreSQL, MariaDB, SQLite, …), with **write** SQL requiring a
  signature — the same read/write-plus-sign model the gate applies to shell,
  applied to SQL. The shape is a per-service allowlist **adapter** with its own
  grammar, built one engine at a time. The typed grammar and canonical argv for
  the daemon-read verbs (BUILD-PLAN step P3.1) is the closest existing piece and
  should be reused, not designed twice. A design proposal exists at
  [docs/proposed/feature2-service-adapters-argv-exec.md](proposed/feature2-service-adapters-argv-exec.md);
  its sandbox section is superseded by the read jail.

- **Publish to agent marketplaces and registries.** Publish the plugin and the
  MCP server to the main agent marketplaces and MCP registries once the product
  shape above is verified with other agents (Codex, Gemini CLI and others).

---

## Planned (design needed)

- **Multi-key gates + provisioning exposure window (#17, redefined).** The old
  "in-place Tier-1 → Tier-2 upgrade" is **rejected**: any unsigned tier-flip path
  the CLI could exercise is a path the agent could emulate — read-only is
  read-only, full stop; re-tiering stays an out-of-band re-provision. In its
  place, two directions: (a) **multiple signer keys per gate** (per-agent
  identity — each agent its own keypair, no shared-key trust), version-aware
  `sshgate add` (upgrade an older installed gate, defer to a newer one, notify
  either way), with single-vs-multiple gate binaries and signer topology as open
  design questions; (b) **shrink the plain-key exposure window in `add`** (run
  add first, it retries while the operator pastes the key out-of-band, and the
  gate swap lands within milliseconds; the fully manual install stays available).
  Further ideas: a combined paste-and-add one-liner (docs only, available today);
  a self-contained provisioning command embedding the pubkey, runnable from any
  admin machine; a one-shot server-side install that never writes a plain key
  line at all; and application-driven enterprise provisioning (pubkey exposed on
  the agent surface, install kept behind the application's own auth). Per-agent
  identity could be backed by short-lived per-agent certificates (see BUILD-PLAN
  work item 4, which plans SSH certificates for the hosted signer), with an
  instant identity lock independent of grant expiry. Full capture:
  [docs/proposed/multi-key-gates-and-add-exposure-2026-07.md](proposed/multi-key-gates-and-add-exposure-2026-07.md).
  Not scheduled; design questions go through critique and review before any
  build.

- **Reconcile tier on the probe-idempotent re-add path.** When `sshgate add`
  re-runs against an already-gated host (the probe-first idempotency that
  recovers a lost `servers.json`), it registers the **caller-supplied** tier
  flag without checking the remote's actual tier: the `SSHGATE_VERSION` probe is
  tier-blind, and `gate.pub` is only uploaded by the full provisioning flow. A
  mismatched flag records wrong state: a read-only host re-added without
  `--read-only` registers as writable, and every write then costs a human
  approval tap before failing with exit 77 at the gate; the inverse
  under-reports a signed-write host as read-only. **Every mismatch direction
  fails closed** (the gate, not the registry, is the enforcement point), so this
  is a state and UX defect, not a boundary break. Likely fix: extend the gate's
  version reply with an additive tier token (for example
  `SSHGATE_VERSION rev=<v> tier=ro|rw`) so the probe path can check the flag it
  registers.

- **Per-gate memory subsystem.** Give each target server a first-class,
  centrally maintained **memory**: an indexed set of markdown/instruction files
  that an agent reads and updates through a gate verb, so operational memory
  lives with the gate install on the machine itself and any agent that logs in
  inherits it. Open questions: a general memory area writable at Tier 1 (no
  signature) versus a **sensitive** area updatable only by a signed request (a
  third "confidential" level probably collapses into those two); whether updates
  should be approval-routed at all; and how it interacts with per-agent identity
  (#17).

- **Gated interactive session mode (#25).** A shell-*like* interactive prompt
  (history, `cd` and environment that feel normal) where **every** command is
  still gated. The safe form is *not* wrapping a live `/bin/sh` — that is the
  read-only arms race on hard mode (persistent shell state, `eval`, history,
  interactive-program escapes like `:!sh`). Instead the gate *is* the shell: it
  reads a line, parses it into `argv` itself, classifies it, runs reads through
  the read jail, prints output, and loops, tracking cwd and environment itself.
  Interactive sub-programs (`vim`, `mysql`, …) are handled by service adapters
  (#24) or blocked. Its session model is decided in the signature terminal's
  design step (BUILD-PLAN work item 3, step T0).

- **Background-job verb (launch / poll / kill).** A first-class long-job
  capability so the agent can start a long command detached and poll it, instead
  of hand-rolling `nohup … & echo $!` (which the classifier routes to approval
  because of the redirect and `&`). The gate owns the launcher, log file and
  PID-directory plumbing and classifies and approves **only the inner command**;
  `status` and `output` are reads, and killing an own job is a low-risk control
  operation. State lives in OS processes and a job directory on the target, so
  the gate stays stateless. Proposed agent tools `job_run` (→ handle + PID),
  `job_status` / `job_tail` / `job_wait` (read-class) and `job_kill`, with gate
  verbs `SSHGATE_JOB_RUN` / `SSHGATE_JOB_STATUS` / `SSHGATE_JOB_KILL`. It must be
  built so that a launched read still runs inside the read jail and a launched
  write is still individually signed; a launcher built on `nohup sh -c` would cut
  a hole through both. With a standing grant the manual `nohup` launch already
  auto-signs today, so this is a UX upgrade, not a prerequisite. Before any
  foreground multi-GB transfer, check whether an approved `run` has a client
  read deadline or wall-clock cap that would kill a large `rsync` mid-transfer.
  - *Context:* concurrency across connections already works — sshd starts a
    separate gate process per connection and the gate is stateless — so there is
    no multiplexer to build. Live progress output to a **human** needs streaming
    of the gate's already-redacted output to the live log as it arrives (the
    rolling log today records a command's output only after it completes). A full
    interactive terminal is the gated session (#25); this job verb is its
    non-interactive fire-and-poll complement.

- **Classifier, approval and audit refinements.** Ideas collected from a survey
  of comparable tools, not yet scheduled: record the parsed command as part of
  the audit record; bind an approval to a hash of the exact payload so it
  invalidates if the command drifts; unwrap more wrappers (`sudo -u`, `env A=B`,
  `nice`, `time`) and walk every node of the parsed command; keep growing the
  bypass corpus (`bash -c`, `eval`, `xargs`, `python -c`, `base64 | sh`) as
  regression tests, never letting a clean parse skip the fail-closed fallback;
  back grant and session windows with certificate expiry so the credential
  itself enforces the limit; a restart-safe kill switch for standing grants that
  defaults off; disable standing grants for commands the classifier cannot fully
  resolve; carry an agent-supplied rationale and deterministic risk annotations
  ("deletes files", "changes firewall", "may print credentials") to the approval
  card (the rationale part is in BUILD-PLAN work item 2).

- **Operator redaction control plane (#82).** An operator-configurable redaction
  layer that main does not have: a signed, append-only redactlist/unredactlist
  with provenance and audit, a signed `SSHGATE_CMD` meta-command envelope with a
  gate dispatcher and sign matrix, a signer `sign-envelope` kind, MCP
  `redact.*`/`unredact.*` tools, operator anchor literals, and a
  standard/thorough `redact.mode` switch (plus a depth-1 decode pass). The
  implementation lives on the `feat/v1.2-redactor` branch but is not mergeable —
  main rewrote the redaction scanner underneath it — so reviving it is a **port
  of the design onto the current scanner**, reusing the branch's store, envelope
  and signer pieces and its signing-model design doc. The branch's "filemode"
  heuristic may no longer be needed on hosts where reads run in the kernel jail.

---

## Operational hardening (surfaced by a multi-server production run)

Driving a real multi-server operational workload through the gate surfaced a set
of reliability, safety and ergonomics gaps, ranked by impact.

- **Client sign-budget must outlast the approval window (fixed).** The MCP sign
  client's per-request budget was shorter than the human approval window, so the
  client gave up minutes before a human could be expected to approve, turning
  every verdict into an opaque "verdict undelivered" timeout. It now comes from
  the single sigwire source of truth
  (`ClientSignTimeout > SignerHandlerTimeout > ApprovalWindow`) with a regression
  test. Follow-on: confirm the MCP host imposes no shorter per-tool-call deadline
  of its own.

- **Output-value redaction is default-deny, not allowlist-by-name (shipped).**
  The read path no longer relies on known field *names* alone: `standard` carries
  a bounded generic default-deny net (the linear `scanGenericRuns` pass —
  telegram-token stitches and generic high-entropy runs behind a 3-class,
  ssh-line-veto and entropy ≥ 3.5 gate), a live `Rule.Entropy` gate on
  broad-prefix rules, a widened `sshgate-sensitive-assignment` rule
  (JSON/camelCase/`*_HASH`/`*_SESSION`/`*_COOKIE`), and new openai-broad,
  github-fine-pat and zoho rules. All four sinks (agent output, MCP live log,
  approval display, gate audit) get it via `redactrules.Combined()`. Spec:
  [docs/proposed/redaction-widening-2026-07.md](proposed/redaction-widening-2026-07.md).
  *Accepted residuals:* bare lowercase-hex secrets and unanchored tokens under 32
  characters are missed by design (see FUTURE.md limitation #8); standard-base64
  (`+`/`/`) and dot- or ANSI-split tokens are not reliably covered because the
  net's alphabet is base64url (documented in the spec §6). The extra scan cost and
  a per-candidate 1 KiB back-scan (a streaming-amplification concern only on
  newline-free, candidate-dense output such as `base64 -w0 bigfile`) motivate the
  scanner performance item under *Deferred*.

- **Distinguish DENY from TIMEOUT at the agent surface; persist verdicts.** When
  a verdict is not delivered, the agent cannot tell "human denied" from "network
  hiccup" — the worst ambiguity for a near-irreversible write. *(Scheduled in
  [BUILD-PLAN.md](BUILD-PLAN.md) work item 2: each verdict is kept in the signer's
  approval record, and the client re-reads it by request id after a lost
  response.)*

- **Per-command re-sign within an approved batch.** One approval mints one short
  signature window for a whole multi-command batch, so slow early commands can
  expire the window and already-approved later commands then fail as expired.
  Re-sign each command at its own start, or return a structured
  expired/ran/skipped result. A standing grant already mitigates this (granted
  commands re-sign fresh). Work item 2's sign-at-approval changes this area;
  re-check after it lands.

- **Targeted single-server reachability check (`ping`) — shipped.** A cheap,
  short-timeout, single-server up/down check (read-class, no approval, no
  signer). Still open: an optional **background monitor** that watches
  reachability and notifies the operator when a threshold is crossed (consecutive
  drops, latency spike).

- **Per-command output cap — shipped.** `run` and `run_batch` cap each command's
  stdout and stderr independently, with an explicit truncation marker, so one
  large read cannot exhaust the agent's context. Default 256 KiB per stream,
  overridable per call with `max_output_bytes` (0 = unlimited). The cap lives in
  the tools layer only; it never touches the `update_gate` readback or the
  `transfer` envelope.

- **`stop_on_error` default for read batches — shipped.** `run_batch` defaults
  to continue-on-error for an all-read batch (reads legitimately exit non-zero)
  and keeps stop-on-error for any batch containing a write. An explicit
  `stop_on_error` always wins.

- **Concurrent gated approvals.** Several gated calls fired at once can
  cross-reject when the local tool-permission prompt and the approval channel
  assume a single pending request. *(Scheduled in [BUILD-PLAN.md](BUILD-PLAN.md)
  work item 2: every approval is its own record keyed by request id.)*

---

## Deferred

- **Tier-3 hosted signer: policy authority and extensions (#83).** The
  `pkg/signerkit` library and `sshgate-signer-server` provide a foundation, but
  the hosted policy authority still needs design and implementation work before
  it is a release-ready approval boundary; that is a v0.2 release gate (see
  above). A stable HTTPS hostname is a deployment prerequisite because passkeys
  and mutation-origin checks are origin-bound. Deferred extensions: per-client
  credentials, hosted Telegram/grants/reveal/transfer, HA, a policy-management UI,
  and metrics. See [approval-architecture.md](approval-architecture.md) and
  [the deployment guide](../src/signer-server/README.md).

- **Gate-side dual-key rotation.** `signerkit.RotateTo` is an atomic cut-over:
  the gate loads exactly one signer public key, so during a rotation in-flight
  envelopes signed with the old key are refused until every gate is
  re-provisioned. Zero-downtime rotation needs the gate to accept an old and a
  new key during a rollover window. Until then rotation is planned maintenance,
  not a live hot-swap.

- **Redaction scanner performance work.** An Aho-Corasick / keyword-prefilter
  rewrite of the redaction scanner for large outputs, with a single-pass line
  index. Security-sensitive, so it waits behind correctness work.

- **Sign-wire struct consolidation.** Internal cleanup of the signed-command
  request structures shared between the signer and the MCP, best done alongside
  the signed-at-rest envelope work.

---

Known limitations of the shipped surface and parked directions: see
[FUTURE.md](FUTURE.md).
