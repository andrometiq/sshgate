# SSHGate Roadmap

> **What to build next is in [BUILD-PLAN.md](BUILD-PLAN.md).** That file is the
> committed build order, with steps and definitions of done. This roadmap is the
> list of planned and possible features that are not yet scheduled, plus release
> status and history. When an item here is scheduled, its definition moves to the
> build plan and the entry here becomes a pointer.

The forward-looking work for SSHGate, roughly in priority order. Design rationale
for individual items lives in the design and decision docs referenced inline.

For the security model these items extend, see [design.md](design.md) and
[approval-architecture.md](approval-architecture.md).

---

## Release status & versioning

**SSHGate is pre-1.0 on purpose.** The current code line is **v0.1.4**. Version
`1.0` is deliberately reserved for the point where SSHGate is a fully stable,
productized tool that anyone can drop into production and rely on continuously —
the bar is "as unremarkable to run in production as the OS itself," not "it works
for us." Until then every release is `v0.x`, and the version number must never
imply the product is finished.

**The next release is v0.2** — the "daily-usable" milestone — but it is **not cut**.
The shipped baseline includes the transfer feature and the 2026-07 release-polish
work (security floor, classifier reduction, ergonomics, installer, redaction, CI,
documentation, and changelog). That baseline is not a claim that the full v0.2
scope is built, integrated, or release-green.

**v0.2 still has several release-critical chains.** #80's hosted policy authority
(Units 3/4) remains design and implementation work. #76 approval-assist and #65
async approval are scheduled as work item 2 of [BUILD-PLAN.md](BUILD-PLAN.md).
Isolated release-truth, test, and public-hygiene fixes also still need
cross-review, integration, and the combined release gates; the final coordinated
version, changelog, and distribution cut comes only after that work is settled.

**#22 — the argv-exec structural classifier fix plus kernel confinement — remains a
safeguard-gated v0.2 blocker** (promoted from a later release on 2026-07-10). The
read/write classifier is a fail-closed *heuristic*, and adversarial review has found
read-as-write bypass classes. On a Tier-1 read-only host the classifier is the only
gate, so each such gap is a real bypass. #22 replaces the heuristic with execution
from a parsed `argv` — the classifier's view becomes exactly what executes — plus
kernel-level confinement, a structural cure rather than another per-tool patch. The
dependent tail follows #22: the background-job verb, #26 explain rendering, #76 risk
annotations, then #24 → #81 → #25. See THREAT-MODEL.md for the honest current
posture ("the classifier only routes; it is not a proof").

**#22 status:** the jail is the read-only wall, and replaces the argv-exec read
path. Phase 1 of the read jail is built, unreleased; its current state and the
remaining Phases 2–7 are work item 1 of [BUILD-PLAN.md](BUILD-PLAN.md).

**Scope ruling (owner, 2026-07-11, from the feature-table review):** v0.2 keeps its
declared scope — the shipped baseline, the ordered v0.2 queue, and #22 — and is **not
tagged until #22 clears the safeguard hold and all preceding release gates pass**. No
interim release is cut. Two explicit scope additions are (a) the **hosted signer as
an embeddable library** callable from any web application, and (b) a **simple
reference web application** as the usable default surface. Everything not in the
ordered v0.2 queue under *Work ordering* is post-v0.2 (v0.3+).

---

## Competitive research (2026-07-11) — findings folded in

A full competitive sweep of the SSHGate-class landscape was run before this freeze
(code-grounded teardown of every same-class repo + an adversarially-verified web
sweep of the broader products). The full cited report is retained in the
project's private research record; the public conclusions are captured below.

**Positioning result (informs #74 product shape):** no surveyed tool does true
*per-command* human approval for SSH — Teleport/StrongDM gate at role/resource/
session granularity (Teleport issue #12117: per-command SSH restriction "would
require a code change"); the 2026 MCP-gateway cluster (Airlock, Preloop, Hoop,
aipermission, McpSshProxy, mcp-ssh) gates at the MCP/tool layer, and the client-side
ones (pi-permissions) are defeatable by `bash -c "ssh …"`. SSHGate's triad —
**cryptographic forced-command boundary + per-command read/write classification +
planned kernel confinement** — is the defensible, differentiated position. Teleport's
own BPF docs (kernel-level `session.command` argv capture, built because shell-text
recording is defeated by `base64|sh`/uploaded-scripts/echo-off; and BPF framed as
"audit, not a substitute for an LSM") independently **validate the #22 argv-exec +
Landlock/seccomp direction and its ordering** (enforcement is the boundary; argv
auditing is complementary).

**Borrow-worthy refinements, mapped onto existing items** (no re-prioritization —
these sharpen items already below; the feature-table review decides scheduling):

- **#22 (argv-exec):** capture the parsed argv as the audit record (classifier view
  == execution view == audit view), mirroring Teleport BPF `session.command`; add an
  approval **payload-hash + stale-detection** (aipermission) so a write-approval is
  bound to the exact argv and auto-invalidates on drift; adopt pi-permissions'
  **wrapper-unwrapping** (`sudo -u`/`env A=B`/`nice`/`time`) + **AST-walk-every-node**
  technique and its `bash -c`/`eval`/`xargs`/`python -c`/`base64|sh` **bypass corpus**
  as acceptance tests (alongside `BYPASS-CATALOGUE.md`); never let a "clean parse"
  skip the fail-closed fallback.
- **#17 (multi-key identity):** back per-agent identity with **short-lived per-agent
  certs** (Teleport Machine ID / `tbot`, OSS-proven); add an **instant key/identity
  lock** (Teleport Session Locks) independent of grant expiry; consider **client-IP
  pinning** on the gate channel (Teleport IP-pinning) to blunt credential pivot.
- **#65 (async approval) / #81 (transparent terminal):** consider backing grant /
  session windows with **certificate expiry** (`ssh-keygen -V '+5m'`) so the limit is
  enforced by the credential itself, not only a gate-side timer; add a **restart-safe
  kill-switch that defaults OFF** so standing grants never silently re-arm
  (aipermission); a **`complete`/uncertainty flag disabling standing grants** when the
  classifier can't fully resolve a command (pi-permissions).
- **#76 (approval-assist):** carry an agent-supplied **per-write rationale** and
  surface it at the tap (AgentGate/Teleport reason field) — the deterministic
  companion to the LLM summary; add deterministic **risk annotations** ("deletes
  files"/"changes firewall"/"may print credentials", aipermission `command_policy`).
- **#80 (gate modes):** OpenClaw ships a 5-mode superset (deny/allowlist/ask/auto/
  full) — validates the design; adopt deny/allowlist/ask/auto and keep the
  no-allow-everything rule (skip "full"); cedws' default-deny hostname/IP/CIDR
  allowlist is a clean reference for strict mode (**pin resolved IP**, avoiding cedws'
  client-name DNS bypass); a declarative permit/forbid policy layer (StrongDM Cedar,
  approval-folded-into-evaluation) is a possible v0.3+ direction, not a v0.2 commit.
- **#24 (service adapters):** the multi-protocol gateways (Hoop) and aipermission's
  **bounded per-capability named-action allowlists** (no raw kubectl/psql) validate
  the adapter direction.
- **#26 (friendlier responses):** a **`/ssh-policy explain` dry-run** ("why would this
  auto-approve / why did it need a tap", pi-permissions) is strong classifier-trust UX.
- **New small hardening/verification task (filed):** audit the forced-command
  `authorized_keys` line for OpenSSH `restrict` / `no-pty` / no-agent-forwarding /
  no-port-forwarding / no-user-rc, and confirm local-state writers (grants/keys/
  session) meet the umask-0077 + symlink-reject (`O_NOFOLLOW`) + atomic-rename bar
  (jeprecated / pi-permissions hygiene). Cheap, high-assurance.

---

## Work ordering (owner direction, 2026-07-11): safeguard-sensitive work goes last

> The committed order of scheduled work is now [BUILD-PLAN.md](BUILD-PLAN.md):
> #22 Phases 2–7, then #76/#65, then #81 and the items after it. Where the
> sequence below differs, the build plan governs. This section records how the
> v0.2 queue was ordered and keeps the relative order of items not yet scheduled.

The #22 argv-exec + kernel-confinement work — and the adversarial classifier
**bypass corpus** that feeds it — tripped an automated model safeguard on 2026-07-10
(false positive; a defensive self-test of our own gate — a review request is filed).
Owner call (2026-07-11): **schedule that exact class of work LAST**, gated on the
safeguard being cleared, and do everything that does *not* trip it first.

- **Safeguard-sensitive → LAST (do not start until the flag clears):** #22
  (argv-exec + Landlock/seccomp); the #22-folded classifier refinements (argv-audit
  capture, approval payload-hash + stale-detection, wrapper-unwrapping + AST-walk +
  the bypass corpus); **#81** transparent-terminal SSH (depends on #22); **#25**
  gated interactive session (depends on #22); **#24** SQL service-adapter classifier
  (design *with* #22 — sequence alongside it).
- **Safeguard-neutral → can proceed first:** the shared-messaging approval anchor;
  **#80** multi-mode gate (mode framework/UX); **#76** approval-assist + per-write
  rationale; **#75** bundled DevOps skills; **#74** product shape/packaging; **#65**
  async approval lifecycle; **#26** friendlier gate responses; **#17** multi-key
  identity (per-agent certs / key-lock / IP-pin); **#23** interactive-prompt
  forwarding; the forced-command `restrict`/no-pty + local-state hygiene audit;
  the operational-hardening tail; branch revivals **#82** (redactor port) / **#83**
  (hosted-signer ship).

**Consequence for v0.2:** v0.2 was originally framed as "everything already built
**+** #22." With #22 deferred to last, that definition now ships last too; the
current declared scope and release status are stated above. The
**feature-table review** (see *Release status & versioning*) had to resolve the central
question: re-scope v0.2 to a safeguard-neutral interim milestone, or keep the
definition and let v0.2's ship wait on the safeguard.

**RESOLVED (owner, 2026-07-11): keep the definition — v0.2 waits on #22; no interim
tag.** The neutral queue proceeds now, in this order, and everything it lands ships
in v0.2:

Ordering follows one rule beyond the safeguard split: **nothing that parses,
executes, or renders classifier internals is built before #22**, because #22
replaces the parse/exec model and that work would be thrown away (and, for the job
launcher, would punch a `/bin/sh` hole straight through #22's guarantee). The three
items that fail that test are split out and moved below #22.

1. **Hardening audit** — forced-command `restrict`/`no-pty`/no-forwarding on the
   `authorized_keys` line + local-state hygiene (umask 0077, `O_NOFOLLOW`, atomic
   rename); settle **D2** (Tier-1 de-provision) and **D3** (signer socket group vs ACL)
   alongside. (SSH-daemon + file-write layer; no overlap with #22's process-level
   Landlock/seccomp.)
2. **#74 product shape + the shared-messaging anchor decision** — one design pass; must
   produce the signer-library embedding API shape (part (e) of #74 is now committed
   v0.2 scope). The anchor decision must **precede** building any approval-plane item
   below (#76/#65/signer) so they ride the shared layer, not the bespoke poller.
3. **#75 bundled DevOps skills.**
4. **#26 friendlier gate responses — core only** (verdict → clear structured message).
   The `explain`/`why` dry-run **reason-rendering is deferred to build *with* #22** — it
   renders classifier internals that #22 replaces.
5. **#80 multi-mode gate** (strict allowlist / auto / ask; sign-to-add vs out-of-band
   allowlist growth). The framework delegates to the classifier ("auto" points at
   whatever it is), so it never rewrites; design the strict/ask allowlist + always-allow
   key on a representation that survives the string→argv migration (contained #22 refit,
   not a rewrite).
6. **Approval plane — converged design once, then build:** signer **library** (revive
   the `feat/v2-hosted-signer` backend as an embeddable library callable by any web app)
   → **reference web app** (usable default surface) → **#76 approval-assist**
   (agent-supplied reason field + LLM check/summary) → **#65 async approval lifecycle**
   (dispatch-and-continue, sign-at-approval, pending queue). #76's **deterministic
   risk-annotation** parsing is deferred to build **with #22** (reuse the argv parser,
   not a throwaway one).
7. **LAST, gated on the safeguard clearing: #22**, then the items whose parse/exec/render
   layer #22 must underpin — **background-job verb** (argv-exec + daemonize launcher;
   building it earlier on `nohup sh -c` is throwaway *and* a `/bin/sh` bypass of #22),
   the **#26 explain reason-rendering**, and the **#76 risk-annotations** — then **#24**
   (designed with #22, built after) **→ #81 → #25.** Then v0.2 tags (after the mandatory
   PII audit).

Post-v0.2 (v0.3+): #17 multi-key identity, per-gate memory subsystem, #82 redactor
port (sequence after #22 — it likely obsoletes that branch's filemode layer), #23
interactive-prompt forwarding (design alongside #25/#81), tier-reconcile on the
re-add probe, redaction scanner perf, background reachability monitor, and the
DENY/TIMEOUT + concurrent-approvals items (subsumed by the anchor unless the anchor
is rejected).

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
  (v0.1.3).** One signed-payload wire change: signer-issued **standing grants**
  (scope `all` or an exact command-set, ≤24h, server-bound, revocable) for
  unattended write windows; an approved **secret-reveal** that bypasses output
  redaction for a single signed command; **per-server identity** binding each
  signature to the target's SSH host-key fingerprint (closes cross-server
  replay); a **two-tier audit trail** — a gate-side append-only authoritative
  log plus an MCP-side rolling live view; a 60s default signature window; and
  `servers.json` 0600. Design:
  [docs/proposed/feature3-grants-reveal-audit-binding.md](proposed/feature3-grants-reveal-audit-binding.md).
- **Gate auto-update (`update_gate` / `SSHGATE_UPDATE`) + verified release
  channel (v0.1.3, deployed).** A signed control verb that updates the gate
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

> **✅ RESOLVED — the anchor decision (owner, 2026-07-12): do NOT route approvals through
> a shared messaging layer. Drop that integration entirely — "forget it."** The #74 design
> pass (security judge finding, re-verified against both trees) established that the signer
> runs as an isolated `sshgatesigner` uid but the login-user-owned approval allowlist
> configuration, its delivery-channel credentials, and its reload control all live in the
> *agent's* uid — so a compromised on-machine agent could edit the allowlist / bind a fake
> delivery endpoint and self-approve,
> making the "off-machine human" verdict a rogue-controlled oracle. That violates the hard
> constraint below (a grant must never replace the signature; the approver must be an
> authenticated off-machine human). **Ruling:** the signer keeps its OWN Telegram poller
> exactly as today — the *stronger*, isolated-domain channel — and the shared-layer variant is
> not pursued, not even as a later signer-owned equivalent. Follow-up task: audit the current poller/signer
> channel and confirm it needs no improvement; leave it as-is if so. *Audit done (2026-07-13):
> the channel's reliability + authz model holds up as-is — one real gap (unbounded Telegram
> HTTP client could wedge the poll goroutine for hours on a black-holed connection) fixed in
> `e6f98e1`; everything else confirmed sound (offset non-persistence, crash windows, double-tap
> idempotence, allowlist/callback authz, replay, approval-to-request binding). Q3 closed.*
> Consequence: the
> ops-hardening items previously marked "(subsumed)" by this anchor (DENY/TIMEOUT verdict
> delivery, concurrent approvals, reachability-monitor push) **un-subsume** and fold into the
> #65 async-approval build. The strike-through item below is kept for history.

- **Route approvals through the shared messaging layer (strategic anchor).** ~~The
  signer currently embeds its own chat-channel integration — long-poll, backoff,~~
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

  **Preferred shape — ride the harness/channel *permission* surface, bound to the
  signature (filed 2026-07-11).** The most natural delivery for the approval tap is
  the agent harness's own **tool-permission prompt** — every coding-agent harness has
  one — bridged to an authenticated human channel. The in-house messaging layer
  already ships exactly that bridge: a **permission-relay** capability that renders a
  pending tool-use as an Allow/Deny prompt on the operator's phone and honors only an
  allowlisted operator's tap. Building the tap on that surface, rather than a bespoke
  poller, is both less code and the right UX for a broader release. **Hard
  constraint:** the harness/channel grant must *trigger* the isolated signer to sign
  the exact command (**sign-at-approval**), and the gate must still verify that
  signature — the cryptographic signature stays the boundary. A bare local-harness
  permission grant must never *replace* the signature: auto-accept / bypass-permission
  modes and a rogue on-machine agent can self-grant, so the approving verdict must come
  from an authenticated **off-machine** human (which the channel permission-relay
  guarantees). Harness permission mechanisms differ across agents and some expose no
  clean hook, so the signature is the **portable** boundary and the harness surface is
  preferred-where-available delivery, never a dependency. Converges with the async
  approval lifecycle (sign-at-approval) and #76 (approval-assist rendered into the same
  prompt). Prior in-house-messaging work already probed the harness intercept (the
  pre-tool-use hook) — build on that probe rather than starting cold.

- **Final product shape — component decomposition & packaging (owner direction,
  filed 2026-07-10).**
  > **✅ RESOLVED (#74 design pass + owner rulings, 2026-07-12).** One repo; six packageable
  > parts, names/binaries UNCHANGED (no rename of the live signer unit): **A1** the whole
  > Claude Code plugin, **A2** the MCP server binary (also its own registry artifact — the
  > cheap seam that buys Codex/Gemini/Cursor reach), **A3** the `sshgate` CLI binary
  > (human-only control plane: pubkey/add/revoke/xfer), **A4** the local Telegram signer
  > (unchanged, the default & stronger Tier-2 channel — see the anchor RESOLVED note above),
  > **A5** the hosted signer as `pkg/signerkit` embeddable library + a 4-page reference web
  > app (BUILD THIS — see the one-codebase requirement below), **A6** the gate (never
  > user-installed; pushed by provisioning). Install story = three roles: agent kit (Tier-1) →
  > + local signer (Tier-2) → + hosted signer (Tier-3). Provisioning stays human-only (no
  > `add_server`). **Q4 one-codebase requirement (owner, hard):** `signerkit` is the SHARED
  > signing core and the existing local `sshgate-signer-telegram` is refactored to consume it —
  > local + hosted are two thin front-ends over ONE signer codebase, not a fork. Build key
  > custody as `crypto.Signer` (KMS/HSM-able), required audit sink, Lock/RotateTo, from a rebase
  > spike of `feat/v2-hosted-signer` first.
  >
  > **Deferred (from the signerkit build, 2026-07-13): gate-side dual-key rotation.**
  > `signerkit.RotateTo` is an *atomic cut-over* — the gate loads exactly one signer pubkey
  > (`gate.LoadPubKey`; `VerifySigned` takes one), so a rotation has a brief window where
  > in-flight envelopes signed with the old key are refused until every gate re-provisions.
  > Zero-downtime rotation needs the gate to accept an old+new key pair during a rollover
  > window; that gate-side change is deferred to a future item. Until then, rotation is a
  > planned-maintenance action, not a live hot-swap.
  >
  > **Q6 marketplace (owner):** publish to the top ~10
  > agent marketplaces/registries; a separate research pass enumerates per-surface requirements,
  > the easy first win, the repo-readiness checklist, and the submission/email contacts so the
  > ball leaves the owner's court (deliver as an HTML file). Verification (T1–T7 on Codex/Gemini)
  > gates the uploads; push stays owner-gated + PII audit. The full design record
  > remains in the project's private research archive.

  Before the public release push, pin down the parts a user
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

- **Read jail (#22) — scheduled.** The kernel jail is the read-only wall; Phase 1
  is built and Phases 2–7 are work item 1 of [BUILD-PLAN.md](BUILD-PLAN.md).

- **Transparent gated SSH from a normal terminal (#81) — scheduled** as the
  signature terminal, work item 3 of [BUILD-PLAN.md](BUILD-PLAN.md).

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
  full pipeline before any build. Combined with transparent-terminal SSH (in
  *Next*), multi-key per-agent identity is the foundation for SSHGate as a full
  Linux login-management & permissions platform — per-identity keys and
  permissions, gate-enforced. Longer-horizon framing, not current scope.

- **Multiple gate enforcement modes (owner direction, filed 2026-07-10).** The gate
  today has one behaviour: a binary allow/deny driven by the read/write classifier.
  Add selectable per-host modes, an analogue to a coding agent's permission modes:
  (1) **strict allowlist** for high-threat hosts — only an explicit exact command set
  runs, everything else needs approval; (2) **auto** — today's classifier
  auto-routing (recognized reads run unsigned, writes/unknowns route to approval),
  the mode #22 hardens; (3) **ask** — every command routes to approval, with an
  "always-allow this exact command" setting that permanently allowlists that one
  command and nothing else. Deliberately NO allow-everything mode (it would make the
  gate pointless); the existing time-limited approve-all (standing grants) stays as
  the escape hatch. Allowlist growth has two selectable sub-paths: **sign-to-add** (an
  approved command joins the allowlist) or **out-of-band only** (the gate can never
  widen its own allowlist; new entries require editing the allowlist file over a
  separate full-access SSH key — the highest-assurance posture). Not scheduled;
  design first.

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

- **Asynchronous approval lifecycle (#65) and LLM approval-assist (#76) —
  scheduled** together as work item 2 of [BUILD-PLAN.md](BUILD-PLAN.md): a reason on
  every write, durable approval records, sign-at-approval, an advisory AI assessment of
  each request, async dispatch with `await_approvals`/`list_pending_approvals`, and
  operator queue controls. Still unscheduled: an optional local watcher that wakes
  an idle agent when a verdict lands (harness-specific; the polling tools stay the
  portable core).

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

- **Operator redaction control plane (deferred — from `feat/v1.2-redactor`).** An
  operator-configurable redaction layer that current main does not have: a signed,
  append-only redactlist/unredactlist with provenance + audit, a signed `SSHGATE_CMD`
  meta-command envelope + gate dispatcher + sign matrix, a signer `sign-envelope`
  kind, MCP `redact.*`/`unredact.*` tools, operator anchor literals, and a
  standard/thorough `redact.mode` switch (plus a depth-1 decode pass). The
  implementation lives on `feat/v1.2-redactor` but is NOT `git merge`-able — main
  rewrote the redaction scanner underneath it, so reviving this is a **port of the
  design onto the current scanner**, reusing the branch's store/envelope/signer
  pieces and its signing-model design doc. The branch's Layer-2 "filemode" heuristic
  is likely obsoleted by #22's argv-exec + kernel confinement.

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
  response, mirroring the existing grant-list reconcile path. *(Scheduled in
  [BUILD-PLAN.md](BUILD-PLAN.md) work item 2: each verdict is kept in the signer's
  approval record, and the client re-reads it by request id after a lost response.)*

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

- **Concurrent gated approvals.** Firing several gated calls at once
  can cross-reject when the local tool-permission prompt and the approval channel
  assume a single pending request. Queue concurrent gated calls or key multiple
  in-flight approvals by request id. *(Scheduled in [BUILD-PLAN.md](BUILD-PLAN.md)
  work item 2: every approval is its own record keyed by request id.)*

---

## Deferred

- **Tier-3 hosted signer foundation (policy authority still pending). — PULLED INTO v0.2 (owner, 2026-07-11),
  library-first:** the `pkg/signerkit` and hosted-server work provide a foundation, but
  the hosted policy authority (Units 3/4) remains design and implementation work before
  it can be a release-ready approval boundary. A stable HTTPS hostname is also a
  deployment prerequisite because passkeys and mutation-origin checks are origin-bound.
  Deferred extensions are per-client credentials, hosted Telegram/grants/reveal/transfer,
  HA, policy-management UI, and metrics. See [approval-architecture.md](approval-architecture.md)
  and [the deployment guide](../src/signer-server/README.md).

- **Redaction scanner performance work.** An Aho-Corasick / keyword-prefilter
  rewrite of the redaction scanner for large outputs. Security-sensitive, so
  deprioritized behind correctness work.

- **Sign-wire struct consolidation.** Internal cleanup of the signed-command
  request structures shared between the signer and the MCP, best done alongside
  the signed-at-rest envelope work.

---

Deferred / longer-term directions and the honest limitations of the shipped
surface: see [FUTURE.md](FUTURE.md).
