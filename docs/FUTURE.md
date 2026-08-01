# SSHGate — deferred directions and honest limitations

This document catalogues deferred architectural directions and the honest limitations of the shipped surface, so contributors don't have to re-discover them by reading every reference doc. It is the durable "what we chose not to do, and why" companion to the roadmap.

For the active, sequenced, priority-ordered work, see [`ROADMAP.md`](ROADMAP.md) — that is the single canonical list of what's being built next. This file does not re-list roadmap items; it records the deferred design space and the limitations the operator should know about.

## Architectural directions (planned but unscheduled)

### Kernel-level read enforcement (Linux Landlock)
- **Why:** SSHGate's three-layer redactor is byte-level filtering *after* the read happens. The bytes have already crossed the user-space boundary by the time we redact. The proper answer is to prevent the read at all — Landlock (Linux kernel 5.13+) lets a process declaratively scope which paths it may open, enforced in-kernel.
- **Status:** deferred to v1.2.1+.
- **Estimated scope:** medium-large. Per-command sandbox setup wrapping the executor's `/bin/sh -c <cmd>` call with a Landlock ruleset that allows reads only outside `~/.sshgate-gate/`, `/etc/shadow`, `/etc/ssh/`, etc. Requires a curated deny-set per host (probed at install time). Non-trivial integration with the existing `src/gate/executor.go`.
- **Open questions:** (1) how to handle dynamic paths (`/proc/<pid>/environ`) where the PID is only known post-fork; (2) whether to expose the Landlock policy file as a signed append-only resource analogous to `redactlist.append-only`; (3) whether to require kernel 5.13+ as a hard floor or fall back to "best effort plus redactor" on older hosts.
- **Trigger condition for prioritisation:** any single confirmed v1.2 redactor bypass in the wild, or operator request for a stronger guarantee on a specific host class (production database boxes, secrets-bearing config hosts).

### `thorough` mode (looser gates + depth-3 decode)
- **Promotion condition FIRED 2026-07-02.** A production multi-server run reported missed-secret categories (unknown-named high-entropy values, telegram tokens, fine-grained PATs) — the (a) trigger below. Rather than gate this behind an unshipped mode, `standard` got the **bounded generic net** (`scanGenericRuns`) plus a **live `Rule.Entropy` gate**, both shipped 2026-07 (see [`redaction-architecture.md`](redaction-architecture.md) changelog and `docs/proposed/redaction-widening-2026-07.md`). So the "unanchored entropy is thorough-only" framing no longer holds — a *gated* generic net is in `standard`.
- **Why (remaining scope):** `standard`'s net is deliberately conservative — 3-class content, ≥ 32 chars, entropy ≥ 3.5, ssh-line veto, lowercase-hex excluded. `thorough` is now the **looser-gates** path: 1-/2-class candidates, lower length/entropy floors (catches bare hex-shaped custom secrets), the *unguarded* gitleaks entropy rules, and 3-level recursive decode for audit workloads where over-redaction is acceptable.
- **Status:** not implemented — the `redact.mode` wire command is part of the unshipped `SSHGATE_CMD` rule-management layer (no stub exists in the tree); ship in v1.2.1+.
- **Estimated scope:** small-medium. The plumbing is there — `Rule.Entropy` is now live and consulted by `scanner.go`, `passesSecretGate` is the reusable gate, `decode.Views(buf, depth)` accepts arbitrary depth. The remaining work is: (a) curating which gitleaks entropy rules survive auto-validation, (b) wiring depth=3 through `scanner.go`, (c) the looser-gate variants, (d) the over-redaction fixtures.
- **Open questions:** does `thorough` need a per-command toggle (some commands always want `standard` even on `thorough` hosts), or only per-host?

### `verified` mode (TruffleHog-style API verification)
- **Why:** for the rules that support live verification (AWS STS `GetCallerIdentity`, GitHub `/user`, Slack `auth.test`, Stripe charges-list-with-limit-0), a 2-second API call confirms whether a candidate is a real credential or an example/fake. Inverts TruffleHog's default to fail-safe: on any verifier failure (timeout, non-200, network) → redact anyway.
- **Status:** parked; not in v1.2.
- **Estimated scope:** medium. Per-rule verifier hooks; plain `http.Client` with explicit timeouts (daemon guideline 11.1 — no `DefaultClient`); no retries on 401/403 (daemon 11.5); per-host 10 req/sec rate limit; per-session in-memory cache. Recall regression (~25 points vs `standard`) is intentional — verified is for audit workflows.
- **Open questions:** does verification ever leak rate-limit signals back to a hostile model? (Probably yes — defer until threat model is updated.)

### BPE token-efficiency scoring (Betterleaks)
- **Why:** research §Betterleaks reports 98.6% recall vs 70.4% entropy-only on CredData (F1 0.8922 best-config). BPE-tokenizer-based scoring catches custom-format secrets that entropy alone misses.
- **Status:** parked.
- **Estimated scope:** medium. Tokenizer-library dependency (cl100k_base, several MB embedded) is the cost in our hot path. Per-token wall-clock measurement would need to confirm it does not blow the per-chunk budget.
- **Open questions:** is the tokenizer dependency acceptable for a single statically-linked binary deployed to every remote? (Probably yes; cl100k_base data is ~1.5 MB.)

### Hosted sshgate-signer-server (WebAuthn + TOTP + Web UI)
- **Why:** v1 ships Telegram-bot-as-signer; v2 vision is a self-hosted HTTP signer service so the approval path isn't tied to a single chat platform. Lets operators bring their own auth (WebAuthn passkey + TOTP), see history in a browser, and federate across multiple operators.
- **Status:** the embeddable signerkit core and `sshgate-signer-server` reference
  foundation are present: machine/human plane separation, SQLite,
  TOTP/WebAuthn, approval policy, embedded UI, audit, and deployment tooling.
  The remaining v0.2 policy-authority work and release gates are tracked in the
  [roadmap](ROADMAP.md). See
  [`src/signer-server/README.md`](../src/signer-server/README.md).
- **Still future:** per-client machine credentials, operator-facing threshold/policy management, hosted standing grants/reveal/transfer, HA storage, readiness/metrics, and a first-class WebAuthn enrollment page.
- See the three install tiers and their approval authority:
  [approval-architecture.md](approval-architecture.md).

### macOS native install (launchd plist)
- **Why:** SSHGate's installer is Linux-systemd-only today. macOS operators can run the MCP and signer, but the install script needs launchd plist generation for the signer service.
- **Status:** deferred to v1.1 cascade or v1.2.1+.
- **Estimated scope:** small. Mirror `scripts/install.sh` with `~/Library/LaunchAgents/` + `launchctl bootstrap`. No code changes to the signer or MCP — the gate binary stays Linux-only since remote hosts are Linux.

### Cross-session HMAC-key recovery for legitimate audit
- **Why:** per-session HMAC keys are non-persistent by design, so even legitimate audit needs (post-incident forensic correlation of redacted spans across sessions) cannot reverse-correlate. A signed admin command that derives a deterministic per-host audit key (separate from per-session) and writes audit-only logs under a master-key-only-readable path could unlock this without breaking the threat model.
- **Status:** parked.
- **Estimated scope:** small-medium. New `redact.derive-audit-key` signed command + audit-log encryption pass.
- **Open questions:** key custody — who can decrypt audit logs? Probably only the same Telegram-tap path that authorises the derivation.

### `redact.list` operator-side UX
- **Why:** the `redact.list` wire command is part of the deferred rule-management surface (the 11-subcommand set), and the operator-side rendering — pagination, filtering by `kind` / `signed` / `session_fp` / `added_at`, a Telegram-rendered list view — is deferred alongside it.
- **Status:** deferred (wire command + UX both part of a future release).
- **Estimated scope:** small. `sshgate.list_redact_rules` is a deferred wire command, not one of the eleven shipped MCP tools; the operator-side work needs a paginated rendering + a Telegram-side compact view.

### Telemetry channel for aggregate redaction counts
- **Why:** to answer the empirical FPR/FNR questions below, SSHGate needs anonymised aggregate stats — count of redactions per mode per host. Never the redacted plaintext.
- **Status:** parked. The telemetry channel itself doesn't exist; v1.2 ships with no phone-home.
- **Estimated scope:** small. Opt-in flag, daily POST to a stats endpoint, structured payload (mode, rule_id histogram, count buckets). Needs operator consent UX.
- **Open questions:** is the histogram itself a side-channel? (Probably not — rule_id is already known to the model via marker output.)

### Per-host audit-log aggregation across sessions
- **Why:** signer's audit log captures every approval; gate's redact-audit log captures every redaction event. There is no cross-host aggregator. An incident-response workflow needs a single pane.
- **Status:** parked.
- **Estimated scope:** small-medium. SSH-pull from each registered host into a local SQLite store; minimal query CLI.

### Automated upstream gitleaks-rule sync
- **Why:** today, re-pulling from gitleaks upstream is a manual workflow per spec §"Rule library". Operator must diff `PROVENANCE.md`'s pinned sha against current upstream, review proposed rule additions one at a time, append, regenerate. This is friction.
- **Status:** intentionally manual in v1.2 (reviewable diffs > automation). Revisit if cadence becomes onerous.
- **Open questions:** can the diff-review step be assisted by an agent without losing the human review gate?

## Operator-facing limitations (known and documented)

These are honest limitations of the redactor design. **Inline secret redaction of command output is shipped and live** (Layer-1 standard-mode named-format detection plus the 2026-07 generic default-deny net, per-session HMAC markers; it runs on every command's output, reads and writes, bypassed only by an approved secret-reveal). The file-mode heuristic (Layer 2), the operator-curated `redactlist`/`unredactlist` layer (Layer 3), the recursive decode pass, and the `redact.*` wire commands are part of the **designed-but-unshipped** redactor architecture (see [`redaction-architecture.md`](redaction-architecture.md) §Implementation status), **not** a shipped surface; the shipped agent surface is exactly the eleven tools (the `redact.*` rule-management commands are not among them). The install banner names the major shipped-side limitations; this list is the exhaustive set across the design.

1. **Detection has false-positive surface on log-shaped content.** gitleaks-class rules sit at ~46% precision on broad corpora per independent benchmarks. SSHGate's named-only `standard` mode does better but does not eliminate it. Use per-host `unmask:` and unredact entries.
2. **Multi-line secrets can straddle buffer boundaries.** 4 KiB safe-prefix + PEM accumulator + 64 KiB ring cap. A 6 KB+ non-PEM secret (rare) could in theory split.
3. **The file-mode heuristic has no published prior art.** It is a SSHGate-original mechanism. The predicate registry will grow; the "Known unhandled bypasses" list in the architecture doc is the honest floor.
4. **The recursive decode pass is not yet shipped** (designed: depth 1 in `standard`, depth 3 in `thorough`). Today an encoded secret is caught only when the encoded run itself trips a named rule or the generic high-entropy net.
5. **Per-session HMAC key never persists.** The redactor cannot recover plaintext for debugging. `redact.why` returns source rule, not plaintext.
6. **The gate binary is the trust anchor.** A compromised gate (replaced via non-SSHGate channel) defeats redaction.
7. **No prior benchmark exists for streaming scanners on command output specifically.** Real-world FPR/FNR on `journalctl`, `env`, `docker inspect` is unknown until shipped and measured. SSHGate's telemetry channel will collect aggregate counts (never the redacted plaintext) post-ship.
8. **Some custom-format secrets remain invisible to defaults.** As of the 2026-07 widening, an unknown-named value that is a ≥ 32-char 3-class high-entropy run IS caught by the generic net. What still slips: **bare lowercase-hex** secrets (git-SHA-shaped — deliberately excluded, hex is the dominant benign ops class) and tokens **< 32 chars** with no name/prefix anchor. These stay invisible unless name-anchored or exactly shaped. Add via `redact.add pattern=…` or wait for `thorough`'s looser gates.
9. **Removing a pattern requires a signed envelope.** Intentional friction.
10. **ReDoS is mitigated but not impossible.** Go's `regexp` is RE2 (no backreferences, no catastrophic backtracking by design). The 6-step auto-validation catches the bulk of bad regexes. A per-chunk wall-clock budget (default 50 ms) as a runtime safety net is a v1.2.1 backlog item.
11. **The honest framing — rat race.** Redaction is defense-in-depth, not a perimeter. The model is assumed not rogue. The right long-term answer is kernel-level read enforcement (Landlock) — see above.
12. **Read-only-gate bypass categories are catalogued; most are now closed or fail closed.** Per [`security-readonly-bypass.md`](security-readonly-bypass.md): the `sed e` flag, `find -fprintf`, environment-variable smuggling (`LD_PRELOAD`, `IFS`), and awk `system()`/`getline` now classify WRITE (corpus-pinned in `tests/testdata/classifier-corpus.txt`); busybox/toybox multiplexers and the wrapper binaries (`nice`, `nohup`, `time`, `taskset`, `chroot`, `unshare`, `setsid`) are not on the read allowlist, so they fail closed as writes. The remaining structural gap is an *unlisted* GNU long-option abbreviation. Status per item under "Read-only gate hardening" below; the classifier stays an arms race until the argv-exec fix (#22) lands.
13. **PTY denial + `~/.ssh/rc` denial — CLOSED.** The forced-command entry that provisioning writes now leads with `restrict` and additionally pins `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding` (`commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`, golden-pinned by a test). A third-party SSH client holding the SSHGate key can no longer allocate a PTY, so `less`/`man`/`vim` of a large file cannot go interactive and `!sh` cannot escape the gate. `restrict` also denies `~/.ssh/rc` execution (`no-user-rc`) — so a landed write to `~/.ssh/rc` cannot yield a shell outside the gate on the next connection — and auto-includes any future OpenSSH restriction. Enforced at the `authorized_keys` layer (OpenSSH ≥ 7.2).
14. **No debug mode, no `--no-redact` flag, no environment override.** A signed `redact.why <key>` (a designed, not-yet-shipped wire command) is the only sanctioned way to learn what a marker references — and it returns only the *source* rule and provenance, never plaintext. Operators who need plaintext today use the approved secret-reveal (`reveal=true`) or the master key path out-of-band.
15. **Cross-session correlation is intentionally lost.** The per-session HMAC salt is rotated per `gate` process. Two markers with the same `key` in different sessions are coincidental, not correlated. 32-bit HMAC collides at scale; if cross-session correlation matters, see "Cross-session HMAC-key recovery for legitimate audit" above.
16. **No retroactive redaction.** The redactor sees bytes as they stream past. If a rule is added mid-session that would have caught an earlier byte, that byte is gone. Operators must restart the session to apply newly-added rules.

## Read-only gate hardening (deferred MINORs/MAJORs from security research)

Tracked from [`security-readonly-bypass.md`](security-readonly-bypass.md). Status against the current classifier is noted per item; the structural end-state for the whole family is the argv-exec fix (#22).

- **`sed -e` / `awk -e` arbitrary expression execution.** sed's `e` flag is direct RCE on a read-allowlisted binary. Same for `find -fprintf` / `-fprint`. **Status: CLOSED** — the classifier does per-binary sub-feature classification for these (`sed` `e`/`w`/`r` script commands, `find -fprint*`/`-fls`, awk `system()`/`getline`/output-redirect; all corpus-pinned WRITE).
- **GNU long-option abbreviation.** `--compress-prog` accepted when `--compress-program` denied. **Status: partially closed, structurally UNSOLVED.** A prefix-matching pass added coverage for the *known-dangerous* long-options (`--in*` → `--in-place`, `--rot*` → `--rotate`, etc.), so the catalogued bypasses are blocked. The open problem: an *unlisted* dangerous long-option still slips through, because the classifier doesn't model each binary's real getopt grammar. The structural fix is one of: (a) parse the full GNU getopt grammar per binary, or (b) maintain per-binary canonical-option tables and resolve any abbreviation against them. Both are non-trivial and unscheduled. Until then this stays an accepted, tracked gap (defense-in-depth, model-assumed-not-rogue framing).
- **Environment-variable smuggling.** `LD_PRELOAD=… cmd`, `IFS=…`, `PATH=…`, `GIT_SSH_COMMAND=…`, `PAGER=…`, `EDITOR=…` passed via `FOO=bar cmd` prefix escape argument filters. **Status: CLOSED** — dangerous assignment prefixes classify WRITE (corpus-pinned: `LD_PRELOAD=… cat`, `IFS=… ls`, `env LD_PRELOAD=… cat`).
- **Wrapper-binary unwrap gaps.** `env`, `nice`, `nohup`, `time`, `taskset`, `chroot`, `unshare`, `setsid` strip the leading wrapper — the real command is what executes. **Status: fail-closed** — `env` gets true recursive unwrap (`src/classify/env.go`); the others are not read-allowlisted, so any wrapper-prefixed command classifies WRITE. Recursive unwrap for the rest would be a read-UX improvement, not a security fix.
- **Busybox / toybox multiplexer dispatch.** `busybox sh -c '…'` would be direct shell access if `busybox` were allowlisted as "known safe". **Status: fail-closed** — neither multiplexer is on the read allowlist; the dispatch classifies WRITE.
- **Line-continuation injection.** `echo "ok \<newline>$(id)"` — POSIX-shell line-continuation behaviour differs from naive tokeniser expectations. **Status: CLOSED** — the classifier honours backslash escapes outside single quotes, and `$(…)` substitution is unconditionally WRITE (both continuation forms verified WRITE against the current classifier).

## Process improvements

### Pre-publish PII cleanup
A real operator's Telegram user_id is the primary PII risk; it lives only in env-loaded config (the placeholder `12345678` is illustrative). Any pre-publish pass should re-sweep `testdata/`, comments, and reference docs for project-specific terms.

### Marketplace publishing path
SSHGate is a Claude Code plugin and should ship to the Anthropic marketplace eventually. Open work:
- Plugin manifest validation against the latest Claude Code plugin schema.
- Signed-release pipeline so operators can verify the gate binary they're deploying — **largely shipped** as the verified release channel (committed `dist/gate/sshgate-gate-linux-amd64` + published `.sha256` + the `verify-gate` reproducible-build CI check); publishing to tagged GitHub Releases remains open.
- Reproducible builds — **shipped**: `make release-gate` pins the Go toolchain from `go.mod` and locks the build env; CI rebuilds and compares hashes. A separate build-attestation artifact per release remains open.
- Discoverability: keywords in `plugin.json`, a polished screenshot/demo in the README, a one-paragraph elevator pitch tested against operators outside the inner circle.

### Hosted deployment extensions
The hosted-server foundation includes a hardened systemd VPS installer,
recoverable TOTP bootstrap artifacts, and WebAuthn registration APIs. The
roadmap tracks the remaining v0.2 authority/release work. A Docker
image/Compose profile, first-class browser passkey-enrollment page, backup
automation, and HA deployment remain future extensions.

### Empirical questions to answer post-ship
- Real-world FPR/FNR on command output across `journalctl`, `env`, `docker inspect`, `kubectl describe`. No public benchmark exists for streaming scanners on command output; SSHGate will publish the first.
- Performance under `thorough` mode with entropy enabled on 10 GB+ `journalctl --no-pager` dumps. May warrant runtime auto-downgrade ("output > 100 MB → drop to standard for this command only"); deferred to avoid v1.2 scope creep.
- HMAC redaction's effect on agent reasoning quality. Does Claude debug effectively when secrets are HMAC tokens? Only operator usage answers.
- Whether exposing the redactlist as a Claude tool (`sshgate.list_redact_patterns`) gives a hostile model the rule names it would need to craft evasions. `sshgate.list_redact_patterns` is a deferred wire command, not one of the eleven shipped MCP tools; the MCP-side tool surface for listing is deferred for this reason.
- Whether to expose the redactlist as machine-readable audit output (SARIF, CycloneDX) for enterprise consumers. Deferred until a request appears.
- Per-chunk wall-clock budget (default 50 ms; configurable) as a ReDoS safety net for pathological regexes that pass auto-validation but degrade on adversarial input. v1.2.1 backlog item.

## Trigger conditions and prioritisation rules

These are the conditions under which a deferred item gets promoted to active work. They keep the backlog from being a wish list.

- **Landlock** — promoted to v1.2.1 active work on (a) any confirmed v1.2 redactor bypass in the wild, OR (b) a production-host class (databases, secret stores) where the operator explicitly requests stronger guarantees. Latter weights higher because Landlock is a per-host opt-in not a global flip.
- **`thorough` mode** — condition (a) **FIRED 2026-07-02** (a production run reported missed-secret categories named-format-only didn't catch). The response shipped the bounded generic net + live `Rule.Entropy` into `standard` rather than a whole mode; `thorough`'s remaining promotion trigger is (b) audit-workflow demand (someone running SSHGate manually to scan a corpus, where the looser 1-/2-class + lower-floor gates and depth-3 decode earn their false-positive cost).
- **`verified` mode** — promoted only when (a) `thorough` is already shipped AND (b) a verified-mode use case appears (audit team wants "this AWS key — is it actually live?"). Otherwise it stays parked indefinitely; the value-per-engineering-week is low.
- **BPE token scoring** — promoted if `thorough` ships and FPR is still too high for audit use. Otherwise parked.
- **Hosted signer extensions** — the core/web foundation is implemented on the
  v0.2 branch, but policy-authority and release gates remain open; after those
  close, promote per-client credentials, hosted Telegram, or HA when a concrete
  multi-client/notification/replica need appears.
- **macOS install** — promoted on first macOS operator request. Small enough to do reactively.
- **`redact.list` UX** — promoted once a v1.2 host crosses ~50 redactlist entries and the operator says "I can't see what's in there." Cheap to ship.
- **Read-only gate hardening** — promoted *immediately* upon any confirmed in-the-wild bypass. The MAJORs from [`security-readonly-bypass.md`](security-readonly-bypass.md) are tracked separately as a hardening sprint, not as feature releases.

## How this document is maintained

- When a feature lands → move its entry from "deferred" / "parked" to a footnote citing the implementing PR / task ID; eventually delete after one release cycle.
- When a new deferral is accepted (e.g. a code review surfaces a MAJOR that won't fit the current release) → append a new section with the same `Why / Status / Estimated scope / Open questions / Trigger` structure.
- The durable reference docs in `docs/` (the architecture, security-research, and redaction references) are the authoritative source for *why* something is deferred. This file is the index; those references carry the rationale.
