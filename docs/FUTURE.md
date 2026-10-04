# SSHGate — deferred directions and honest limitations

This document catalogues parked directions and the honest limitations of the shipped surface, so contributors don't have to re-discover them by reading every reference doc. It is the "what we chose not to do yet, and why" companion to the roadmap.

It is **not** the list of what is being built. What is built next, in order, is [`BUILD-PLAN.md`](BUILD-PLAN.md); release status and unscheduled features are in [`ROADMAP.md`](ROADMAP.md). The security posture, including the kernel read jail and its residual risks, is in [`THREAT-MODEL.md`](THREAT-MODEL.md). Most entries below concern the redactor; anything that gets scheduled moves to the build plan and leaves this file.

## Architectural directions (planned but unscheduled)

Kernel-level read enforcement, once listed here, is built: reads run in the `ro-v1` kernel jail (user, mount and IPC namespaces, read-only mounts, Landlock and seccomp) on hosts that support it. See [`THREAT-MODEL.md`](THREAT-MODEL.md) and work item 1 of [`BUILD-PLAN.md`](BUILD-PLAN.md). Note that the jail stops reads from *changing* the host; it does not hide files the SSH user can read, so redaction is still the only filter on secrets in output.

### `thorough` mode (looser gates + depth-3 decode)
- **Promotion condition FIRED 2026-07-02.** A production multi-server run reported missed-secret categories (unknown-named high-entropy values, telegram tokens, fine-grained PATs) — the (a) trigger below. Rather than gate this behind an unshipped mode, `standard` got the **bounded generic net** (`scanGenericRuns`) plus a **live `Rule.Entropy` gate**, both shipped 2026-07 (see [`redaction-architecture.md`](redaction-architecture.md) changelog and `docs/proposed/redaction-widening-2026-07.md`). So the "unanchored entropy is thorough-only" framing no longer holds — a *gated* generic net is in `standard`.
- **Why (remaining scope):** `standard`'s net is deliberately conservative — 3-class content, ≥ 32 chars, entropy ≥ 3.5, ssh-line veto, lowercase-hex excluded. `thorough` is now the **looser-gates** path: 1-/2-class candidates, lower length/entropy floors (catches bare hex-shaped custom secrets), the *unguarded* gitleaks entropy rules, and 3-level recursive decode for audit workloads where over-redaction is acceptable.
- **Status:** not implemented and not scheduled — the `redact.mode` wire command is part of the unshipped `SSHGATE_CMD` rule-management layer (no stub exists in the tree; see the operator redaction control plane, #82, in [`ROADMAP.md`](ROADMAP.md)).
- **Estimated scope:** small-medium. The plumbing is there — `Rule.Entropy` is now live and consulted by `scanner.go`, `passesSecretGate` is the reusable gate, `decode.Views(buf, depth)` accepts arbitrary depth. The remaining work is: (a) curating which gitleaks entropy rules survive auto-validation, (b) wiring depth=3 through `scanner.go`, (c) the looser-gate variants, (d) the over-redaction fixtures.
- **Open questions:** does `thorough` need a per-command toggle (some commands always want `standard` even on `thorough` hosts), or only per-host?

### `verified` mode (TruffleHog-style API verification)
- **Why:** for the rules that support live verification (AWS STS `GetCallerIdentity`, GitHub `/user`, Slack `auth.test`, Stripe charges-list-with-limit-0), a 2-second API call confirms whether a candidate is a real credential or an example/fake. Inverts TruffleHog's default to fail-safe: on any verifier failure (timeout, non-200, network) → redact anyway.
- **Status:** parked.
- **Estimated scope:** medium. Per-rule verifier hooks; plain `http.Client` with explicit timeouts (daemon guideline 11.1 — no `DefaultClient`); no retries on 401/403 (daemon 11.5); per-host 10 req/sec rate limit; per-session in-memory cache. Recall regression (~25 points vs `standard`) is intentional — verified is for audit workflows.
- **Open questions:** does verification ever leak rate-limit signals back to a hostile model? (Probably yes — defer until threat model is updated.)

### BPE token-efficiency scoring (Betterleaks)
- **Why:** research §Betterleaks reports 98.6% recall vs 70.4% entropy-only on CredData (F1 0.8922 best-config). BPE-tokenizer-based scoring catches custom-format secrets that entropy alone misses.
- **Status:** parked.
- **Estimated scope:** medium. Tokenizer-library dependency (cl100k_base, several MB embedded) is the cost in our hot path. Per-token wall-clock measurement would need to confirm it does not blow the per-chunk budget.
- **Open questions:** is the tokenizer dependency acceptable for a single statically-linked binary deployed to every remote? (Probably yes; cl100k_base data is ~1.5 MB.)

### Hosted signer
The hosted signer (`sshgate-signer-server`, Tier 3) is a foundation in the repository; its remaining release work and deferred extensions are tracked in [`ROADMAP.md`](ROADMAP.md) §"Deferred", and running it as a remote MCP server is work item 4 of [`BUILD-PLAN.md`](BUILD-PLAN.md). See [approval-architecture.md](approval-architecture.md) and [`src/signer-server/README.md`](../src/signer-server/README.md).

### macOS native install (launchd plist)
- **Why:** SSHGate's installer is Linux-systemd-only today. macOS operators can run the MCP and signer, but the install script needs launchd plist generation for the signer service.
- **Status:** parked until a macOS operator asks for it. macOS operators can build and run the MCP server and the signer today; only the service installer is missing.
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
- **Status:** parked. The telemetry channel itself doesn't exist; SSHGate has no phone-home.
- **Estimated scope:** small. Opt-in flag, daily POST to a stats endpoint, structured payload (mode, rule_id histogram, count buckets). Needs operator consent UX.
- **Open questions:** is the histogram itself a side-channel? (Probably not — rule_id is already known to the model via marker output.)

### Per-host audit-log aggregation across sessions
- **Why:** signer's audit log captures every approval; gate's redact-audit log captures every redaction event. There is no cross-host aggregator. An incident-response workflow needs a single pane.
- **Status:** parked.
- **Estimated scope:** small-medium. SSH-pull from each registered host into a local SQLite store; minimal query CLI.

### Automated upstream gitleaks-rule sync
- **Why:** today, re-pulling from gitleaks upstream is a manual workflow per spec §"Rule library". Operator must diff `PROVENANCE.md`'s pinned sha against current upstream, review proposed rule additions one at a time, append, regenerate. This is friction.
- **Status:** intentionally manual (reviewable diffs > automation). Revisit if cadence becomes onerous.
- **Open questions:** can the diff-review step be assisted by an agent without losing the human review gate?

## Operator-facing limitations (known and documented)

These are honest limitations of the redactor design. **Inline secret redaction of command output is shipped and live** (Layer-1 standard-mode named-format detection plus the 2026-07 generic default-deny net, per-session HMAC markers; it runs on every command's output, reads and writes, bypassed only by an approved secret-reveal). The file-mode heuristic (Layer 2), the operator-curated `redactlist`/`unredactlist` layer (Layer 3), the recursive decode pass, and the `redact.*` wire commands are part of the **designed-but-unshipped** redactor architecture (see [`redaction-architecture.md`](redaction-architecture.md) §Implementation status), **not** a shipped surface; the shipped agent surface is exactly the eleven tools (the `redact.*` rule-management commands are not among them). The install banner names the major shipped-side limitations; this list is the exhaustive set across the design.

1. **Detection has false-positive surface on log-shaped content.** gitleaks-class rules sit at ~46% precision on broad corpora per independent benchmarks. SSHGate's named-only `standard` mode does better but does not eliminate it. Per-host `unmask:` and unredact entries are the designed remedy; they are part of the unshipped rule-management layer.
2. **Multi-line secrets can straddle buffer boundaries.** 4 KiB safe-prefix + PEM accumulator + 64 KiB ring cap. A 6 KB+ non-PEM secret (rare) could in theory split.
3. **The file-mode heuristic has no published prior art.** It is a SSHGate-original mechanism. The predicate registry will grow; the "Known unhandled bypasses" list in the architecture doc is the honest floor.
4. **The recursive decode pass is not yet shipped** (designed: depth 1 in `standard`, depth 3 in `thorough`). Today an encoded secret is caught only when the encoded run itself trips a named rule or the generic high-entropy net.
5. **Per-session HMAC key never persists.** The redactor cannot recover plaintext for debugging. `redact.why` returns source rule, not plaintext.
6. **The gate binary is the trust anchor.** A compromised gate (replaced via non-SSHGate channel) defeats redaction.
7. **No prior benchmark exists for streaming scanners on command output specifically.** Real-world FPR/FNR on `journalctl`, `env`, `docker inspect` is unknown until measured. The parked telemetry channel above would collect aggregate counts (never the redacted plaintext).
8. **Some custom-format secrets remain invisible to defaults.** As of the 2026-07 widening, an unknown-named value that is a ≥ 32-char 3-class high-entropy run IS caught by the generic net. What still slips: **bare lowercase-hex** secrets (git-SHA-shaped — deliberately excluded, hex is the dominant benign ops class) and tokens **< 32 chars** with no name/prefix anchor. These stay invisible unless name-anchored or exactly shaped. The designed remedies, `redact.add pattern=…` and `thorough`'s looser gates, are not shipped.
9. **Removing a pattern requires a signed envelope.** Intentional friction.
10. **ReDoS is mitigated but not impossible.** Go's `regexp` is RE2 (no backreferences, no catastrophic backtracking by design). The 6-step auto-validation catches the bulk of bad regexes. A per-chunk wall-clock budget (default 50 ms) as a runtime safety net is a parked backlog item.
11. **The honest framing — rat race.** Redaction is defense-in-depth, not a perimeter. The model is assumed not rogue. The kernel read jail (built, on hosts that support it) stops reads from changing the host, but it does not stop a read from *seeing* a secret the SSH user can read; only redaction filters that.
12. **Read-only-gate bypass categories are catalogued; most are now closed or fail closed.** Per [`security-readonly-bypass.md`](security-readonly-bypass.md): the `sed e` flag, `find -fprintf`, environment-variable smuggling (`LD_PRELOAD`, `IFS`), and awk `system()`/`getline` now classify WRITE (corpus-pinned in `tests/testdata/classifier-corpus.txt`); busybox/toybox multiplexers and the wrapper binaries (`nice`, `nohup`, `time`, `taskset`, `chroot`, `unshare`, `setsid`) are not on the read allowlist, so they fail closed as writes. The remaining structural gap is an *unlisted* GNU long-option abbreviation. Status per item under "Read-only gate hardening" below. The classifier stays an arms race; on hosts with the kernel read jail a misjudged read is bounded by the jail (it cannot change host files, reach Unix-socket daemons or touch other processes, but it keeps network access), and on hosts without it there is no second wall. See [`THREAT-MODEL.md`](THREAT-MODEL.md).
13. **PTY denial + `~/.ssh/rc` denial — CLOSED.** The forced-command entry that provisioning writes now leads with `restrict` and additionally pins `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding` (`commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`, golden-pinned by a test). A third-party SSH client holding the SSHGate key can no longer allocate a PTY, so `less`/`man`/`vim` of a large file cannot go interactive and `!sh` cannot escape the gate. `restrict` also denies `~/.ssh/rc` execution (`no-user-rc`) — so a landed write to `~/.ssh/rc` cannot yield a shell outside the gate on the next connection — and auto-includes any future OpenSSH restriction. Enforced at the `authorized_keys` layer (OpenSSH ≥ 7.2).
14. **No debug mode, no `--no-redact` flag, no environment override.** A signed `redact.why <key>` (a designed, not-yet-shipped wire command) is the only sanctioned way to learn what a marker references — and it returns only the *source* rule and provenance, never plaintext. Operators who need plaintext today use the approved secret-reveal (`reveal=true`) or the master key path out-of-band.
15. **Cross-session correlation is intentionally lost.** The per-session HMAC salt is rotated per `gate` process. Two markers with the same `key` in different sessions are coincidental, not correlated. 32-bit HMAC collides at scale; if cross-session correlation matters, see "Cross-session HMAC-key recovery for legitimate audit" above.
16. **No retroactive redaction.** The redactor sees bytes as they stream past. If a rule is added mid-session that would have caught an earlier byte, that byte is gone. Operators must restart the session to apply newly-added rules.

## Read-only gate hardening (deferred MINORs/MAJORs from security research)

Tracked from [`security-readonly-bypass.md`](security-readonly-bypass.md). Status against the current classifier is noted per item. The project's structural answer for the whole family is the kernel read jail, which limits what a misjudged read can do rather than making the classifier perfect; it applies only on hosts that support it.

- **`sed -e` / `awk -e` arbitrary expression execution.** sed's `e` flag is direct RCE on a read-allowlisted binary. Same for `find -fprintf` / `-fprint`. **Status: CLOSED** — the classifier does per-binary sub-feature classification for these (`sed` `e`/`w`/`r` script commands, `find -fprint*`/`-fls`, awk `system()`/`getline`/output-redirect; all corpus-pinned WRITE).
- **GNU long-option abbreviation.** `--compress-prog` accepted when `--compress-program` denied. **Status: partially closed, structurally UNSOLVED.** A prefix-matching pass added coverage for the *known-dangerous* long-options (`--in*` → `--in-place`, `--rot*` → `--rotate`, etc.), so the catalogued bypasses are blocked. The open problem: an *unlisted* dangerous long-option still slips through, because the classifier doesn't model each binary's real getopt grammar. The structural fix is one of: (a) parse the full GNU getopt grammar per binary, or (b) maintain per-binary canonical-option tables and resolve any abbreviation against them. Both are non-trivial and unscheduled. Until then this stays an accepted, tracked gap (defense-in-depth, model-assumed-not-rogue framing).
- **Environment-variable smuggling.** `LD_PRELOAD=… cmd`, `IFS=…`, `PATH=…`, `GIT_SSH_COMMAND=…`, `PAGER=…`, `EDITOR=…` passed via `FOO=bar cmd` prefix escape argument filters. **Status: CLOSED** — dangerous assignment prefixes classify WRITE (corpus-pinned: `LD_PRELOAD=… cat`, `IFS=… ls`, `env LD_PRELOAD=… cat`).
- **Wrapper-binary unwrap gaps.** `env`, `nice`, `nohup`, `time`, `taskset`, `chroot`, `unshare`, `setsid` strip the leading wrapper — the real command is what executes. **Status: fail-closed** — `env` gets true recursive unwrap (`src/classify/env.go`); the others are not read-allowlisted, so any wrapper-prefixed command classifies WRITE. Recursive unwrap for the rest would be a read-UX improvement, not a security fix.
- **Busybox / toybox multiplexer dispatch.** `busybox sh -c '…'` would be direct shell access if `busybox` were allowlisted as "known safe". **Status: fail-closed** — neither multiplexer is on the read allowlist; the dispatch classifies WRITE.
- **Line-continuation injection.** `echo "ok \<newline>$(id)"` — POSIX-shell line-continuation behaviour differs from naive tokeniser expectations. **Status: CLOSED** — the classifier honours backslash escapes outside single quotes, and `$(…)` substitution is unconditionally WRITE (both continuation forms verified WRITE against the current classifier).

## Release and distribution

- **Tagged releases.** The verified release channel is built (the committed `dist/gate/sshgate-gate-linux-amd64`, its published `.sha256`, and the reproducible-build CI check; `make release-gate` pins the Go toolchain from `go.mod` and locks the build environment). Still open: tagged GitHub Releases and a build-attestation artifact per release.
- **Plugin manifest validation** against the current Claude Code plugin schema before each publish.
- **Hosted deployment extensions:** a Docker image or Compose profile, a first-class browser passkey-enrollment page, backup automation and HA deployment for the hosted signer.

### Empirical questions to answer post-ship
- Real-world FPR/FNR on command output across `journalctl`, `env`, `docker inspect`, `kubectl describe`. No public benchmark exists for streaming scanners on command output; SSHGate will publish the first.
- Performance under `thorough` mode with entropy enabled on 10 GB+ `journalctl --no-pager` dumps. May warrant runtime auto-downgrade ("output > 100 MB → drop to standard for this command only"); deferred.
- HMAC redaction's effect on agent reasoning quality. Does Claude debug effectively when secrets are HMAC tokens? Only operator usage answers.
- Whether exposing the redactlist as a Claude tool (`sshgate.list_redact_patterns`) gives a hostile model the rule names it would need to craft evasions. `sshgate.list_redact_patterns` is a deferred wire command, not one of the eleven shipped MCP tools; the MCP-side tool surface for listing is deferred for this reason.
- Whether to expose the redactlist as machine-readable audit output (SARIF, CycloneDX) for enterprise consumers. Deferred until a request appears.
- Per-chunk wall-clock budget (default 50 ms; configurable) as a ReDoS safety net for pathological regexes that pass auto-validation but degrade on adversarial input. Parked backlog item.

## Trigger conditions and prioritisation rules

These are the conditions under which a deferred item gets promoted to active work. They keep the backlog from being a wish list.

- **`thorough` mode** — condition (a) **FIRED 2026-07-02** (a production run reported missed-secret categories named-format-only didn't catch). The response shipped the bounded generic net + live `Rule.Entropy` into `standard` rather than a whole mode; `thorough`'s remaining promotion trigger is (b) audit-workflow demand (someone running SSHGate manually to scan a corpus, where the looser 1-/2-class + lower-floor gates and depth-3 decode earn their false-positive cost).
- **`verified` mode** — promoted only when (a) `thorough` is already shipped AND (b) a verified-mode use case appears (audit team wants "this AWS key — is it actually live?"). Otherwise it stays parked indefinitely; the value-per-engineering-week is low.
- **BPE token scoring** — promoted if `thorough` ships and FPR is still too high for audit use. Otherwise parked.
- **Hosted signer extensions** — the core and web foundation is in the
  repository, but its policy authority and release gates remain open (see
  [`ROADMAP.md`](ROADMAP.md)); after those close, promote per-client credentials,
  hosted Telegram, or HA when a concrete multi-client, notification or replica
  need appears.
- **macOS install** — promoted on first macOS operator request. Small enough to do reactively.
- **`redact.list` UX** — promoted once the redactlist exists and a host crosses ~50 entries and the operator says "I can't see what's in there." Cheap to ship.
- **Read-only gate hardening** — promoted *immediately* upon any confirmed in-the-wild bypass. The MAJORs from [`security-readonly-bypass.md`](security-readonly-bypass.md) are tracked separately as a hardening sprint, not as feature releases.

## How this document is maintained

- When an item is scheduled, it moves to [`BUILD-PLAN.md`](BUILD-PLAN.md) and its entry here is removed or becomes a one-line pointer. When it is built, the pointer goes too.
- When a new deferral is accepted (e.g. a code review surfaces a MAJOR that won't fit the current release) → append a new section with the same `Why / Status / Estimated scope / Open questions / Trigger` structure.
- The durable reference docs in `docs/` (the architecture, security-research, and redaction references) are the authoritative source for *why* something is deferred. This file is the index; those references carry the rationale.
