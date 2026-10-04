# Changelog

All notable changes to SSHGate are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Dates are intentionally omitted where a release has not yet been tagged and
published; entries are ordered newest-first by version.

## [0.1.5]

The kernel read jail (phase 1 of work item #22), plus public-release polish:
lead with the threat model, cut the daily-driver tap tax, close the remaining
forced-command gap, and make the repo page trustworthy (CI and honest docs). This
is a code line, not a tagged release, and not the v0.2 milestone: v0.2 is cut
only when its release gates pass (see `docs/ROADMAP.md`).

### Added

- **Kernel read jail (`ro-v1`)** — on a host with unprivileged user namespaces
  (able to mount) and Landlock, the gate runs every command the classifier calls
  a read inside a jail: its own user, mount and IPC namespaces (the host PID
  namespace is kept), a read-only view of the host (host `/tmp` and `/var/tmp`
  stay visible, read-only), a private 64 MiB `/dev/shm` as the only scratch
  space, Landlock, and a seccomp filter that rules on every syscall. A read
  there cannot write files or file metadata on the host, reach a local daemon
  over a Unix socket, or signal or trace other processes. The jail checks itself
  before the command runs and refuses the read (exit 77) if setup or any check
  fails; it never falls back to running the read unconfined. Reads keep TCP/UDP
  network access. A fixed allowlist of `systemctl`/`docker` read verbs runs
  outside the jail, shell-free, because it needs the daemon sockets. Signed
  writes and the admin verbs run exactly as before. A host without both user
  namespaces and Landlock runs reads unconfined, as before.
- **`gate doctor`** — run on the host, it reports whether reads there are
  jailed, unconfined or denied. `gate doctor --pin` writes a `jail-floor` file
  holding `full`, after which the gate refuses reads (exit 77) rather than run
  them unconfined if the jail becomes unavailable. Residual gaps are listed in
  `docs/THREAT-MODEL.md`.
- **Exact exit status** — when the jailed worker's status is known, the gate
  returns the command's real exit code (or 128 + signal), also after a
  cancellation or when the client went away. When that status is unavailable it
  returns 143 if the read was cancelled, and otherwise the jail shim's own
  status. The audit record keeps the process status apart from output delivery
  (dropped bytes, delivery and cleanup errors).
- **Jail proof suite** — `make test-jail` runs the jail's acceptance matrix (CI
  workflow `jail`), and `make test-jail-mutate MUTATE=<ids>` proves each of the
  jail's 195 protections is load-bearing by removing it and requiring a named
  test to catch the change.
- **Build plan** — `docs/BUILD-PLAN.md` lists the work that comes next, in
  order.
- **`ping` tool** — a read-class single-server reachability probe (a
  short-timeout `SSHGATE_OK` check against one named server). No approval, no
  signer, and cheaper than `status` because it does not fan out across every
  registered server. The agent MCP surface is now **eleven tools**.
- **Per-command output cap** — a single command's output is bounded before it
  reaches the conversation, so one noisy read can't flood the context.
- **Server tier surfacing** — `list_servers`, `status`, and `ping` now report
  each server's tier as a `read_only` boolean (`true` = Tier-1 read-only,
  absent/`false` = signed-write).
- **CI test workflow** — a `tests` GitHub Actions workflow runs `go vet` plus
  the race-enabled unit suite (including the classifier regression corpus in
  `tests/testdata/classifier-corpus.txt`) on every push and pull request. A
  status badge is on the README so the test gate is verifiable from the repo
  page. `verify-gate` (the reproducible-build check on the committed gate
  binary) continues to run as a separate workflow.
- **`docs/THREAT-MODEL.md`** — an honest one-page threat model: what SSHGate
  enforces and where, what the classifier is and is **not**, what each tier
  buys, and the residuals it does **not** protect against. The README points
  to it before install.

### Changed

- **README rewritten** for a first-time reader: what SSHGate is and why, a
  read-only quick start, how it works, and what it does and does not protect
  (linking the threat model), then install, tiers, tools and the read jail. It
  states plainly that the signature plus the OpenSSH forced command is the
  security boundary, while the read/write classifier only *routes*.
- **Read-batch default is now continue-on-error** — a read-only `run_batch` no
  longer aborts the rest of a diagnostic sweep when one read fails. Write
  batches still stop on the first failure (each write is individually signed).
- **Single interactive installer pass** — Tier-2 signer setup now prompts for
  the Telegram user-id and bot token in one run. The old flow (install.sh →
  hand-edit a root-owned TOML with tee/sed → install.sh a second time) is gone.
- **Classifier false-positive cut** — allowlisted common read utilities and
  additional read subcommands (kubectl/docker/git/systemctl) and treated
  stderr-only redirects (`2>&1`, `2>/dev/null`) as non-writes, cutting the tap
  tax on daily use. Fail-closed remains the default: anything not affirmatively
  a known-safe read still routes to approval.
- **`uninstall.sh --purge`** now warns before destroying the master signing key
  (which would orphan the whole fleet) instead of silently wiping it.
- **Honest install claims** — removed the "30-second install" framing in favor
  of real time estimates (~2 min Tier 1, ~10 min Tier 2), consistent with
  `INSTALL.md`.

### Fixed

- **Tier-1 revoke short-circuit + honest re-tier messaging** — `revoke_server`
  now short-circuits a read-only (Tier-1) host with a clear message *before*
  spending a Telegram tap, and the docs/error strings no longer prescribe the
  structurally-impossible in-place tier-upgrade path.
- **#62 tier-reconcile** — a probe-idempotent re-add now reconciles a server's
  recorded tier instead of leaving the registry marked signed-write while the
  host stays read-only.
- **Friendlier denials** — when the gate or classifier refuses or routes to
  approval, the message says *why* (which segment, which rule) and what to do.
- **Redaction — certificate/public-key over-redaction** — completed PEM blocks
  are now type-checked: certificates, public keys, and CSRs are no longer
  hard-redacted, so `cat server.crt` stays readable. Only private-key blocks
  (and unrecognized BEGIN labels, fail-closed) redact wholesale.
- **Redaction — SSH public-key false positive** — the generic/high-entropy net
  no longer eats SSH public-key bodies (`AAAA…`) on `authorized_keys`-style
  lines, via an ssh-line veto with an anti-spoof body-prefix check.

### Security

- **`restrict` forced-command hardening** — the OpenSSH forced-command option
  template now leads with `restrict` (OpenSSH ≥ 7.2), in addition to the explicit
  `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding` list.
  `restrict` is the deny-all catch-all: it closes the one gap the explicit list
  left open — **`no-user-rc`** (with a forced command, sshd otherwise runs a
  pre-existing `~/.ssh/rc` as a full shell *before* the forced command, so an
  agent that ever landed a write to `~/.ssh/rc` would get a shell outside the
  gate on the next connection) — and auto-includes any future OpenSSH
  restriction, so the line is deny-by-default rather than allowlist-by-omission.
  The gate never asks for a PTY or `~/.ssh/rc`, so this only removes out-of-band
  escape surfaces and never affects SSHGate's own traffic. Requires OpenSSH ≥ 7.2
  on the target (2016; a safe floor for modern hosts — a pre-7.2 sshd would
  reject the line). New provisions get `restrict` automatically. **Already-
  provisioned hosts keep their old `authorized_keys` line until re-provisioned**
  (a re-`add` on a registered alias is refused with a de-provision-first error,
  and the idempotent recovery path never rewrites an already-gated line): to
  harden an existing host, strip SSHGate's forced `command="..."` line from its
  `~/.ssh/authorized_keys`, drop the alias from `~/.config/sshgate/servers.json`,
  then re-run `sshgate add`.
- **`no-pty` forced-command hardening** — the OpenSSH forced-command option
  template now pins `no-pty` alongside `no-port-forwarding`,
  `no-X11-forwarding`, and `no-agent-forwarding`. Without it, a third-party SSH
  client holding the SSHGate key could request a PTY and turn a read-allowlisted
  pager/editor (`less`, `man`, `vi`) interactive for a `!sh` escape that bypasses
  the gate. New provisions get `no-pty` automatically. **Already-provisioned
  hosts keep their old (PTY-permitting) `authorized_keys` line until they are
  manually re-provisioned** — a bare `sshgate add` on an already-gated host is
  idempotent and does NOT rewrite the forced-command line, so it does not apply
  `no-pty` to an existing host. To harden an existing host, de-provision it by
  hand (strip SSHGate's forced `command="..."` line from the host's
  `~/.ssh/authorized_keys` so the gate stops answering, and drop the alias from
  `~/.config/sshgate/servers.json`), then re-run `sshgate add`.

## [0.1.4]

Box→box secret transfer, and the gate binary release that ships it.

### Added

- **`transfer` MCP tool** — moves a secret file between two registered servers,
  end-to-end encrypted through the gate under one human approval. The agent
  supplies only aliases and absolute paths; the source gate seals the value to
  the destination's registered box key and the MCP relays only ciphertext.
- **`sshgate` CLI transfer verbs** — `xfer-register`, `xfer-rotate`, and
  `xfer-status` enroll, re-key, and inspect a host's transfer keypairs. Like
  provisioning, these are human-only — there is no agent tool for them.
- **Gate `genkeys` subcommand** — generates each host's transfer keypairs
  (X25519 box key + Ed25519 identity key) on the host; the private keys never
  leave it. Tier-2 provisioning runs it over the bootstrap leg and registers the
  host under its computed fingerprint.

### Changed

- **VERSION `0.1.3` → `0.1.4`**, and the gate binary in `dist/gate/` was
  regenerated (now carrying the transfer/genkeys code paths) and re-published
  with its `.sha256`, verified reproducible by the `verify-gate` check.

### Security

- **Transfer plaintext never reaches the agent or any log** — the MCP relays
  ciphertext only; the agent gets metadata only (transfer id, byte count). One
  human "SECRET TRANSFER" Telegram approval covers both signed, host-bound legs;
  a standing grant can **never** auto-sign a transfer; read-only (Tier-1)
  endpoints are refused before any tap.
- **Signer trust registry** — transfer keys are taken **only** from a
  human-maintained per-server registry on the signer, and the sign path rejects
  any `SSHGATE_XFER_*` payload before grant-matching. Transfers require the local
  Tier-2 Telegram signer; the hosted Tier-3 signer does not support them yet and
  fails closed.
