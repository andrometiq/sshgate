# SSHGate — threat model (read this first)

One page, honest, no marketing. It states what SSHGate actually enforces, what it
only routes, and what it does **not** stop. Everything here is a condensation of
the reference docs; each residual cites its source so nothing overstates. For the
full reasoning see [`design.md`](design.md),
[`approval-architecture.md`](approval-architecture.md),
[`FUTURE.md`](FUTURE.md), and
[`security-readonly-bypass.md`](security-readonly-bypass.md).

## The boundary — what actually enforces

**The security boundary is the signature plus the OpenSSH forced command, checked
on each remote server. The read/write classifier only *routes*; it is not the
wall.**

- SSHGate's dedicated key is pinned on every remote to a forced command
  (`restrict,command="~/.sshgate-gate/gate"`, plus `no-pty,no-port-forwarding,no-X11-forwarding,
  no-agent-forwarding`; `restrict` also denies `~/.ssh/rc` execution and any future OpenSSH
  capability). **OpenSSH enforces this server-side**: that key can only
  ever invoke the gate — never a shell or an arbitrary program.
  (`design.md` §"Provisioning", §"What the design protects against".)
- A **write** runs only if it carries a valid Ed25519 signature the gate verifies
  against the signing pubkey deployed on that host. No pubkey on the host
  (read-only / Tier 1) ⇒ no write can be signed ⇒ the gate refuses it
  locally, before any approval channel is even consulted.
- The signature carries a **bounded validity window** and a **per-host binding**
  (the target's TOFU-pinned host-key fingerprint), so an approved write cannot be
  replayed indefinitely or against a different host.

That chain — forced command + signature verification + host binding — is what a
skeptical reader should evaluate. It holds independently on each remote and does
not depend on the agent, the laptop, or Telegram behaving.

## What is enforced, and where

| Control | Enforced by | Where it runs |
|---|---|---|
| Key can only invoke the gate (no shell) | OpenSSH forced command | remote server |
| Write requires a valid signature | gate signature check | remote server |
| Read-only host refuses all writes | gate (no pubkey present) | remote server |
| Per-host binding + bounded TTL on a signed write | gate ⇄ signer | remote + signer |
| Inline secret redaction of command output | gate redactor | remote server |
| Human approval of a write | signer (Telegram tap / hosted signer) | operator machine or hosted host |
| Read-vs-write **routing** | shared classifier (fail-closed) | MCP + gate |

Note the last row is **routing**, not enforcement: the classifier decides whether
a command needs a signature. If it wrongly calls a write a "read", that command
runs without approval — which is why the classifier is discussed honestly below.

## What the classifier is, and is not

- **Is:** a **fail-closed heuristic** over `/bin/sh` syntax and each allowlisted
  tool's write/exec-capable flags. Anything not affirmatively a known-safe read —
  unknown binaries, pipes into non-reads, redirects, `;`/`&&`/`||`, command
  substitution, `sudo` — collapses to *write* and is routed to approval.
  (`design.md` §"Read/write classification".)
- **Is not:** a proof. Because reads are ultimately handed to a shell, an obscure
  tool flag or a shell-parse mismatch can in principle let a command the
  classifier deemed "read" do more than read. The default-deny structure holds
  (unknown ⇒ write), but per-tool flag enumeration cannot be proven complete
  against every tool on every server. The durable fix is structural — execute
  reads from a parsed `argv` with no intervening shell (the tracked argv-exec
  item). (`design.md` §"Read/write classification",
  `security-readonly-bypass.md`.)

## Tiers — what each one buys

- **Tier 1 — read-only.** The gate is deployed but no signing pubkey is
  pushed, so **writes are denied at the gate** — a real, server-side wall (a
  write literally cannot be signed). It is a *safety rail on the read side*: it
  still trusts the agent not to weaponize read access (file enumeration, log
  harvesting), and reads run without approval via the fail-closed classifier
  above. The fastest, lowest-trust on-ramp — not a full security posture.
- **Tier 2 — local Telegram signer.** The
  master key is isolated under a separate Unix user; writes need one phone tap.
  This is **a safety rail, not a hard wall**: it reliably catches mistakes and
  naïve prompt-injection and stops an *unprivileged* rogue agent, but an agent
  that can escalate privileges on the host (e.g. has `sudo`) can read the signing
  key directly and forge approvals. This caveat is load-bearing and surfaced to
  the operator, not buried. (`design.md` §"Install tiers",
  `approval-architecture.md`.)
- **Tier 3 — hosted signer boundary.** When the release-complete signer runs on
  a separate machine the agent cannot touch, the agent can only *ask* it to
  sign — it cannot read the key or forge an approval. **This is the only tier
  designed to be a hard boundary against a privileged rogue laptop agent.**
  The current branch contains the hosted backend, embedded TOTP/WebAuthn UI,
  SQLite approval foundation, and systemd deployment, but its v0.2
  policy-authority and release gates are still open. TLS/DNS, backups, and
  secret distribution remain operator responsibilities. (`design.md` §"Install tiers",
  `src/signer-server/README.md`.)

## What SSHGate does NOT protect against (be honest)

- **A privileged rogue agent on the same machine (Tier 2 local signer).** If the
  agent can escalate to root or to the signer's user, it can read the
  key and forge approvals. After its release gates close, use the hosted signer
  (Tier 3) when you need a hard guarantee. (`design.md` §"What the design
  protects against, and what it does not".)
- **The read-path classifier residual.** Most historically-catalogued read-only
  bypasses are now closed or fail closed in the live classifier (`sed e`,
  `find -fprintf`, env-var smuggling, awk `system()`; multiplexers and wrapper
  binaries are non-allowlisted). The tracked **structural** gap that remains is an
  *unlisted* GNU long-option abbreviation, open until the argv-exec fix lands.
  (`security-readonly-bypass.md`
  §"Security research — read-only gate bypass landscape", opening "Status
  update (2026-07)" callout, and
  §"Bypass categories cross-referenced with SSHGate"; `FUTURE.md`
  §"Operator-facing limitations (known and documented)", item 12, and
  §"Read-only gate hardening (deferred MINORs/MAJORs from security research)".)
  Do not read this as "solved"; read it as "default-deny + a standing regression
  corpus, with one known structural hole".
- **Kernel confinement of reads — partial and host-dependent.** On a host with
  unprivileged user namespaces (the full jail) or Landlock (the Landlock-only
  jail), the gate runs every command the classifier calls a read, signed or not,
  inside a kernel jail. There it cannot write any file or file metadata outside
  its own throwaway scratch space (two narrow exceptions are listed below), cannot connect to a local daemon over a Unix
  socket, and cannot signal or trace other processes (in the Landlock-only jail,
  blocking signals needs Landlock ABI 6 or newer). Unsigned reads in the jail have
  no network (TCP/UDP sockets denied), including localhost, until the pin's network
  permission lands. What it does **not** cover yet:
  - **Two narrow write paths remain on some hosts.** In the full jail on a host
    without Landlock, a read can still write into a named pipe (FIFO) that
    already exists on the host, reaching whatever process reads it; with root
    as the SSH user that includes root-only daemon FIFOs. The Landlock-only
    jail has no IPC namespace, so a read can remove or change System V IPC
    objects, such as shared memory segments, owned by the same user.
  - **Hosts with neither feature stay classifier-only.** Reads there run
    unconfined, exactly as before, and the gate's audit log labels them
    `unconfined`. `gate doctor`, run on the host, reports which level applies;
    `gate doctor --pin` records the current level as a floor, and the gate then
    refuses reads rather than run them below it.
  - **A fixed allowlist of `systemctl` and `docker` read verbs runs outside the
    jail**, because those reads need a local daemon socket. They run without a
    shell, from a fixed binary path, with a fixed minimal environment that
    also stops `docker` from reading the SSH user's own `~/.docker` config.
  - **Display and scratch differences in the full jail.** Files owned by other
    users may list as `nobody`/`65534`; access is unchanged. Each read gets a
    private, empty `/tmp`, `/var/tmp` and `/dev/shm`, so it cannot see the
    host's files there.

  This does not move the boundary stated above: the classifier still decides
  what needs a signature; the jail limits what a misjudged read can do on a
  capable host.
- **PTY-based escapes and `~/.ssh/rc` execution at the `authorized_keys` layer —
  closed.** The forced-command entry leads with `restrict` (the OpenSSH ≥ 7.2
  deny-all catch-all) and additionally pins
  `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding`
  (`commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`, golden-pinned by a
  test). `restrict` also denies `~/.ssh/rc` execution (`no-user-rc`) — so even if
  an agent ever landed a write to `~/.ssh/rc`, sshd will not run it as a shell
  before the forced command — and auto-includes any future OpenSSH restriction. A
  third-party SSH client holding the key can no longer request a PTY, so
  `less`/`man`/`vim` cannot be turned interactive for an `!sh` escape. Enforced at
  that layer. (`FUTURE.md`
  §"Operator-facing limitations (known and documented)", item 13.)
- **A compromised gate binary.** The gate is the on-remote trust anchor for both
  signature verification and redaction. A gate replaced through a non-SSHGate
  channel defeats both. The verified release channel (committed `dist/gate/`
  binary + published `.sha256` + the reproducible-build CI check) exists so the
  operator can confirm the bytes they deploy; it does not defend a host already
  compromised out-of-band. (`FUTURE.md` limitation #6.)
- **Redaction is defense-in-depth, not a perimeter.** Inline secret redaction
  scrubs secret-shaped output before it reaches the agent, but it is byte-level
  filtering *after* the read happened, with a known false-negative floor
  (bare-hex and short unnamed secrets). The model is assumed not rogue; the durable
  answer is kernel-level read enforcement. (`FUTURE.md` §Operator-facing
  limitations, §Landlock.)

## The trust the operator machine holds

Even at Tier 2, the operator's laptop is inside the trust boundary: it
holds the signing key (under a separate Unix user), the server registry (which
hosts the agent may reach), the staged gate bytes that `update_gate` pushes, and
the Telegram bot token. Provisioning — *defining* which machines the agent can
reach — is deliberately **human-only** and off the agent's tool surface, so the
agent can never expand its own reach; it only operates within boundaries a human
established (`design.md` §"Provisioning: control plane vs data plane"). A host
compromise of the laptop is therefore a compromise of the Tier-2 boundary.
After its policy-authority and release gates close, Tier 3 is intended for
operators who need the key off the agent's machine entirely.

## Where to read more

- [`design.md`](design.md) — full architecture, the three install tiers, and the
  protected/not-protected list this page condenses.
- [`approval-architecture.md`](approval-architecture.md) — why the boundary is
  *where the signer runs*, and the current approval surface for each tier.
- [`security-readonly-bypass.md`](security-readonly-bypass.md) — the read-only
  bypass landscape and per-item CLOSED/open status.
- [`FUTURE.md`](FUTURE.md) — the honest limitations list and the deferred
  hardening (argv-exec, Landlock).
