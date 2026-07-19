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
  (read-only / Install Tier 1) ⇒ no write can be signed ⇒ the gate refuses it
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
  (`design.md:147-167`.)
- **Is not:** a proof. Because reads are ultimately handed to a shell, an obscure
  tool flag or a shell-parse mismatch can in principle let a command the
  classifier deemed "read" do more than read. The default-deny structure holds
  (unknown ⇒ write), but per-tool flag enumeration cannot be proven complete
  against every tool on every server. The durable fix is structural — execute
  reads from a parsed `argv` with no intervening shell (the tracked argv-exec
  item). (`design.md:154-167`, `security-readonly-bypass.md`.)

## Tiers — what each one buys

SSHGate numbers install tiers and approval tiers differently; the mapping is in
`design.md:293-295` (**do not** use `approval-architecture.md`'s bare "Tier 1/2"
headers, which currently number the opposite way — see the redline draft).

- **Install Tier 1 — read-only.** The gate is deployed but no signing pubkey is
  pushed, so **writes are denied at the gate** — a real, server-side wall (a
  write literally cannot be signed). It is a *safety rail on the read side*: it
  still trusts the agent not to weaponize read access (file enumeration, log
  harvesting), and reads run without approval via the fail-closed classifier
  above. The fastest, lowest-trust on-ramp — not a full security posture.
- **Install Tier 2 — same-machine Telegram signer (= Approval Tier 1).** The
  master key is isolated under a separate Unix user; writes need one phone tap.
  This is **a safety rail, not a hard wall**: it reliably catches mistakes and
  naïve prompt-injection and stops an *unprivileged* rogue agent, but an agent
  that can escalate privileges on the host (e.g. has `sudo`) can read the signing
  key directly and forge approvals. This caveat is load-bearing and surfaced to
  the operator, not buried. (`design.md:235-249`, `approval-architecture.md`.)
- **Install Tier 3 — hosted signer (= Approval Tier 2).** The signer runs on a
  separate machine the agent cannot touch, so the agent can only *ask* it to
  sign — it cannot read the key or forge an approval. **This is the only tier
  that is a hard boundary against a privileged rogue laptop agent.** v0.2 ships
  the hosted backend, embedded TOTP/WebAuthn UI, SQLite approval policy, and
  systemd deployment; TLS/DNS, backups, and secret distribution remain operator
  responsibilities. (`design.md:251-291`, `src/signer-server/README.md`.)

## What SSHGate does NOT protect against (be honest)

- **A privileged rogue agent on the same machine (Install Tier 2 / Approval Tier
  1).** If the agent can escalate to root or to the signer's user, it can read the
  key and forge approvals. Use the hosted signer (Tier 3) when you need a hard
  guarantee. (`design.md:315-320`.)
- **The read-path classifier residual.** Most historically-catalogued read-only
  bypasses are now closed or fail closed in the live classifier (`sed e`,
  `find -fprintf`, env-var smuggling, awk `system()`; multiplexers and wrapper
  binaries are non-allowlisted). The tracked **structural** gap that remains is an
  *unlisted* GNU long-option abbreviation, open until the argv-exec fix lands.
  (`security-readonly-bypass.md:5-14`, `FUTURE.md:89, 95-104`.) Do not read this
  as "solved"; read it as "default-deny + a standing regression corpus, with one
  known structural hole".
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
  that layer. (`FUTURE.md:90`.)
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

Even at Install Tier 2, the operator's laptop is inside the trust boundary: it
holds the signing key (under a separate Unix user), the server registry (which
hosts the agent may reach), the staged gate bytes that `update_gate` pushes, and
the Telegram bot token. Provisioning — *defining* which machines the agent can
reach — is deliberately **human-only** and off the agent's tool surface, so the
agent can never expand its own reach; it only operates within boundaries a human
established (`design.md` §"Provisioning: control plane vs data plane"). A host
compromise of the laptop is therefore a compromise of the Tier-2 boundary — which
is exactly why Tier 3 (hosted signer) exists for anyone who needs the key off the
agent's machine entirely.

## Where to read more

- [`design.md`](design.md) — full architecture, the two-tier approval model, and
  the protected/not-protected list this page condenses.
- [`approval-architecture.md`](approval-architecture.md) — why the boundary is
  *where the signer runs*, not which bot delivers the message.
- [`security-readonly-bypass.md`](security-readonly-bypass.md) — the read-only
  bypass landscape and per-item CLOSED/open status.
- [`FUTURE.md`](FUTURE.md) — the honest limitations list and the deferred
  hardening (argv-exec, Landlock).
