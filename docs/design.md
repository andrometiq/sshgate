# SSHGate — Design, Architecture, and Threat Model

SSHGate is a Claude Code plugin that lets an AI agent SSH into Linux servers to
diagnose and operate them. **Read** commands run freely; **write** commands
require an explicit human approval delivered to a phone over Telegram. A small
binary on each remote server enforces this split independently of the agent.

This document describes what SSHGate is, the trust boundaries it draws, how the
remote gate and the signed-write protocol work, and what the design does and
does not protect against.

---

## The security goal

Full SSH access for an autonomous agent is dangerous. A mistaken `rm -rf`, an
accidental `truncate`, a hallucinated `systemctl stop`, or a prompt-injection
that turns into a destructive command — any of these on a production host is a
bad day. The conventional safeguard is to keep a human in the loop, relaying
every command by hand. That is slow and wasteful.

SSHGate's goal is a gate that does not waste the human's time:

```
read command              → execute
write command + signature → verify → execute
write command, no sig     → deny
```

Diagnostics stream through automatically. Anything that mutates state pauses for
an explicit human "yes." The signing key that authorizes writes is held outside
the agent's reach, so the agent can *request* an approval but cannot *produce*
one.

---

## The three trust domains

SSHGate separates three parties so that no single one can both decide to run a
write and authorize it:

1. **The user domain** — the operating-system user that runs Claude Code, the
   SSHGate MCP server, and the SSHGate SSH client key. This domain initiates
   commands. It holds the dedicated SSH client key but **not** the master
   signing key.

2. **The signer domain** — a separate, dedicated Unix user that owns the master
   Ed25519 signing key, the Telegram bot token, and the approval socket. Because
   it is a different OS user with `0600` key files and (on modern Linux)
   `kernel.yama.ptrace_scope=1`, the user domain cannot read its key file or
   trace its process memory. The signer signs a write only after a verified
   human approval.

3. **The Telegram domain** — the operator's phone. Telegram authenticates the
   approver at the protocol level: the signer only honors a callback whose
   `from.id` matches the single allowlisted operator id, and the agent has no
   Telegram identity tied to that id and no path to obtain one.

The separation is what makes "approver ≠ runner" real. If the signing key lived
in the same domain as the agent, the agent could forge its own approvals and the
gate would be theater. (See *The two-tier approval model* below for the honest
limits of same-machine separation.)

---

## The remote gate

On every registered server a single small Go binary, the **gate**, sits between
OpenSSH and shell execution. It lives at `~/.sshgate-gate/gate` and is reached
through OpenSSH's forced-command mechanism.

### Forced command and key pinning

When a server is provisioned, the SSHGate SSH public key is pinned in the
remote's `~/.ssh/authorized_keys` as a restricted entry:

```
restrict,command="~/.sshgate-gate/gate",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... sshgate
```

The `command="..."` clause traps **every** connection made with that key into
the gate. The key can run the gate and nothing else — never an interactive
shell, never an arbitrary program. OpenSSH enforces this server-side; it is not
something the client can opt out of. The real command the client requested
arrives to the gate in `SSH_ORIGINAL_COMMAND`.

A dedicated key is used precisely so this forcing is total. Reusing a normal
login key would route every interactive `ssh`, `git push`, and `scp` through the
gate, and an existing unrestricted `authorized_keys` entry for that key would let
any process holding it bypass the gate entirely. The dedicated key also bounds
blast radius: if it leaks, the damage is limited to gate-mediated operations on
the registered servers.

### What the gate does per command

1. **Classify** the command as read or write (see *Read/write classification*).
2. If **read**, execute it directly and return output (streamed through the
   inline secret redactor; see below).
3. If **write**, require a valid signature: the command must arrive wrapped in an
   `SSHGATE_SIG` envelope that verifies against the signing public key deployed
   to the host. A valid, unexpired signature whose payload matches the command
   is executed; anything else is denied.

The gate stores no mutable configuration. Its classifier is compiled in, and its
only trust anchor is the deployed signing public key (`gate.pub`). On a
read-only host no public key is deployed at all, so writes can never be
authorized there regardless of what the client sends.

### Signed-write wire format

A write is carried as a single envelope prefixed to the command, of the shape:

```
SSHGATE_SIG:<signature>:<payload> <command>
```

The signed `payload` is a small JSON object — the command text plus an issued-at
timestamp and an expiry. The gate:

- decodes the envelope and re-marshals the payload to obtain the exact bytes that
  were signed,
- verifies the Ed25519 signature over those bytes against the deployed public
  key, then executes the command carried in the signed payload — integrity comes
  from the signature over those bytes, not from any comparison against the
  forwarded `SSH_ORIGINAL_COMMAND`,
- rejects malformed or non-positive timestamps, and rejects a token whose
  validity window (`exp − ts`) exceeds the maximum allowed lifetime, and
- rejects an expired token (`now ≥ exp`).

Only a payload that passes every check is executed. Because each command is
signed individually, the audit trail is per command even when many are approved
in one tap. The bounded validity window caps how long an approved signature
remains usable.

Denials are reported with conventional sysexits-style exit codes so the agent can
react precisely — for example, a missing signature or a host with no signer
public key is distinguishable from a bad or expired signature (the latter usually
clock skew or a stale approval, safe to retry once).

---

## Read/write classification

The gate and the MCP share one classifier so that both agree on which commands
need approval (the signer signs what the MCP hands it; it does not classify).

The classifier is **fail-closed**: anything that is not affirmatively a known
read command is treated as a write and routed through approval. Pipes,
redirects, control operators (`;`, `&&`, `||`), command substitution, `sudo`
prefixes, and unknown binaries all collapse to *write* by design. Read status is
granted only to an allowlist of known-read binaries invoked with known-safe
flags.

### Known limitation

The classifier is a heuristic that reasons about `/bin/sh` syntax and about each
allowlisted tool's write/exec-capable flags. Because reads are ultimately handed
to a shell, this is an inherent arms race: an obscure flag or a shell-parsing
mismatch can let a command the classifier deemed "read" do more than read. The
default-deny structure holds — unknown binaries are always writes — but per-tool
flag enumeration cannot be proven complete against every tool on every server.

The durable fix is structural: execute reads from a parsed `argv` directly
(`execve`, no intervening shell) so the classifier's view of the command is
exactly the view that executes, eliminating the entire shell-parse-mismatch
class. This is a tracked roadmap item (the argv-exec classifier fix). Until then
the fail-closed posture and a standing regression corpus are the mitigation.

---

## Inline secret redaction

Command output can contain secret-shaped strings — private keys, tokens,
passwords in config dumps. The gate redacts these inline as it streams output
back — for reads and writes alike — so secrets are scrubbed before they ever
reach the agent's context. The only bypass is a human-approved secret-reveal
carried in a single signed command. Redaction runs in the gate itself; it is
part of the remote-side trust boundary, not a client-side courtesy.

---

## Provisioning: control plane vs data plane

SSHGate draws a deliberate line between **defining** which machines the agent may
reach and **operating** within those machines.

- **Provisioning is the control plane and is human-only.** There is no agent tool
  to add a server. A human registers a machine with the `sshgate` CLI at a
  terminal:
  1. `sshgate pubkey` prints SSHGate's dedicated public-key line.
  2. The human pastes that line into the target's `~/.ssh/authorized_keys`
     out-of-band, using existing admin access to the box.
  3. `sshgate add <alias> <user@host>[:port] [--read-only]` connects with
     SSHGate's own key, installs the gate, and rewrites the pasted plain line
     into the locked `command="~/.sshgate-gate/gate"` forced-command entry. The
     alias is recorded in the local server registry that the MCP reads.

  Keeping provisioning off the agent surface means the agent can never expand its
  own reach. It only ever operates within boundaries a human established.

- **Operating is the data plane and is the agent's surface.** The MCP exposes
  exactly eleven tools:

  | Tool | Purpose |
  |---|---|
  | `run` | Run one command on a registered server. Reads run immediately; writes request approval, then run. |
  | `run_batch` | Run several commands; writes bulk-approve together in one Telegram tap. `stop_on_error` defaults to true for a batch containing any write and to continue-on-error for an all-read batch (override explicitly). |
  | `list_servers` | List the registered server aliases (each with its `read_only` tier). |
  | `status` | Report signer health and per-server reachability (each with its `read_only` tier). |
  | `ping` | Probe reachability of ONE named server (short SSHGATE_OK check). READ-class — no approval, no signer, no fan-out across every server. |
  | `revoke_server` | Uninstall the gate from a server (itself an approved action). |
  | `request_grant` | Request a standing grant so matching writes auto-sign for a window (≤ 24h); the human must approve a distinct "STANDING GRANT" Telegram message — the agent can only request, never self-grant. |
  | `revoke_grant` | Drop a server's standing grant so writes prompt again. De-escalation only — always safe, needs no approval. |
  | `list_grants` | List the live standing grants the signer currently holds (optionally filtered to one alias). Read-only, no approval — used to reconcile true grant state after a `request_grant` whose approval may have timed out. |
  | `update_gate` | Request a signed, in-place update of the gate binary on an already-registered server. The agent supplies only the alias; the MCP hashes the operator's locally-staged gate binary and the human must approve a distinct "GATE BINARY UPDATE" Telegram banner bound to that exact SHA-256. Fail-closed (hash mismatch / wrong-arch binary / Tier-1 all refuse and write nothing), signed, and audited; onboards no new server (so it can't expand the agent's reach) and a standing grant never auto-signs it. |
  | `transfer` | Move a secret file between two registered servers end-to-end encrypted through the gate under one human approval. The agent supplies only aliases + absolute paths (never keys, fingerprints, or an id); the MCP relays only ciphertext (SEND stdout → RECV stdin), so the plaintext never reaches the agent or any log. A standing grant can never auto-sign it, and read-only (Tier-1) servers are refused before any tap. Requires the local Tier-2 Telegram signer (the hosted Tier-3 signer fails closed on transfers). |

  There is intentionally no provisioning tool here. If asked to add a server, the
  agent directs the human to the CLI steps above.

For reads the MCP SSHes directly and returns output. For writes it assembles a
sign request, sends it to the signer over the local socket, waits for the
operator's decision, and only then SSHes the signed command across. When several
writes are queued together they go into a single sign request, so one approval
tap covers all of them while each command stays individually signed.

---

## The two-tier approval model

The strength of an approval depends on **where the signer runs relative to the
agent**, not on which channel delivers the message. SSHGate offers two approval
tiers and is honest about what each one buys. (For the full reasoning, see
[approval-architecture.md](approval-architecture.md).)

### Approval Tier 1 — same machine (a safety rail, not a wall)

The signer runs on the same machine as the agent, as a separate Unix user, and
approvals are routed through the operator's existing Telegram setup.

This is the easy path: no separate signing infrastructure to stand up. The OS
user separation (`0600` key, `ptrace_scope=1`) raises the bar against an
*unprivileged* rogue agent and reliably catches **mistakes** (a wrong or
destructive command) and **naïve prompt-injection**.

It is explicitly **not** a hard boundary. An agent that can escalate privileges
on the host — for example, one that has `sudo` — can read the signing key
directly and forge approvals, bypassing the gate. No message-routing choice
changes that. On one machine, approval is a safety rail, not a security wall.
This caveat is load-bearing and is surfaced to the operator, not buried.

### Approval Tier 2 — separate hosted signer (the real boundary)

The signer runs as a hosted service on a separate machine the agent cannot
touch. The agent can only *ask* it to sign over the network; it cannot read the
key, forge an approval, or escalate. This is the recommended path for anyone who
needs an actual guarantee.

Because the key and the approval check live on a host the agent has no access to,
theft of a bot token or compromise of any single channel degrades only to denial
of service (the request just is not approved) — never to a forged approval. The
cryptographic operator factor (passkey / WebAuthn, and N-of-M approval) lives in
the server; a channel such as Telegram is a notification surface for it, not the
root of trust.

Both tiers share one signer core: the same approval logic, the same signed-command
wire format, the same timeout chain, and the same audit log. Only the channel
differs.

---

## Install tiers

The setup flow is tiered and idempotent. Start with the lightest tier that meets
your needs and upgrade later without tearing anything down.

- **Tier 1 — read-only.** The gate is deployed to each remote, but **no** signing
  public key is uploaded. Reads work; every write is denied at the gate. No
  Telegram bot, no signer daemon, no `sudo` required. This is the fastest install
  and the natural starting point.

- **Tier 2 — local Telegram signer (signed-write).** A signer daemon runs on the
  operator's machine under a dedicated Unix user, holding the master signing key
  and the bot token. Writes are approved with one tap on Telegram and then signed.
  This corresponds to same-machine approval (Approval Tier 1 above): a strong
  safety rail with the documented same-machine caveat.

- **Tier 3 — hosted signer (separate machine).** The signer runs on a separate
  host the agent cannot reach, giving the real boundary (Approval Tier 2 above),
  with a richer approval surface (web UI plus Telegram, N-of-M approval,
  centralized audit). This tier is the recommended investment where a hard
  guarantee is required; its remaining productization is tracked on the roadmap.

> Naming note: the install tiers and the approval tiers number differently.
> Install Tier 2 (local Telegram signer) is approval Tier 1 (same machine);
> install Tier 3 (hosted signer) is approval Tier 2 (separate machine).

---

## What the design protects against, and what it does not

**Protected:**

- The agent cannot run a write on any server without a valid signature, and it
  cannot mint one on a server with no deployed signing key (read-only hosts).
- The pinned forced command means the SSHGate key can only invoke the gate —
  never a shell or arbitrary program — and OpenSSH enforces this server-side.
- An *unprivileged* rogue agent on the operator's machine cannot read the signing
  key, trace the signer, or impersonate the operator on Telegram.
- Command output is redacted of secret-shaped strings before it reaches the
  agent (reads and writes alike; only an approved secret-reveal bypasses it).
- A bounded signature validity window caps the lifetime of any approved write.

**Not protected (be honest about it):**

- On the same machine (install Tier 2 / approval Tier 1), a *privileged* rogue
  agent that can escalate to root or to the signer's user can read the key and
  forge approvals. The same-machine tier is a safety rail against mistakes and
  naïve injection, not a wall against a determined privileged adversary. Use the
  hosted signer (install Tier 3 / approval Tier 2) when a hard guarantee is
  required.
- The read/write classifier is a fail-closed heuristic over shell syntax; until
  the argv-exec structural fix lands, obscure tool flags or shell-parsing
  mismatches remain a residual risk on the read path, mitigated by default-deny
  and a regression corpus.
