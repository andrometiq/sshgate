# SSHGate

[![tests](https://github.com/karthikeyan5/SSHGate/actions/workflows/tests.yml/badge.svg)](https://github.com/karthikeyan5/SSHGate/actions/workflows/tests.yml)

A Claude Code plugin that lets a coding agent SSH into your Linux servers — where **every write needs your fingerprint on the phone, reads are safe-listed, and the server itself enforces it, not the client.** Reads run freely. Writes need one tap on your phone.

> **Start with the threat model.** Read [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) first — one honest page on what SSHGate actually enforces, what it only *routes*, and what it does **not** stop. If you are going to attack the design, that page is where to aim.

---

## The boundary — what actually enforces

The security boundary is the **Ed25519 signature plus the OpenSSH forced command, checked on each remote server.** The read/write classifier only *routes*; it is **not the wall.**

- SSHGate's dedicated key is pinned on every remote to a forced command (`restrict,command="~/.sshgate-gate/gate"`, plus `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding`; `restrict` also denies `~/.ssh/rc` execution and any future OpenSSH capability). **OpenSSH enforces this server-side**: that key can only ever invoke the gate — never a shell or an arbitrary program.
- A **write** runs only if it carries a valid Ed25519 signature the gate verifies against the signing pubkey deployed on that host. No pubkey on the host (read-only / Tier 1) ⇒ no write can be signed ⇒ the gate refuses it locally, before any approval channel is even consulted.
- The signature carries a **bounded validity window** and a **per-host binding** (the target's TOFU-pinned host-key fingerprint), so an approved write cannot be replayed indefinitely or against a different host.

That chain — forced command + signature verification + host binding — holds independently on each remote and does **not** depend on the agent, the laptop, or Telegram behaving. The classifier decides only *whether a command needs a signature*; if it ever misjudges a write as a read, that command runs without approval — which is exactly why the classifier is documented honestly rather than sold as a wall. The full, honest treatment (enforced-where table, what the classifier is and is not, per-tier guarantees, and the residuals SSHGate does **not** stop) is in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## The problem

When an AI agent needs to diagnose a remote server, the workflow today is a relay. The human SSHes in, runs a command, pastes the output back into the chat. The agent reads it, asks for the next command. The human SSHes again. Twenty round-trips later, the agent has a guess at what's wrong. The agent could have done this in seconds on its own.

The reason it doesn't is that full SSH access for an agent is dangerous. `rm -rf` on the wrong path, an accidental `truncate`, a supply-chain compromise of the agent's runtime, a hallucinated `systemctl stop` — any of these on a production server is a bad day. The human stays in the loop not to be useful, but to be a gate.

The right shape is a gate that doesn't waste the human's time. Diagnostics flow through automatically. Anything that mutates state pauses for an explicit human "yes."

---

## SSHGate solves this

SSHGate puts a small binary on every remote server that classifies each incoming command and enforces the gate:

```
read command              → execute
write command + signature → verify → execute
write command, no sig     → deny
```

Three lines of logic. The signing key is held by a separate Unix user the agent cannot read from, and it only signs after you tap "approve" on Telegram. The agent never holds the key. The human never types another shell command.

---

## Install

SSHGate is a Claude Code plugin. Anthropic-marketplace publication is on the roadmap; until then, install from a local clone.

> **Launch Claude Code normally with `claude`.** SSHGate does NOT require `--dangerously-load-development-channels`. That flag is for plugins that stream channel notifications INTO Claude's context. SSHGate only uses standard MCP tool calls; its approvals flow OUT to your phone via Telegram, not into the conversation.

**Agent-guided install.** In any Claude Code session, paste:

```
follow https://github.com/karthikeyan5/SSHGate/blob/main/INSTALL.md to install sshgate
```

The agent walks you through it: it hands you the clone/build/PATH commands to run in your terminal, tells you which steps only you can perform (the `/plugin` commands and the quit-and-relaunch), and then drives `/sshgate:setup`. Tier 2's signer setup is a **single interactive pass** — `/sshgate:setup` prompts for your Telegram user-id and bot token in the same run; there is no hand-editing of a config file and no second pass.

> **YOU run the plugin commands — not the agent.** Registering and installing the plugin are interactive commands an agent cannot issue. In the Claude Code UI, *you personally* type `/plugin marketplace add <clone>`, then `/plugin install sshgate@sshgate`, and then **quit and relaunch Claude Code**. (`sshgate@sshgate` parses as `<plugin-name>@<marketplace-name>` — both come from `.claude-plugin/marketplace.json`; run `/plugin` first to confirm the marketplace id before installing.) The relaunch is mandatory: `/reload-plugins` activates the slash commands, but the new plugin's stdio MCP server (`sshgate-mcp`) only spawns on a fresh Claude Code start.

You'll be asked for sudo (Tier 2 only) and a Telegram bot token (Tier 2 only). Realistic time to a working install: **~2 minutes for Tier 1**, **~10 minutes for Tier 2** (the extra time is creating the Telegram bot and the sudo-backed signer user).

**Manual install.** Clone the repo, run `make install-local` to put the binaries on your `$PATH`, persist `~/go/bin` to your LOGIN profile, add the plugin (`/plugin marketplace add <clone>` then `/plugin install sshgate@sshgate`), **fully quit and relaunch Claude Code** (not `/reload-plugins` — the stdio MCP server only spawns on a fresh start), confirm `/mcp` lists `sshgate` connected, then run `/sshgate:setup`. The canonical step-by-step — with the exact PATH/relaunch sequence and copy-paste shell blocks for each tier — lives in one place: [`docs/install-step-by-step.md`](docs/install-step-by-step.md).

`/sshgate:setup` walks you through Tier 1 first (read-only), and offers the Tier 2 upgrade in the same flow when you're ready. It probes on-disk state on every run, so re-running it is safe.

Requirements: Go 1.25+; Linux with systemd (Tier 2 only — Tier 1 needs no systemd), sudo (Tier 2 only), `jq` (Tier 2 only — `/sshgate:setup` uses it to enumerate registered servers), a Telegram account (Tier 2 only). Remote servers must be reachable over SSH and run Linux.

macOS: cross-compile only for now; a native install path is a future release. See [the install guide](docs/install-step-by-step.md#macos-users) for status.

---

## Three tiers of setup

`/sshgate:setup` is tiered and idempotent. Start with the lightest tier that meets your needs; you can upgrade later without tearing anything down.

**Tier 1 — Read-only.** gate is deployed to every remote, but no signing key is uploaded. Reads work; writes are denied at the gate. No Telegram bot, no signer daemon, no sudo. Fastest install. Recommended for the first run while you decide whether you want write access at all.

**Tier 2 — Local Telegram signer.** The full v1 install. Master keypair under the `sshgatesigner` system user, signer-telegram systemd unit, dedicated Telegram bot for approvals. Writes require a phone tap. This is the default for daily use.

**Tier 3 — Hosted server.** Not yet available. Reserved for the v2 architecture (hosted `sshgate-signer-server` with WebAuthn + TOTP web auth, multi-operator approval rules, central audit). The signer-telegram backend interface is the swap point; gate, the MCP, and the slash commands stay the same.

**Approval architecture (two tiers):** see [docs/approval-architecture.md](docs/approval-architecture.md).

---

## The tool surface — components

**gate** (`sshgate-gate`) — the remote-side Go binary: a ~500-line `main` dispatching into ~1.9k lines of gate library code (executor, signature verification, audit, keystore) plus a ~2k-line compiled-in classifier. Lives at `~/.sshgate-gate/gate` on each server you register. OpenSSH calls it via `command="..."` forcing in `authorized_keys`, so every connection on the SSHGate key routes through it. gate classifies the command, verifies the `SSHGATE_SIG:` prefix if present, and runs or denies. The classifier is compiled in; gate stores no config.

**signer-telegram** (`sshgate-signer-telegram`) — the local approval daemon on your laptop. Runs as a separate Unix user (`sshgatesigner`) so Claude — running as you — cannot read its key file, ptrace its process, or read its Telegram bot token. When a write arrives, signer-telegram DMs you on a dedicated Telegram bot with the command list and Approve/Deny buttons; it signs only after your tap, and only if Telegram's `from.id` matches the allowlisted user.

**MCP server** (`sshgate-mcp`) — the Claude Code plugin half. Exposes exactly eleven MCP tools: `run`, `run_batch`, `list_servers`, `status`, `ping`, `revoke_server`, `request_grant`, `revoke_grant`, `list_grants`, `update_gate`, and `transfer`. Reads SSH directly; writes go to signer-telegram first for approval, then SSH the signed command across. (`ping` is a READ-class single-server reachability probe — a short-timeout SSHGATE_OK check against one named server, no approval and no signer, so it costs neither a Telegram tap nor a fan-out across every server. `request_grant`/`revoke_grant` manage *standing grants* — a human-approved window in which matching writes auto-sign without a tap each; the agent can only request a grant, never create one. `list_grants` is a read-only query of the grants the signer currently holds — no approval — used to reconcile true grant state after a `request_grant` whose approval may have timed out. `update_gate` requests a *signed, in-place update of the gate binary* on an already-registered server: the agent supplies only the alias, the MCP hashes the operator's locally-staged gate binary, and the operator must approve a distinct "GATE BINARY UPDATE" Telegram banner bound to that exact SHA-256 before it runs — fail-closed, signed, audited, never auto-signed by a standing grant, and it onboards no new server so it can't expand the agent's reach. `transfer` moves a secret file between two registered servers end-to-end encrypted through the gate under one human approval — the agent supplies only aliases + absolute paths, the MCP relays only ciphertext, so the plaintext never reaches the agent or any log; a standing grant can never auto-sign it and Tier-1 servers are refused before any tap; transfers require the local Tier-2 Telegram signer — the hosted Tier-3 signer does not support them yet and fails closed.) Provisioning a server is *not* among these tools — see **gate** above and the `sshgate` CLI below; it is deliberately human-only.

**sshgate CLI** (`sshgate`) — the human-only provisioning tool, installed to `~/go/bin/sshgate` by `make install-local`. Onboarding a new server is the control plane (it defines which machines the agent can reach), so it is kept off the agent/MCP surface entirely: the agent can never expand its own reach by adding a machine. `sshgate pubkey` prints SSHGate's dedicated public-key line; you paste it into the target's `~/.ssh/authorized_keys` by hand; `sshgate add <alias> <user@host> [--read-only]` then connects with that key, installs the gate, and rewrites the pasted line into the locked forced-command entry.

---

## What you get

- Ask Claude to debug a server in plain English. Reads stream back instantly with no approval friction. "What's eating disk on prod-db" becomes one chat turn instead of fifteen.
- Restart services, install packages, edit configs with one tap on your phone. Your laptop and your phone are the two trust domains; the agent is neither.
- Bulk-approve a sequence of writes in one tap. Claude queues `apt update && apt install nginx && systemctl enable nginx && systemctl start nginx` as a single approval. Each command is still individually signed for audit; the "bulk" is purely the UI.
- Register a new server with the human-only `sshgate` CLI: `sshgate pubkey` prints the key line to paste into the target's `authorized_keys`, then `sshgate add prod-db ubuntu@prod-db.example.com` installs gate, locks that pasted line down to the restricted `authorized_keys` entry, and verifies end-to-end with a probe. The agent never runs this — provisioning stays in human hands so the agent can only operate within boundaries you set.
- Your master signing key never sits in the same trust domain as the agent. The agent can request signatures; it cannot produce them. On the same machine this is a safety rail, not a hard wall — an agent that can escalate privileges on the host (e.g. has `sudo`) could read the signing key directly and bypass approval. For a guarantee that holds against a privileged rogue agent, run the signer on a separate machine (the hosted-signer tier). See [docs/approval-architecture.md](docs/approval-architecture.md).

---

## Usage examples

**Read — no approval.**

> "What's eating disk on prod-db?"

Claude calls `sshgate.run("prod-db", "df -h")`, then `du -sh /var/log/*`, then `find /var -size +100M`. All three are reads. They stream back into chat with no Telegram pings. Claude surfaces the culprit.

**Single write — one tap.**

> "Restart nginx on prod-db."

Claude calls `sshgate.run("prod-db", "systemctl restart nginx")`. Your phone buzzes with:

```
SSHGate approval — prod-db
1. systemctl restart nginx

[Approve]   [Deny]
```

Tap approve. The command runs. Claude reports the result.

**Bulk write — one tap for four commands.**

> "Update the nginx config and restart it."

Claude calls `sshgate.run_batch("prod-db", [...])` with four commands. Your phone buzzes once:

```
SSHGate approval — prod-db
4 commands queued:
1. cat > /etc/nginx/sites-available/app.conf <<'EOF' ...
2. nginx -t
3. systemctl reload nginx
4. systemctl status nginx

[Approve all]   [Deny]
```

Tap approve. All four run in order. If any fails, the rest stop.

---

## What SSHGate is NOT

- Not a replacement for SSH. It sits on top of SSH.
- Not a configuration management tool (Ansible, Chef, Puppet). It runs the commands you (or the agent) write; it does not own desired state.
- Not a full access proxy (Teleport, StrongDM). No session recording, no MFA at the SSH layer, no SSO, no per-user RBAC.
- Not a secret manager. It gates commands, not credentials.
- Not a multi-operator approval system in v1. One operator, one phone, one Telegram DM. Multi-operator is a v2 feature.

---

## Status

The provisioning CLI (`sshgate pubkey` / `sshgate add`) and the full eleven-tool agent MCP surface (`run`, `run_batch`, `list_servers`, `status`, `ping`, `revoke_server`, `request_grant`, `revoke_grant`, `list_grants`, `update_gate`, `transfer`) are shipped. Both write tiers work: Tier 1 read-only (gate deployed, writes denied locally) and Tier 2 signed-write (local Telegram signer, one phone tap per approval). Inline secret redaction of command output is live (see *Secret redaction* below). The test suites — a race-enabled unit suite plus a Docker-backed integration suite — run locally via `make test` / `make test-integration` (`make preflight` is the pre-push gate); CI runs the race-enabled unit suite on every push/PR (the `tests` workflow, badged above), and `verify-gate` reproducibly rebuilds and checks the committed gate binary.

The hosted Tier-3 signer (a separate machine the agent cannot reach, with WebAuthn/TOTP web auth and multi-operator approval) is deferred. The backend is scaffolded in `src/signer-server/`; what remains is the web UI, the Telegram channel on the hosted signer, and deployment.

- Architecture and threat model: [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) (start here), then [`docs/design.md`](docs/design.md)
- Roadmap and deferred work: [`docs/ROADMAP.md`](docs/ROADMAP.md)
- Release history: [`CHANGELOG.md`](CHANGELOG.md)

---

## Secret redaction

Every command's output — reads and writes alike — streams through an inline
redactor in the gate before it reaches the agent. A detected secret is replaced
in place with the marker

```
[SSHGATE_REDACTED key=<8hex>]
```

where `<8hex>` is a per-session HMAC of the secret: the same secret gets the
same key within a session (the agent can recognise "same value as before"
without learning it), and keys do not correlate across sessions. The redactor
deliberately errs toward **over**-redaction — high-entropy base64 blobs, private-key
PEM blocks, and values assigned to `*_KEY=`-style names are redacted; public
certificates, CSRs, and SSH public-key bodies are deliberately *not* over-redacted
(a type check on completed PEM blocks and an ssh-line veto keep `cat server.crt`
and `cat authorized_keys` readable). When the raw value is genuinely needed,
request a reveal: `run(alias, command, reveal=true, reason="…")` runs that one
command un-redacted. A reveal is single-command only, takes its own distinct
Telegram approval, and is never auto-signed by a standing grant.

Full design: [`docs/redaction-architecture.md`](docs/redaction-architecture.md).

---

## Architecture

Full diagram, trust-domain breakdown, wire protocol, and threat model: [`docs/design.md`](docs/design.md). For the condensed, honest one-pager, start with [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

Short version: three trust domains — your user (runs Claude + the MCP, holds the SSH client key), the `sshgatesigner` user (runs signer-telegram, holds the master signing key + bot token), and Telegram (authenticates your phone). Each remote server runs gate as the only thing the SSHGate SSH key can invoke, enforced by OpenSSH's `command=` forcing. Reads pass; writes need a fresh Ed25519 signature from signer-telegram, which signer-telegram only produces after a verified phone tap.

## Security testing — the gate red-team rig

The gate's read-only classifier is the security backbone (a write that
misclassifies as a read runs unsigned). `gate-redteam` is a standing,
disposable harness that fires an adversarial corpus + fuzzer at the **real
gate** in a throwaway container and reports, per command, whether a write
slipped through — with an in-container write tripwire that catches a
mutation **anywhere**, by any mechanism. Bring it up once, fire many
commands, tear it down:

```sh
go build -o bin/gate-redteam ./cmd/gate-redteam
./bin/gate-redteam up && ./bin/gate-redteam campaign --iterations 1 && ./bin/gate-redteam down
```

Full threat model, verdict schema, and agent-operator prompt:
[`internal/redteam/README.md`](internal/redteam/README.md).

---

## Verified release channel — approving a gate update

`sshgate.update_gate(<alias>)` replaces a server's gate binary in place with a
single signed Telegram tap, instead of a full re-provision. The agent supplies
only the alias; the MCP hashes the operator's locally-staged gate binary and the
approval banner commits to that exact SHA-256, so the installed bytes can never
differ from what was approved (the gate re-hashes and refuses on mismatch).

That guarantees *what is installed == what was approved*. It does **not** by
itself guarantee *what was approved == the real, audited gate* — the staged
binary lives in the agent user's own home, so a compromised agent could swap its
bytes before they are hashed. The **verified release channel** closes that by
moving the trust anchor **off the machine**:

- Every gate build is committed to this repo at
  [`dist/gate/sshgate-gate-linux-amd64`](dist/gate/) alongside its published
  `.sha256`, versioned by the top-level [`VERSION`](VERSION) file.
- The `verify-gate` CI check reproducibly rebuilds the gate from source on every
  push/PR with the pinned toolchain and **fails unless** the freshly-built hash
  matches the committed one. A green tick certifies the committed binary is
  exactly what the audited source produces — you cannot change the gate's code
  without also re-committing (and re-publishing the hash of) the built binary.
- Before approving, the operator cross-checks the banner hash against the
  published hash on a **separate trusted device** (github.com). Swapped staging
  bytes then match nothing published and are denied.

### Approver runbook — do this on your phone before tapping ✓ Approve

When the **⚠️ GATE BINARY UPDATE** banner arrives:

1. Read from the banner: the target `<alias>`, the `New gate SHA-256: <64hex>`,
   and the `Build:` line.
2. On a **separate trusted device** (your phone browser, or a different machine —
   **not** the box running the agent), open this repo on **github.com**.
3. Confirm the commit shows a **green `verify-gate` tick** — proof the committed
   binary reproducibly builds from the audited source.
4. Open `dist/gate/sshgate-gate-linux-amd64.sha256` **at the default-branch HEAD**
   (`main`) and read the published hash. HEAD is the right default: it is the
   current audited gate. Looking up an *older* version's hash is a deliberate
   **downgrade** path — do it only when *you* initiated the downgrade and know
   why, never as the routine lookup.
5. Compare the published hash to `New gate SHA-256` in the banner — the **full 64
   hex characters**, not a prefix (a prefix collision is cheap). They must be
   identical.
6. Treat the banner's `Build:` line as **untrusted context, not proof** — it is
   MCP-constructed, unsigned, and spoofable. The **only** trusted field is the
   hash. A banner whose hash matches only an *older* commit's `.sha256` and not
   HEAD's is a downgrade signal a spoofed version line cannot hide.
7. **Only if** the full hash matches HEAD's published hash **and** CI is green
   **and** the version is what you expect → tap **Approve**. Otherwise tap
   **Deny** and investigate: a mismatch means the staged binary is **not** the
   audited gate — treat it as a compromise signal, not a retry.

### Dev override — `$SSHGATE_GATE_BIN`

`$SSHGATE_GATE_BIN` points the MCP at an arbitrary local gate binary for
development. Such a build is **by definition** not the published artifact, so its
banner hash will **not** match any published `.sha256`. That mismatch is
**expected on a dev box**. On a **production** server a hash mismatch must
**never** be approved — it is the compromise signal the runbook step 7 describes.

---

## License

MIT — see `LICENSE`.
