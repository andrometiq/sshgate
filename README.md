# SSHGate

[![tests](https://github.com/andrometiq/sshgate/actions/workflows/tests.yml/badge.svg)](https://github.com/andrometiq/sshgate/actions/workflows/tests.yml)

**Let your AI coding agent diagnose and fix your Linux servers over SSH, without giving it a shell.**
Read commands run straight away. Every write waits for one tap on your phone, and each server
refuses any write you did not approve.

SSHGate is a Claude Code plugin and a plain MCP server, so it also works with Codex, Gemini CLI,
Cursor and other MCP clients.

When an agent needs to look at a server today, you have two bad options:

- **Be the relay.** You SSH in, run the command, paste the output back, and wait for the next
  one. One diagnosis takes twenty round trips.
- **Hand over a shell.** Fast, until the agent runs `rm -rf` on the wrong path, a hallucinated
  `systemctl stop`, or a command injected by something it read.

SSHGate removes the relay without handing over the shell:

- **Reads run at once.** `df -h`, `journalctl -u nginx`, `ss -tlnp` go straight through and the
  output comes back to the agent. "What's eating disk on prod-db?" becomes one chat turn.
- **Writes need your tap.** A restart, an install or a config edit shows up on your phone as the
  exact commands, with Approve and Deny. Several writes can share one tap.
- **The server enforces it, not the agent.** SSHGate's SSH key can only start the `gate` program
  on each server (an OpenSSH forced command). The gate runs a write only if it carries an Ed25519
  signature made after your tap, valid for a short window and for that one host. The agent never
  holds the signing key.
- **Reads are jailed by the kernel.** On hosts that support it, reads run in a kernel jail that
  cannot write to the host's files, reach local daemons over Unix sockets, or signal other
  processes, even if a write were mistaken for a read.

Start read-only: no phone, no sudo, about two minutes. Add phone approvals when you want writes.

## Try it: read-only in about two minutes

You need Go 1.25 or newer, Claude Code, and a Linux (x86-64) server you can already SSH into.

```sh
git clone https://github.com/andrometiq/sshgate ~/src/SSHGate
cd ~/src/SSHGate && make install-local                   # builds sshgate and sshgate-mcp into ~/go/bin
echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zprofile   # bash: ~/.bash_profile. Then open a new login shell.
```

Start Claude Code from that new shell and type these two commands yourself (an agent cannot run them):

```
/plugin marketplace add ~/src/SSHGate
/plugin install sshgate@sshgate
```

Quit and relaunch Claude Code (the MCP server only starts on a fresh launch), then register a server:

```sh
sshgate pubkey     # prints SSHGate's key line: add it to ~/.ssh/authorized_keys on the server
sshgate add web1 ubuntu@web1.example.com --read-only
```

Now ask the agent: *"Why is web1 slow? Check load, memory and disk."*

Prefer to be walked through it? Paste this into Claude Code and the agent guides you, including
the optional phone-approval setup:

```
follow https://github.com/andrometiq/sshgate/blob/main/INSTALL.md to install sshgate
```

---

## How it works

```
 LAPTOP                               EACH SERVER

 agent                                OpenSSH: SSHGate's key can only start the gate
   │ tool call                          │
   ▼                                    ▼
 sshgate-mcp ──────── SSH ──────────► gate
   │                                    ├─ read ─────────────────► run (jailed if supported)
   │ writes: get a signature first      ├─ write + valid signature ► run
   ▼                                    └─ write, no signature ───► refuse
 signer (own Unix user, holds the key)
   │  ▲
   ▼  │ Approve / Deny
 your phone (Telegram)
```

1. The agent calls an SSHGate tool, for example `run(alias="web1", command="df -h")`.
2. **A read** goes straight over SSH. On the server, OpenSSH can only start the gate. The gate
   checks the command, runs it (inside the kernel jail where the host supports it), passes the
   output through a secret redactor, and sends it back.
3. **A write** goes to the signer first. The signer runs as a separate Unix user, so the agent
   cannot read its key. It sends the commands to your phone. Only after you tap Approve does it
   sign each command, binding the signature to that server's host key and a short validity
   window.
4. The signed command goes over SSH. The gate verifies the signature against the public key
   installed on that server, then runs it. A missing, expired, wrong-host or forged signature is
   refused.

Deciding "read or write" is the classifier's job, and it fails closed: a command counts as a read
only when every part of it is a known read; anything it does not recognise, any redirect such as
`>`, or any write segment makes the whole command a write. The classifier only routes. The wall is
the forced command plus the signature check on each server, which does not depend on the agent,
the laptop or Telegram behaving.

## What it protects, and what it does not

SSHGate protects your servers from an agent that makes a mistake, misreads its task, or is steered
by something it read. It does that with one hard boundary and softer layers around it:

- **Hard boundary:** no write runs on a server without a valid signature from your approval. This
  holds on each server on its own.
- **Bounded reads:** on a jail-capable host, a read cannot change the host's files, reach local
  daemons over Unix sockets, or signal other processes.
- **Secrets in output** are redacted before they reach the agent.

What it does **not** do, stated plainly (details in the threat model):

- **The classifier can be wrong.** If it ever judges a write to be a read, that command runs
  without approval. On a jail-capable host the jail limits what such a command can do; on other
  hosts, the classifier is the only thing in the way.
- **Reads can use the network.** Jailed reads keep TCP and UDP access, including to services on
  localhost. A read can send data out or talk to a local TCP service.
- **Reads can see what the SSH user can see.** The jail stops writes, not reads. Anything the
  server's SSH user can read, the agent can read, apart from what the redactor catches.
- **The local signer is a safety rail, not a wall, against a privileged agent.** If the agent can
  get root on your laptop (for example through `sudo`), it can read the signing key. A signer on a
  separate machine (Tier 3) is meant to close this; it is not release-ready yet.

Read **[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)** before you rely on SSHGate. It is the honest
account of what is enforced where, what each tier buys, and the residual risks. If you want to
attack the design, start there.

---

## Install

There are three ways in; all of them build from a clone (there are no published releases yet).

- **Agent-guided:** paste the `follow …/INSTALL.md` line above into Claude Code.
  [INSTALL.md](INSTALL.md) is the script it follows. You will still type the `/plugin` commands
  and relaunch Claude Code yourself, because an agent cannot.
- **By hand:** [docs/install-step-by-step.md](docs/install-step-by-step.md) has copy-paste shell
  blocks for each tier, the Telegram bot setup and troubleshooting.
- **Any MCP client:** after `make install-local`, point your client at `sshgate-mcp`:

  ```json
  {
    "mcpServers": {
      "sshgate": {
        "command": "sshgate-mcp",
        "env": { "SSHGATE_SIGNER_SOCK": "/run/sshgatesigner/sock" }
      }
    }
  }
  ```

  Codex can also install the plugin directly (`codex plugin marketplace add andrometiq/sshgate`,
  then `codex plugin add sshgate@sshgate`), and Gemini CLI reads the root `gemini-extension.json`.
  Per-client details, including a Cursor deeplink, are in
  [docs/install-generic-mcp.md](docs/install-generic-mcp.md). Without the signer, any client gets
  read-only operation.

In Claude Code, `/sshgate:setup` checks what is already installed and walks you through the next
tier. It is safe to re-run.

**Requirements**

- Laptop: Go 1.25 or newer (the build may download the pinned Go toolchain on first run). Linux
  for the Tier 2 signer, which also needs systemd, sudo and `jq`. macOS can build the agent side;
  a native signer install is not available yet
  ([details](docs/install-step-by-step.md#macos-users)).
- Phone: a Telegram account (Tier 2 only).
- Servers: Linux on x86-64, reachable over SSH, OpenSSH 7.2 or newer. For the kernel read jail,
  see [the jail section](#the-kernel-read-jail) below.

Realistic time: about 2 minutes for Tier 1, about 10 minutes for Tier 2 (creating the Telegram bot
and the signer user).

## Tiers

Start with the lightest tier that does the job.

| Tier | Writes | What you set up |
|------|--------|-----------------|
| **1 — Read-only** | Refused by the gate on the server | Nothing beyond the install. No signer, no Telegram, no sudo. |
| **2 — Local Telegram signer** | Run after one phone tap | A signer daemon under its own Unix user (`sshgatesigner`), a systemd unit, and your own Telegram bot. The daily-driver setup. |
| **3 — Hosted signer** | Run after approval in a web UI | `sshgate-signer-server` on a separate machine, with TOTP/WebAuthn sign-in and N-of-M approval policy. A foundation only: not release-ready. |

A Tier 1 server has no signing public key installed, so every write is refused on the server
before any approval is asked for. Moving an existing server from Tier 1 to Tier 2 is deliberately
manual: install the signer, de-provision the server (`sshgate revoke <alias>` prints the exact
steps), then `sshgate add` it again without `--read-only`. Tier 3 status and deployment
requirements: [src/signer-server/README.md](src/signer-server/README.md). How approval authority
differs by tier: [docs/approval-architecture.md](docs/approval-architecture.md).

## What the agent can do

The MCP server gives the agent exactly eleven tools:

| Tool | What it does | Approval |
|------|--------------|----------|
| `run` | Run one command on a server | Writes: one tap |
| `run_batch` | Run several commands in order | All writes in the batch share one tap |
| `list_servers` | List registered servers and each one's tier | None |
| `status` | Signer health and reachability of every server | None |
| `ping` | Cheap reachability check of one server | None |
| `revoke_server` | Remove the gate and SSHGate's key from a server | One tap |
| `request_grant` | Ask for a standing grant: matching writes auto-sign for up to 24 hours | One tap to grant |
| `revoke_grant` | Drop a server's standing grant | None |
| `list_grants` | Show the grants the signer holds | None |
| `update_gate` | Replace a server's gate binary with the verified build | One tap, on a distinct banner |
| `transfer` | Move a secret file between two servers, end-to-end encrypted, so the agent never sees it | One tap (Tier 2 only) |

Adding a server is **not** an agent tool. Provisioning uses the human-only `sshgate` CLI
(`sshgate pubkey`, `sshgate add`), so the agent can never widen its own reach. Standing grants,
gate updates, secret reveals and transfers each get their own approval banner, and a standing
grant never auto-signs a gate update, a reveal or a transfer.

Claude Code also gets slash commands: `/sshgate:setup`, `/sshgate:status`, `/sshgate:run`,
`/sshgate:run_batch` and `/sshgate:revoke`. Tool details: [docs/design.md](docs/design.md).

### Examples

**Read, no approval.** *"What's eating disk on prod-db?"* The agent runs `df -h`, then
`du -sh /var/log/*`, then `find /var -size +100M`. All are reads, so they run immediately and no
phone notification is sent.

**Write, one tap.** *"Restart nginx on prod-db."* The agent calls
`run(alias="prod-db", command="systemctl restart nginx")` and your phone shows:

```
🔐 SSHGate approval — prod-db

1 command queued:
1. systemctl restart nginx

Request ID: …
Expires in …

[✓ Approve all]   [✗ Deny]
```

**Several writes, one tap.** *"Update the nginx config and reload it."* The agent sends the config
write, `nginx -t`, `systemctl reload nginx` and `systemctl status nginx` as one `run_batch`. You
get one approval card listing all of them. Each command is still signed on its own, and if a write
fails the rest stop.

---

## The kernel read jail

New in 0.1.5. On a host that supports it, the gate runs every command the classifier calls a read
inside a kernel jail (profile `ro-v1`):

- the command gets its own user, mount and IPC namespaces (it shares the host's PID namespace);
- the host filesystem is mounted read-only; host `/tmp` and `/var/tmp` stay visible, read-only;
- the only writable places are `/dev/null` and a private 64 MiB `/dev/shm`, which `TMPDIR` points
  at and which is thrown away when the read ends;
- Landlock and a seccomp filter that rules on every system call block file and metadata writes,
  Unix-socket connections to local daemons, and signalling or tracing other processes;
- the jail checks itself before the command starts, and refuses the read if any check fails.

**Which hosts get it.** The host needs unprivileged user namespaces that can mount, and Landlock
(Linux 5.13 or newer, with Landlock enabled). On a host without both, reads run unconfined, guarded
by the classifier only, as they did before 0.1.5. Some distributions, such as Ubuntu 24.04,
restrict unprivileged user namespaces through AppArmor; on those, reads run unconfined until root
lifts that restriction or gives the gate an AppArmor profile that allows it.

**Check a host.** Log in to the server yourself (not through SSHGate) as the user SSHGate was
installed for, and run:

```sh
~/.sshgate-gate/gate doctor          # human-readable; add --json for JSON
```

The `reads:` line says what happens to reads on that host: `jailed:full`, `unconfined`, or
`denied: <reason>`.

**Refuse unjailed reads.** `~/.sshgate-gate/gate doctor --pin` records `full` in a `jail-floor`
file next to the gate. From then on, if the jail ever becomes unavailable on that host, the gate
refuses reads (exit 77, "read jail unavailable") instead of running them unconfined. A jail that
fails to set up, or a capability check that fails for an unexplained reason, is always refused;
the gate never quietly falls back to an unconfined read on a host that supports the jail.

**What runs outside the jail.** A short, fixed list of `systemctl` and `docker` read commands
(such as `systemctl status` and `docker ps`) needs the daemons' Unix sockets, so it runs outside
the jail without a shell, with an allowlist of flags. Signed writes and the gate's own admin
commands run exactly as before, and a jail problem never blocks them.

**What it does not stop.** Jailed reads keep network access, and some narrow residual effects
remain. Both are listed in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). A per-server network
permission is planned in [docs/BUILD-PLAN.md](docs/BUILD-PLAN.md).

## Secret redaction

All command output, reads and writes alike, passes through a redactor in the gate before it
reaches the agent. A detected secret is replaced in place with

```
[SSHGATE_REDACTED key=<8hex>]
```

where `<8hex>` is a per-session keyed hash: the same secret gets the same marker within a session,
so the agent can tell "same value as before" without learning it, and markers do not match across
sessions. The redactor errs toward redacting too much: private-key PEM blocks, high-entropy blobs
and values assigned to names such as `*_KEY=` are hidden, while certificates, CSRs and SSH public
keys stay readable. When the agent genuinely needs a raw value it can ask for a reveal:
`run(alias, command, reveal=true, reason="…")` runs that one command unredacted after its own,
clearly marked approval. A standing grant never covers a reveal. Design and limits:
[docs/redaction-architecture.md](docs/redaction-architecture.md).

## Approving a gate update

`update_gate(alias)` replaces a server's gate binary in place with one signed approval, instead of
a full re-provision. The agent supplies only the alias. The MCP hashes the gate binary staged on
your laptop, the approval banner shows that exact SHA-256, and the gate re-hashes what it receives
and refuses a mismatch. So what is installed is what you approved.

That alone does not prove that what you approved is the real, audited gate: the staged binary sits
in your user's home, where a compromised agent could swap it. The check against that lives off the
machine:

- Every gate build is committed at [`dist/gate/sshgate-gate-linux-amd64`](dist/gate/) with its
  `.sha256`, versioned by [`VERSION`](VERSION).
- The `verify-gate` CI workflow rebuilds the gate from source with the pinned toolchain on every
  push and pull request, and fails unless the hash matches the committed one.

### Before you tap Approve on a GATE BINARY UPDATE banner

1. Note the target alias and the `New gate SHA-256: <64 hex>` line from the banner.
2. On a **separate trusted device** (your phone's browser, not the machine running the agent),
   open this repository on github.com.
3. Check that the latest commit on `main` has a green `verify-gate` check.
4. Open `dist/gate/sshgate-gate-linux-amd64.sha256` on `main` and compare **all 64 hex
   characters** with the banner. A prefix match is not enough.
5. Treat the banner's `Build:` line as unverified context: it is built by the MCP and not signed.
   Only the hash counts. A hash that matches an older commit's `.sha256` but not `main`'s is a
   downgrade; approve that only if you started the downgrade on purpose.
6. Approve only if the full hash matches and CI is green. Otherwise deny and investigate: a
   mismatch means the staged binary is not the audited gate. Treat it as a compromise signal, not
   something to retry.

`$SSHGATE_GATE_BIN` points the MCP at a different local gate binary for development. Such a build
never matches a published hash, which is expected on a development box. On a production server,
never approve a mismatch.

---

## Testing and verification

- `make test`: race-enabled unit tests. CI runs it with `go vet` on every push and pull request
  (the `tests` badge above).
- `make test-integration`: Docker-backed integration tests. `make preflight` is the pre-push check.
- `make test-jail`: the read jail's acceptance matrix. It needs a host with unprivileged user
  namespaces and Landlock, and fails rather than skips when they are missing. CI runs it as the
  `jail` workflow.
- `make test-jail-mutate MUTATE=<ids>`: removes one jail protection at a time (195 in total) and
  requires a named test to catch each removal, proving each protection is load-bearing.
- `verify-gate` (CI) and `make verify-dist`: check that the committed gate binary is exactly what
  the source builds.
- **Red-team rig:** `gate-redteam` fires an adversarial corpus and a fuzzer at the real gate in a
  throwaway container and reports any write that got through, using an in-container tripwire that
  catches a change made by any means. See [internal/redteam/README.md](internal/redteam/README.md).

The full guide, including which tests need root or a disposable host, is
[docs/TESTING.md](docs/TESTING.md).

## Project status

The code line is **v0.1.5**. There are no tagged releases yet; install from a clone of `main`.

- **Working today:** Tier 1 (read-only) and Tier 2 (local Telegram signer), the eleven agent tools,
  human-only provisioning, standing grants, secret redaction and reveal, verified gate updates,
  encrypted server-to-server transfer, and the kernel read jail on supporting hosts.
- **Not ready:** the hosted Tier 3 signer is present as source and deployment tooling, but it is
  not a release-ready separate-machine boundary. Hosted grants, reveals and transfers fail closed;
  use the local signer for those.
- **v0.2** is a milestone that has not been cut; its release gates are still open.

What gets built next, in order: [docs/BUILD-PLAN.md](docs/BUILD-PLAN.md). Release status and
unscheduled ideas: [docs/ROADMAP.md](docs/ROADMAP.md). History: [CHANGELOG.md](CHANGELOG.md).
Architecture, trust domains and wire protocol: [docs/design.md](docs/design.md).

## What SSHGate is not

- Not a replacement for SSH. It sits on top of OpenSSH.
- Not configuration management (Ansible, Chef, Puppet). It runs the commands you or the agent
  write; it does not own desired state.
- Not an access proxy (Teleport, StrongDM). No session recording, no SSO, no per-user access
  control.
- Not a secret manager. It gates commands, not credentials.
- Not multi-operator on the local signer: one operator, one phone, one Telegram chat. Multi-person
  approval exists only in the not-yet-ready hosted tier.

## Contributing and security

- Found a way to run a write without approval, escape the read jail, or read the signing key?
  Please report it privately: see [SECURITY.md](SECURITY.md).
- Working on the code (by hand or with an agent): read [AGENTS.md](AGENTS.md) for the repo's
  rules and checks, and [docs/TESTING.md](docs/TESTING.md). Run `make preflight` before you push.

## License

MIT. See [LICENSE](LICENSE).
