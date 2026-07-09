# Install SSHGate

> **For human users:** open a Claude Code session in any directory and paste:
>
>     follow https://github.com/karthikeyan5/SSHGate/blob/main/INSTALL.md to install sshgate
>
> (or `follow /path/to/local/SSHGate/INSTALL.md` if you've cloned locally)
>
> The agent walks you through everything below. A few steps are YOURS to run
> personally because no agent can issue them: the interactive `/plugin
> marketplace add` + `/plugin install` commands in the Claude Code UI, and the
> QUIT+RELAUNCH of Claude Code that activates the MCP server (step 3). You'll
> also be asked for sudo (Tier 2 only) and a Telegram bot token (Tier 2 only).
> Tier 1 is read-only and needs no sudo.

> **For Claude Code (or any) agent reading this:** you are installing SSHGate
> for the user. Before any commands, **surface the Preamble section below
> verbatim to the user and wait for explicit go-ahead** (default-yes on
> empty / "y" / "yes" / "sure" / "ok"; only "n" / "no" stops). Then execute
> the numbered steps in order. Surface errors verbatim and stop on first
> failure. Don't paraphrase commands — run them exactly. Every step is
> idempotent (safe to re-run).

> **Launch flag — NOT required.** Unlike plugins that stream channel
> notifications into the conversation, SSHGate does NOT need
> `--dangerously-load-development-channels`. SSHGate is a regular MCP plugin
> that exposes tool calls; approvals flow OUT to the user's phone via
> Telegram, never INTO the Claude conversation. Plain `claude` works.

---

## Preamble — what SSHGate is and what you're about to install

> **Agent: this section is for the human. Surface it as written. After the
> "Proceed with install?" line, wait for their answer.**

### What SSHGate is

SSHGate is a Claude Code plugin that lets the agent SSH into your Linux
servers to read diagnostics or apply fixes. Read commands (`df -h`,
`journalctl`, `top`, etc.) execute freely and stream the output back to the
conversation. Write commands (restart, install, edit, anything that mutates
state) trigger ONE phone-tap approval via a dedicated Telegram bot before
they run.

The signing key that authorizes writes is isolated under a separate Unix
user, so the agent cannot forge approvals even if it tried. On the same
machine this is a safety rail, not a hard wall — an agent that can escalate
privileges on the host (e.g. has `sudo`) could read the signing key directly
and bypass approval. For a guarantee that holds against a privileged rogue
agent, run the signer on a separate machine (the hosted-signer tier). See
`docs/approval-architecture.md`. The
cryptographic gate is enforced on each remote server independently.

### What we're about to set up

1. A dedicated SSH key pair — separate from your daily-driver `~/.ssh/id_*`,
   used only by SSHGate to reach remote servers through the gate.
2. *(Tier 2 only)* A `sshgatesigner` Unix user that holds the master Ed25519
   signing key. Isolated from your Claude session — Claude cannot read it.
3. *(Tier 2 only)* A Telegram bot — your phone-side approval endpoint. Made
   via @BotFather. If you don't have one yet, you'll be walked through it.
4. `~/.config/sshgate/` and *(Tier 2 only)* `/var/lib/sshgatesigner/` — local
   config + key + audit-log paths, mode-tightened (dirs 0700 / 0750; key,
   token, and audit-log files 0600).
5. SSHGate binaries — installed by `make install-local`. `sshgate-mcp`,
   `sshgate-signer-telegram`, and the human-only `sshgate` provisioning CLI
   are built from your clone onto your `$PATH`;
   the remote `sshgate-gate-linux-amd64` is **copied** from the committed,
   CI-verified `dist/gate/` artifact into `~/.config/sshgate/bin/` — it is
   never rebuilt locally, because a local rebuild would hash to something
   no published release matches and fail the update approval cross-check.
   See README's "Verified release channel" section for how gate updates
   are approved. No remote dependencies fetched at runtime.

### What you'll need handy

- **Tier 1 (read-only):** nothing beyond Go ≥1.25 and one Linux server you
  can SSH into right now. No sudo, no Telegram. ~2 minutes.
- **Tier 2 (full v1):** sudo access on this machine, `jq` on `$PATH`
  (`/sshgate:setup` uses it to enumerate registered servers), a Telegram
  account, and ~10 minutes. The bot token and your Telegram user-id can be
  generated mid-flow if you don't have them yet — you'll be pointed at
  @BotFather and @userinfobot.

### Choose the tier when prompted

Pick **Tier 1** first if you want to try SSHGate without committing to the
phone-tap flow. **Tier 2** is the upgrade path — re-run `/sshgate:setup`
any time to add the signer. **Tier 3** (hosted server signer) is scaffolded
but not yet deployable; the menu will tell you so.

**Proceed with install?** *(default: yes — just hit enter)*

---

## 1. Verify prerequisites

```bash
go version
```

If "command not found": tell the user to install Go ≥1.25 from
https://go.dev/dl/, then re-run this install. Stop.

If the printed version is older than 1.25: tell the user to upgrade Go and
re-run. Stop.

Tier 2 also needs `sudo` access on the local machine and a Telegram account
(for the approval bot). Tier 1 needs neither — defer those checks until the
user picks a tier in step 5 (`/sshgate:setup`).

The remote hosts must be Linux with SSH reachable. They get checked
per-server later, when you provision each one with the human-only `sshgate`
CLI (`sshgate pubkey` + `sshgate add`), not here.

## 2. Clone the repo, build binaries onto $PATH, persist the PATH

Claude Code's `/plugin install` copies ONLY the plugin subtree
(`.claude-plugin/`, `commands/`, `skills/`, `.mcp.json`) into a versioned
cache — it strips `src/`, `scripts/`, `Makefile`, and `bin/`. So the MCP
binary cannot live under the cache; it must be on your `$PATH`. The
canonical fresh-machine order is: install Go → clone → `make install-local`
→ PERSIST `~/go/bin` to your LOGIN profile → confirm `command -v sshgate-mcp`
→ THEN (re)launch Claude Code from a PATH-correct shell, before
`/plugin install`.

Tell the user, in order:

> "1. Pick a directory to keep the SSHGate source (e.g. `~/src`), clone it,
>    and build the binaries onto your PATH:
>
>        mkdir -p ~/src && cd ~/src && git clone https://github.com/karthikeyan5/SSHGate
>        cd ~/src/SSHGate && make install-local
>
>    `make install-local` puts `sshgate-mcp`, `sshgate-signer-telegram`, and
>    the human-only `sshgate` provisioning CLI in `~/go/bin`, and the remote
>    gate binary in `~/.config/sshgate/bin/`.
>
> 2. PERSIST `~/go/bin` to your LOGIN profile — not just an interactive rc
>    file. Claude Code spawns plugin MCP servers with its LAUNCH-time env, and
>    GUI/login launches read the login profile, not `~/.zshrc`/`~/.bashrc`.
>    Append the export to the file your login shell sources (`~/.zprofile`
>    for zsh login, `~/.bash_profile` for bash login, or `~/.zshenv`):
>
>        echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zprofile   # zsh; use ~/.bash_profile for bash
>
> 3. Open a NEW login shell (or log out and back in) so the persisted PATH
>    takes effect, then confirm the binary resolves:
>
>        command -v sshgate-mcp || echo 'NOT ON PATH — add ~/go/bin (or `go env GOPATH`/bin) to your LOGIN profile and re-open the shell'
>
>    A `command -v` pass in this terminal does NOT by itself guarantee the
>    spawned MCP server will see `~/go/bin`: Claude Code inherits the PATH of
>    the shell it was LAUNCHED from. That is why the PATH must be persisted to
>    the login profile AND Claude Code launched from a shell where it resolves."

Wait for the user to confirm `command -v sshgate-mcp` resolves and capture
the clone path (we'll need it in step 3). Do NOT proceed to `/plugin install`
until the binary is on PATH in a login shell.

## 3. (RE)LAUNCH Claude Code, then install the plugin — YOU run these, not the agent

> **YOU — the human — must run these in the Claude Code UI. An agent cannot
> issue them.** `/plugin marketplace add`, `/plugin install`, and the restart
> below are interactive commands typed into the Claude Code client; the agent
> driving this install has no way to invoke them. Run them yourself.

First, (re)launch Claude Code FROM the login shell where `command -v
sshgate-mcp` resolved in step 2. Claude Code spawns the `sshgate-mcp` MCP
server with its own launch-time env, so it must start from a PATH-correct
shell. Then, in the Claude Code UI, run:

```
/plugin marketplace add ~/src/SSHGate
/plugin install sshgate@sshgate
```

Replace `~/src/SSHGate` with wherever you cloned.

`sshgate@sshgate` parses as `<plugin-name>@<marketplace-name>` — both come
from `.claude-plugin/marketplace.json` (the marketplace `name` and the
plugin `name` happen to both be `sshgate`). Before installing, run `/plugin`
and confirm the marketplace id that `add` registered, so `install` targets
the right `@<marketplace-name>`.

Then **fully QUIT and RELAUNCH Claude Code** (not `/reload-plugins`). This
is the UNCONDITIONAL final step of plugin install, not a PATH edge-case:
`/reload-plugins` activates the new slash-commands and skills, but a NEW
plugin's stdio MCP server (`sshgate-mcp`) is only spawned on a fresh Claude
Code start. Until you quit and relaunch, the slash commands appear but the
`sshgate` MCP tools do not exist.

> **Resume after the relaunch.** The relaunch discards this session, so the
> agent driving this install loses its context here — this breadcrumb, not
> agent memory, is what carries the install forward. In the fresh session,
> continue at step 4 below: run `/mcp` to confirm the `sshgate` server is
> connected, then `/sshgate:setup` — it re-probes on-disk state, classifies
> the current tier, and picks up exactly where you left off.

## 4. Verify the plugin loaded — binary on PATH AND the MCP server live

After the relaunch in step 3, two separate things must hold. Binary-on-PATH
is necessary but NOT sufficient — the MCP server must actually be spawned and
connected.

First, confirm the binaries resolve (the cache does NOT contain `src/` or
`go.mod` — that is expected and correct; the binaries live on `$PATH`):

```bash
command -v sshgate-mcp >/dev/null 2>&1 && echo "mcp-bin: ok ($(command -v sshgate-mcp))" || echo "mcp-bin: MISSING — re-run 'make install-local' in your clone and ensure ~/go/bin is on your LOGIN profile PATH"
command -v sshgate-signer-telegram >/dev/null 2>&1 && echo "signer-bin: ok" || echo "signer-bin: MISSING (only needed for Tier 2) — re-run 'make install-local'"
```

Then verify the MCP SERVER is live. In the Claude Code UI, run:

```
/mcp
```

Confirm an `sshgate` server appears and is **connected**. Treat the plugin
as "loaded" ONLY once `/mcp` shows the `sshgate` server connected — the
slash commands appearing is not enough.

If `/mcp` does NOT list `sshgate`:

1. Fully QUIT and RELAUNCH Claude Code (a stdio MCP server for a freshly
   installed plugin only spawns on a clean start), then re-run `/mcp`.
2. If it is still missing, run the server by hand in a shell to read its
   startup error:

   ```bash
   sshgate-mcp </dev/null
   ```

   The most common cause is `sshgate-mcp` not resolving on the PATH Claude
   Code was launched with — go back to step 2, persist `~/go/bin` to the
   login profile, and relaunch Claude Code from that login shell.

If `sshgate-mcp` is MISSING from `command -v`, the binary is not on `$PATH`:
send the user back to step 2's `make install-local` and the login-profile
PATH persistence. The MCP tool surface stays dead until `sshgate-mcp`
resolves on `$PATH` AND Claude Code has been relaunched from that shell.

## 5. Run /sshgate:setup

`/sshgate:setup` is the tiered installer. It probes on-disk state, classifies
the current tier (fresh, tier-1 present, tier-2 present, or partial), and
either offers a tier menu or a re-run menu. It's idempotent — safe to invoke
any time.

Tell the user:

> "In this Claude Code session, run:
>
>     /sshgate:setup
>
> It will ask which tier you want:
>
>   - **Tier 1 (read-only)** — gate is deployed on remotes, no signer.
>     Reads work; writes are denied locally at the gate. No sudo, no
>     Telegram, fastest install (~2 min).
>   - **Tier 2 (local Telegram signer)** — full v1. Master keypair under
>     `sshgatesigner` system user, systemd unit, Telegram bot for
>     approvals. Writes need a phone tap. Adds ~10 min and a sudo run.
>   - **Tier 3 (hosted server signer)** — NOT YET AVAILABLE (v2.x).
>
> Pick Tier 1 first if you want to try SSHGate without committing to the
> phone-tap flow. You can upgrade to Tier 2 later by re-running this same
> command."

The setup command walks every step itself. For Tier 2 it will:

- Confirm the binaries from `make install-local` are on `$PATH`
  (`sshgate-mcp`, `sshgate-signer-telegram`) and the gate cross-binary is
  staged at `~/.config/sshgate/bin/sshgate-gate-linux-amd64`.
- PAUSE for the user to run `sudo scripts/install.sh` from their clone
  (e.g. `sudo ~/src/SSHGate/scripts/install.sh`) in a separate terminal —
  the plugin cache has no `scripts/`, so the script runs from the clone. This
  is a SINGLE interactive pass: it prompts for the Telegram user_id and the
  bot token in the same run (no hand-editing of the config, no second pass).
- Have the user_id (from @userinfobot) and a @BotFather bot token ready to
  paste into that one pass.
- Capture chat_id from a `/start` Telegram message.
- (Optional) the LLM command-explainer add-on — see
  `docs/install-step-by-step.md` §4b.

The agent driving this INSTALL.md script does NOT need to duplicate
`/sshgate:setup`'s logic — just invoke it and let the user respond to its
prompts. Surface errors verbatim if `/sshgate:setup` reports any.

## 6. Verify

After `/sshgate:setup` reports completion, run:

```
/sshgate:status
```

For a Tier 1 install with no servers yet registered, expect (note the
`status: not configured` line — the signer socket is absent on Tier 1,
which is the normal read-only state, NOT an error):

```
Signer
  socket:    /run/sshgatesigner/sock
  status:    not configured (read-only / Tier 1) — writes denied at the gate

No servers registered. Provision one with the `sshgate` CLI:
  sshgate pubkey   # paste the printed line into the target's authorized_keys
  sshgate add <alias> <user@host> [--read-only]
```

For a Tier 2 install with no servers yet, expect the signer socket
reachable. Either case is healthy at this point.

If status reports `configured: true` AND `reachable: no` (Tier 2 only — the
socket file exists but the dial failed), the daemon didn't come up. Run
`systemctl status sshgate-signer-telegram` and
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`, surface the
output, and ask the user whether to keep debugging or roll back. On Tier 1
a `not configured` signer is expected — do NOT debug a daemon that was
never installed.

## 7. Tell the user the install is complete

> "Installation complete.
>
> **No special launch flag needed** — plain `claude` is fine. (Unlike
> plugins that stream channel notifications into the conversation,
> SSHGate doesn't push anything into the conversation; all tool I/O is
> normal MCP request/response, and approvals flow to your phone via
> Telegram.)
>
> Add a server — this is a human-only CLI step (I, the agent, can't do it; provisioning is deliberately off my tool surface):
>
>     sshgate pubkey                                  # prints SSHGate's key line
>     # paste that line into <host>:~/.ssh/authorized_keys yourself
>     sshgate add <alias> <user@host> [--read-only]   # installs gate, locks the key down
>
> Then ask me anything in plain English — `What's eating disk on prod-db?`
> or `Restart nginx on staging.` Reads stream back instantly. Writes
> queue for a Telegram approval and run after you tap approve.
>
> Provisioning (human-only `sshgate` CLI):
>   `sshgate pubkey`   — print SSHGate's dedicated public-key line to paste
>   `sshgate add`      — install gate on a server + lock the key down + register
>
> Useful slash commands going forward (agent-callable):
>   `/sshgate:setup`   — re-run the tiered installer (idempotent)
>   `/sshgate:status`  — health check signer + every registered server
>   `/sshgate:run`     — explicit one-shot SSH command (debug aid)
>   `/sshgate:revoke`  — uninstall gate from a server (needs approval)
>
> Day-to-day guide: `docs/install-step-by-step.md` covers the manual flow
> and troubleshooting if anything in `/sshgate:setup` falls over."

End.

---

## Manual install (without an agent)

The same steps run by hand work fine — see
[`docs/install-step-by-step.md`](docs/install-step-by-step.md) for the full
human-readable walkthrough with copy-paste shell blocks for each tier, the
Telegram bot creation flow, the optional LLM command explainer, and the
troubleshooting guide.
