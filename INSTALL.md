# Install SSHGate

## For humans

Open a Claude Code session in any directory and paste:

    follow https://github.com/andrometiq/sshgate/blob/main/INSTALL.md to install sshgate

(or `follow /path/to/your/clone/INSTALL.md` if you have already cloned the repo).

The agent walks you through everything below. A few steps are yours, because no agent can run
them:

- the `/plugin marketplace add` and `/plugin install` commands, typed into the Claude Code UI;
- quitting and relaunching Claude Code so the MCP server starts (step 3);
- the `sudo` installer run and the Telegram bot token (Tier 2 only);
- adding servers with the `sshgate` CLI (step 7). The agent cannot add servers by design.

Tier 1 is read-only and needs no sudo and no Telegram. Plain `claude` is fine: SSHGate needs no
special launch flags.

If you would rather do it all by hand, use
[docs/install-step-by-step.md](docs/install-step-by-step.md).

## For the agent

You are installing SSHGate for the user. Before running anything, **show the user the Preamble
section below as written and wait for their go-ahead** (empty, "y", "yes", "sure" or "ok" means
yes; only "n" or "no" stops). Then follow the numbered steps in order. Run commands exactly as
written, show errors verbatim, and stop at the first failure. Every step is safe to re-run.

---

## Preamble — what SSHGate is and what you are about to install

> **Agent: this section is for the human. Show it as written. After the "Proceed with install?"
> line, wait for their answer.**

### What SSHGate is

SSHGate lets an AI agent work on your Linux servers over SSH without a shell. Read commands
(`df -h`, `journalctl`, `ps`, and so on) run immediately and their output comes back to the
conversation. Write commands (restart, install, edit, anything that changes state) wait for one
tap on your phone, through your own Telegram bot, before they run.

Each server enforces this on its own. SSHGate's SSH key can only start the `gate` program there,
and the gate runs a write only if it carries a signature made after your tap. The signing key
lives under a separate Unix user that the agent cannot read. On one machine that is a safety
rail, not a wall: an agent that can get root on this machine (for example through `sudo`) could
read the key. A signer on a separate machine (Tier 3) is meant to close that gap, but it is not
release-ready yet. See [docs/approval-architecture.md](docs/approval-architecture.md) and
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

On servers that support it, the gate also runs every read inside a kernel jail, so a read cannot
change the server's files, reach local daemons over Unix sockets, or signal other processes. You
can check each server after adding it (step 7).

### What gets set up

1. A dedicated SSH key pair, separate from your own `~/.ssh/id_*`, used only by SSHGate.
2. SSHGate's binaries, built from your clone by `make install-local`: `sshgate-mcp` (the MCP
   server), `sshgate-signer-telegram` (the signer), and `sshgate` (the human-only provisioning
   CLI) go into `~/go/bin`. The server-side gate is **copied**, not rebuilt, from the committed,
   CI-verified `dist/gate/` build into `~/.config/sshgate/bin/`. A local rebuild would not match
   the published hash that gate updates are checked against (see the README's "Approving a gate
   update").
3. `~/.config/sshgate/` for your key, server list and staged gate.
4. *(Tier 2 only)* A `sshgatesigner` system user that holds the Ed25519 signing key, a
   `sshgate-signer-telegram` systemd service, and `/var/lib/sshgatesigner/` for its key, bot
   token, config and approval log (directories 0700/0750; key, token and log files 0600).
5. *(Tier 2 only)* Your own Telegram bot, made with @BotFather. You will be walked through it.

### What you need

- **Tier 1 (read-only):** Go 1.25 or newer, and a Linux (x86-64) server you can already SSH into.
  No sudo, no Telegram. About 2 minutes.
- **Tier 2 (phone approvals):** also a systemd-based Linux machine where you have sudo, `jq` on
  your `PATH`, and a Telegram account. About 10 minutes. You can create the bot token and look up
  your Telegram user ID during the install (@BotFather and @userinfobot).

### Which tier

Pick **Tier 1** to try SSHGate without the phone flow. **Tier 2** adds phone approvals; re-run
`/sshgate:setup` any time to add it. Servers you added under Tier 1 stay read-only until you
remove and re-add them. **Tier 3** (a hosted signer on a separate machine with a web approval UI)
exists as source code but is not release-ready, and this installer does not set it up; see
[src/signer-server/README.md](src/signer-server/README.md).

**Proceed with install?** *(default: yes, just press enter)*

---

## 1. Check prerequisites

```bash
go version
```

If the command is not found, tell the user to install Go 1.25 or newer from https://go.dev/dl/
and re-run this install. Stop.

If the version is older than 1.25, tell the user to upgrade Go and re-run. Stop. (Go 1.25 will
download the toolchain version pinned in `go.mod` on the first build; that needs network access.)

Tier 2 also needs sudo on this machine and a Telegram account. Don't check those yet; the user
picks a tier in step 5.

Servers are checked later, one at a time, when the user adds each with `sshgate add`.

## 2. Clone, build, and put the binaries on PATH

Tell the user to run these in their terminal:

> "1. Clone SSHGate (any directory works; `~/src` is used here) and build it:
>
>        mkdir -p ~/src && cd ~/src && git clone https://github.com/andrometiq/sshgate SSHGate
>        cd ~/src/SSHGate && make install-local
>
> 2. Add `~/go/bin` to your PATH in your **login** profile, not only `~/.bashrc` or `~/.zshrc`:
>
>        echo 'export PATH="$HOME/go/bin:$PATH"' >> ~/.zprofile   # zsh; for bash use ~/.bash_profile
>
> 3. Open a **new login shell** (or log out and back in), then check:
>
>        command -v sshgate-mcp || echo 'NOT ON PATH: add ~/go/bin (or $(go env GOPATH)/bin) to your login profile and open a new shell'"

Why the login profile: Claude Code starts the `sshgate-mcp` server with the environment Claude
Code itself was launched with. `/plugin install` copies only the plugin files
(`.claude-plugin/`, `commands/`, `skills/`, `.mcp.json`) into a cache, not the source or `bin/`,
so the MCP binary must be found on `PATH`. A shell where `command -v` works is not enough if
Claude Code was started from somewhere else.

Wait until the user confirms `command -v sshgate-mcp` prints a path, and note the clone path for
step 3. Do not go on to step 3 before that.

## 3. Relaunch Claude Code and install the plugin (the user does this)

> **The user must type these in the Claude Code UI. An agent cannot run them.**

First, quit Claude Code and start it again **from the login shell** where `command -v sshgate-mcp`
worked. Then, in the Claude Code UI:

```
/plugin marketplace add ~/src/SSHGate
/plugin install sshgate@sshgate
```

Replace `~/src/SSHGate` with the clone path. `sshgate@sshgate` means
`<plugin-name>@<marketplace-name>`; both are `sshgate` (from `.claude-plugin/marketplace.json`).
If unsure, run `/plugin` first to see the marketplace name that `add` registered.

Then **quit and relaunch Claude Code once more** (not `/reload-plugins`). This is always required:
`/reload-plugins` loads the slash commands, but a newly installed plugin's MCP server only starts
when Claude Code starts. Until then the slash commands appear but the `sshgate` tools do not.

> **Resume after the relaunch.** The relaunch ends this session, so the agent loses its context
> here. In the new session, continue at step 4: run `/mcp` to confirm `sshgate` is connected, then
> `/sshgate:setup`. Setup checks what is already installed and continues from there.

## 4. Check the plugin loaded

Two things must hold: the binaries are on `PATH`, and the MCP server is running.

```bash
command -v sshgate-mcp >/dev/null 2>&1 && echo "mcp-bin: ok ($(command -v sshgate-mcp))" || echo "mcp-bin: MISSING: re-run 'make install-local' in the clone and put ~/go/bin on your login-profile PATH"
command -v sshgate-signer-telegram >/dev/null 2>&1 && echo "signer-bin: ok" || echo "signer-bin: MISSING (only needed for Tier 2): re-run 'make install-local'"
command -v sshgate >/dev/null 2>&1 && echo "cli: ok" || echo "cli: MISSING: re-run 'make install-local'"
```

The plugin cache has no `src/` or `go.mod`; that is expected.

Then, in the Claude Code UI:

```
/mcp
```

The plugin is loaded only when `/mcp` lists an `sshgate` server as **connected**. Slash commands
showing up is not enough.

If `/mcp` does not list `sshgate`:

1. Quit and relaunch Claude Code (from the login shell), then run `/mcp` again.
2. If it is still missing, start the server by hand to see its startup error:

   ```bash
   sshgate-mcp </dev/null
   ```

   The usual cause is that `sshgate-mcp` is not on the `PATH` Claude Code was launched with. Go
   back to step 2, fix the login profile, and relaunch Claude Code from a new login shell.

## 5. Run /sshgate:setup

`/sshgate:setup` is the tiered installer. It checks what is already on disk, works out the
current state (fresh, Tier 1, Tier 2, or a half-finished install), and offers the next steps. It
is safe to run any time.

Tell the user:

> "In this Claude Code session, run:
>
>     /sshgate:setup
>
> It asks which tier you want:
>
>   - **Tier 1 (read-only)**: the gate goes on your servers with no signer. Reads work; writes
>     are refused on the server. No sudo, no Telegram, about 2 minutes.
>   - **Tier 2 (local Telegram signer)**: a signing key under a separate `sshgatesigner` user, a
>     systemd service, and your own Telegram bot. Writes need a phone tap. About 10 more
>     minutes and one sudo run.
>   - **Tier 3 (hosted signer)**: not release-ready. Setup only points you to
>     `src/signer-server/README.md`; it does not install anything.
>
> Pick Tier 1 to try SSHGate first. You can add Tier 2 later by running this command again, but
> servers added under Tier 1 stay read-only until you remove and re-add them."

Let `/sshgate:setup` do the work; don't repeat its steps here. For Tier 2 it will:

- confirm the binaries from `make install-local` are on `PATH` and the gate is staged at
  `~/.config/sshgate/bin/sshgate-gate-linux-amd64`;
- pause while the user runs the installer from the clone in a separate terminal, for example
  `sudo ~/src/SSHGate/scripts/install.sh` (the plugin cache has no `scripts/`). This is one
  interactive run that asks for the Telegram user ID (from @userinfobot) and the bot token (from
  @BotFather); there is no config file to edit by hand;
- capture the Telegram chat when the user sends `/start` to the new bot;
- ask the user to **log out and back in, then relaunch Claude Code**. The installer adds the user
  to the `sshgatesigner` group, and a group only takes effect in a new login session. Until then
  reads work but every write fails with "permission denied" at the signer socket. Running
  `newgrp` in another terminal does not fix an already-running Claude Code;
- optionally, set up the LLM command explainer (see
  [docs/install-step-by-step.md](docs/install-step-by-step.md) §4b).

Show any error `/sshgate:setup` reports verbatim.

## 6. Check the install

After `/sshgate:setup` finishes, run:

```
/sshgate:status
```

**Tier 1, no servers yet:** the signer shows as *not configured* (read-only / Tier 1, writes
refused at the gate), followed by a hint to add a server with `sshgate pubkey` and `sshgate add`.
A not-configured signer is normal on Tier 1. Do not debug a daemon that was never installed.

**Tier 2, no servers yet:** the signer socket is reachable.

If the signer shows as **present but not accessible (permission denied)**, the Claude Code
session is not in the `sshgatesigner` group yet: log out and back in, relaunch Claude Code, and
check again. The daemon is fine.

If the signer is configured but **not reachable** (Tier 2), the daemon did not start. Run
`systemctl status sshgate-signer-telegram` and
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`, show the output, and ask the user
whether to keep debugging or roll back.

## 7. Add a server, check its read jail, and finish

Tell the user:

> "Installation complete.
>
> **Add a server.** This is a human-only step on purpose: the agent can never add machines to
> its own reach. In your terminal:
>
>     sshgate pubkey
>     # add the printed line to ~/.ssh/authorized_keys on the server yourself
>     sshgate add <alias> <user@host>[:port] --read-only   # Tier 1
>     sshgate add <alias> <user@host>[:port]               # Tier 2 (signed writes)
>
> `sshgate add` connects with SSHGate's key, installs the gate, and locks that key line down so it
> can only start the gate. On Tier 1 you must pass `--read-only`, because there is no signer key
> to install yet. The alias is lowercase letters, digits and dashes, starting with a letter.
>
> **Check the read jail (optional, recommended).** Log in to the server yourself, as the same
> user you gave to `sshgate add`, and run:
>
>     ~/.sshgate-gate/gate doctor
>
> The `reads:` line shows what happens to reads there: `jailed:full` means reads run inside the
> kernel jail; `unconfined` means the host lacks unprivileged user namespaces or Landlock, so reads
> are guarded by the classifier only, as before. Stock Ubuntu 24.04 restricts the unprivileged
> user namespaces the jail needs through AppArmor (`gate doctor` then shows
> `apparmor_userns_clamp: yes`); reads there run unconfined until root lifts that restriction or
> gives the gate an AppArmor profile. If the host is `jailed:full`, you can run
> `~/.sshgate-gate/gate doctor --pin` so that from then on the gate refuses reads rather than ever
> running them unjailed there.
>
> **Use it.** Ask me in plain English, for example *What's eating disk on prod-db?* or
> *Restart nginx on staging.* Reads come back at once. On Tier 2, writes wait for your tap on
> Telegram.
>
> **Useful commands**
>
> - `/sshgate:setup`: run the installer again (safe to repeat; adds Tier 2 later)
> - `/sshgate:status`: health of the signer and every server
> - `/sshgate:run`, `/sshgate:run_batch`: run one command, or several with one approval
> - `/sshgate:revoke`: remove the gate from a Tier 2 server (needs approval)
> - `sshgate revoke <alias>`: prints the exact manual steps to remove a server; this is the only
>   way for a Tier 1 server, and it changes nothing itself
>
> For the manual flow and troubleshooting, see `docs/install-step-by-step.md`."

End.

---

## Manual install (without an agent)

Every step above also works by hand. [docs/install-step-by-step.md](docs/install-step-by-step.md)
has the full walkthrough with copy-paste shell blocks for each tier, the Telegram bot setup, the
optional LLM command explainer, troubleshooting, and uninstall. For MCP clients other than
Claude Code, see [docs/install-generic-mcp.md](docs/install-generic-mcp.md).
