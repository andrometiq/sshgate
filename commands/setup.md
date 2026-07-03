---
description: One-time setup for SSHGate — tiered install (read-only, local Telegram signer, or hosted)
argument-hint:
allowed-tools: Read, Bash, Write, Edit, AskUserQuestion
---

You are walking the user through SSHGate installation. The command
is tiered and idempotent — every run starts by probing on-disk state,
then either offers tier selection (fresh install) or a re-run menu
(upgrade an existing install).

Be terse. Surface every command verbatim. Stop on the first failure
and print the literal error. PAUSE markers mean "wait for user input
before proceeding."

## When to surface to the user

Stop and ask the user for direction (do not silently retry) in any of
these situations. Surface the literal command, its full error output,
and one concrete next step.

- **`scripts/install.sh` exits non-zero.** Print the script's last 20
  lines of output and ask the user to re-run it manually in their
  sudo terminal so they see the prompts directly. Do not loop.
- **`systemctl is-active sshgate-signer-telegram` returns anything
  other than `active` after two install attempts.** Surface
  `journalctl -u sshgate-signer-telegram -n 50 --no-pager` and ask
  the user whether to continue debugging or roll back.
- **The Telegram `/start` capture poll exits with "not yet" after the
  full 30-second window AND a manual re-poll.** Ask the user to
  confirm the bot username they sent `/start` to, and to confirm the
  `allowed_user_id` matches @userinfobot's reply. Do not silently
  re-poll a third time.
- **Step 0 classifies the install as `PARTIAL`.** Report each on-disk
  probe (`ssh/user/key/tg`) verbatim and ask the user whether to run
  `scripts/uninstall.sh` or to clean state by hand. Never auto-clean.
- **The user denies any approval-related step (token paste, sudo
  prompt, Telegram link).** Stop. Do not re-prompt — ask why and
  offer to skip the tier or roll back.
- **A required external dependency is missing (Go < 1.25, `jq`
  missing for the registry-enumeration step, `systemctl` absent
  because the user is on macOS or a non-systemd distro).** Tell the
  user which dependency is missing and stop; do not try to install
  it yourself.
- **`sshgate-mcp` cannot read `~/.config/sshgate/servers.json`
  during T2.6.** Surface the file's perms and ask the user to fix
  them; do not chmod-by-yourself.

## Tier overview (for your own reference; do not narrate verbatim)

- **Tier 1 — Read-only:** gate is deployed on remotes but NO
  gate.pub is uploaded. Reads work; writes are denied locally at
  the gate. No signer, no Telegram, no master key. Fastest install.
- **Tier 2 — Local Telegram signer:** master keypair under the
  `sshgatesigner` system user, `sshgate-signer-telegram` systemd
  unit, Telegram bot for approvals. Writes get a phone-tap
  approval. gate.pub pushed to every already-registered server
  (tier-1 → tier-2 upgrade).
- **Tier 3 — Hosted server signer:** NOT YET AVAILABLE. The hosted
  signer (`src/signer-server`) needs the v2.x web UI + WebAuthn
  flow to ship before this can be wired in.

**Naming bridge (used throughout the rest of this file):** the Unix
user is `sshgatesigner` (no hyphen). The binary, the `/usr/local/bin`
filename, and the systemd service unit are all `sshgate-signer-telegram`.
If you see `sshgatesigner` in a `useradd`/`getent`/`-u`-style context
it is the Unix user; if you see `sshgate-signer-telegram` in a
`systemctl`/`journalctl`/`./bin/`-style context it is the binary or
service unit.

---

## Step -1 — Plugin-load preflight

The MCP binary is on the user's `$PATH` (Claude Code's `/plugin install`
strips `src/`/`bin/` from the cache, so it cannot live there). Verify the
binary resolves AND locate the user's clone (which has `src/` for builds).

```bash
command -v sshgate-mcp >/dev/null 2>&1 && echo "mcp-bin:ok ($(command -v sshgate-mcp))" || echo "mcp-bin:missing"
```

Ask the user for their clone path if you don't already have it (it is where
they ran `git clone` / `make install-local` — typically `~/src/SSHGate`).
Verify the clone has the build inputs:

```bash
CLONE="${SSHGATE_CLONE:-$HOME/src/SSHGate}"
test -f "$CLONE/go.mod" && echo "clone:ok ($CLONE)" || echo "clone:missing"
```

If `mcp-bin:missing`, tell the user verbatim:

> "The `sshgate-mcp` binary is not on your `$PATH`. Claude Code's
> `/plugin install` only copies the plugin subtree — it does not build or
> ship binaries. Build them from your clone:
>
> 1. Clone if you haven't: `git clone https://github.com/karthikeyan5/SSHGate ~/src/SSHGate`
> 2. Build onto PATH: `cd ~/src/SSHGate && make install-local`
> 3. Persist `~/go/bin` (or `\`go env GOPATH\`/bin`) to your LOGIN profile
>    (`~/.zprofile`/`~/.bash_profile`/`~/.zshenv`, not just `~/.zshrc`/`~/.bashrc`)
>    — Claude Code spawns the MCP server with its launch-time env.
> 4. QUIT and RELAUNCH Claude Code from a shell where `command -v sshgate-mcp`
>    resolves, then re-run `/sshgate:setup`."

If `clone:missing`, ask the user for the actual clone path and re-probe.
Stop on either failure. Do not silently proceed. Remember the clone path as
`$CLONE` — the build steps below run there, NOT in `${CLAUDE_PLUGIN_ROOT}`.

Binary-on-PATH is necessary but NOT sufficient: the `sshgate-mcp` stdio MCP
server must also be spawned and connected. A freshly `/plugin install`ed
plugin's MCP server only spawns on a fresh Claude Code start — `/reload-plugins`
activates the slash commands and skills but does NOT spawn the new MCP server.
So a QUIT+RELAUNCH of Claude Code is the UNCONDITIONAL final step of plugin
install, not a PATH edge-case. Tell the user to confirm the server is live:

> "In the Claude Code UI, run `/mcp` and confirm an `sshgate` server appears
> and is connected. Treat the plugin as loaded ONLY once `/mcp` shows
> `sshgate` connected — the slash commands appearing is not enough.
>
> If `/mcp` does NOT list `sshgate`: fully quit and relaunch Claude Code, then
> re-run `/mcp`. If it is still missing, run `sshgate-mcp </dev/null` in a
> shell to see the startup error (usually `sshgate-mcp` not resolving on the
> PATH Claude Code was launched with — persist `~/go/bin` to the login profile
> and relaunch Claude Code from that login shell)."

Do not proceed past Step -1 until the user confirms `/mcp` shows the `sshgate`
server connected.

---

## Step 0 — Probe on-disk state

Run these to detect the current tier. Capture each one's result; you
will branch on them below.

```bash
test -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519" && echo "ssh:yes" || echo "ssh:no"
```

```bash
getent passwd sshgatesigner >/dev/null 2>&1 && echo "user:yes" || echo "user:no"
```

```bash
systemctl is-active sshgate-signer-telegram 2>/dev/null || echo inactive
```

```bash
sudo test -f /var/lib/sshgatesigner/keys/gate.key 2>/dev/null && echo "key:yes" || echo "key:no"
```

```bash
sudo grep -E '^[[:space:]]*type[[:space:]]*=[[:space:]]*"telegram"' /var/lib/sshgatesigner/config/config.toml 2>/dev/null && echo "tg:yes" || echo "tg:no"
```

Classify:

- `ssh:no` AND `user:no` → **FRESH** install.
- `ssh:yes` AND `user:no` → **TIER-1 PRESENT** (read-only).
- `ssh:yes` AND `user:yes` AND `tg:yes` → **TIER-2 PRESENT** (local Telegram signer).
- Anything else → **PARTIAL** (mid-install; report the mismatch and ask the user to clean up before continuing).

Tell the user the detected tier in one line, e.g.
`Detected: fresh install (no SSHGate SSH key, no sshgatesigner user).`

## Step 1 — Branch on detected tier

### Branch A: FRESH install

Use `AskUserQuestion` to offer the three tiers. Question:
`"Which install tier do you want? You can upgrade from tier 1 to tier 2 later by re-running this command."`

Options (header / description):

1. `"Read-only"` / `"Tier 1 — deploy gate to remotes, NO signer.
   Reads work; writes are denied at the gate. Fastest install, no
   sudo for the rest of the flow. Recommended for first try."`
2. `"Local Telegram signer"` / `"Tier 2 — install sshgate-signer-telegram +  master
   key + Telegram bot. Writes require a phone-tap approval. Adds
   ~10 minutes of setup."`
3. `"Hosted server signer"` / `"Tier 3 — NOT YET AVAILABLE. The
   hosted signer needs the v2.x web UI + WebAuthn flow. Pick read-only
   or local-telegram for now."`

Branch on the answer:

- Tier 1 → continue to **Tier 1 flow**.
- Tier 2 → continue to **Tier 2 flow** (do tier-1 prep first, then tier-2 add-ons).
- Tier 3 → print:
  `Hosted server signer is not yet available (waiting on web UI + WebAuthn auth — tracked in src/signer-server/README.md). Pick read-only or local-telegram for now.`
  Stop.

### Branch B: TIER-1 PRESENT (re-run)

Use `AskUserQuestion` with:
`"Tier 1 is already installed. What would you like to do?"`

Options:

1. `"Verify"` / `"Re-check on-disk state, confirm the SSHGate SSH key is intact."`
2. `"Add local Telegram signer"` / `"Upgrade tier 1 → tier 2. Generate the master key, install sshgate-signer-telegram, configure Telegram bot, push gate.pub to all registered servers."`
3. `"Add hosted server signer"` / `"Tier 3 — NOT YET AVAILABLE."`

Branch on the answer:

- Verify → run **Verify flow**.
- Tier 2 → continue to **Tier 2 flow**.
- Tier 3 → print the not-available message from Branch A and stop.

### Branch C: TIER-2 PRESENT (re-run)

Use `AskUserQuestion` with:
`"Tier 2 is already installed. What would you like to do?"`

Options:

1. `"Verify"` / `"Re-check on-disk state, confirm sshgate-signer-telegram is active and the Telegram link works."`
2. `"Reconfigure Telegram"` / `"Re-prompt for the bot token and/or allowed_user_id. Useful if you rotated the bot."`
3. `"Add hosted server signer"` / `"Tier 3 — NOT YET AVAILABLE."`

Branch on the answer:

- Verify → run **Verify flow**.
- Reconfigure → jump to **Tier 2 — Telegram configure** section.
- Tier 3 → print the not-available message and stop.

### Branch D: PARTIAL

Print the detected state line by line (which of `ssh/user/key/tg`
came back yes/no) and tell the user the install is mid-migration.
Suggest running `scripts/uninstall.sh` or manually cleaning state.
Stop.

---

## Tier 1 flow — read-only

### T1.1 — Probe prerequisites

```bash
go version
```

If not 1.25 or newer, tell the user to install Go from
https://go.dev/dl/ and stop.

### T1.2 — Build binaries (in the user's clone, NOT the plugin cache)

Build runs in `$CLONE` (the git clone, which has `src/`), never in
`${CLAUDE_PLUGIN_ROOT}` (the cache has no `src/`). `make install-local`
puts `sshgate-mcp` on `$PATH` and stages the remote gate binary at
`~/.config/sshgate/bin/sshgate-gate-linux-amd64`. (`sshgate-signer-telegram`
is also built but unused in Tier 1.)

```bash
cd "$CLONE" && make install-local
```

Confirm the gate cross-binary was staged and the MCP binary is on PATH:

```bash
ls -la "${HOME}/.config/sshgate/bin/sshgate-gate-linux-amd64" && command -v sshgate-mcp
```

Report both. If `sshgate-mcp` does not resolve, tell the user to add
`~/go/bin` (or `` `go env GOPATH`/bin ``) to their `$PATH` and re-open the
shell, then re-run. Because `.mcp.json` invokes the bare PATH command
`sshgate-mcp`, after adding `~/go/bin` to PATH the user must fully **restart**
Claude Code (quit and relaunch) — not just `/reload-plugins` — so the
`sshgate-mcp` server is spawned with the updated PATH.

### T1.3 — Create the SSHGate SSH key

The SSHGate dedicated SSH key (`sshgate_ed25519`) is what the
`sshgate add` CLI lays into each remote's `authorized_keys` behind
the `command="~/.sshgate-gate/gate"` forcing entry. The key never
leaves the laptop; the public half goes to the remote.

```bash
mkdir -p "${HOME}/.config/sshgate/ssh" && chmod 700 "${HOME}/.config/sshgate/ssh"
```

Skip key generation if it already exists (idempotent):

```bash
test -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519" && echo "exists" || ssh-keygen -t ed25519 -N '' -C 'sshgate-dedicated' -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
```

Verify mode is 0600:

```bash
stat -c '%a' "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
```

Expect `600`. If looser (e.g. 644), tighten:

```bash
chmod 600 "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
chmod 644 "${HOME}/.config/sshgate/ssh/sshgate_ed25519.pub"
```

### T1.4 — Initialise the registry

```bash
mkdir -p "${HOME}/.config/sshgate" && touch "${HOME}/.config/sshgate/servers.json"
```

If the file is empty (a fresh `touch` left it 0 bytes), write the
empty-registry JSON skeleton:

```bash
test -s "${HOME}/.config/sshgate/servers.json" || echo '{}' > "${HOME}/.config/sshgate/servers.json"
```

### T1.5 — Summarise

Print verbatim:

> SSHGate tier 1 (read-only) is ready.
>
> - SSH key: ~/.config/sshgate/ssh/sshgate_ed25519
> - Registry: ~/.config/sshgate/servers.json
> - gate binary: ~/.config/sshgate/bin/sshgate-gate-linux-amd64
>
> Add a server (read-only — no signer yet on Tier 1). Provisioning is a
> human-only CLI step; paste SSHGate's key (`sshgate pubkey`) into the host
> first, then:
>
>     sshgate add <alias> <user@host> --read-only
>
> Reads will work through the gate; writes will be denied locally with:
>
>     gate: no signing key configured (read-only install — re-run /sshgate:setup to add a signer)
>
> Re-run /sshgate:setup any time to add a Telegram signer.

If the caller picked Tier 1, stop here. If they picked Tier 2,
continue to **Tier 2 flow** (Tier-1 state is the prerequisite).

---

## Tier 2 flow — local Telegram signer

This builds on Tier 1 (which must be in place — re-probe Step 0 if you
got here without running Tier 1 first).

### T2.1 — Confirm the signer binary + bin/ artifacts (already built by install-local)

`make install-local` (run in T1.2) depends on `make build`, so it already
produced the clone's `bin/*` artifacts — including `bin/sshgate-signer-telegram`
and `bin/sshgate-gate-linux-amd64` — that `scripts/install.sh` (T2.2)
consumes from `$CLONE/bin/`. Do NOT run a separate `make build`;
`install-local` is the single build command.

Just confirm the artifacts install.sh needs are present:

```bash
ls -la "$CLONE/bin/sshgate-signer-telegram" "$CLONE/bin/sshgate-gate-linux-amd64"
```

If either is missing (e.g. T1.2 was skipped), run `cd "$CLONE" && make install-local`.

### T2.2 — Run the installer (first pass)

`scripts/install.sh` is the single entry point for the system-level
install (sshgatesigner user, /var/lib/sshgatesigner/ skeleton, systemd unit,
--init for the signing keypair).

**PAUSE** and tell the user verbatim:

> Open a separate terminal and run:
>
>     sudo $CLONE/scripts/install.sh
>
> (replace `$CLONE` with the actual path printed below).
>
> The script is idempotent — safe to re-run if it fails partway. Tell
> me when it's done.

Print the resolved path with:

```bash
echo "$CLONE/scripts/install.sh"
```

After confirmation, verify the daemon:

```bash
systemctl is-active sshgate-signer-telegram
```

Expect `active`. If `failed`, run:

```bash
journalctl -u sshgate-signer-telegram -n 30 --no-pager
```

…surface the output and stop.

`scripts/install.sh` adds the user's account to the `sshgatesigner` group.
This is load-bearing: the signer's Unix socket is mode `0660`, owned by
`sshgatesigner`, so the MCP server (which runs as the user) can connect to it
ONLY if the user is in the `sshgatesigner` group AND that membership is ACTIVE
in the session. Without an active group membership every write is
permission-denied at the socket. (Reading the audit log under
`/var/lib/sshgatesigner/` without sudo is a secondary convenience of the same
group.) Group membership only activates in NEW login sessions — `newgrp
sshgatesigner` in a side terminal does NOT help the already-running Claude
Code, because the MCP server inherited the group set from the session Claude
Code was launched in. The user must log out and back in AND relaunch Claude
Code before writes work (enforced as a mandatory step after T2.7).

### T2.3 — Tier 2 — Telegram configure

The `--init`-generated config has `type = "stub"`. Switch it to
`telegram` and add the user_id + chatstore pointers.

**PAUSE** and tell the user:

> Find your numeric Telegram user_id. Easiest way: message @userinfobot
> on Telegram and copy the `Id:` line.

Use `AskUserQuestion` with:
`"What is your Telegram user_id? (numeric, e.g. 12345678)"`

Then sanity-check the answer with:

```bash
printf '%s' "<ANSWER>" | grep -Eq '^[0-9]+$' && echo "ok" || echo "bad: not a positive integer"
```

If bad, re-ask.

Read the current config so you know what `--init` produced:

```bash
sudo cat /var/lib/sshgatesigner/config/config.toml
```

If the file already has `type = "telegram"` AND a `[backend.telegram]`
block with this user's id, log "config already configured for telegram;
skipping" and proceed to T2.4.

Otherwise, tell the user to run (substituting their user_id for `NNNN`):

```bash
sudo tee -a /var/lib/sshgatesigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path        = "/var/lib/sshgatesigner/tokens/telegram.token"
allowed_user_id   = NNNN
chatstore_path    = "/var/lib/sshgatesigner/config/peer.json"
EOF
```

…and then flip the backend type:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' /var/lib/sshgatesigner/config/config.toml
```

Re-read the file and confirm with the user (`type = "telegram"`, the
three telegram keys, no duplicates). If duplicates exist, ask the user
to clean by hand.

### T2.4 — Run the installer again (token + restart)

Now that the config selects telegram, re-running install.sh will
prompt for the bot token (echoed nothing — `read -rs`) and restart
the daemon.

**PAUSE** and tell the user:

> First, create a Telegram bot via @BotFather (https://t.me/BotFather):
> send `/newbot`, pick a name, pick a username ending in `bot`.
> BotFather replies with a token shaped like `7123456789:AAH...`.
>
> Then, in your sudo terminal, run:
>
>     sudo $CLONE/scripts/install.sh
>
> The script will detect the new `type = "telegram"` and prompt:
>
>     [install] Paste the BotFather token (input hidden), or press Enter to skip:
>
> Paste the token. Input is hidden — nothing echoes. Press Enter.
>
> The script writes the token to `/var/lib/sshgatesigner/tokens/telegram.token`
> (mode 0600, owned by `sshgatesigner`) and restarts the daemon. Tell me
> when it's done.

After confirmation, verify:

```bash
sudo stat -c '%a %U:%G' /var/lib/sshgatesigner/tokens/telegram.token
```

Expect `600 sshgatesigner:sshgatesigner`.

```bash
systemctl is-active sshgate-signer-telegram
```

Expect `active`. If not, run `journalctl -u sshgate-signer-telegram -n 30 --no-pager`
and surface the output.

### T2.5 — Capture chat_id from /start

**PAUSE** and tell the user:

> Open Telegram, find the bot you just created (search the username
> you gave to @BotFather), and send `/start`. the signer's poller will
> capture your chat_id and write it to
> `/var/lib/sshgatesigner/config/peer.json`.

Poll for the file (up to ~30 seconds):

```bash
for i in $(seq 1 30); do
  if sudo test -f /var/lib/sshgatesigner/config/peer.json; then
    echo "captured"
    break
  fi
  sleep 1
done
sudo test -f /var/lib/sshgatesigner/config/peer.json || echo "not yet"
```

If captured, read it and report the chat_id back:

```bash
sudo cat /var/lib/sshgatesigner/config/peer.json
```

If still not present after 30s, tell the user to double-check they
sent `/start` to the right bot, then re-poll once. If still nothing,
stop and surface `journalctl -u sshgate-signer-telegram -n 30 --no-pager`.

### T2.6 — Push gate.pub to all registered servers

The signer is now live with a new master key. Every server registered
in tier 1 has gate but NO gate.pub on it — pushing the pubkey
flips each one from "read-only" to "signed-write."

Make the pubkey available to the MCP layer at the canonical local
path:

```bash
mkdir -p "${HOME}/.config/sshgate/pubkey-distrib"
sudo cp /var/lib/sshgatesigner/keys/gate.pub "${HOME}/.config/sshgate/pubkey-distrib/gate.pub"
sudo chown "$USER" "${HOME}/.config/sshgate/pubkey-distrib/gate.pub"
chmod 644 "${HOME}/.config/sshgate/pubkey-distrib/gate.pub"
```

Then enumerate the servers in the registry:

```bash
jq -r '.servers | keys[]' "${HOME}/.config/sshgate/servers.json" 2>/dev/null || echo "(no servers registered)"
```

If the list is empty, skip to T2.7 — there's nothing to upgrade.

> ⚠️ **There is no in-place tier-1 → tier-2 upgrade — by design.**
> Re-running `sshgate add <alias> <user@host>` on an already-registered
> alias is **rejected** ("alias already registered; run `sshgate revoke`
> first") — it does NOT upgrade in place. An in-place tier flip was
> considered and rejected for security: any unsigned upgrade path the CLI
> could exercise is a path the agent could emulate — read-only is
> read-only (see roadmap #17, redefined, in `docs/ROADMAP.md`). Re-tiering
> is always revoke + re-provision: `/sshgate:revoke <alias>` (its Telegram
> approval is kept), then `sshgate add <alias> <user@host>` without
> `--read-only` (with the signer already set up), which finds the staged
> `gate.pub` and deploys signed-write.

### T2.7 — Final summary

First check whether the `sshgatesigner` group is ACTIVE in the session this
Claude Code (and thus the MCP server) is running in:

```bash
id -nG | tr ' ' '\n' | grep -qx sshgatesigner && echo 'group:active' || echo 'group:INACTIVE — log out/in and relaunch Claude Code before writes'
```

If this prints `group:INACTIVE`, the install is complete on disk but the MCP
server CANNOT connect to the signer socket yet (socket is `0660
sshgatesigner`; the user's group set was fixed when Claude Code was launched).
Do NOT declare Tier 2 ready-for-writes. Print the group-activation step below
and tell the user writes will be permission-denied until they complete it.

Print verbatim:

> SSHGate tier 2 (local Telegram signer) is installed.
>
> - Daemon: sshgate-signer-telegram (active, running as user `sshgatesigner`)
> - Socket: /run/sshgatesigner/sock
> - Audit log: /var/lib/sshgatesigner/log/approvals.log
> - Telegram bot chat_id captured: <N>
> - gate.pub distributed to: <list of registered aliases>
>
> Reads route directly; writes will buzz your phone for approval.
>
> Re-run /sshgate:setup any time — it's idempotent and detects the
> current tier.

### T2.8 — MANDATORY: activate the sshgatesigner group (required before writes)

This is a required happy-path step, not troubleshooting. `scripts/install.sh`
added your account to the `sshgatesigner` group, but a Unix group only
activates in NEW login sessions. The MCP server inherited its group set from
the session Claude Code was launched in, so it does NOT yet have
`sshgatesigner` active — and the signer socket is `0660 sshgatesigner`, so
every write will be permission-denied until the group is active.

`newgrp sshgatesigner` in a side terminal does NOT fix the already-running
Claude Code. You MUST:

1. **Log out and back in** (or fully restart your login session) so the
   `sshgatesigner` group becomes part of your active group set.
2. **Relaunch Claude Code** from that fresh login session.

Then confirm the group is active:

```bash
id -nG | tr ' ' '\n' | grep -qx sshgatesigner && echo 'group:active' || echo 'group:INACTIVE — log out/in and relaunch Claude Code before writes'
```

Only once this prints `group:active` is Tier 2 ready for writes. Until then,
reads work but every write returns a permission-denied at the signer socket.

---

## Verify flow

Run these checks in order; report each one's pass/fail.

```bash
test -f "${HOME}/.config/sshgate/ssh/sshgate_ed25519" && stat -c '%a' "${HOME}/.config/sshgate/ssh/sshgate_ed25519"
```

Expect `600`.

```bash
test -f "${HOME}/.config/sshgate/servers.json" && jq -r '.servers | length' "${HOME}/.config/sshgate/servers.json"
```

Reports the count of registered servers.

If Tier 2 is supposed to be present:

```bash
getent passwd sshgatesigner
systemctl is-active sshgate-signer-telegram
sudo test -f /var/lib/sshgatesigner/keys/gate.key && echo "key:yes" || echo "key:no"
sudo test -f /var/lib/sshgatesigner/config/peer.json && echo "peer:yes" || echo "peer:no"
sudo -u sshgatesigner /usr/local/bin/sshgate-signer-telegram --version
id -nG | tr ' ' '\n' | grep -qx sshgatesigner && echo 'group:active' || echo 'group:INACTIVE — log out/in and relaunch Claude Code before writes'
```

Report each line. Any failure tells the user which tier-2 piece is
missing and points back at the relevant section. If the last line reports
`group:INACTIVE`, do NOT declare Tier 2 ready-for-writes: the MCP server
cannot reach the `0660 sshgatesigner` socket until the user logs out/in and
relaunches Claude Code (T2.8) so the `sshgatesigner` group is active.
