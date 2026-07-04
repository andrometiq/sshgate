# SSHGate — install step-by-step

This is the human-readable install guide. The quick path is to let
Claude Code drive: open a Claude Code session in this repo and run
`/sshgate:setup`. The slash command walks the tiered flow below and
pauses for your input where needed.

If you'd rather do it by hand (or don't have Claude Code installed),
follow the manual path.

---

## Launch flag — NOT REQUIRED

Launch Claude Code normally with `claude`. SSHGate is a regular MCP
plugin and does **not** need `--dangerously-load-development-channels`.
That flag is for plugins that stream channel notifications INTO
the Claude conversation. SSHGate only uses standard MCP tool calls; its
approvals flow OUT to your phone via Telegram, not into the conversation.
If you've habit-launched with the dev-channels flag for some other
plugin, that's fine — it's a no-op for SSHGate — but it's not required.

---

## Tiers

SSHGate ships three install tiers. Pick the one matching how much
trust you want to delegate.

### Tier 1 — Read-only

- gate is deployed on each remote; the SSHGate dedicated SSH key
  is forced through it via `command="~/.sshgate-gate/gate"`.
- **No** signer is installed: `sshgatesigner` user/daemon does not exist,
  no master key, no Telegram bot.
- gate's keystore treats the absent `gate.pub` as "no signing
  key configured" — reads execute, writes exit 77 with:
  `gate: no signing key configured (read-only install — re-run /sshgate:setup to add a signer)`.
- **Trust model:** you trust Claude not to actively exploit SSH read
  access (file enumeration, log harvesting); you rely on gate to
  deny writes locally without any approval channel.
- **Use when:** you want to try the gate quickly; you don't yet have
  a phone you want tied to the laptop; the remotes are low-stakes.

### Tier 2 — Local Telegram signer

- Everything in tier 1, plus:
  - `sshgate-signer-telegram` Unix user (no shell, no login) owns
    `/var/lib/sshgatesigner/keys/gate.key` — the master signing key.
  - `sshgate-signer-telegram.service` systemd unit talks Telegram.
  - Each write command queues for a phone-tap approval before
    signer signs it; gate verifies the signature against
    `gate.pub` on the remote.
- **Trust model:** the master key is isolated under a dedicated Unix
  user. Claude (running as you) cannot read it. On the same machine this
  is a safety rail, not a hard wall — an agent that can escalate privileges
  on the host (e.g. has `sudo`) could read the signing key directly and
  bypass approval. For a guarantee that holds against a privileged rogue
  agent, run the signer on a separate machine (the hosted-signer tier).
  See `approval-architecture.md`. Every write
  requires your active tap on Telegram. The bot's `allowed_user_id` pins the
  channel to your account.
- **Use when:** you want active human-in-the-loop approvals; you're
  comfortable with a Telegram bot as the second factor.

### Tier 3 — Hosted server signer

- **NOT YET AVAILABLE (v2.x).** The hosted signer
  (`src/signer-server`) is scaffolded but the web UI + WebAuthn
  approval flow is incomplete.
- Master key lives on a dedicated VPS behind WebAuthn; multiple
  operators can share approvals. Documented for completeness.
- **Use when:** v2.x ships and you want to share SSHGate access
  across a team without each operator running their own signer.

---

## Prerequisites

**Tier 1 (read-only) needs only:**

- Go 1.25 or newer on `$PATH` (https://go.dev/dl/) — to build the
  binaries. The local side is plain Go; no sudo, no systemd, no Telegram.
- One or more remote **Linux** servers reachable over SSH; you provision them
  yourself with the human-only `sshgate` CLI (`sshgate pubkey` + `sshgate add`).
  The gate runs on the remote — that's the only side that must be Linux.

**Tier 2 (local Telegram signer) additionally needs:**

- A **systemd-based Linux** local machine (Ubuntu 22.04+, Debian 12+,
  Arch — anything systemd-based); the signer runs as a systemd service.
- `sudo` access on the local machine — we create a system user, install
  binaries to `/usr/local`, and drop a systemd unit.
- A Telegram account and access to @BotFather to create the approval bot.
- `jq` on `$PATH` — `/sshgate:setup` uses it to enumerate registered
  servers during the Tier-2 steps.

### macOS users

macOS install is **not yet automated** — `make darwin` produces
working `sshgate-mcp` and `sshgate-signer-telegram` binaries for
darwin/amd64 and darwin/arm64, but the install path
(`scripts/install.sh`, systemd unit, sshgatesigner user provisioning)
is Linux-only, so a macOS install is manual today. A scripted native
macOS install (launchd plist + `install-darwin.sh`) is a deferred
roadmap item with no committed release. The rest of this guide assumes
Linux.

---

## Quick path — `/sshgate:setup`

```
/sshgate:setup
```

That's it. Claude Code probes on-disk state, classifies the current
tier, and either offers a tier menu (fresh install) or a re-run menu
(upgrade an existing install). Tier 1 needs no sudo at all; Tier 2
pauses for `sudo ./scripts/install.sh` runs. The command is
idempotent; re-running is safe.

---

## Manual path — Tier 1 (read-only)

Three steps, no sudo.

### 1. Verify Go is installed

```bash
go version
```

You need 1.25 or newer. If missing, install from https://go.dev/dl/.

### 2. Build the binaries onto your PATH

```bash
make install-local
```

This puts `sshgate-mcp`, the human-only `sshgate` provisioning CLI (used
in step 4), and `sshgate-signer-telegram` (unused in Tier 1) in `~/go/bin`,
and the remote gate binary at
`~/.config/sshgate/bin/sshgate-gate-linux-amd64`. The MCP server is spawned
from your `$PATH`, so confirm it resolves:

```bash
command -v sshgate-mcp || echo "NOT ON PATH — add ~/go/bin (or \`go env GOPATH\`/bin) to PATH"
```

`make install-local` is required because Claude Code's `/plugin install`
strips `src/` and `bin/` from the plugin cache.

### 3. Create the SSHGate SSH key + registry

```bash
mkdir -p ~/.config/sshgate/ssh && chmod 700 ~/.config/sshgate/ssh
ssh-keygen -t ed25519 -N '' -C 'sshgate-dedicated' \
    -f ~/.config/sshgate/ssh/sshgate_ed25519
echo '{}' > ~/.config/sshgate/servers.json
```

Confirm the private key is mode 0600:

```bash
stat -c '%a' ~/.config/sshgate/ssh/sshgate_ed25519
# expect: 600
```

### 4. Provision a server (read-only deploy)

Provisioning is a **human-only** step run from your terminal with the
`sshgate` CLI (installed to `~/go/bin/sshgate` by `make install-local`).
It is deliberately NOT an agent/MCP tool: onboarding a machine is the
control plane — it defines which servers the agent can reach — so the
agent can never expand its own reach by adding a host.

First, print SSHGate's dedicated public-key line:

```bash
sshgate pubkey
```

Paste that single line, plain, into the **target** server's
`~/.ssh/authorized_keys` by hand — you already administer that box
out-of-band. Then lock the key down and register the alias:

```bash
sshgate add <alias> <user@host> --read-only
```

`sshgate add` connects to the target **using SSHGate's own key** (the
line you just pasted, which currently has full shell), installs the gate,
and rewrites that plain line into the restricted
`command="~/.sshgate-gate/gate"` forced-command entry — locking the key
down. The `--read-only` flag skips uploading `gate.pub`, so the remote
runs in read-only mode: reads succeed, writes return exit 77 with the
"no signing key configured" message.

> There is a brief window — between pasting the plain key and
> `sshgate add` rewriting it — where that key grants full shell. This is
> accepted and human-controlled. `sshgate add` warns about it, and if
> setup fails it rolls back to the plain line and tells you to remove it
> yourself if it can't.

To move a tier-1 server to tier-2 later (after you've added a signer),
**revoke and re-provision** it: run `/sshgate:revoke <alias>` (which keeps
its Telegram approval), then `sshgate add <alias> <user@host>` **without**
`--read-only`. The key is already gated, so the tier change is a
re-provision rather than a re-add. An in-place tier flip was considered
and rejected for security (any unsigned upgrade path the CLI
could exercise, the agent could emulate); revoke + re-provision stays the
only path — see roadmap #17 (redefined).

---

## Manual path — Tier 2 (local Telegram signer)

Assumes Tier 1 is already in place (binaries built, SSH key + registry
exist). Three sudo touchpoints (two `install.sh` runs and the token
paste prompt is folded inside the second one). Every step is
idempotent: re-running after a partial failure is safe.

### 1. Build the binaries

`make install-local` is the single build command — it depends on
`make build`, so it produces the clone's `bin/*` artifacts (including
`bin/sshgate-signer-telegram` and `bin/sshgate-gate-linux-amd64`, which
`scripts/install.sh` copies in step 2) AND puts the laptop binaries on
your `$PATH` and stages the gate. If you already ran it for Tier 1, the
artifacts are present — skip to step 2. Otherwise:

```bash
make install-local
```

There is no separate `make build` to run: `install-local` already covers
it.

### 2. Run the installer (first pass)

```bash
sudo ./scripts/install.sh
```

One idempotent pass does all of the following:

- Creates the `sshgatesigner` system user (no shell, no login).
- Creates `/var/lib/sshgatesigner/{keys,tokens,config,log,bin}` with the
  right ownership and modes.
- Adds your account (`$SUDO_USER`) to the `sshgatesigner` group. This is
  REQUIRED for the MCP server to work: the signer's Unix socket is mode
  `0660`, owned by `sshgatesigner`, and the MCP server runs as you — so
  without this group membership active in the session, every write is
  permission-denied at the socket. (Being able to stat the runtime dir and
  read the audit log without sudo is a secondary convenience of the same
  group.) Membership only activates in a NEW login session — `newgrp
  sshgatesigner` in a side terminal does NOT help an already-running Claude
  Code. You must log out and back in and relaunch Claude Code (see step 6).
- Copies `bin/sshgate-signer-telegram` to `/usr/local/bin/sshgate-signer-telegram` and
  `bin/sshgate-gate-linux-amd64` to `/usr/local/share/sshgate/`.
- Writes `/etc/systemd/system/sshgate-signer-telegram.service` with hardened
  settings (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, etc.).
- Runs `signer --init` (as the `sshgatesigner` user) to generate
  `keys/gate.{key,pub}` and the skeleton `config/config.toml`
  (initial `type = "stub"`).
- `systemctl enable --now sshgate-signer-telegram`.

The script exits non-zero with a clear message if the daemon fails
to come up. Verify:

```bash
systemctl is-active sshgate-signer-telegram
# expect: active
```

### 3. Configure the Telegram backend

The `--init`-generated config selects the stub backend. To get
phone-tap approvals you switch it to telegram and add your numeric
user_id.

Find your Telegram user_id by messaging @userinfobot — it replies
with `Id: NNNN`. That number is your `allowed_user_id`.

Append the telegram block (replace `NNNN`):

```bash
sudo tee -a /var/lib/sshgatesigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram]
token_path      = "/var/lib/sshgatesigner/tokens/telegram.token"
allowed_user_id = NNNN
chatstore_path  = "/var/lib/sshgatesigner/config/peer.json"
# api_base_url  = "https://tg-proxy.example.com"   # optional; see below
EOF
```

**Optional — `api_base_url` (api.telegram.org bypass).** If `api.telegram.org`
is IP-blocked from this host (the rest of the internet works, but Telegram's
IPs time out), route the approval bot through a maintainer-owned **reverse
proxy** that forwards `<base>/bot<token>/<method>` → `api.telegram.org/bot…`.
Set `api_base_url` in `[backend.telegram]` (or the env var
`SSHGATE_TELEGRAM_API_URL`, which overrides the config). It must be `https://`
(plain `http://` is allowed **only** for a `localhost`/`127.0.0.1` proxy, since
the bot token transits the URL path). Empty/absent ⇒ `api.telegram.org`
(default). On startup the daemon logs `telegram: routing Bot-API via custom
endpoint <base>` so you can confirm the bypass is active. Example nginx:
`location / { proxy_pass https://api.telegram.org; proxy_ssl_server_name on; }`.

Flip the backend type:

```bash
sudo sed -i 's/^type = "stub"$/type = "telegram"/' \
    /var/lib/sshgatesigner/config/config.toml
```

Sanity-check with `sudo cat /var/lib/sshgatesigner/config/config.toml`.
You should see `type = "telegram"` and the three telegram keys, no
duplicates.

### 4. Run the installer again (token + restart)

Create the Telegram bot first: message @BotFather, send `/newbot`,
choose a name and a username ending in `bot`. BotFather replies with
a token shaped like `7123456789:AAH...`. Copy it.

Now re-run the installer:

```bash
sudo ./scripts/install.sh
```

It detects `type = "telegram"` and the missing token file, then
prompts:

```
[install] Paste the BotFather token (input hidden), or press Enter to skip:
```

Paste the token. Input is hidden (terminal echo disabled) — nothing
appears on screen. Press Enter.

The installer writes the token to
`/var/lib/sshgatesigner/tokens/telegram.token` (mode `0600`, owned by
`sshgatesigner:sshgatesigner`), restarts the daemon, and asserts it came up.

Verify:

```bash
sudo stat -c '%a %U:%G' /var/lib/sshgatesigner/tokens/telegram.token
# expect: 600 sshgatesigner:sshgatesigner

systemctl is-active sshgate-signer-telegram
# expect: active
```

If the daemon fails after the token write, run
`journalctl -u sshgate-signer-telegram -n 30 --no-pager`. Common causes: token
copy-paste included a stray newline (the installer's regex catches
this and refuses to write, but check the file mode if it's there),
or `allowed_user_id = 0` (you forgot to substitute `NNNN`).

### 5. Capture chat_id from `/start` and validate

Open Telegram, find the bot you created (search the username you
gave to BotFather), and send it `/start`. signer's polling loop
captures the chat_id and writes it to
`/var/lib/sshgatesigner/config/peer.json`.

**Expected reply on Telegram:**

> Linked — SSHGate approvals will now reach you here.

If you see that text in the bot DM, the link succeeded. If you sent
`/start` from a Telegram account whose user_id does not match
`allowed_user_id`, the bot replies with "this bot only serves
…" and silently drops the message — signer stays in the
unlinked state.

Confirm on the laptop side:

```bash
sudo cat /var/lib/sshgatesigner/config/peer.json
# expect a JSON object containing your chat_id
```

If nothing appears after ~30 seconds, check the logs:

```bash
journalctl -u sshgate-signer-telegram -n 30 --no-pager
```

What to look for in the log:

- `telegram backend ready` — the daemon reached its polling loop.
- `/start: linked chat_id=NNN for user_id=NNN` — capture succeeded.
- `/start from unauthorized user_id=NNN ignored` — wrong Telegram
  account; check `allowed_user_id` matches your @userinfobot reply.
- `401 Unauthorized` from `getMe` / `getUpdates` — the bot token is
  wrong or was revoked in BotFather.

Final validation:

```bash
sudo -u sshgatesigner /usr/local/bin/sshgate-signer-telegram --version
systemctl status sshgate-signer-telegram --no-pager
```

You should see `Active: active (running)` and the version string.

If you upgraded from Tier 1 — that is, you had read-only servers
already registered — you also need to push the new `gate.pub` to
each one so signed writes can be verified. Copy the pubkey to the
MCP-side distribution path:

```bash
mkdir -p ~/.config/sshgate/pubkey-distrib
sudo cp /var/lib/sshgatesigner/keys/gate.pub \
    ~/.config/sshgate/pubkey-distrib/gate.pub
sudo chown "$USER" ~/.config/sshgate/pubkey-distrib/gate.pub
chmod 644 ~/.config/sshgate/pubkey-distrib/gate.pub
```

Then bring each existing read-only server up to signed-write. Because the
SSHGate key is already gated on those hosts, the tier change is a
re-provision, not a re-add: for each registered alias, run
`/sshgate:revoke <alias>` (its Telegram approval is kept) and then
`sshgate add <alias> <user@host>` **without** `--read-only`, which now
finds the staged `gate.pub` and deploys signed-write. (Servers you
provision fresh from here on pick up `gate.pub` automatically. An in-place
read-only→write upgrade was considered and rejected for security — any
unsigned tier-flip the CLI could exercise, the agent could emulate; revoke +
re-provision stays the only path — see roadmap #17, redefined.)

### 6. Activate the sshgatesigner group, relaunch Claude Code (REQUIRED before writes)

This is a mandatory happy-path step, not troubleshooting. `scripts/install.sh`
added your account to the `sshgatesigner` group, but a Unix group only
activates in a NEW login session. The MCP server inherited its group set from
the session Claude Code was launched in, so it does not yet have
`sshgatesigner` active — and the signer socket is `0660 sshgatesigner`, so
every write is permission-denied until the group is active. `newgrp
sshgatesigner` in a side terminal does NOT fix the already-running Claude
Code.

You must:

1. **Log out and back in** (or restart your login session) so `sshgatesigner`
   joins your active group set.
2. **Relaunch Claude Code** from that fresh login session.

Then confirm the group is active:

```bash
id -nG | tr ' ' '\n' | grep -qx sshgatesigner && echo 'group:active' || echo 'group:INACTIVE — log out/in and relaunch Claude Code before writes'
```

Tier 2 is ready for writes only once this prints `group:active`. Until then,
reads work but every write returns permission-denied at the signer socket.

### 6b. (Optional) LLM command explainer

> **You can skip this step.** Tier 2 is fully functional once the
> `sshgatesigner` group is active (step 6) — the approval messages list every
> command verbatim. This step
> only adds a one-line plain-English gloss beneath each command in
> the Telegram approval message, drawn from an OpenAI-compatible LLM.
> It's a quality-of-life add-on; if you don't want a third-party LLM
> in the loop or want to defer this decision, jump to **Troubleshooting**.

By default the approval message lists the queued commands verbatim.
With this step enabled, signer additionally asks an OpenAI-compatible
LLM to write a one-sentence plain-English explanation of each command
and renders them beneath the corresponding command line — handy when
you're approving from your phone and don't want to mentally parse
`certbot --nginx -d example.com` at a glance.

Approval is **never blocked** on the LLM: if the call times out or
errors, signer sends the message without explanations and adds a
small `(no explanations: …)` footer noting why.

**a. Pick a provider + model.** Any OpenAI-compatible Chat Completions
endpoint works. Two reasonable choices:

- **OpenRouter** — pay-as-you-go, broad model catalogue. Endpoint
  `https://openrouter.ai/api/v1/chat/completions`; a good cheap+fast
  model for one-liner explanations is `anthropic/claude-haiku-4.5`.
- **OpenAI** — endpoint
  `https://api.openai.com/v1/chat/completions`; `gpt-4o-mini` is the
  cost-sensible default.

Local options (LM Studio, llama.cpp's `server`) also work — point
`endpoint` at the local URL and leave any string in the key file.

**b. Write the API key to disk.** Substitute your real key on stdin:

```bash
sudo install -o sshgatesigner -g sshgatesigner -m 600 /dev/null \
    /var/lib/sshgatesigner/tokens/llm-api.key
sudo -u sshgatesigner tee /var/lib/sshgatesigner/tokens/llm-api.key >/dev/null
# paste key, ctrl-D
sudo stat -c '%a %U:%G' /var/lib/sshgatesigner/tokens/llm-api.key
# expect: 600 sshgatesigner:sshgatesigner
```

**c. Add the `[backend.telegram.explainer]` block to the config.**
Replace the endpoint and model with your choice:

```bash
sudo tee -a /var/lib/sshgatesigner/config/config.toml >/dev/null <<'EOF'

[backend.telegram.explainer]
enabled      = true
endpoint     = "https://openrouter.ai/api/v1/chat/completions"
model        = "anthropic/claude-haiku-4.5"
api_key_path = "/var/lib/sshgatesigner/tokens/llm-api.key"
timeout_sec  = 5
EOF
```

**d. Restart and verify.**

```bash
sudo systemctl restart sshgate-signer-telegram
journalctl -u sshgate-signer-telegram -n 10 --no-pager
# expect a line like:
#   telegram explainer enabled (model=… endpoint=… timeout=5s)
```

On the next approval request you should see, beneath each command,
an indented `→ <plain-English explanation>` line. If the LLM is
unreachable or slow, you'll see the verbatim commands plus a
`(no explanations: …)` footer — the daemon still asks for approval
exactly as before.

To disable the explainer later, set `enabled = false` (or remove the
block entirely) and restart the daemon.

---

## Troubleshooting

**`systemctl status sshgate-signer-telegram` shows `failed`.**
Run `journalctl -u sshgate-signer-telegram -n 50 --no-pager`. The most common
causes are a missing or malformed `config.toml` (the daemon refuses
to start if `backend.telegram.allowed_user_id` is 0 or the token file
is unreadable), or a permissions mismatch on `/var/lib/sshgatesigner/`
(re-run `scripts/install.sh` to repair — it's idempotent and re-applies
the canonical modes).

**`401 Unauthorized` in the log.**
The bot token is wrong. Re-run `sudo ./scripts/install.sh` after
removing the bad token: `sudo rm /var/lib/sshgatesigner/tokens/telegram.token`.
The installer will prompt again.

**`peer.json` never appears.**
You sent `/start` to the wrong bot, or your `allowed_user_id` doesn't
match the user that sent the message — signer drops messages from
other users silently. Double-check `Id:` from @userinfobot.

**"Address already in use" on the socket.**
A previous signer is still running. `sudo systemctl restart sshgate-signer-telegram`
clears it; if that fails, find the holder with
`sudo fuser /run/sshgatesigner/sock`.

**`go build` fails with "cannot find module".**
You're not in the SSHGate repo root. `cd` to the directory containing
`go.mod` and re-run.

**Approval messages always show `(no explanations: …)`.**
The LLM explainer is configured but every call is failing. Check
`journalctl -u sshgate-signer-telegram -n 50 --no-pager` for the underlying error.
Common causes: wrong/expired API key, unreachable endpoint URL,
`timeout_sec` set too low for the chosen model. Set
`enabled = false` in `[backend.telegram.explainer]` and restart to
disable the explainer entirely while you investigate.

---

## Uninstall

```bash
sudo ./scripts/uninstall.sh
```

This stops + disables the systemd unit, removes the unit file, removes
`/usr/local/bin/sshgate-signer-telegram` and `/usr/local/share/sshgate/`, and prompts
before removing `/var/lib/sshgatesigner/` (which holds the master signing
key and audit log — destructive). Pass `--purge` to skip the prompts.

Removing `/var/lib/sshgatesigner/` invalidates every gate deployment
keyed against this signer; you'll need to re-provision every server with
the `sshgate` CLI (`sshgate pubkey` + `sshgate add`) after re-installing.
