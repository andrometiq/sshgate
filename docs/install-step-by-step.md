# SSHGate — install step-by-step

This is the human-readable install guide. The quick path is to let
Claude Code drive: open a Claude Code session in this repo and run
`/sshgate:setup`. The slash command walks the tiered flow below and
pauses for your input where needed.

If you'd rather do it by hand (or don't have Claude Code installed),
follow the manual path.

---

Launch Claude Code normally with `claude`; SSHGate needs no special
launch flags.

There are no tagged releases or prebuilt binaries yet (the code line is
v0.1.5), so every path below builds from a clone of the repository.

**Names used below.** The signer's Unix user is `sshgatesigner` (no
hyphen). The signer binary and its systemd service are both
`sshgate-signer-telegram`. The program that runs on each server is the
*gate*, installed at `~/.sshgate-gate/gate` in the SSH user's home.

---

## Tiers

SSHGate defines three install tiers. Tier 1 and Tier 2 are usable now; Tier 3's
source foundation is present but is not release-ready. Pick only a tier whose
release status and trust boundary match your needs.

### Tier 1 — Read-only

- gate is deployed on each remote; the SSHGate dedicated SSH key
  is forced through it via `command="~/.sshgate-gate/gate"`.
- **No** signer is installed: `sshgatesigner` user/daemon does not exist,
  no master key, no Telegram bot.
- gate's keystore treats the absent `gate.pub` as "no signing
  key configured" — reads execute, writes exit 77 with:
  `gate: no signing key configured (read-only install — re-run /sshgate:setup to add a signer)`.
- **Trust model:** the agent can read whatever the SSH user can read
  (files, logs, process lists), and reads keep network access. Writes are
  denied by the gate itself, with no approval channel at all. On a server
  that supports it (see [step 5](#5-check-the-servers-read-jail)), the gate
  also runs reads inside a kernel jail, so a command the classifier
  wrongly took for a read still cannot write files on the host, reach a
  local daemon over a Unix socket, or signal other processes. On a server
  without the jail, the classifier is the only thing standing between a
  disguised write and the host.
- **Use when:** you want to try the gate quickly; you don't yet have
  a phone you want tied to the laptop; the remotes are low-stakes.

### Tier 2 — Local Telegram signer

- Everything in tier 1, plus:
  - The `sshgatesigner` system user (no shell, no login) owns
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
  agent, the signer has to run on a separate machine (Tier 3, not yet
  release-ready). See [approval-architecture.md](approval-architecture.md).
  Every write requires your active tap on Telegram. The bot's
  `allowed_user_id` pins the channel to your account.
- **Use when:** you want active human-in-the-loop approvals; you're
  comfortable with a Telegram bot as the second factor.

### Tier 3 — Hosted server signer

- **Foundation present; not yet release-ready.** The hosted signer
  (`src/signer-server`) contains a systemd installer, embedded approval UI,
  TOTP/WebAuthn authentication, and N-of-M/deny-veto policy. The work that
  lets it enforce approval policy on its own (the "hosted policy authority")
  and the v0.2 release gates are still open (see [ROADMAP.md](ROADMAP.md)),
  so do not treat it as an installable hosted release. The local
  `/sshgate:setup` menu does not automate this tier; follow
  [`src/signer-server/README.md`](../src/signer-server/README.md) for the
  current engineering/deployment requirements.
- The master key lives on a dedicated VPS; multiple operators can share the
  approval roster. TLS/DNS, backups, reverse-proxy policy, and secure client-key
  distribution remain operator responsibilities.
- **Use after the hosted release gates close when:** you need a boundary that
  still holds if the laptop-side agent can escalate privileges, or you need
  multi-operator approval.

---

## Prerequisites

**Tier 1 (read-only) needs only:**

- Go 1.25 or newer on `$PATH` (https://go.dev/dl/) — to build the
  binaries. The repo pins toolchain go1.26.4 in `go.mod`, so an older Go
  downloads it on the first build (this needs network access). The local
  side is plain Go; no sudo, no systemd, no Telegram.
- One or more remote **Linux** servers (x86-64) reachable over SSH; you
  provision them yourself with the human-only `sshgate` CLI
  (`sshgate pubkey` + `sshgate add`). The gate runs on the remote — that's
  the only side that must be Linux.

**For the kernel read jail, each server additionally needs** (optional —
without them reads still work, unconfined):

- **Landlock** enabled in the running kernel (Linux 5.13 or newer, with
  `landlock` in the active security-module list).
- **Unprivileged user namespaces** that may mount. Some systems turn these
  off: `user.max_user_namespaces=0`, Debian's
  `kernel.unprivileged_userns_clone=0`, or the AppArmor restriction
  `kernel.apparmor_restrict_unprivileged_userns=1` that Ubuntu 23.10 and
  newer enable by default.

The jail needs both. [Step 5](#5-check-the-servers-read-jail) shows how to
check a server.

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

Claude Code probes on-disk state, classifies the current
tier, and either offers a tier menu (fresh install) or a re-run menu
(upgrade an existing install). Tier 1 needs no sudo at all; Tier 2
pauses for `sudo ./scripts/install.sh` runs. The command is
idempotent; re-running is safe.

Adding servers is not part of `/sshgate:setup`: you do that yourself with
the `sshgate` CLI ([Tier 1 step 4](#4-provision-a-server-read-only-deploy)).
After adding one, check whether its reads get the kernel jail
([Tier 1 step 5](#5-check-the-servers-read-jail)).

---

## Manual path — Tier 1 (read-only)

Four steps, plus an optional check of each server. No sudo.

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
in step 4), and `sshgate-signer-telegram` (unused in Tier 1) in `~/go/bin`.
It also copies the committed, verified gate binary
(`dist/gate/sshgate-gate-linux-amd64`; it is copied, never rebuilt) to
`~/.config/sshgate/bin/sshgate-gate-linux-amd64`. That copy is what
`sshgate add` installs on each server and what `update_gate` later pushes.
The MCP server is spawned from your `$PATH`, so confirm it resolves:

```bash
command -v sshgate-mcp || echo "NOT ON PATH — add ~/go/bin (or \`go env GOPATH\`/bin) to PATH"
```

`make install-local` is required even if you installed the plugin with
Claude Code's `/plugin install`: that installs the plugin files only, not
the Go binaries.

### 3. (Optional) Create the SSHGate SSH key + registry

`sshgate pubkey` (step 4) creates the key if it does not exist, and the
registry is created on the first `sshgate add`, so you can skip this
step. To create them by hand:

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

The alias must match `[a-z][a-z0-9-]{0,30}`. For a non-standard SSH
port, use `<user@host>:<port>`.

`sshgate add` connects to the target **using SSHGate's own key** (the
line you just pasted, which currently has full shell), installs the gate,
and rewrites that plain line into the restricted
`command="~/.sshgate-gate/gate"` forced-command entry — locking the key
down. The `--read-only` flag skips uploading `gate.pub`, so the remote
runs in read-only mode: reads succeed, writes return exit 77 with the
"no signing key configured" message.

> There is a brief window — between pasting the plain key and
> `sshgate add` rewriting it — where that key grants full shell. This is
> accepted and human-controlled. If setup fails, `sshgate add` rolls the
> key back to the plain line you pasted and tells you to remove it (or
> re-run `sshgate add` to finish the lockdown); if even the rollback
> fails, it tells you to inspect `authorized_keys` by hand.

**Keep the server's `AcceptEnv` narrow.** The SSH client can send
environment variables that sshd passes on to the gate, and the gate does not
filter them before running a command. Most distributions ship
`AcceptEnv LANG LC_*` in `/etc/ssh/sshd_config`, or no `AcceptEnv` at all;
both are fine. Do not widen it on a server you register with SSHGate.

To move a tier-1 server to tier-2 later (after you've added a signer),
**de-provision and re-add** it by hand: on the host, replace SSHGate's forced
`command="..."` line in `~/.ssh/authorized_keys` with `sshgate pubkey`'s plain
line, drop the alias from the registry (`~/.config/sshgate/servers.json`), then
`sshgate add <alias> <user@host>` **without** `--read-only`.
`sshgate revoke <alias>` prints these exact commands for one alias; it
changes nothing itself. A tier-1 gate has no signer pubkey, so a signed
remote revoke can't run on it — `/sshgate:revoke` refuses a read-only host
before any tap, which is why the tier change is a manual de-provision rather
than a `revoke`. An in-place tier flip was also considered and rejected for
security (any unsigned upgrade path the CLI could exercise, the agent could
emulate) — see #17 in [ROADMAP.md](ROADMAP.md).

### 5. Check the server's read jail

The gate decides per server whether it can run reads inside the kernel
read jail (profile `ro-v1`). Inside the jail a read sees the host's files
read-only; its only writable space is a private 64 MiB scratch area at
`/dev/shm` (and `/dev/null`). It cannot write files or file metadata on
the host, connect to a local daemon over a Unix socket, or signal or
trace other processes. It **does** keep TCP/UDP network access, including
to services on localhost. A short, fixed list of `systemctl` and `docker`
read commands runs outside the jail because they need those daemons'
sockets. Signed writes never run in the jail.

There are only two levels: `full` (jailed) and `unconfined` (classifier
only, as before the jail existed). To see which applies, log in to the
server **with your own admin access** (not SSHGate's key, which only runs
the gate) as the same user you registered, and run:

```bash
~/.sshgate-gate/gate doctor
```

The `reads:` line is the verdict:

- `jailed:full` — reads run in the jail.
- `unconfined` — this host lacks Landlock or usable user namespaces, so
  reads run unconfined. The `userns`, `landlock_abi`,
  `apparmor_userns_clamp` and `notes` lines say which part is missing.
- `denied: <reason>` — the gate is refusing reads (see below).

`--json` prints the same report as JSON.

On Ubuntu 23.10 and newer, `apparmor_userns_clamp: yes` means the default
AppArmor restriction blocks the namespaces the jail needs. SSHGate does not
ship an AppArmor profile for the gate yet. Turning the restriction off
(`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`, plus a
file in `/etc/sysctl.d/` to keep it after a reboot) lets the gate
build the jail, but it also allows unprivileged user namespaces for every
user on that host, so weigh that before you do it.

**Optional: pin the jail floor.** Without a pin, a host that loses the
jail (a kernel or sysctl change) quietly goes back to unconfined reads. To
make the gate refuse reads instead, run this once on a host that reports
`jailed:full`:

```bash
~/.sshgate-gate/gate doctor --pin
```

It writes `full` to `~/.sshgate-gate/jail-floor`. From then on, if the jail
is unavailable, the gate refuses reads with exit 77 and the message
`gate: read jail unavailable` (the fixed `systemctl`/`docker` list, which
never uses the jail, still runs), and the agent is told to ask you to run
`gate doctor`. A damaged floor file (unreadable, group- or world-writable,
or holding anything other than `full` or `unconfined`) also makes the gate
refuse reads. `--pin` never lowers an existing floor; to remove the pin,
delete the file by hand.

Even without a pin, the gate never falls back to an unconfined read on a
host that supports the jail: if the jail check fails for an unexplained
reason, or the jail cannot be set up for a read, that read is refused with
exit 77.

---

## Manual path — Tier 2 (local Telegram signer)

Assumes Tier 1 is already in place (binaries built, SSH key + registry
exist). ONE sudo touchpoint: a single interactive `install.sh` pass that
prompts for your Telegram user_id and bot token in the same run — no
hand-editing of the root-owned config, no second pass. Every step is
idempotent: re-running after a partial failure is safe.

### 1. Build the binaries

`make install-local` is the single build command — it depends on
`make build`, so it produces the clone's `bin/*` artifacts AND puts the
laptop binaries on your `$PATH` and stages the gate. `scripts/install.sh`
(step 2) needs `bin/sshgate-mcp` and `bin/sshgate-signer-telegram` from that
build, plus the committed gate binary `dist/gate/sshgate-gate-linux-amd64`,
which is already in the clone. If you already ran `make install-local` for
Tier 1, skip to step 2. Otherwise:

```bash
make install-local
```

There is no separate `make build` to run: `install-local` already covers
it.

### 2. Run the installer (single pass — user_id + token in one run)

Have two things ready before you run it — the installer prompts for each in
order:

- **Your numeric Telegram user_id.** Message @userinfobot; it replies with
  `Id: NNNN`. That number is your `allowed_user_id` — the only account whose
  taps can approve writes.
- **A Telegram bot token.** Create the bot via @BotFather: send `/newbot`,
  choose a name and a username ending in `bot`. BotFather replies with a token
  shaped like `7123456789:AAH...`. Copy it.

Then run:

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
  Code. You must log out and back in and relaunch Claude Code (see step 4).
- Copies `bin/sshgate-signer-telegram` to `/usr/local/bin/sshgate-signer-telegram` and
  the committed `dist/gate/sshgate-gate-linux-amd64` to `/usr/local/share/sshgate/`.
- Writes `/etc/systemd/system/sshgate-signer-telegram.service` with hardened
  settings (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, etc.).
- Runs `signer --init` (as the `sshgatesigner` user) to generate
  `keys/gate.{key,pub}` and the skeleton `config/config.toml`
  (initial `type = "stub"`).
- **Configures the Telegram backend in the SAME run.** It prompts:

  ```
  [install] Telegram user_id (numeric), or press Enter to skip:
  ```

  Paste your user_id. The installer appends the `[backend.telegram]` block
  (with the `token_path` / `allowed_user_id` / `chatstore_path` pointers) and
  flips the backend type from `stub` to `telegram`, idempotently (a re-run
  does not duplicate the block). Then it prompts:

  ```
  [install] Paste the BotFather token (input hidden), or press Enter to skip:
  ```

  Paste the token. Input is hidden (terminal echo disabled) — nothing appears
  on screen. Press Enter. The installer writes it to
  `/var/lib/sshgatesigner/tokens/telegram.token` (mode `0600`, owned by
  `sshgatesigner:sshgatesigner`).
- `systemctl enable --now sshgate-signer-telegram`.
- Copies the new signer public key to
  `~/.config/sshgate/pubkey-distrib/gate.pub` in your home, where
  `sshgate add` looks for it.

The script exits non-zero with a clear message if the daemon fails to come up.
Verify the daemon, the config, and the token file:

```bash
systemctl is-active sshgate-signer-telegram
# expect: active

sudo grep -E '^type|allowed_user_id' /var/lib/sshgatesigner/config/config.toml
# expect: type = "telegram"  and a non-zero numeric allowed_user_id

sudo stat -c '%a %U:%G' /var/lib/sshgatesigner/tokens/telegram.token
# expect: 600 sshgatesigner:sshgatesigner
```

If the type is still `stub` or `allowed_user_id = 0`, you pressed Enter past
the user_id prompt — re-run `sudo ./scripts/install.sh` and enter the id (it's
idempotent and won't duplicate the block). If the daemon fails after the token
write, run `journalctl -u sshgate-signer-telegram -n 30 --no-pager`; a common
cause is a token copy-paste with a stray newline (the installer's regex catches
this and refuses to write it).

**Optional — `api_base_url` (api.telegram.org bypass).** If `api.telegram.org`
is IP-blocked from this host (the rest of the internet works, but Telegram's
IPs time out), route the approval bot through a **reverse proxy you run**
somewhere that can reach Telegram. It must forward
`<base>/bot<token>/<method>` → `https://api.telegram.org/bot<token>/<method>`.
Add an `api_base_url` line to the `[backend.telegram]` block the installer
wrote (or set the env var `SSHGATE_TELEGRAM_API_URL`, which overrides the
config), then `sudo systemctl restart sshgate-signer-telegram`:

```bash
# append inside the [backend.telegram] block in
# /var/lib/sshgatesigner/config/config.toml:
#   api_base_url = "https://tg-proxy.example.com"
```

It must be `https://` (plain `http://` is allowed **only** for a
`localhost`/`127.0.0.1` proxy, since the bot token transits the URL path).
Empty/absent ⇒ `api.telegram.org` (default). On startup the daemon logs
`telegram: routing Bot-API via custom endpoint <base>` so you can confirm the
bypass is active. The core of an nginx config for such a proxy is
`location / { proxy_pass https://api.telegram.org; proxy_ssl_server_name on; }`
inside an HTTPS `server` block. The bot token travels in the URL path, so
serve the proxy over TLS and keep its access logs private.

### 3. Capture chat_id from `/start` and validate

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
already registered — each of them still has no `gate.pub` and stays
read-only. `scripts/install.sh` already staged the new pubkey at
`~/.config/sshgate/pubkey-distrib/gate.pub`. Copy it by hand only if you
run SSHGate with a custom `$XDG_CONFIG_HOME` (the installer cannot see
it under `sudo`), into the matching directory:

```bash
mkdir -p "$XDG_CONFIG_HOME/sshgate/pubkey-distrib"
sudo cp /var/lib/sshgatesigner/keys/gate.pub \
    "$XDG_CONFIG_HOME/sshgate/pubkey-distrib/gate.pub"
sudo chown "$USER" "$XDG_CONFIG_HOME/sshgate/pubkey-distrib/gate.pub"
chmod 644 "$XDG_CONFIG_HOME/sshgate/pubkey-distrib/gate.pub"
```

Then bring each existing read-only server up to signed-write. A tier-1 gate has
no signer pubkey, so a signed remote revoke can't run on it — `/sshgate:revoke`
refuses a read-only host before any tap — so the tier change is a manual
de-provision + re-add: for each registered alias, on the host replace SSHGate's
forced `command="..."` line in `~/.ssh/authorized_keys` with `sshgate pubkey`'s
plain line, drop the alias from the registry (`~/.config/sshgate/servers.json`),
then run `sshgate add <alias> <user@host>` **without** `--read-only`, which now
finds the staged `gate.pub` and deploys signed-write. `sshgate revoke <alias>`
prints the exact commands for one alias. (Servers you provision fresh from
here on pick up `gate.pub` automatically. An in-place read-only→write upgrade
was rejected for security, as explained in Tier 1 step 4.)

### 4. Activate the sshgatesigner group, relaunch Claude Code (REQUIRED before writes)

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
3. **Resume** in the new session: run `/sshgate:status`, then `/sshgate:setup`
   — it re-probes on-disk state, detects Tier 2, and confirms you're ready for
   writes. (`scripts/install.sh` prints these same resume steps in its final
   banner.)

Then confirm the group is active:

```bash
id -nG | tr ' ' '\n' | grep -qx sshgatesigner && echo 'group:active' || echo 'group:INACTIVE — log out/in and relaunch Claude Code before writes'
```

Tier 2 is ready for writes only once this prints `group:active`. Until then,
reads work but every write returns permission-denied at the signer socket.

### 4b. (Optional) LLM command explainer

> **You can skip this step.** Tier 2 is fully functional once the
> `sshgatesigner` group is active (step 4) — the approval messages list every
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
  `https://openrouter.ai/api/v1/chat/completions`; pick a small, fast
  model (the example below uses `anthropic/claude-haiku-4.5`).
- **OpenAI** — endpoint
  `https://api.openai.com/v1/chat/completions`, with any small chat model.

Model names change often; the ones here are examples, not
recommendations.

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

**A read fails with exit 77 and `gate: read jail unavailable`.**
The gate on that server refused to run the read because it could not
confirm or set up the kernel read jail. Nothing ran. Run
`~/.sshgate-gate/gate doctor` on the server (Tier 1 step 5) and read its
`reads:` and `notes:` lines. The usual cause is a pinned `jail-floor` on a
host that lost Landlock or user namespaces; fix the host, or delete the
`jail-floor` file to accept unconfined reads there.

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
