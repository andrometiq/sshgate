---
name: debugging-remote-servers
description: This skill should be used when the user asks to debug, diagnose, or operate a remote server registered with SSHGate — phrases like "debug X on prod-db", "what's eating disk on staging", "restart nginx on the app server", "is my server reachable", "ssh into prod and check journalctl", "tail the logs on web-1", "fix the broken nginx config on staging", "copy the .env from prod to staging", or "remove web-1 from SSHGate". Teaches the right tool order (list_servers → run for diagnostics → run_batch for fixes), the cost shape (reads are free, writes need one Telegram tap each), the bulk-approval pattern that keeps a multi-step fix to one approval, and how to read denials, exit codes and the read jail.
---

# Debugging remote servers with SSHGate

SSHGate gives you SSH access to the user's registered servers. Read commands
run at once. Write commands need the user to tap an approval button in
Telegram, usually on their phone. Optimise for fast diagnosis, one approval
per fix, and no surprises.

Your tool surface is exactly eleven tools:

| Tool | What it does | Approval |
|---|---|---|
| `sshgate.list_servers` | Registered aliases, with host, user and tier | none |
| `sshgate.run` | One command. Reads run directly; a write asks for a tap | write: one tap |
| `sshgate.run_batch` | A list of commands; all its writes share one tap | one tap for all writes |
| `sshgate.ping` | Is ONE server reachable right now (short probe) | none |
| `sshgate.status` | Signer health plus reachability of every server | none |
| `sshgate.request_grant` | Ask for a standing grant (tap-free write window) | its own tap |
| `sshgate.revoke_grant` | Drop a grant early | none |
| `sshgate.list_grants` | List live grants | none |
| `sshgate.update_gate` | Signed update of the gate binary on a server | its own tap |
| `sshgate.transfer` | Move a secret file between two servers, end-to-end encrypted | its own tap |
| `sshgate.revoke_server` | Remove SSHGate from a server and forget the alias | its own tap |

Most debugging uses the first three.

**You cannot add a server.** Provisioning is a human-only `sshgate` CLI step
(`sshgate pubkey`, paste the key on the host, then `sshgate add <alias>
<user@host>`). It is deliberately off your tool surface, so you can only reach
servers a human already registered. If the user wants a new server, give them
those steps; never try to onboard one yourself.

## Tool order

1. **`sshgate.list_servers`** first, every session. Confirm the alias the user
   named is registered and note its tier. If it is not registered, say so and
   stop.
2. **`sshgate.run`** for diagnostics. Reads run immediately, with no approval
   and no notification.
3. **`sshgate.run_batch`** for fixes. Put every write of one logical change in
   one batch so the user approves once, not N times.
4. **`sshgate.run`** again at the end, to verify the fix landed.

## Cost shape: reads are free, writes cost a tap

Every write sends the user a Telegram message with the command text and
Approve / Deny buttons. The user is probably away from the laptop, so each
prompt is an interruption.

- One `sshgate.run` with a write costs **one tap**.
- One `sshgate.run_batch` with N writes costs **one tap in total**.
- N separate `sshgate.run` writes cost **N taps**. Avoid this; batch related
  writes.

Reads cost nothing. Run as many as you need.

## Diagnostics: the free part

For "what's wrong with X", start with these (all reads):

- `df -h`: disk full?
- `free -h`: memory pressure?
- `top -bn1 | head -30`: what's hot?
- `uptime` and `who`: load, and who is logged in.
- `systemctl status <unit>`: is the service alive?
- `journalctl -u <unit> -n 50 --no-pager`: recent log lines.
- `ss -tlnp` or `ss -tnp state established`: open sockets.
- `ls -lah <path>` / `cat <file>`: inspect specific paths.

Send them one after another with `sshgate.run`. The user is not pinged.

**Never run a command that does not end on its own** (`tail -f`,
`journalctl -f`, `watch`, `top` without `-b -n1`). The gate puts no time limit
on a read, so the call just hangs. Always bound reads with `-n`, `--since` or
`| tail`.

**Output is capped.** `run` and `run_batch` cut each command's stdout and
stderr at 256 KiB by default and add a truncation marker. Prefer a narrower
read over a bigger cap. `max_output_bytes` overrides the cap for one call
(`0` means unlimited; use it rarely, since the whole output enters your
context).

## Reads run in a kernel read jail

On hosts whose kernel supports it, the gate runs every read in a kernel jail.
The jail is what makes "reads can't change anything" true on the server
itself, not just in the classifier. What this means for you:

- **A read cannot write to the host.** The host filesystem is read-only, and
  `/tmp` and `/var/tmp` are visible but read-only. The only writable space is
  a private 64 MiB `/dev/shm` (`TMPDIR` points there), discarded when the read
  ends. Anything that has to change the box is a write: put it in a batch.
- **Network still works.** A read can reach TCP/UDP services, including
  `curl http://localhost:<port>/health`.
- **No local daemons over Unix sockets.** A fixed set of `systemctl` and
  `docker` reads still works, because the gate runs them outside the jail,
  but only in their plain form: one command, no pipe, no quotes.
  - `systemctl status | is-active | is-enabled | is-failed | list-units |
    list-unit-files | show | cat | get-default`, with display flags such as
    `--no-pager`, `-l`/`--full`, `-a`/`--all`, `--no-legend`, `--plain`,
    `--type=…`, `--state=…`, `-n`/`--lines`, `-p`/`--property`.
  - `docker ps | inspect | logs | images | version | info | top`, and
    `docker stats --no-stream`.

  So `systemctl list-units --state=failed` works on a jailed host, but
  `systemctl list-units | grep nginx`, `timedatectl` and
  `systemctl is-system-running` fail there with a "Failed to connect to bus"
  style error. Read the plain output yourself instead of piping it.
- **Root-only kernel reads can fail.** `dmesg` may print "Operation not
  permitted" because the jail drops capabilities. `journalctl -k` reads the
  same kernel messages.
- **Other processes' open files are hidden.** A jailed read cannot look into
  another process's file descriptors, so `lsof -i :80` finds nothing and the
  process column of `ss -tlnp` stays empty (`ss` also prints a harmless
  "Cannot open netlink socket" line). `ss -tln` still shows which ports listen; find the owner with `systemctl status <unit>` or `ps aux | grep <name>`.
- **On a host without jail support**, reads run as before, protected by the
  classifier only. You can't see which one applies; a human can check with
  `~/.sshgate-gate/gate doctor` on the host.

If a read comes back with **exit 77 and stderr `gate: read jail unavailable`**
(in `run`, the denial class is `read_jail_unavailable`), nothing ran: the gate
could not confirm or set up the jail (or the host is pinned to require it and
lacks it), and in that case it never falls back to running the read unjailed.
Don't retry, because every read on that host fails the same
way until it is fixed. Tell the user to run `~/.sshgate-gate/gate doctor` on
the host. Writes are not affected.

## Fixes: the batched part

Before calling `run_batch`, **show the user the planned writes** in a fenced
block, exactly the commands you will send:

```
Planned writes on prod-db (one Telegram approval covers all 4):

  1. cp /etc/nginx/sites-available/app.conf /etc/nginx/sites-available/app.conf.bak
  2. sed -i 's#/live/old-domain/#/live/new-domain/#' /etc/nginx/sites-available/app.conf
  3. nginx -t                                  # validate before reloading
  4. systemctl reload nginx

Approving the prompt on your phone runs them in order. Reply "go" to
proceed, or tell me what to change.
```

Wait for the user's go. Then call `sshgate.run_batch` with the same list.

`stop_on_error` defaults to **true** for a batch that contains any write: the
batch stops at the first **write** that exits non-zero, so a failed `nginx -t`
never reaches the reload. A read inside a write batch that exits non-zero
(an empty `grep`, a missing file) does not stop it unless you set
`stop_on_error: true` explicitly. An all-read batch defaults to continuing past
failures. A stopped batch can leave earlier steps applied (here, the edited
file), so say how to roll back (`cp …app.conf.bak …app.conf`).

Show the per-step output when it comes back, then run one more read
(`systemctl status nginx`, `curl -sI http://localhost`) to confirm the fix.

**Multi-line file content.** To write a file, send the content inline in the
command (a heredoc or `printf`), never as a reference to a file you assume is
already on the box. The command string must contain real newlines and an
unindented closing `EOF`:

```
cat > /etc/systemd/system/app.service <<'EOF'
[Unit]
After=network.target
[Service]
ExecStart=/srv/app/bin/app
EOF
```

## Standing grants: a tap-free write window

When you expect **many writes** on one server while the user can't tap each
one (an overnight maintenance run, a long unattended build), request a
standing grant instead:

- **`sshgate.request_grant(alias, scope, commands?, duration_hours, reason?)`**
  only *asks*. The user approves a distinct "STANDING GRANT" message. You can
  never grant yourself. Once approved, matching writes are signed without a
  tap until the grant expires.
- **`scope`:** prefer `commands`: only the exact strings you list (exact match,
  no patterns) are signed automatically; everything else still prompts. Use
  `scope=all` only on a throwaway or dedicated box, never a live server that
  holds anything that matters.
- **Bounds:** `duration_hours` is 1 to 24. The grant lives in the signer's
  memory and dies if the signer restarts.
- **Never covered by a grant:** secret-reveal, `update_gate`, `transfer` and
  `revoke_server` always need their own tap.
- **`sshgate.revoke_grant(alias)`** drops the grant early. Always safe, no
  approval. Drop it as soon as the work is done.
- **`sshgate.list_grants(alias?)`** shows live grants. Read-only.

Always show the user the exact scope and command list before requesting.

**If `request_grant` errors or times out, the grant may still be live**: the
user approved but the reply didn't reach you. Call `sshgate.list_grants` before
asking again; a blind re-request prompts the user twice and risks a double
grant.

## Secret-reveal: seeing one value raw

Output is redacted by default. To see ONE secret value raw, call
`sshgate.run(alias, command, reveal=true, reason="…")`. It needs its own
approval and a non-empty `reason` (shown to the approver), works for a single
`run` only (never `run_batch`), and is never covered by a grant. The value
then sits in your context and the transcript, so use it rarely. To move a
secret between servers, use `transfer` instead.

## Moving a secret file: `transfer`

`sshgate.transfer(src_alias, src_path, dest_alias, dest_path, mode?)` copies one
file from one registered server to another without the secret ever reaching
you. The source gate encrypts it for the destination; the MCP relays only
ciphertext; the destination gate decrypts and writes it. You get back only
metadata (`xfer_id`, byte count).

- Paths are absolute. `mode` is optional and only `0600` is accepted today.
  The file is replaced atomically if it exists. The limit is 8 MiB.
- One "SECRET TRANSFER" approval covers both ends; a grant never covers it.
- Both servers must be signed-write (Tier-2) and registered for transfer, and
  it needs the local Telegram signer (the hosted signer refuses transfers).
- `src/dest server not registered for transfer` means that server has no
  transfer key yet. The user runs `sshgate xfer-register <alias>` on their
  machine; then retry.

Prefer `transfer` to `cat`-with-reveal plus a write: it keeps the value out of
your context and the logs.

## Updating a server's gate: `update_gate`

When a gate change (a new redaction rule, a classifier fix) must reach an
already-registered server, call **`sshgate.update_gate(alias)`**. You supply
only the alias, never bytes or a hash. The MCP hashes the gate binary the
operator staged locally, and the user approves a distinct "GATE BINARY UPDATE"
message bound to that SHA-256. It refuses and writes nothing on a hash
mismatch, a wrong-architecture binary or a read-only server. It onboards no
new server and is never covered by a grant.

## Removing a server: `revoke_server`

Use **`sshgate.revoke_server(alias)`** only when the user explicitly asks to
remove SSHGate from a server. After one approval, the gate removes its
`authorized_keys` line (keeping a backup at
`~/.ssh/authorized_keys.sshgate-revoke-backup`) and its `~/.sshgate-gate/`
directory, and the alias is dropped from the registry. After that you can't
reach the server at all, and only a human can re-add it. A read-only (Tier-1)
server is refused before any tap; a human removes it by hand
(`sshgate revoke <alias>` prints the steps).

## Long-running tasks: launch detached, then poll

For anything that runs more than about a minute (dumps, restores, `rsync`,
builds, big installs), don't make a blocking `sshgate.run` call. It holds
your turn, and the job is killed if the SSH connection drops. Launch it
detached instead:

1. **Launch** (a write; under a matching grant it is signed without a tap):
   `nohup <cmd> >~/job.log 2>&1 & echo $!` returns the PID at once. To capture
   the exit code, launch `nohup sh -c '<cmd>; echo done:$? >~/job.done' >~/job.log 2>&1 &`.
2. **Poll with reads** (free): `tail -n 40 ~/job.log`,
   `ps -p <pid> -o pid=,stat=,etime=`, `cat ~/job.done`.
3. **Cancel:** `kill <pid>` (a write).

The detached job survives a dropped connection; its state lives in the log
file on the server.

## Read-only (Tier-1) servers

A server added with `sshgate add … --read-only` has the gate but no signer
key, so it runs reads and refuses every write. `list_servers`, `status` and
`ping` show `read_only: true` for such a server (the field is absent for a
signed-write server). A write to it is refused **before any Telegram prompt**
(denial class `read_only_server`), with an error like:

```
server "prod-db" is registered read-only — writes are denied at the gate (no signer pubkey was pushed).
```

Don't retry. If you meant the command as a read, simplify it and resend. If
it is a real write, the user has to change the tier, which is a human-only
step: set up a signer with `/sshgate:setup` if there is none, remove the
server by hand (`sshgate revoke <alias>` prints the exact steps and changes
nothing), then `sshgate add <alias> <user@host>` without `--read-only`. There
is no in-place tier switch, by design. Reads on the server keep working.

## Denials, timeouts and signer problems

When a command does not run, `run` and `run_batch` return a structured
`denial` object next to the error text:

- `verdict_class`: what happened (for example `approval_denied`).
- `summary`: one line in plain words.
- `required_action`: `retry`, `stop_do_not_retry`, `escalate_to_human`,
  `rephrase_as_read` or `provide_reason`.
- `retryable`: true only for `approval_timeout` and `bad_signature`.
- `how_to`: the concrete next steps.

**Read `required_action` first and follow `how_to`.** The common cases:

| `verdict_class` | Meaning | What to do |
|---|---|---|
| `approval_denied` | The user tapped Deny | Don't resubmit. Ask why and propose an alternative. |
| `approval_timeout` | No tap within the 5-minute window | Resubmit the same call **once**. If it times out again, ask the user when they can approve. |
| `verdict_unknown` | The signer decided, but the answer never arrived; it may have been a Deny | Don't auto-retry. Check `sshgate.status` and ask the user what they tapped. |
| `bad_signature` | Exit 65: signature expired or invalid (clock skew, stale approval) | Resubmit once. If it fails again, check the host clock. |
| `missing_signature` | Exit 77 on a write: the host has no signer key, or the signature was missing | Don't retry. Check `sshgate.status`; a human fixes the tier. |
| `read_only_server` | Write to a Tier-1 server | See the read-only section above. |
| `read_jail_unavailable` | Exit 77 on a read: the jail could not be set up | Don't retry. A human runs `~/.sshgate-gate/gate doctor`. |
| `no_signer_configured` | No signer installed yet | The user runs `/sshgate:setup`. |
| `signer_permission` | The signer runs, but this session isn't in the `sshgatesigner` group yet (normal right after the first setup) | Stop. The user logs out and back in, restarts Claude Code fully and runs `/mcp`. The daemon is not dead. |
| `signer_unreachable` | The signer socket exists but doesn't answer | Stop. The user checks `systemctl status sshgate-signer-telegram` and `journalctl -u sshgate-signer-telegram -n 50`. |
| `reveal_needs_reason` | `reveal=true` without a reason | Resend with a real reason. |

In `run_batch`, a denied or timed-out approval returns `denied: true`, no
results and the `denial` object; nothing ran. A gate refusal of one write
inside a batch that otherwise ran shows up in that command's stderr and the
batch-level `denial`. A read refused by the jail inside a batch shows as exit
77 with `gate: read jail unavailable` in its stderr.

## What counts as a read

The MCP and the gate classify every command with the same classifier. It
**fails closed**: a command is a read only when every part of it is a
recognised read. Anything it can't confirm is a write and needs a tap. The
classifier only decides the route; on a signed-write server the gate's
signature check is what actually blocks unapproved writes, and on a jailed
host the jail blocks reads from writing.

- **Chains of reads are reads.** `df -h && free -h`, `df -h; free -h`,
  `ps aux | grep nginx` and `cat /x 2>/dev/null || echo missing` are reads.
  One write or unrecognised segment makes the whole command a write:
  `df -h && nginx -t` is a write. One simple command per call is still the
  safest habit.
- **`sh -c`, `bash -c`, `xargs`, `sudo`** are always writes.
- **Redirects into a file** (`>`, `>>`) are writes, even into `/dev/shm`.
  Redirects to `/dev/null` and `2>&1` are fine.
- **`$(...)`, backticks, `<(...)`, `>(...)`** are always writes.
- **An unquoted newline separates commands**, like `;`: `ls` newline `rm -rf x`
  is a write.
- **Tool forms that change state** are writes: `tee`; `sed -i` in any spelling
  (`-ni`, `-Ei`, `-i.bak`); `find -delete` / `-exec` / `-fprint`; `awk` with
  `system()`; `curl -X POST` or `curl -o <file>`; `journalctl --rotate` /
  `--vacuum-*`; `docker exec`; `kill`; `apt update`.
- **Not on the read list, so writes:** `nginx -t`, `sshd -t`, `ufw status`,
  `nft list ruleset`, `iptables -L`, `blkid`, `findmnt`, `dpkg -l`,
  `apt-cache policy`, `openssl x509 …`, and most `--version` flags on tools
  outside the read list (`nginx -v`, `psql --version`, `git --version`,
  `docker --version`, `systemctl --version`). `systemctl --failed` is also a
  write; use `systemctl list-units --state=failed`.
- **Some env prefixes** (`PAGER=`, `LD_PRELOAD=`, `HOME=`, `PATH=` …) make a
  command a write. Plain prefixes such as `LANG=C` are fine.

When a read comes back classified as a write, the error says which segment
and why. **Simplify it** (drop the redirect, split the chain, use a common
tool) instead of resending it unchanged or wrapping it. If a check really
needs an unrecognised tool, fold it into the write batch it belongs to.

## Concrete example: the bulk-approval pattern

User: "The nginx config on prod-db is wrong; ssl_certificate points at the
old path. Fix it."

1. `sshgate.list_servers` → `prod-db` is registered and not read-only.
2. `sshgate.run prod-db "cat /etc/nginx/sites-available/app.conf"` → the
   `ssl_certificate` line points at `/etc/letsencrypt/live/old-domain/`.
3. `sshgate.run prod-db "ls -la /etc/letsencrypt/live/"` → the new directory
   is `new-domain`.
4. Show the plan (the four writes from **Fixes** above) and wait for "go".
5. `sshgate.run_batch` with those four commands: one tap covers all four.
   Each command is still signed separately and audited.
6. `sshgate.run prod-db "systemctl status nginx"` → confirm the reload
   worked and the log shows no errors.

That's the pattern: one read pass, one proposal, one approval, one verify
pass.
