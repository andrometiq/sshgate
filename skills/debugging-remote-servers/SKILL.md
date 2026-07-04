---
name: debugging-remote-servers
description: This skill should be used when the user asks to debug, diagnose, or operate a remote server registered with SSHGate — phrases like "debug X on prod-db", "what's eating disk on staging", "restart nginx on the app server", "is my server reachable", "ssh into prod and check journalctl", "tail the logs on web-1", or "fix the broken nginx config on staging". Teaches the right tool order (list_servers → run for diagnostics → run_batch for fixes), the cost shape (reads are free, writes need one Telegram tap each), and the bulk-approval pattern that keeps multi-step fixes to a single approval.
---

# Debugging remote servers with SSHGate

SSHGate gives you SSH access to the user's registered servers. Your MCP
tool surface is exactly ten tools — `sshgate.run`, `sshgate.run_batch`,
`sshgate.list_servers`, `sshgate.status`, `sshgate.revoke_server`,
`sshgate.request_grant`, `sshgate.revoke_grant`, `sshgate.list_grants`,
`sshgate.update_gate`, and `sshgate.transfer` — and debugging mostly uses the
first three (the grant tools are for unattended write windows, `update_gate`
pushes a signed, human-approved update of the gate binary itself, and
`sshgate.transfer` moves a secret file between two registered servers end-to-end
encrypted through the gate under one human approval — the MCP relays only
ciphertext, so the plaintext never reaches you — see **Standing grants** and
**Updating a server's gate** below). Read commands run instantly. Write
commands need the user to tap a Telegram approval button on their phone.
Optimise for: fast diagnosis, one approval per fix, no surprises.

**You cannot add a server.** Provisioning a new machine is a human-only
`sshgate` CLI step (`sshgate pubkey` then `sshgate add`), deliberately kept
off your tool surface so you can only operate within the servers a human
has already registered. If the user wants a new server reachable, point
them at that CLI — never attempt to onboard one yourself.

## Tool order

1. **`sshgate.list_servers`** first, every session, before touching
   anything. Confirms the alias the user mentioned is actually
   registered and surfaces the host/user so you can speak about it
   accurately. If the alias is not registered, say so and stop — tell the
   user to provision it with the human-only `sshgate` CLI (`sshgate pubkey`
   then `sshgate add <alias> <user@host>`) rather than guessing. You have
   no tool to add it yourself.
2. **`sshgate.run`** for diagnostics. Reads execute on the remote
   immediately, no approval, no notification. Stream the output back
   and reason from it.
3. **`sshgate.run_batch`** for fixes. Group every write that belongs
   to one logical change into a single batch so the user approves
   once, not N times.
4. **`sshgate.run`** again at the end, to verify the fix landed.

## Cost shape — reads free, writes tap

Every write command triggers a Telegram DM to the user with the
command text and `[✓ Approve all] [✗ Deny]` buttons. The user is
probably away from the laptop; each prompt is a small interruption.

- A single `sshgate.run` with a write costs **one tap**.
- A `sshgate.run_batch` with N writes costs **one tap total** — the
  user approves the whole batch in one go.
- N separate `sshgate.run` calls with writes cost **N taps**. Avoid
  this. Always batch related writes.

Read commands cost nothing. Run as many as you need to understand
the situation.

## Standing grants — a tap-free write window

When you expect **many writes** on one server over a stretch where the
user can't tap each (an overnight maintenance run, a migration, a long
unattended build), ask for a **standing grant** instead of N approvals:

- **`sshgate.request_grant(alias, scope, commands?, duration_hours, reason?)`**
  *requests* a grant — it does **not** create one. The user must approve a
  distinct "STANDING GRANT" Telegram message (alias + scope + duration). You
  can never self-grant. Once approved, matching writes **auto-sign for the
  window with no further tap**.
- **`scope`:** prefer `commands` — only the exact command strings you list
  (exact match, no patterns) auto-sign; everything else still prompts. Use
  `scope=all` (every write auto-signs) **only** for a throwaway/dedicated
  target, never a live box that holds anything that matters.
- **Bounds:** `duration_hours` ≤ 24h, and the grant lives **in-memory in the
  signer** — it dies on signer restart. **Reveal never auto-signs** — a
  secret-read always prompts even under a grant.
- **`sshgate.revoke_grant(alias)`** drops the grant early. Pure
  de-escalation: always safe, no approval, no-op if none exists. Drop a grant
  as soon as the window's work is done.
- **`sshgate.list_grants(alias?)`** lists the signer's live standing grants
  (optionally filtered to one alias). Read-only, no approval, always safe — it
  reports state, never changes it.

Always show the user the exact scope + command set before requesting.

**Phantom-live grant after a `request_grant` error/timeout.** If `request_grant`
returns an error or times out, the grant may still have gone live — the human
approved, but the response didn't make it back to you. Call `sshgate.list_grants`
to check the true state *before* re-requesting. Re-requesting blindly would
prompt the human a second time and risk a double grant.

## Updating a server's gate

When a gate change needs to reach an **already-registered** server (a new
redaction rule, a classifier fix), you don't re-provision — you request a
signed, in-place binary update:

- **`sshgate.update_gate(alias)`** pushes a fresh gate binary onto the named
  server. You supply **only the alias** — never binary bytes or a hash. The MCP
  hashes the operator's locally-staged gate binary and the user must approve a
  distinct **"GATE BINARY UPDATE"** Telegram banner bound to that exact SHA-256
  before it runs.
- It is **fail-closed**: a hash mismatch, a wrong-architecture binary, or a
  read-only (Tier-1) server all refuse locally and write nothing — same as any
  other write. It is signed and audited.
- It does **not** expand your reach — no new server is onboarded (provisioning
  stays the human-only `sshgate` CLI), and a **standing grant never auto-signs an
  update** (any admin verb always forces a fresh human tap).

## Secret-reveal — the rare "see a value" escape hatch

Your reads are **redacted by default**. To see ONE secret value raw, call
`sshgate.run(alias, command, reveal=true, reason="…")` — it bypasses the
redactor for that single command. It takes its **own distinct approval**, a
**mandatory** `reason`, is **single-command only** (never in `run_batch`),
and is **never** auto-signed under a standing grant (every secret-read
prompts, even mid-grant). The raw value enters your context → transcript, so
use it sparingly; prefer moving secret-bearing files box-to-box instead.

## Diagnostics — the free part

For "what's wrong with X" questions, lead with these:

- `df -h` — disk full?
- `free -h` — memory pressure?
- `top -bn1 | head -30` — what's hot?
- `uptime` and `who` — when did it start, who's logged in?
- `systemctl status <unit>` — is the service alive?
- `journalctl -u <unit> -n 50 --no-pager` — recent log lines.
- `ss -tlnp` or `ss -tnp state established` — open sockets.
- `ls -lah <path>` / `cat <file>` — inspect specific paths.

All of these are reads. Fire them off one after another via
`sshgate.run`. The user does not get pinged.

## Fixes — the batched part

Before calling `run_batch`, **show the user the planned writes**. Use
a fenced block, exactly the commands you'll send, no surprises:

```
Planned writes on prod-db (one Telegram approval covers all 4):

  1. nginx -t                                # validate new config
  2. cp /etc/nginx/sites-available/app.conf /etc/nginx/sites-available/app.conf.bak
  3. tee /etc/nginx/sites-available/app.conf < /tmp/new-app.conf
  4. systemctl reload nginx

Approving the prompt on your phone will run them in order. Reply
"go" to proceed, or tell me to adjust.
```

Wait for the user to acknowledge. Then call `sshgate.run_batch` with
the same list, `stop_on_error: true` (the default — abort the
sequence if any step fails). Surface the per-step output verbatim
when it comes back. After a successful batch, run one more diagnostic
read (`systemctl status nginx`, `nginx -t`, whatever proves the fix)
to confirm.

## Long-running tasks — launch detached, then poll (don't block)

For anything that runs more than ~a minute (DB dumps/restores, `rsync`,
backups, builds, package installs), do **not** call a blocking
`sshgate.run` and wait. A synchronous `run` holds your whole turn for the
duration **and** dies if the SSH pipe drops (the remote job gets SIGHUP and
is killed). Instead launch it **detached** and poll:

1. **Launch** (one write — the redirect/`&` make it a write; under a standing
   grant on that server it auto-approves with no tap):
   `sshgate.run <alias> "nohup <cmd> >~/job.log 2>&1 & echo $!"` → returns the
   **PID** immediately. For an exit code, launch as
   `nohup sh -c '<cmd>; echo done:$? >~/job.done' &`.
2. **Poll with reads** (free, no tap): `sshgate.run <alias> "tail -n 40 ~/job.log"`,
   `sshgate.run <alias> "ps -p <pid> -o pid=,stat=,etime="`, or
   `sshgate.run <alias> "cat ~/job.done"` for completion.
3. **Cancel** (your "Ctrl-C"): `sshgate.run <alias> "kill <pid>"` (a write).

The detached job **survives a dropped pipe**; a synchronous long `run` does
not. State lives in the OS + the logfile on the target, so nothing is lost if
your session is interrupted — reconnect and `tail` the log.

> A first-class `job_run` / `job_status` / `job_kill` tool family (gate verbs
> `SSHGATE_JOB_RUN` / `SSHGATE_JOB_STATUS` / `SSHGATE_JOB_KILL`) is planned —
> see the roadmap. When it ships, prefer it over hand-rolled `nohup`; until
> then, use the `nohup` + poll pattern above.

## Read-only (Tier-1) servers — writes refused before any tap

A server can be provisioned **read-only** (a human ran
`sshgate add … --read-only`): the gate is installed but no signer pubkey
was pushed, so it executes reads and denies every write locally. When you
send a write to such a server, `sshgate.run` / `sshgate.run_batch`
**refuse it before soliciting any Telegram approval** — no tap is wasted —
and return an error like:

```
server "prod-db" is registered read-only — writes are denied at the
gate (no signer pubkey was pushed).
```

Do NOT retry. Surface the correct upgrade path to the user and stop:
making the server signed-write is a **human-only** action — they run
`/sshgate:setup` to add a Telegram signer (if they don't have one), then
`/sshgate:revoke prod-db` (its Telegram approval is kept) and re-provision
with `sshgate add prod-db <user@host>` (no `--read-only`). You have no tool
to do this, and an in-place upgrade was considered and rejected for security
(any unsigned tier-flip the CLI could exercise, the agent could emulate);
revoke + re-provision is the only path — see roadmap #17 (redefined). Reads on
the same server still work normally — keep diagnosing with `sshgate.run`.

## Denial, timeout, and signer-access handling

A failed write surfaces one of these. **Do not loop** on any of them —
resubmitting the same batch is rude and (for the first three) hopeless.

- **Denied** (`denied by operator`) — the user tapped Deny. Surface it
  verbatim; ask why (wrong time, wrong server, command needs a tweak);
  propose an alternative or wait for direction.
- **Timeout** (`approval timed out`) — the approval window elapsed
  (signer's default is ~5 minutes / 300s). The user was probably away. Tell them and
  offer to re-send when they're ready, but don't auto-resubmit.
- **Verdict undelivered** (`verdict undelivered — the signer decided but the
  response did not arrive; a human may have DENIED this`) — the signer reached a
  decision but its response never got back to you, so a Deny may be hiding behind
  this. **Do NOT auto-retry** — a denied write must never be silently
  re-submitted. Check `sshgate.status` and the Telegram approval thread; resubmit
  only once you confirm it was not a denial.
- **Signer permission denied** (`signer socket … is present but not
  accessible (permission denied) — your shell/session is not yet in the
  sshgatesigner group`) — the daemon is ALIVE; the current Claude Code
  session just hasn't picked up `sshgatesigner` group membership. This
  happens right after the first `/sshgate:setup`. STOP and tell the user
  to **log out and back in, fully restart Claude Code, then run `/mcp`**
  to confirm the `sshgate` server is live before retrying. Do not treat
  this as "the daemon is dead."
- **Unreachable** (`signer unreachable` / "not configured") — if
  `sshgate.status` reports the socket `configured:false`, there is no
  signer at all (Tier-1 read-only): writes need `/sshgate:setup`. If it
  reports `configured:true` but UNREACHABLE, the daemon is installed but
  down — escalate with `systemctl status sshgate-signer-telegram` and
  `journalctl -u sshgate-signer-telegram -n 50`.

### Gate deny exit codes (77 / 65)

A write that reaches the gate but is rejected there comes back with a
non-zero exit, now **annotated** with remediation: `sshgate.run`
surfaces it as the tool error; `sshgate.run_batch` folds it into the
failing command's stderr and the batch summary. You don't have to
memorise the codes, but:

- **exit 77** — missing signature OR the host has no signer pubkey
  (read-only / Tier-1). Check `sshgate.status`; if the signer is not
  configured, the user runs `/sshgate:setup`, then revokes and re-provisions
  the server (`/sshgate:revoke <alias>` + `sshgate add`, no `--read-only`) to
  upgrade — a human-only step you can't perform.
- **exit 65** — bad / expired signature: usually clock skew or a stale
  approval. Retry once.

## Classification gotchas

The local classifier flags any command as a write if it can't prove
it's a read. A few non-obvious cases:

- **`journalctl --rotate`**, **`journalctl --vacuum-time=…`** — writes
  (they mutate the journal).
- **`apt update`** — write (mutates the apt cache).
- **`curl -X POST …`**, any non-GET HTTP method — write.
- **Pipelines are classified per-segment** (since v1.1). A pure-read
  pipeline like `cat /etc/hosts | grep foo` or `ps aux | grep nginx`
  is a READ — no Telegram approval. A pipeline with *any* write
  segment (e.g. `cat /etc/foo | tee /tmp/bar`, or `cmd > /tmp/x |
  echo done`) is a WRITE.
- **An unquoted newline is a command separator** (like `;`). The gate
  execs via `sh -c`, so `ls\nrm -rf x` runs two commands — the
  classifier splits on the newline and any write segment makes the
  whole thing a WRITE. (This closed a read-only-gate bypass where a
  read first line masked a write second line. Newlines *inside* quotes
  do not split.)
- **Redirects (`>`, `>>`)** are ALWAYS WRITE, regardless of what's on
  the left side.
- **Command substitution `$(...)`** and **process substitution
  `<(...)`, `>(...)`** are ALWAYS WRITE (fail-safe: the classifier
  doesn't try to inspect the substituted command).
- **`tee`, `sudo`, `find -delete / -exec / -fprint*`, `awk` with
  `system()`, `sed` with `e`/`w`/`r` script flags** — always WRITE
  (true-write triggers, no exceptions).
- **`sed -i` / `--in-place`, including bundled short flags** — always
  WRITE. The classifier catches the in-place flag even when it is
  bundled onto other no-arg flags, e.g. `sed -ni`, `sed -Ei`,
  `sed -ri`, `sed -si`, `sed -nri …`, and suffix forms like `-i.bak`.
  (A bundled `-i` editing in place is a file mutation, not a read —
  this closed a read-only-gate bypass.) Plain `sed 's/a/b/' file`
  with no `-i` and no dangerous script flag is still a READ.
- **`docker exec …`** — write (the inner command is opaque to the
  classifier).

If a pure-read pipeline still classifies as write (e.g. an obscure
read tool the classifier doesn't recognise), run the segments
unpipelined and grep the output yourself in the conversation.

## Concrete example — bulk-approval pattern

User: "The nginx config on prod-db is wrong; ssl_certificate points
at the old path. Fix it."

1. `sshgate.list_servers` → confirm `prod-db` is registered.
2. `sshgate.run prod-db "cat /etc/nginx/sites-available/app.conf"` →
   read the current config. Diagnose: `ssl_certificate` line points
   at `/etc/letsencrypt/live/old-domain/fullchain.pem`.
3. `sshgate.run prod-db "ls -la /etc/letsencrypt/live/"` → find the
   new cert dir.
4. Compose the fixed config locally (in conversation). Show it to
   the user.
5. Show the user the planned write batch:

   ```
   Planned writes on prod-db (one approval, 4 commands):
     1. cp /etc/nginx/sites-available/app.conf /etc/nginx/sites-available/app.conf.bak
     2. tee /etc/nginx/sites-available/app.conf < /tmp/new-app.conf
     3. nginx -t
     4. systemctl reload nginx
   ```

6. On "go" → `sshgate.run_batch` with those 4 commands. One Telegram
   tap covers all 4. Each command is still individually signed —
   audit log is preserved.
7. After approval and run, `sshgate.run prod-db "systemctl status
   nginx"` → confirm reload succeeded, no errors in the most recent
   log lines.

That's the pattern. One read pass → propose → one approval → one
verify pass.
