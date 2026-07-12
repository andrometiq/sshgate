---
name: server-setup
description: This skill should be used when the user asks to bring a fresh or newly-provisioned server up to a working, hardened state through SSHGate — phrases like "set up nginx on web-1", "configure the new box", "harden staging", "create a deploy user on prod", "set up a systemd service for the app", "configure the firewall on host-gcp", "set the timezone and NTP", or "get the new server ready for the app". Teaches a discover-first method: read the whole current state, plan the ENTIRE write set, get ONE approval (run_batch tap or a scoped standing grant), then verify each stage — with hard stop-points for lockout-risking and irreversible steps.
---

# Server setup with SSHGate

Bringing a fresh box to a serviceable state is where an agent most easily
thrashes: it makes one change, taps, discovers it needed another, taps again,
and half-configures the machine across a dozen interruptions. The cure is a
**method**: discover the whole picture with free reads, design the *complete*
write set on paper, get **one** approval, then verify. This skill teaches that
method. For the gate mechanics it leans on — read/write classification, the
tap cost model, standing grants, denial/timeout handling, exit codes — see the
`debugging-remote-servers` skill; this one does not re-teach them.

The tool surface is the same eleven tools. Setup lives almost entirely in
`sshgate.run` (reads, to discover and verify) and `sshgate.run_batch` (the one
batched write that does the actual configuration), with `sshgate.request_grant`
as the option for a longer session. **You cannot add or re-tier a server** —
provisioning is the human-only `sshgate` CLI. If the target isn't registered,
or is registered read-only (Tier-1) and the user wants writes, stop and point
them at the CLI; you have no tool for it.

## The method — four phases, in order

**1. DISCOVER (all reads, no taps).**
**2. PLAN the full write set (on paper, no execution).**
**3. APPROVE once — one `run_batch` tap, or a scoped grant for the session.**
**4. VERIFY each stage with reads.**

Never interleave discovery and writes. The whole point is that by the time you
ask for a tap, you already know everything you're going to change.

## Phase 1 — Discover (free reads)

Confirm the alias with `sshgate.list_servers` and its tier (`read_only`). A
read-only box can't be set up through the gate — say so and stop. Then build a
complete picture with single, simple reads (fire them one after another; the
user isn't pinged):

- **OS / release:** `cat /etc/os-release` — distro + version drives package
  manager and defaults.
- **Arch / kernel:** `uname -m` and `uname -r`.
- **Disk layout:** `df -h` and `lsblk` — mounts, free space, whether the data
  disk you were told about is actually mounted.
- **Memory:** `free -h`.
- **Network:** `ip -brief addr` and `ip route` — interfaces, addresses,
  default gateway. `ss -tlnp` — what's already listening (esp. port 22).
- **Existing users / groups:** `getent passwd` and `getent group` — before you
  create a user, check it doesn't already exist.
- **Existing services:** `systemctl list-units --type=service --state=running`
  and `systemctl list-unit-files --state=enabled`.
- **Firewall state:** `command -v ufw nft iptables` (a READ) tells you which
  exists — but the status commands themselves (`ufw status verbose`,
  `nft list ruleset`, `iptables -L`) are NOT recognized read tools: the gate
  fails closed and classifies them WRITE, so each costs a tap (and is refused
  outright on Tier-1). Prefer plain-file reads where they answer the question
  (`cat /etc/ufw/ufw.conf` shows `ENABLED=`, `cat /etc/ufw/user.rules` shows
  rules), or fold ONE `ufw status verbose` into the approved write batch
  (Phase 3) instead of running it standalone. Critical to know before you touch
  it (see the lockout stop-point).
- **Timezone / clock:** `timedatectl`.
- **What's installed:** `command -v <tool>` for the specific packages the task
  needs, rather than listing everything.

If any read is refused as a write, **simplify it** — drop a redirect, a
compound, or an uncommon tool — don't retry or wrap it. (Details in
`debugging-remote-servers` § classification.)

## Phase 2 — Plan the full write set

Write down *every* change before asking for a single tap. Group the whole setup
into one ordered list. A typical bring-up covers:

- **Users / groups:** create the service/deploy user, its group, ssh dir.
- **SSH hardening:** drop-in under `/etc/ssh/sshd_config.d/` (keys-only, no
  root login) — **plan, don't apply yet; see the lockout stop-point.**
- **Firewall:** allow SSH *first*, then the service ports, then enable — order
  is safety-critical (lockout stop-point).
- **Packages:** the software the box is for (installing is its own methodology —
  see the `software-installation` skill for pkg-manager detection and the
  `apt update`-is-a-write / slow-download reality).
- **Timezone / NTP:** `timedatectl set-timezone …`, enable time sync.
- **Directories / permissions:** app dirs, log dirs, ownership, modes.
- **systemd units:** unit file, `daemon-reload`, enable, start.

Order matters because `run_batch` runs the list top-to-bottom and, for a batch
containing writes, **stops on the first failure by default** — so put
validations before the thing they gate (e.g. `nginx -t` before
`systemctl reload nginx`), and put the firewall's allow-SSH rule before enabling
the firewall.

**Idempotency — make every step re-runnable.** A setup batch may be run twice
(a denial, a partial failure, a re-provision). Check-before-create so re-runs
are clean, not errors:

- Users: `id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy` — but
  note the `||` compound (and the `useradd`) make this a write (fine, it's in the
  batch); the `>/dev/null 2>&1` redirect alone would not — prefer tools that are
  natively idempotent where possible.
- Directories: `mkdir -p` (already idempotent), `install -d -o deploy -g deploy -m 0750 /srv/app`.
- Config: write drop-in files (`/etc/ssh/sshd_config.d/…`, a fresh unit file)
  rather than editing shared files in place; overwriting a drop-in is idempotent.
- Packages: the package manager already skips already-installed packages.

Then **show the user the full plan** as a fenced block — exact commands, in
order — before any tap, exactly as the `debugging-remote-servers` bulk pattern
does. No surprises.

## Phase 3 — Approve once

Two shapes, pick by how the session will run:

**A) One `run_batch` tap (default).** The whole ordered write set goes in a
single `sshgate.run_batch(alias, commands[])`. One Telegram tap approves every
write in it; each command is still individually signed and audited. Keep
`stop_on_error` at its default (true for a write batch) so an early failure
aborts before later steps run against a broken half-state. This is the right
choice when you can present the plan and the user is available to tap once.

**B) A scoped standing grant (longer / unattended session).** If setup will
span many separate writes over a stretch where the user can't tap each — an
overnight bring-up, an iterative configure-test-reconfigure loop — request a
grant instead: `sshgate.request_grant(alias, scope, commands?, duration_hours,
reason?)`. **This still needs the human's tap** — a distinct "STANDING GRANT"
approval; you can never self-grant. State the **scope and expiry** explicitly
when you ask:

- Prefer `scope=commands` with the exact command strings — only those auto-sign.
- Use `scope=all` **only** on a throwaway/dedicated box being set up from
  scratch that holds nothing yet, never a live machine.
- `duration_hours` ≤ 24 (hard ceiling); the grant is in-memory and dies on
  signer restart. **Revoke it the moment setup is done** with
  `sshgate.revoke_grant(alias)` — de-escalation is always safe and needs no tap.

Full grant mechanics (phantom-live grants after a timeout, `list_grants`
reconciliation) are in `debugging-remote-servers`.

## Phase 4 — Verify each stage

After the writes land, prove each stage with reads — don't assume the batch
succeeding means the box is correctly configured:

- User created: `id deploy`, `getent passwd deploy`.
- SSH config valid: `sshd -t` (validate) — **run this as part of the batch,
  before any reload, not after.**
- Firewall: confirming the ruleset (`ufw status verbose` / `nft list ruleset`)
  is itself a **write** (neither is a recognized read) — so make it the **final
  entry of the Phase 3 batch**, riding the same tap, rather than a free
  post-verify read here. Check SSH is still allowed *and reachable* (see
  stop-point) before trusting the rest.
- Service up: `systemctl status <unit>` and `systemctl is-enabled <unit>`.
- Listening: `ss -tlnp` — the service is actually bound to its port.
- Timezone: `timedatectl`.

If a stage failed, diagnose with reads and plan a corrective batch — don't
resubmit the whole original batch blindly.

## Stop-points — irreversible and lockout-risking steps

Some steps can lock you (and the user) out of the box or can't be undone. For
each of these, **stop, spell out the risk, and get an explicit go-ahead** before
including it in a batch — never fold them silently into a larger plan.

- **Firewall enablement — the classic lockout.** Enabling a firewall whose
  default-in is deny, without an allow-SSH rule *already in place*, cuts the
  session mid-command and there is no way back in through the gate (SSHGate
  reaches the box over that same SSH port). Order is the safeguard, and it is
  non-negotiable: **(1) add the allow rule for the SSH port (22, or the real one
  from your `ss -tlnp` read), (2) add the service-port rules, (3) verify the
  ruleset (a `ufw status`/`nft list` check — itself a write, so it's a batch
  step, not a free read), (4) only then enable.** Put them in that order in the
  batch. Call the lockout risk out to the user explicitly before the tap.
- **sshd config changes.** A bad `sshd_config` that fails to reload can lock out
  future logins. Always `sshd -t` (validate) in the batch *before* any
  `systemctl reload ssh`, and never disable password auth in the same breath as
  changing the port or the key setup without confirming key-based login works.
  Prefer a drop-in file so the base config stays intact.
- **Partitioning / filesystem creation** — `parted`, `fdisk`, `mkfs`,
  `wipefs`, `pvcreate`/`vgcreate`. These **destroy data** and are irreversible.
  **Never** put them in an automated batch on your own initiative. Read the disk
  layout (`lsblk -f` — an allowlisted read that shows FS type/UUID; `blkid` is
  NOT allowlisted, so it costs a tap), show the user exactly which device you'd act on,
  state plainly that it erases that device, and get explicit per-operation
  confirmation. Confirm you have the right device — a wrong `/dev/sdX` is
  catastrophic.
- **Any `rm -rf`, `dd`, DB drop, or mass `chown -R` on a broad path** — same
  stop-and-confirm framing. Show the exact target, confirm scope, get a yes.

When in doubt whether something is reversible, treat it as if it isn't: pause
and ask. A ten-second confirmation is cheaper than a re-provision.

## Worked example — bring up a deploy user + service on a fresh Tier-2 box

User: "Set up web-1 for the app — a `deploy` user, firewall for HTTP/HTTPS,
timezone Asia/Kolkata, and a systemd service for the app that's already at
`/srv/app`."

1. **Discover:** `sshgate.list_servers` (web-1 registered, `read_only` false).
   Reads: `cat /etc/os-release` (Ubuntu 24.04), `ss -tlnp` (sshd on 22, nothing
   else), `getent passwd deploy` (absent), `command -v ufw` (present),
   `cat /etc/ufw/ufw.conf` (`ENABLED=no` → inactive; `ufw status` itself is a
   write, so read the file), `timedatectl` (UTC), `ls -la /srv/app` (exists,
   root-owned).
2. **Plan** the full ordered write set and show it:

   ```
   Planned setup on web-1 (one approval, ordered — firewall allows SSH FIRST):
     1. id deploy >/dev/null 2>&1 || useradd -m -s /bin/bash deploy
     2. install -d -o deploy -g deploy -m 0750 /srv/app/releases
     3. chown -R deploy:deploy /srv/app
     4. timedatectl set-timezone Asia/Kolkata
     5. ufw allow 22/tcp                      # SSH FIRST — avoid lockout
     6. ufw allow 80/tcp
     7. ufw allow 443/tcp
     8. ufw --force enable                     # only after SSH is allowed
     9. cat > /etc/systemd/system/app.service <<'EOF'   # write the unit inline
          [Unit]
          After=network.target
          [Service]
          User=deploy
          ExecStart=/srv/app/bin/app
          [Install]
          WantedBy=multi-user.target
        EOF
    10. systemctl daemon-reload
    11. systemctl enable --now app.service
    12. ufw status verbose                     # firewall check rides the batch (it's a write)
   ```

   Flag the lockout risk explicitly: "Step 5 allows SSH before step 8 enables
   the firewall — that ordering is what keeps us from being locked out. Reply
   'go' to approve all in one tap." (The unit file is written inline at step 9 —
   its content reaches the box only through the command string; nothing is
   pre-staged in /tmp.)
3. **Approve once:** on "go", `sshgate.run_batch` with those 12 commands
   (`stop_on_error` default true — aborts if any step fails). One Telegram tap —
   the firewall check (step 12) rides it, since `ufw status verbose` is a write
   and can't be a free read afterward.
4. **Verify:** `sshgate.run web-1 "id deploy"`, `"systemctl status app.service"`,
   `"ss -tlnp"` (app bound), `"timedatectl"` — all reads. Firewall state was
   confirmed in-batch at step 12 (SSH still allowed). Report each back.

One discover pass → one plan → one approval → one verify pass. That's the
method: the machine is configured in a single deliberate step, not drifted into
across a dozen taps.
