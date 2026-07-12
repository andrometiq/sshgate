---
name: software-installation
description: This skill should be used when the user asks to install, upgrade, or deploy a package, service, or application on a server registered with SSHGate — phrases like "install docker on prod-db", "get nginx running on staging", "apt/dnf/yum install X on web-1", "add postgres to the app box", "upgrade node on staging", "deploy the app to prod", "set up redis", or "why did the install fail". Teaches a repeatable install METHOD — preflight reads → one batched, ordered install plan → one Telegram tap (or a scoped grant for long/repeat runs) → post-install verification reads — plus the upgrade-vs-fresh backup discipline and honest handling of long-running/failed installs.
---

# Installing software on a gated server with SSHGate

Installing is not "run the install command and hope." Left without a method,
an agent guesses a package name, fires a write, watches it half-work, fires
another, and burns taps. This skill gives you the method: **look before you
install, install as one ordered batch, verify it actually landed.** Every
step is shaped for the gate — reads run free, writes cost one human tap.

For the gate mechanics themselves — read-vs-write classification, the
cost shape, standing grants, denial/timeout handling, exit codes 77/65 —
see the **debugging-remote-servers** skill. This skill assumes those and
focuses on the install *method*. It applies to **Tier-2 (signed-write)**
servers; a **Tier-1 read-only** server refuses every install locally before
any tap (see that skill's read-only section) — surface it and stop.

## The method, in one line

**Preflight (reads) → plan the install as one ordered `run_batch` → one tap
(or a scoped grant) → verify (reads).** Never install blind; never leave an
install unverified.

## Step 1 — Preflight, entirely with reads (free, no tap)

Before proposing a single write, answer these with `sshgate.run` reads. Each
is one simple command per call — don't chain them with `&&`/`;` (that would
classify the whole thing as a write). Send them as separate calls:

- **`sshgate.list_servers`** — confirm the alias is registered and read its
  `read_only` tier. If it's Tier-1, stop here: installs are writes and will be
  refused before any tap.
- **Already installed?** — `which <bin>` / `command -v <bin>` (both READs). Note
  `<bin> --version` is only classified a read for the common interpreters
  (python/node/perl/ruby); for anything else the fail-closed gate calls it a
  WRITE. Get the version from a read where you can, or put the `--version` check
  **inside the install batch** (first or last entry — covered by the same tap).
  If it's already at the wanted version, say so and stop — don't reinstall for
  no reason.
- **What distro / package manager?** — `cat /etc/os-release`. This decides
  `apt` (Debian/Ubuntu) vs `dnf`/`yum` (RHEL/Fedora) vs `apk` (Alpine) vs
  `pacman`. Never assume.
- **Service manager?** — `systemctl --version` (almost always systemd). Tells
  you the enable/start verbs for step 3.
- **Disk headroom?** — `df -h /` and `df -h /var`. A package cache or a big
  container image needs room; a full disk is the most common silent failure.
- **Conflicts?** — is an older/rival package present, is the target port
  already in use (`ss -tlnp | grep :<port>`), is a previous half-install
  lying around? Read `systemctl status <unit>` if a unit name is likely.

**Source decision — prefer the honest, boring path.** Pick the install source
in this order and say which you chose and why:

1. **Distro package manager** (`apt install nginx`) — first choice. Signed by
   the distro, auto-patched, clean removal. Use it unless the user needs a
   version the distro doesn't carry.
2. **Vendor repo** (add Docker's / PostgreSQL's official apt/dnf repo, then
   install) — when you need current upstream versions. Costs an extra
   add-repo + add-key write in the batch.
3. **Binary release / tarball / install script** — last resort, when there's
   no package at all. State that it won't auto-update and where it lands.

Don't reach for a curl-pipe-to-shell installer when a package exists. If the
user insists on `curl … | sh`, treat it like any destructive unknown: show
them the exact command and get an explicit go-ahead before batching it.

## Step 2 — Plan the whole install as ONE ordered batch

Assemble every write the install needs into a single, correctly-ordered
`run_batch`. One tap approves the lot. Typical order:

1. **Add repo + signing key** (only for the vendor-repo path).
2. **Refresh the package index** — `apt update` / `dnf makecache`. Note: this
   is a **write** (it mutates the package cache), so it belongs in the batch,
   not as a "free" preflight read.
3. **Install** — `apt install -y <pkg>` / `dnf install -y <pkg>`. Always the
   non-interactive flag (`-y`) so it doesn't hang waiting on a prompt the
   human can't answer — you're not attached to a live terminal.
4. **Configure** — drop config files, set values. Prefer writing a staged file
   with `tee` (a write) over in-place `sed -i` surgery; it's auditable and
   reversible.
5. **Enable + start the service** — `systemctl enable <unit>` then
   `systemctl start <unit>` (or `enable --now`).
6. **Open the firewall** *only if needed* — `ufw allow <port>` /
   `firewall-cmd --add-service=<svc> --permanent` + reload. Don't punch holes
   you didn't confirm are wanted.

**Show the user the exact batch before you send it** — a fenced block, the
real commands, in order — exactly as the debugging skill's fix pattern shows.
Then call `sshgate.run_batch`. Leave `stop_on_error` at its default (a batch
with writes stops on the first failure) so a failed `apt update` doesn't march
on into a broken `install`.

```
Planned install on staging — Docker via the official apt repo
(one Telegram approval covers all 8):

  1. install -m 0755 -d /etc/apt/keyrings
  2. curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
       -o /etc/apt/keyrings/docker.asc          # -o writes the file (a write)
  3. chmod a+r /etc/apt/keyrings/docker.asc
  4. cat > /etc/apt/sources.list.d/docker.list <<'EOF'
       deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.asc] \
         https://download.docker.com/linux/ubuntu <codename> stable
       EOF
  5. apt update
  6. apt install -y docker-ce docker-ce-cli containerd.io
  7. systemctl enable --now docker
  8. docker --version                            # batched verify (rides same tap)

Approving on your phone runs them in order, stopping if any step fails.
Reply "go" or tell me to adjust. The key and repo-list content reaches the box
only through these commands — nothing is pre-staged in /tmp.
```

## Step 3 — Verify with reads (free) — never declare success blind

An approved batch is not a landed install. Confirm with reads:

- **Version** — `<bin> --version` shows the expected version, but note it's a
  free read only for the common interpreters (python/node/perl/ruby); for any
  other binary the gate classifies `--version` a **write**, so fold that check
  into the install batch (last entry) rather than running it standalone here.
- **Service active** — `systemctl is-active <unit>` / `systemctl status <unit>`.
- **Port listening** — `ss -tlnp | grep :<port>`.
- **Logs clean** — `journalctl -u <unit> -n 40 --no-pager` — no crash loop.
- **Health endpoint** (if the app has one) — `curl -s http://localhost:<port>/health`.
  A plain GET `curl` is a read; a `-X POST` is a write.

Report what each check showed. If a check fails, go to failure handling below —
don't paper over it.

## Upgrades vs fresh installs — back up BEFORE the tap

A fresh install has nothing to lose; an **upgrade can break a running
service**. When upgrading:

- **Back up first, inside the same batch, before the upgrade step** — copy the
  config and, for a datastore, note where the data lives:
  `cp -a /etc/<svc> /etc/<svc>.bak-$(date +%F)` (the `$(...)` makes it a write —
  fine, it's in the batch). For a database, snapshot/dump before the upgrade.
- **State the rollback path out loud** before requesting approval: "if this
  breaks, we downgrade with `apt install <pkg>=<oldver>` and restore
  `/etc/<svc>.bak`." An upgrade the user can't undo is an upgrade you shouldn't
  fire.
- **Preserve config** — package upgrades that prompt about conffiles will
  stall non-interactively; prefer the manager's keep-old / keep-new flag
  explicitly rather than letting it hang.

## Long-running installs & big downloads — grant, then poll

Large installs (a full `apt dist-upgrade`, a multi-hundred-MB image pull, a
`docker pull`, a source build, a `dnf group install`) run longer than one
turn and can outlive a dropped SSH pipe. Never use `nohup`/`sh -c` wrapping to
**dodge classification or slip past a tap** — but the detached-launch pattern
below is the sanctioned route for a genuinely long job, and its launch is still
a write (one tap, or the grant in step 1). The honest current pattern:

1. **Request a scoped standing grant** so the launch **auto-signs** without a
   live tap — the human isn't watching:
   `sshgate.request_grant(alias, scope="commands", commands=[…], duration_hours=<small>, reason="unattended install")`.
   Grant matching is **exact-string, no patterns**: `commands` must contain
   verbatim, character-for-character, the **exact string you will pass to
   `sshgate.run`** — i.e. the full wrapped launch line
   `nohup apt install -y <pkg> >~/install.log 2>&1 & echo $!`, not the bare
   `apt install` command. Decide that launch string first, then request the
   grant for it — otherwise the wrapped line isn't in the list, so it prompts
   anyway (or times out unattended, the exact case the grant was meant to cover).
   This needs its own distinct human "STANDING GRANT" tap up front — you can
   never self-grant. Prefer `scope="commands"` (exact strings only) over
   `scope="all"`; reserve `all` for a throwaway box.
2. **Launch detached and poll with reads** exactly as the debugging skill's
   long-running-tasks section describes — `nohup … >~/install.log 2>&1 &`,
   then `tail -n 40 ~/install.log` / `ps -p <pid>` on a loop. Under the grant
   the launch write auto-signs; the polls are reads and always free.
3. **Revoke the grant** (`sshgate.revoke_grant(alias)`) the moment the install
   is done and verified. Pure de-escalation, always safe.

A synchronous blocking `run` on a 20-minute install holds your whole turn and
dies if the pipe drops (the remote job gets SIGHUP). Detached + poll survives.

## Failure handling — read the logs, don't loop the write

When an install step fails, **do not resubmit the same failing write** — that
just re-prompts the human for a guaranteed-identical failure. Instead:

1. **Read the error** — the batch surfaces the failing step's stderr. `apt`
   and `dnf` say why (missing dep, held package, no candidate, 404 on a repo,
   disk full, dpkg lock held).
2. **Diagnose with reads** — `df -h` (out of space?),
   `journalctl -xe --no-pager | tail`, `cat /var/log/dpkg.log | tail`,
   `cat /etc/apt/sources.list.d/<repo>.list` (all reads). Note `apt-cache policy
   <pkg>` (does the version even exist?) and `dpkg -l` are **not** recognized
   reads — each costs one tap; acceptable during failure triage, but reach for
   the plain-file reads first. A held dpkg/apt lock means another package process
   is running — `ps aux | grep -E 'apt|dpkg'` (a read) and wait, don't force it.
3. **Fix the cause, then re-plan** — a corrected batch (right package name,
   added missing repo, freed disk), shown to the user, one new tap. One
   diagnosed retry, not a retry loop.

**Destructive steps always get a stop-and-confirm.** If an install path wants
to `rm -rf` an existing install dir, drop a database, repartition, `dd`, or
`mkfs` — stop, spell out exactly what will be destroyed and whether it's
recoverable, and get an explicit "yes, do it" before it goes in a batch. Never
fold a destructive step silently into an install batch.

## Worked example — install and verify PostgreSQL on `app-db`

1. Preflight reads: `sshgate.list_servers` (confirm `app-db`, Tier-2) →
   `command -v psql` (not installed — `psql --version` would be a write, so use
   `command -v` here) → `cat /etc/os-release` (Ubuntu 22.04, `apt`) →
   `df -h /var` (plenty of room) → `ss -tlnp | grep :5432` (port free).
2. Source decision: distro `postgresql` is 14; user wants 16 → use the
   **official PGDG apt repo** (vendor-repo path). Say so.
3. Show the batch: fetch the PGDG key (`curl -o`) + write the repo list inline
   (`cat > … <<'EOF'`), `apt update`, `apt install -y postgresql-16`,
   `systemctl enable --now postgresql`, and `psql --version` as the final entry
   (the version check is a write for `psql`, so it rides the batch). Wait for "go".
4. `sshgate.run_batch` → one tap covers all of it, including the version check.
5. Verify with reads: `systemctl is-active postgresql` (active),
   `ss -tlnp | grep :5432` (listening), `journalctl -u postgresql -n 20
   --no-pager` (clean). The version (16.x) was confirmed in-batch at the last step.
6. Report: installed 16.x, service up, listening on 5432, logs clean.

That's the whole method: look, plan as one batch, verify. One read pass →
one approval → one verify pass.
