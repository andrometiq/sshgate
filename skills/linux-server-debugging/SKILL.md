---
name: linux-server-debugging
description: This skill should be used when something is WRONG on a registered Linux server and you need a method to find the cause, not a command dump — phrases like "why is X slow", "the server is down / not responding", "diagnose high load on staging", "prod-db is throwing 500s", "the box is out of disk", "why did the app get OOM-killed", "the service won't start", "figure out what's wrong with web-1", or "narrow down what's happening". Teaches a systematic triage METHOD — classify the symptom, run the cheapest discriminating read first, state a hypothesis and pick the ONE read that confirms or kills it, stop when confirmed, then propose the fix as a batched approval. Complements debugging-remote-servers (which owns the gate mechanics); this owns HOW TO THINK through a diagnosis.
---

# Linux server debugging — a triage method

The failure mode this skill exists to kill: an agent driving the gate
**keeps reading with no method** — fires off `df`, `top`, `free`, twenty
`journalctl` calls, and wanders until it stumbles on the cause or gives up.
Reads are free, so nothing stops the wandering. What's missing is a *method*.

This skill is the method. It's a decision tree, not a command list. For the
**gate mechanics** it leans on — read-vs-write classification, one-tap batch
approval, standing grants, denial/timeout handling, Tier-1 read-only servers,
long-job launching, the read jail and the output cap — see the
**`debugging-remote-servers`** skill. This skill
does not re-teach those; it tells you *what to run, in what order, and when to
stop*.

## The five rules of the method

1. **Classify the symptom first.** Every "something is wrong" collapses into
   one of five classes (below). The class picks your first read. Don't run
   anything until you've named the class.
2. **Cheapest discriminating read first.** Order reads by how much they narrow
   the space per call, not by habit. One `uptime` (load averages) often
   discriminates "slow" better than a full `top`. Fire the read that splits the
   hypothesis space most.
3. **Hypothesis → the ONE read that decides it.** Before every read, say (to
   yourself, and to the user when it matters): *"I think it's X; this read
   confirms or kills X."* If a read can't change your mind, don't run it.
4. **Stop when confirmed.** The moment a read confirms the cause, STOP reading.
   Don't gather three more confirmations. Move to the fix. Over-reading is the
   exact failure this skill exists to prevent.
5. **Bounded reads, always.** Never `cat` a whole log or `journalctl` with no
   limit. Every log read is bounded (`-n`, `--since`, `| tail`, `| grep`) so
   you get signal, not a wall. A single unbounded read can bury the finding
   (and output past 256 KiB is cut off). Never use a follow mode (`-f`,
   `watch`): the call never returns.

## Step 0 — orient (two reads, always the same)

Before classifying, know the box is reachable and which box it is:

- `sshgate.list_servers` — confirm the alias is registered and note its tier
  (`read_only`). If it's not registered, stop and point the user at the
  human-only `sshgate` CLI (see `debugging-remote-servers`).
- `sshgate.ping <alias>` — is it up *right now*? READ-class, no tap. If the
  symptom is "server is down" and ping fails, you've already learned the box or
  its SSH path is unreachable — that's a network/host-level problem, not an
  in-box one, and no amount of `run` will reach it (say so; escalate to the
  human).

## The five symptom classes → first read

| Class | Symptom the user reports | Cheapest discriminating first read |
|---|---|---|
| **DOWN** | "not responding", "can't reach it", a service is dead | `sshgate.ping <alias>`, then `systemctl status <unit>` / `systemctl list-units --state=failed` |
| **SLOW** | "sluggish", "requests hang", "high latency" | `uptime` (load vs core count) |
| **ERRORING** | "throwing 500s", "app crashes", "logs full of errors" | `journalctl -u <unit> -n 50 --no-pager` (or the app's own log, bounded) |
| **DISK** | "out of space", "can't write", "disk full" | `df -h` |
| **MEMORY** | "OOM", "killed", "swapping", "eating RAM" | `free -h` |

Pick the row. Run its first read. Then follow the hypothesis chain for that
class below. **Resist running the other four classes' reads** unless the first
read points you there — that's the wandering.

## Per-class hypothesis chains

Each chain is: first read → what each outcome means → the ONE next read that
decides. Stop the instant you've named the cause.

### SLOW
1. `uptime` → load averages. Compare to core count (`nproc`).
   - **Load ≫ cores** → CPU or run-queue saturation. Next: `top -bn1 | head -20`
     — is one process pinning CPU, or is the run queue deep from I/O wait?
   - **Load ≈ cores, still slow** → likely I/O or memory. Jump to `free -h`
     (swapping?) then `top` `%wa` (I/O wait). High `wa` → disk-bound; check
     `df -h` for a full/failing FS.
   - **Load low but "slow"** → it's not the box; it's the app or the network.
     Read the service log (ERRORING chain) or check `ss -tnp state established`
     for connection pileups. Don't keep hunting box metrics — you've *ruled the
     box out*, which is a real conclusion.

### ERRORING
1. `journalctl -u <unit> -n 50 --no-pager` (bounded). Read the newest errors.
   - Repeating stack trace / clear error string → you likely have the cause.
     One targeted `grep` confirms: `journalctl -u <unit> --since "-15min" | grep -i <error-token>`.
   - "failed to bind / address in use" → port conflict. Next: `ss -tlnp` — who
     holds the port.
   - "permission denied / no such file" → config or filesystem. Next:
     `ls -la <path>` / `stat <path>` on the exact path from the log.
   - Nothing in the unit log → widen ONCE: `journalctl -n 80 --no-pager` (all
     units, bounded) or the app's own logfile via `tail -n 80 <path>`. If still
     nothing, that's a signal the service isn't even starting — jump to DOWN.

### DOWN
1. `systemctl status <unit>` (or `systemctl list-units --state=failed` if you
   don't know the unit; `systemctl --failed` classifies as a write).
   - `active (running)` but user says down → it's up but not *serving*; treat as
     ERRORING (read its log) or SLOW (network/bind). Don't declare it down.
   - `failed` / `inactive` → read *why*: `journalctl -u <unit> -n 40 --no-pager`.
     The last lines before exit are the cause. Common: config parse error, a
     dependency (DB) down, a full disk (`df -h`), or OOM (MEMORY chain).
   - Unit won't be found → wrong unit name. List the unit files and search
     them: `ls /etc/systemd/system /usr/lib/systemd/system | grep -i <name>`.
     (Don't pipe `systemctl` itself: on a jailed host only its plain form can
     reach systemd.)

### DISK
1. `df -h` → which filesystem is full (watch `/`, `/var`, `/tmp`).
   - One FS at 100% → find the weight, bounded and targeted, don't `du /`:
     `du -xh --max-depth=1 <that-mountpoint> 2>/dev/null | sort -rh | head -15`.
     Recurse one level at a time into the biggest child — this is a *binary
     search on disk*, not a full-tree scan.
   - Inodes, not bytes (`df -h` fine but writes fail) → `df -i` to confirm inode
     exhaustion, then hunt the directory with millions of small files the same
     `du`/`ls | wc -l` way.
   - Usual culprits: unrotated logs in `/var/log`, a runaway journal
     (`journalctl --disk-usage`), old package caches, a fat `/tmp`.

### MEMORY
1. `free -h` → is RAM exhausted, is swap in use?
   - Something got OOM-killed → confirm:
     `journalctl -k --since "-1h" --no-pager | grep -i "killed process"`. That
     names the victim PID and process. (`dmesg -T | grep -i "killed process"`
     shows the same, but `dmesg` can fail with "Operation not permitted" inside
     the read jail.)
   - RAM high, nothing killed yet → who's holding it:
     `ps -eo pid,rss,comm --sort=-rss | head -10`.
   - Swapping hard (high `si/so`) → same `ps` by RSS; the fix is usually
     restarting or capping the memory hog, or adding a memory limit.

## When to widen vs when to conclude

- **Widen** only when the current read *contradicts* your hypothesis or comes
  back empty — and widen by exactly one step (one more unit, one directory
  level, one broader `journalctl`). Never widen by re-running all five classes.
- **Conclude** as soon as a read confirms a cause — *including the conclusion
  "it's not the box."* Ruling the server out (load low, disk fine, memory fine,
  service healthy → it's the app logic or an upstream/network dependency) is a
  legitimate, valuable finding. State it and stop; don't keep drilling for a
  box-level cause that isn't there.
- If **four+ reads haven't narrowed anything**, stop and say so plainly:
  "reads aren't converging — here's what I've ruled out (X, Y, Z), here's what
  I'd need (app logs / a reproduction / the human's context)." That's better
  than a tenth aimless read.

## Log-reading strategy (bounded, never cat-everything)

- Default log read: `journalctl -u <unit> -n 50 --no-pager`. Add `--since "-30min"`
  to time-box a live incident. These are single simple reads — no tap.
- Grep at the source, one pipe, read-tools only:
  `journalctl -u <unit> --since "-1h" | grep -i error` (a simple pipe between
  read tools stays a READ — see `debugging-remote-servers` for why).
- App logfiles: `tail -n 80 /var/log/<app>/<file>.log`, or
  `tail -n 200 <file> | grep -i <token>`. Never `cat` a multi-MB log.
- Prefer **separate `sshgate.run` calls**, one simple command each. A chain of
  reads (`df -h && free -h`) is still a read, but one unrecognised segment
  makes the whole chain a write, and `sh -c` is always a write. One read per
  call keeps every read free and its output easy to attribute.
- If a read is refused as a write, **simplify it** (drop the redirect/compound/
  uncommon tool) — don't retry the same thing. Note `journalctl --rotate` /
  `--vacuum-*` are genuine writes (they mutate the journal); a plain bounded
  read is not.

## Resource checks — each is ONE read

`df -h`, `df -i`, `free -h`, `uptime`, `nproc`, `top -bn1 | head -20`,
`ps -eo pid,rss,comm --sort=-rss | head`, `ss -tlnp`,
`ss -tnp state established | head`, `journalctl -k -n 20 --no-pager`. All
reads, all free, all single simple commands. Fire them per the chain — not all
at once as a reflex.

## When a FIX becomes appropriate

You've confirmed a cause. Only now do you touch a write. The method for the fix:

1. **Confirm the tier.** Writes to a **Tier-1 read-only** server are refused
   locally before any tap (you saw `read_only:true` in step 0) — so on a Tier-1
   box, stop at the diagnosis: report the cause and the fix you *would* run, and
   let the human apply it. Don't attempt the write.
2. **Propose the write set.** Show the user the exact commands you'll run, in
   order, in a fenced block — no surprises. Include a backup/validate step where
   the change is reversible-sensitive (config edits: copy the file first, then
   validate with the service's own checker like `nginx -t` before reloading).
3. **Batch them.** Put every write of the one logical fix into
   `sshgate.run_batch` so the whole fix is **one Telegram tap**, not N taps —
   the human may be reached via the approval channel but is **not watching
   live**, so respect their attention. (Mechanics: see `debugging-remote-servers`
   §Fixes and §Cost shape.)
4. **Request the tap explicitly.** Tell the user what the batch does and that
   approving the prompt on their phone runs it in order. Wait for their "go".
5. **Repetitive write session?** If the fix is really a long series of writes
   the human can't tap one-by-one (a migration, an overnight cleanup),
   `sshgate.request_grant` for a *narrow* `scope=commands` window instead — but
   that itself needs a distinct human **STANDING GRANT tap**, so surface the
   exact command set first. Drop it with `revoke_grant` the moment you're done.
6. **Verify.** After the batch runs, re-run the ONE read that proves the cause
   is gone (`df -h` shows space back, `systemctl status` shows active, the error
   is absent from a fresh bounded log read). Diagnosis → propose → one approval
   → verify. Done.

## Destructive operations — stop and confirm, every time

Some fixes are irreversible. `rm` / `rm -rf`, `dd`, `mkfs`, `fdisk`/`parted`
partition ops, `truncate`, a DB `DROP`/`DELETE`, `docker volume rm`, force-
wiping a directory. For any of these:

- **Never** fold a destructive command silently into a batch. Call it out
  explicitly: "step 3 is destructive — it permanently deletes X".
- Prefer the reversible route first: rotate/compress a log instead of `rm`-ing
  it; move to a `.bak` instead of overwriting; `systemctl stop` before deleting
  a service's data. Show the reversible option as the default.
- If deletion is genuinely the fix (a full disk from a 40 GB stale logfile),
  show the *exact* target and its size from your diagnosis, get an explicit
  "yes, delete it" from the user, and let the human tap the approval — that tap
  IS the second confirmation. Two humans-in-the-loop for anything unrecoverable.
- **Never** try to route around the gate to run a destructive command — no
  `sh -c` wrapping to dodge classification, no asking the user to disable the
  gate, no raw `ssh`. The tap is the safety rail; keep it.

## Worked example — SLOW, traced end to end

User: "prod-db has gone really sluggish in the last hour, figure out why."

1. **Orient.** `sshgate.list_servers` → `prod-db` registered, no `read_only`
   flag (Tier-2, signed-write). `sshgate.ping prod-db` → reachable, 40 ms.
   It's up; this is an in-box problem. **Class: SLOW.**
2. **Cheapest discriminating read.** `sshgate.run prod-db "uptime"` →
   `load average: 9.80, 8.40, 5.10`. `sshgate.run prod-db "nproc"` → `4`.
   *Hypothesis: load ≫ 4 cores → saturation. Is it CPU or I/O wait?*
3. **The ONE read that decides.** `sshgate.run prod-db "top -bn1 | head -20"` →
   `%wa` is 61%, no single process pinning CPU. *Hypothesis flips: not CPU —
   this is I/O-bound.* Likely disk pressure or swapping.
4. **Discriminate I/O cause.** `sshgate.run prod-db "free -h"` → swap barely
   touched. Not memory. `sshgate.run prod-db "df -h"` → `/var` at **100%**.
   *Cause candidate: the DB partition is full and thrashing on writes.* **Stop —
   this is the cause.** (Four reads, each one narrowed the space.)
5. **Find the weight, bounded.**
   `sshgate.run prod-db "du -xh --max-depth=1 /var 2>/dev/null | sort -rh | head -10"`
   → `/var/log/postgresql` is 38 G — a stale debug log left on.
6. **Propose the fix (writes shown first).** Not a blind `rm` — rotate safely:
   ```
   Planned writes on prod-db (one Telegram approval, 3 commands):
     1. truncate -s 0 /var/log/postgresql/debug.log   # reclaim 38 G in place, keeps the file
     2. systemctl reload postgresql        # reopen its log handle after the truncate
     3. df -h /var                          # verify space is back
   ```
   "Step 1 empties a 38 G log file in place (not a delete of the file itself).
   Approve the prompt on your phone to run these in order — reply 'go'."
7. **Run + verify.** On "go" → `sshgate.run_batch` (one tap). Then
   `sshgate.run prod-db "uptime"` → load falling back toward 4;
   `df -h /var` → 22% used. Cause fixed, verified, done.

That's the method: name the class → cheapest discriminating read → hypothesis →
the one read that decides → **stop on confirmation** → propose → one tap →
verify. No wandering.
