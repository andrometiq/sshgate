# SSHGate — threat model (read this first)

Short and honest, no marketing. It states what SSHGate actually enforces, what it
only routes, and what it does **not** stop. Each claim points at the reference doc
or the code it comes from, so nothing here overstates. For the full reasoning see
[`design.md`](design.md),
[`approval-architecture.md`](approval-architecture.md),
[`FUTURE.md`](FUTURE.md), and
[`security-readonly-bypass.md`](security-readonly-bypass.md).

## The boundary — what actually enforces

**The security boundary is the signature plus the OpenSSH forced command, checked
on each remote server. The read/write classifier only *routes*; it is not the
wall.**

- SSHGate's dedicated key is pinned on every remote to a forced command
  (`restrict,command="~/.sshgate-gate/gate"`, plus `no-pty,no-port-forwarding,no-X11-forwarding,
  no-agent-forwarding`; `restrict` also denies `~/.ssh/rc` execution and any future OpenSSH
  capability). **OpenSSH enforces this server-side**: that key can only
  ever invoke the gate — never a shell or an arbitrary program.
  (`design.md` §"Forced command and key pinning".)
- A **write** runs only if it carries a valid Ed25519 signature the gate verifies
  against the signing pubkey deployed on that host. No pubkey on the host
  (read-only / Tier 1) ⇒ no write can be signed ⇒ the gate refuses it
  locally, before any approval channel is even consulted.
- The signature carries a **bounded validity window** (at most 5 minutes) and a
  **per-host binding** (the target's TOFU-pinned host-key fingerprint), so an
  approved write cannot be replayed indefinitely or against a different host. It
  *can* be replayed on the same host inside its window: the gate keeps no nonce
  ledger (`TESTING.md` §4.4).

That chain — forced command + signature verification + host binding — is what a
skeptical reader should evaluate. It holds independently on each remote and does
not depend on the agent, the laptop, or Telegram behaving.

## What is enforced, and where

| Control | Enforced by | Where it runs |
|---|---|---|
| Key can only invoke the gate (no shell) | OpenSSH forced command | remote server |
| Write requires a valid signature | gate signature check | remote server |
| Read-only host refuses all writes | gate (no pubkey present) | remote server |
| Per-host binding + bounded TTL on a signed write | gate ⇄ signer | remote + signer |
| A read cannot change host files, reach local daemons over Unix sockets, or touch other processes | kernel read jail (namespaces, read-only mounts, Landlock, seccomp) | remote server, **only on hosts that support it** (see below) |
| Inline secret redaction of command output | gate redactor | remote server |
| Human approval of a write | signer (Telegram tap / hosted signer) | operator machine or hosted host |
| Read-vs-write **routing** | shared classifier (fail-closed) | MCP + gate |

The last row is **routing**, not enforcement: the classifier decides whether
a command needs a signature. If it wrongly calls a write a "read", that command
runs without approval. On a host with the read jail, the jail then limits what
that misjudged command can do; on a host without it, nothing does. That is why
the classifier and the jail are both discussed honestly below.

## What the classifier is, and is not

- **Is:** a **fail-closed heuristic** over `/bin/sh` syntax and each allowlisted
  tool's write/exec-capable flags. Anything not affirmatively a known-safe read —
  unknown binaries, pipes into non-reads, redirects, `;`/`&&`/`||`, command
  substitution, `sudo` — collapses to *write* and is routed to approval.
  (`design.md` §"Read/write classification".)
- **Is not:** a proof. Reads are still handed to `/bin/sh` (inside the jail where
  there is one), so an obscure tool flag or a shell-parse mismatch can in principle
  let a command the classifier deemed "read" try to do more than read. The
  default-deny structure holds (unknown ⇒ write), but per-tool flag enumeration
  cannot be proven complete against every tool on every server. The structural
  answer SSHGate chose is the kernel read jail below: it does not make the
  classifier right, it limits what a wrong verdict can do.
  (`design.md` §"Read/write classification", `security-readonly-bypass.md`.)

## Tiers — what each one buys

- **Tier 1 — read-only.** The gate is deployed but no signing pubkey is
  pushed, so **writes are denied at the gate** — a real, server-side wall (a
  write literally cannot be signed). On the read side it is a *safety rail*: it
  still trusts the agent not to abuse read access (file enumeration, log
  harvesting, network use), and reads run without approval via the fail-closed
  classifier, inside the read jail where the host supports one. The fastest,
  lowest-trust on-ramp — not a full security posture.
- **Tier 2 — local Telegram signer.** The
  master key is isolated under a separate Unix user; writes need one phone tap.
  This is **a safety rail, not a hard wall**: it reliably catches mistakes and
  naïve prompt-injection and stops an *unprivileged* rogue agent, but an agent
  that can escalate privileges on the operator's machine (e.g. has `sudo`) can
  read the signing key directly and forge approvals. This caveat is load-bearing
  and surfaced to the operator, not buried. (`design.md` §"Install tiers",
  `approval-architecture.md`.)
- **Tier 3 — hosted signer boundary.** When the signer runs on a separate
  machine the agent cannot touch, the agent can only *ask* it to sign — it
  cannot read the key or forge an approval. **This is the only tier designed to
  be a hard boundary against a privileged rogue laptop agent.** The repository
  contains the hosted backend, embedded TOTP/WebAuthn UI, SQLite approval
  foundation, and systemd deployment, but its policy-authority work and release
  gates are still open ([ROADMAP.md](ROADMAP.md)), so treat it as a foundation,
  not a finished boundary. TLS/DNS, backups, and secret distribution remain
  operator responsibilities. (`design.md` §"Install tiers",
  `src/signer-server/README.md`.)

## The kernel read jail (phase 1, profile `ro-v1`)

Code: `src/gate/confine/` (the jail) and `src/gate/cmd/sshgate-gate/rung.go`
(which hosts use it). The remaining phases are work item 1 of
[BUILD-PLAN.md](BUILD-PLAN.md).

### Which hosts get it

A host gets the jail only if it has **both**:

- unprivileged **user namespaces** that are allowed to mount (stock Ubuntu 24.04
  blocks this through an AppArmor restriction until root lifts it, and some
  container-based VPSes and older distributions do not offer it), **and**
- **Landlock** (kernel ABI 1 or newer).

There is no partial jail: a host with only one of the two gets none. The rest of
the profile (seccomp, `mount_setattr`, a `/dev/shm` directory) is checked when the
jail is built for each read.

Run `~/.sshgate-gate/gate doctor` on the host (from a normal shell, not through
SSHGate) to see which case applies. On every read the gate does one of three
things:

| Host state | What happens to a read |
|---|---|
| Jail available | Runs inside the jail. |
| Jail not available, no floor pinned | Runs **unconfined**, exactly as before the jail: the classifier is the only control. The gate's audit log labels it `unconfined`. |
| Jail not available, floor pinned | **Denied** with exit 77 and `read jail unavailable` on stderr. Nothing runs. |

The floor is a file named `jail-floor` in the gate directory holding `full`.
`gate doctor --pin` writes it, and only on a host where the jail works. A damaged
floor file (unreadable, group- or world-writable, or holding anything else) also
denies reads. Two more cases always deny with exit 77 and never fall back to
running the read unconfined: the host probe failing for an unexplained reason,
and the jail failing to build or failing one of its own checks for this read.

A small fixed list of `systemctl` and `docker` read verbs (for example
`systemctl status`, `docker ps`, `docker logs`) **always runs outside the jail**,
on every host, because those reads need the daemon's Unix socket. They run
without a shell, from a fixed binary path, with only allowlisted flags and a
fixed minimal environment that also stops `docker` from reading the SSH user's
own `~/.docker` config (`src/gate/cmd/sshgate-gate/lane2.go`). Remember that
`docker.sock` is root-equivalent: these verbs are trusted to be read-only by
their own design, not by the kernel.

Signed writes and the admin verbs (`SSHGATE_REVOKE`, `SSHGATE_UPDATE`,
`SSHGATE_XFER_*`) run exactly as before, unconfined; a jail problem never
blocks them. Signed reads (for example an approved secret-reveal) are jailed
like any other read.

### What a jailed read cannot do

Inside the jail the command gets its own user, mount and IPC namespaces (it stays
in the host's PID namespace, so `ps` and `top` still show host processes), a
read-only view of the host filesystem, Landlock, and a seccomp filter that rules
on every syscall. The jail checks the state it built before the command starts
and refuses the read if any check fails. With that, a jailed read **cannot**:

- write, create, delete or rename a file, or change file metadata (mode, owner,
  timestamps, extended attributes) anywhere on the host, including writing into
  or resizing an existing named pipe (FIFO);
- connect to a local daemon over a Unix socket, or reach the host's System V or
  POSIX IPC objects or kernel keyrings;
- signal, trace or re-tune (priority, CPU affinity) a process outside the jail,
  or read its memory, file descriptors or environment;
- change mounts, namespaces or sysctls, or use any capability in the host's
  user namespace.

### What a jailed read can still do

- **Use the network.** Jailed reads keep TCP and UDP access, including to
  `localhost`, exactly as they had before the jail. A read can send data out,
  or talk to a local TCP service (a database, an admin HTTP endpoint) and make
  that service change state. Making network a per-server permission, off by
  default, is the next scheduled step ([BUILD-PLAN.md](BUILD-PLAN.md) P2.1).
- **Read anything the SSH user can read.** That includes the host's `/tmp` and
  `/var/tmp`, which stay visible **read-only** (they are not emptied), other
  users' world-readable files, and process command lines. Redaction is the only
  thing between those bytes and the agent.
- **Write to its own scratch space.** The only writable places are a private
  64 MiB tmpfs at `/dev/shm` (`TMPDIR`, `TMP`, `HISTFILE` and the `XDG_*`
  directories point there), thrown away when the read ends, and `/dev/null`.
  A tool that insists on writing to `/tmp` fails.

Small visible differences: files owned by users the jail does not map may list as
`nobody`/`65534` (access is unchanged), and tools that need privileges the jail
removes (`sudo`, `dmesg` on a restricted host, `iptables -L`) do not work.

### Residual risks in phase 1 (accepted, stated plainly)

These are known gaps of the shipped jail. Some close in later phases of work
item 1; others are outside what a read jail can promise.

- **Hosts without the jail run reads unconfined.** Every classifier bypass in
  [`security-readonly-bypass.md`](security-readonly-bypass.md) is live there. Pin
  `jail-floor` if you would rather refuse reads than run them unconfined.
- **Network is open** (see above). Anything reachable over TCP/UDP from the host
  is reachable from a read, including local services that act on requests.
- **A mount the jail cannot hide stays visible.** The jail hides, with an empty
  read-only cover, every mount whose filesystem type is not on a reviewed
  read-safe list (FUSE, network filesystems such as NFS or SMB, `overlay`,
  unknown types) or that sits on a loop, network or other indirect block device.
  When it cannot place a cover — for example the root filesystem itself is
  `overlay` (containers) or ZFS, or the mount sits below a directory the SSH user
  cannot enter and the jail cannot cover a parent — phase 1 still runs the read
  and the mount stays visible. It is still read-only, but the program or remote
  server behind it (a FUSE daemon, an NFS server) sees the read and may act on
  some requests that the read-only flags do not stop. Phase 1 does not record this
  gap in the audit log.
- **Something outside the read can expose a hidden mount while it runs.** The
  covers are placed when the read starts. If another process — another user,
  root, an approved write, or the same account used outside SSHGate — renames a
  directory out from under a cover while the read runs, the mount below it
  becomes reachable from the read. The agent's own unsigned reads cannot do this
  (they are jailed read-only).
- **Reading a named pipe consumes its data.** A jailed read cannot write into an
  existing host FIFO, but it can open one it is allowed to read and drain the data
  another process wrote into it. That read is destructive: the intended reader
  never gets those bytes. There is no way to allow reading a FIFO without this.
- **Locks.** A read can take shared file locks (`flock` shared, `fcntl` read
  locks) on files it can read. They block a writer that wants an exclusive lock
  for as long as the read runs, and reads have no gate-side time limit.
- **Crashes, core dumps and kernel logs.** A crashing read can write lines to the
  kernel log and journal. Core files are never written (the filesystem is
  read-only). A pipe `core_pattern` handler (systemd-coredump, apport) is skipped
  only when the read inherits a hard core limit of at least 1, which the jail
  then lowers to 1; if the gate inherits a hard limit of 0, the kernel still runs
  the pipe handler and it receives the read's memory dump outside the jail. On
  kernel 6.17 or newer, a `core_pattern` that sends cores to a socket handler
  also receives the dump.
- **Process lifecycle.** Cleanup of a read's child processes is best effort with a
  five-second deadline. If the gate is killed, a read forks faster than cleanup
  can follow, or cleanup fails, jailed descendants can keep running. They stay
  confined, but nothing bounds them: reads have no execution deadline, and a root
  SSH user is not held by the process-count limit.
- **Output and audit stalls.** The gate writes its audit record synchronously.
  If the audit log's filesystem stalls (a hung NFS mount, a failing disk), the
  gate can hang after the command has finished. If the gate's own output goes to
  a regular file on a stalled filesystem, the gate can hang after a cancellation.
- **Shared machine resources.** CPU, memory, page cache and similar quotas are
  shared with the host. A read can slow the host, or evict a file's cached pages
  (a performance effect, no data change). CPU-time timers can affect other
  processes' timer accounting.
- **Side effects of reading.** Some reads are not inert: filesystem watchers
  (inotify/fanotify) see them; some driver-specific `/proc` and `/sys` entries
  change when read; filesystems can do housekeeping on access (for example ext4
  noting the last mount point, XFS releasing preallocated space, btrfs repairing
  a damaged copy, or reacting to on-disk corruption the read runs into).
- **Kernel boundaries.** "Cannot" means "cannot without a kernel bug". On kernels
  before 6.14 a read can make the kernel try to load a module. A binary format
  handler that root registered with a fixed interpreter runs that interpreter even
  if it lives on a hidden mount. A read can squat an abstract Unix socket name so a
  daemon starting at that moment cannot bind it.
- **Daemon-read verbs** run outside the jail (see above); their safety rests on
  the fixed verb and flag list and on the installed `systemctl`/`docker` client.
- **Proof gaps.** Every jail protection has a test that fails when the protection
  is removed (`TESTING.md` §12), but a few are proved only by the error the kernel
  returns, not by observing the effect (for example the page-migration calls,
  which need a machine with two NUMA nodes to observe).

## What SSHGate does NOT protect against (be honest)

- **A privileged rogue agent on the same machine (Tier 2 local signer).** If the
  agent can escalate to root or to the signer's user, it can read the
  key and forge approvals. Once its release gates close, use the hosted signer
  (Tier 3) when you need a hard guarantee. (`design.md` §"What the design
  protects against, and what it does not".)
- **The read-path classifier residual.** Most historically-catalogued read-only
  bypasses are now closed or fail closed in the live classifier (`sed e`,
  `find -fprintf`, env-var smuggling, awk `system()`; multiplexers and wrapper
  binaries are non-allowlisted). The tracked **structural** gap that remains is an
  *unlisted* GNU long-option abbreviation. On a host with the read jail, a read
  that slips through this way still cannot change host files, reach Unix-socket
  daemons or touch other processes, but it can use the network; on a host without
  the jail it runs unconfined.
  (`security-readonly-bypass.md`
  §"Security research — read-only gate bypass landscape", opening "Status
  update (2026-07)" callout, and
  §"Bypass categories cross-referenced with SSHGate"; `FUTURE.md`
  §"Operator-facing limitations (known and documented)", item 12, and
  §"Read-only gate hardening (deferred MINORs/MAJORs from security research)".)
  Do not read this as "solved"; read it as "default-deny + a standing regression
  corpus + the jail where available, with one known structural hole".
- **Reads that do harm without writing a file** — network use, the residuals in
  the read-jail section above, and everything on a host without the jail.
- **PTY-based escapes and `~/.ssh/rc` execution at the `authorized_keys` layer —
  closed.** The forced-command entry leads with `restrict` (the OpenSSH ≥ 7.2
  deny-all catch-all) and additionally pins
  `no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding`
  (`commandForcingFmt` in `src/mcp/tools/authorizedkeys.go`, golden-pinned by a
  test). `restrict` also denies `~/.ssh/rc` execution (`no-user-rc`) — so even if
  an agent ever landed a write to `~/.ssh/rc`, sshd will not run it as a shell
  before the forced command — and auto-includes any future OpenSSH restriction. A
  third-party SSH client holding the key can no longer request a PTY, so
  `less`/`man`/`vim` cannot be turned interactive for an `!sh` escape. Enforced at
  that layer. (`FUTURE.md`
  §"Operator-facing limitations (known and documented)", item 13.)
- **A compromised gate binary.** The gate is the on-remote trust anchor for
  signature verification, the read jail and redaction. A gate replaced through a
  non-SSHGate channel defeats all three. The verified release channel (committed
  `dist/gate/` binary + published `.sha256` + the reproducible-build CI check)
  exists so the operator can confirm the bytes they deploy; it does not defend a
  host already compromised out-of-band. (`FUTURE.md` limitation #6.)
- **Redaction is defense-in-depth, not a perimeter.** Inline secret redaction
  scrubs secret-shaped output before it reaches the agent, but it is byte-level
  filtering *after* the read happened, with a known false-negative floor
  (bare-hex and short unnamed secrets). The read jail does not hide readable
  secrets either: it stops changes, not reads. (`FUTURE.md` §"Operator-facing
  limitations (known and documented)".)

## The trust the operator machine holds

Even at Tier 2, the operator's laptop is inside the trust boundary: it
holds the signing key (under a separate Unix user), the server registry (which
hosts the agent may reach), the staged gate bytes that `update_gate` pushes, and
the Telegram bot token. Provisioning — *defining* which machines the agent can
reach — is deliberately **human-only** and off the agent's tool surface, so the
agent can never expand its own reach; it only operates within boundaries a human
established (`design.md` §"Provisioning: control plane vs data plane"). A
compromise of the laptop is therefore a compromise of the Tier-2 boundary.
Once its policy-authority work and release gates close, Tier 3 is intended for
operators who need the key off the agent's machine entirely.

## Where to read more

- [`design.md`](design.md) — full architecture, the three install tiers, the read
  jail's place in the gate, and the protected/not-protected list this page
  condenses.
- [`approval-architecture.md`](approval-architecture.md) — why the boundary is
  *where the signer runs*, and the current approval surface for each tier.
- [`security-readonly-bypass.md`](security-readonly-bypass.md) — the read-only
  bypass landscape and per-item CLOSED/open status.
- [`BUILD-PLAN.md`](BUILD-PLAN.md) — what is built next, including the remaining
  phases of the read jail (network as a permission, a host pin, labels).
- [`TESTING.md`](TESTING.md) — how the jail's protections are proved.
- [`FUTURE.md`](FUTURE.md) — the honest limitations list and deferred directions.
