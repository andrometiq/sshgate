# SSHGate build plan

The committed build order for SSHGate: what is built next, in what order, and when each step
counts as done. Anyone picking up the repository, a developer or a coding agent, starts here.

## How to use this file

- **Work proceeds top to bottom.** Work item 1 comes before work item 2, and so on. Inside a work
  item, steps run in their numbered order unless a step's *Depends* line allows otherwise.
- **Every step has a definition of done.** Its *Acceptance* list says what must be true and
  which commands must pass. A step whose acceptance is not met is not done, however much code
  has landed.
- **Status.** Each step carries `Status: open`, `in progress`, `done` or `deferred`. The change
  that completes a step sets it to `done` in the same commit. A step that is split, reordered or
  dropped is changed here in the same commit as the code, with the reason in the commit message.
- **Not here:** ideas that are not scheduled. Those live in [ROADMAP.md](ROADMAP.md); deferred
  directions and known limitations live in [FUTURE.md](FUTURE.md). When a roadmap item is
  scheduled, its definition and steps move here and the roadmap entry becomes a pointer.
- **Testing rules** are in [TESTING.md](TESTING.md). The security posture each step changes is in
  [THREAT-MODEL.md](THREAT-MODEL.md); a step that changes what SSHGate claims updates that page in
  the same step.

**Rules for every step.**

- `make vet` and `make test` pass at every commit, plus the step's own acceptance commands.
- `make preflight` passes before anything is pushed.
- Each step's full diff is reviewed for correctness, conformance to this plan and security
  before the step is marked done. Every blocking finding is fixed and re-reviewed.
- Never edit `dist/gate/` by hand; only `make release-gate` writes it, as part of a release.
- Never weaken a golden or frozen test. A golden changes only where a step names the change.
- Wire formats, signed payloads, schemas, migrations and trust boundaries are high-stakes: they
  get a critique pass and an independent review before code, and again on the built code.
- After a third fix round on the same subsystem, stop patching, write down how the subsystem
  actually works, and redesign it.
- This repository is public. Docs, code, tests and commits carry no personal or customer names,
  private hostnames or addresses, internal paths or session identifiers.

---

## Current state

### Shipped baseline

The eleven-tool MCP surface (`run`, `run_batch`, `list_servers`, `status`, `ping`,
`revoke_server`, `request_grant`, `revoke_grant`, `list_grants`, `update_gate`, `transfer`),
human-only provisioning through the `sshgate` CLI, read-only (Tier-1) and signed-write (Tier-2)
servers, the local Telegram signer, standing grants, secret reveal, inline output redaction,
the verified gate-update channel, encrypted box-to-box transfer, and the hosted signer
foundation (Tier-3), whose remaining release gates are tracked in [ROADMAP.md](ROADMAP.md). See
[README.md](../README.md) and [design.md](design.md).

### The read jail (#22), Phase 1

The gate runs reads inside a kernel jail with one enforced profile, `ro-v1`. On a host that meets
the profile's floor (unprivileged user, mount and IPC namespaces, `mount_setattr`, Landlock ABI 1
or newer, seccomp, and a `/dev/shm` directory), every command the classifier calls a read runs in
the jail, except the fixed `systemctl`/`docker` read verbs, which still run outside it. Other
hosts run reads classifier-only, as before. What Phase 1 built:

- **Namespaces.** The command runs in new user, mount and IPC namespaces. It stays in the host
  PID namespace, so `ps`, `top` and `pgrep` see host processes. Signalling, tracing and retuning
  processes outside the jail are blocked by Landlock's signal scope (ABI 6 and newer) or seccomp
  rules (below ABI 6), seccomp argument filters on the retune calls, and the cross-namespace
  ptrace rules. The command starts in its own session and process group.
- **A read-only view of `/`.** The whole view is recursively read-only, `nodev` and `nosuid`.
  Host `/proc`, `/tmp` and `/var/tmp` stay visible, read-only. The only writable mount is a
  private 64 MiB `/dev/shm`, discarded at exit. The jail covers with an empty read-only tmpfs
  every reachable mount whose filesystem type is not on a reviewed read-safe list (FUSE, network
  filesystems, `overlay`, unknown types), or whose backing block device is not directly attached
  (`loop`, `nbd`, `ublk`, network transports), wherever it can place the cover. Phase 1 runs
  non-strict: a mount it cannot cover (for example an `overlay` or ZFS root filesystem, or a
  mount below a directory the SSH user cannot enter whose parent cannot be covered either) is
  recorded as an unmet fact inside the jail, not refused, and stays visible, read-only. Strict
  runs that refuse such a read arrive with P2.1. The command's working directory is re-resolved
  inside the final view.
- **Credentials and filters.** Every capability is dropped, `no_new_privs` is set, Landlock is
  required, and seccomp runs a total syscall table whose default is `ENOSYS`, with allowlists
  for `socket`, `socketpair`, `fcntl` and `flock`, named `ioctl` blocks, and a locked
  `RLIMIT_CORE`.
- **Self-checks.** Before `execve`, the worker checks the kernel-reported state it built: the
  mount table, credentials and the Landlock ABI. A failed check aborts the read.
- **Status protocol.** The worker reports its setup result on fd 4: a setup failure with its
  stage and errno, or an `I` report followed by `X` just before `execve`. The shim then
  publishes the command's wait status. The gate can therefore tell a read that never started
  from one that ran, and never re-runs a read that reached `X`. Descendant cleanup and output
  delivery are best effort and bounded after cancellation.
- **Network.** Reads keep TCP/UDP network access, as before the jail. Network becomes a
  permission in Phase 2 (P2.1) and Phase 4.
- **Unchanged.** Signed writes and the admin verbs (`SSHGATE_REVOKE`, `SSHGATE_UPDATE`,
  `SSHGATE_XFER_*`) run exactly as before the jail; a jail problem never blocks them.
- **Test system.** Every Phase-1 protection has a registry ID, a hook that exists only in
  mutation builds, and tests that go red when the protection is removed (see *Test-system
  rules* below).

What Phase 1 does not do yet, and where it is done:

| Gap | Step |
|---|---|
| Whether a read is jailed is still decided by the interim capability probe and the older `jail-floor` pin | P2.1 |
| Runs are non-strict: a mount the jail cannot cover stays visible instead of refusing the read, and the gap is not in the audit record | P2.1 |
| Reads have network access | P2.1, P4.2–P4.4 |
| The fixed `systemctl`/`docker` read verbs run outside the jail | P3.2 |
| No `SSHGATE_JAIL` capability verb; the MCP shows only the signer tier | P2.2, P5.1 |
| No host is labelled kernel read-only; the label is compiled off | P7.1 |
| The MCP instructions and user docs do not yet explain network permissions, pins and labels | P5.2 |
| A read the jail refuses inside `run_batch` returns exit 77 and stderr but no structured `denial` object (`run` has one) | P5.1 |

---

## Work item 1: Read jail (#22), Phases 2–7

**Definition.** The kernel jail is the read-only wall. A read on a host labelled
`read-only (kernel)` cannot change files, contact local daemons, affect other processes, change
kernel settings, or open network sockets unless that network was approved. A host that cannot
meet the full guarantee on a given run is never given that label. Network is a permission,
denied by default, granted per command by a signed request or per host by the operator.

### Terms

- **Profile `ro-v1`.** The one jail recipe. A host passes all of it on a run or the jail does not
  apply on that run; there are no partial levels.
- **The `jail` pin.** Static operator config in the gate directory, same trust class as
  `gate.pub`: `profile=ro-v1`, `net=allow|deny`, optional `docker_socket=` and
  `accept_fs=network[,autofs]`. It is written only by `gate doctor --pin` or by a human-approved
  signed write; the command path never writes it. A pin that fails its checks is *damaged*.
- **Absent and Failed.** A jail setup failure is *Absent* when it comes from boot configuration,
  root-only sysctls or LSM policy (for example user namespaces disabled), and *Failed* otherwise.
  Nothing the agent controls can produce Absent.
- **Strict run.** A run in which any unmet label clause aborts before `X`. A run is strict on a
  pinned host and whenever the read requires confinement.
- **Requires confinement.** True for a read with a signed network grant, a read on a host pinned
  `net=allow`, and a read sent in the unsigned envelope `SSHGATE_READ1 confined <cmd>`. Such a
  read is never run outside the jail, whatever the failure class.
- **Daemon-read verbs.** The fixed allowlist of `systemctl` and `docker` read verbs that need a
  local daemon socket (`lane2` in the code). They carry their own label:
  `daemon read, limited verbs: <binary> (not kernel read-only)`.
- **Protection IDs.** Each protection has an ID (`P-…`) in the registry
  (`src/gate/confine/protections_test.go`) and a hook (`jailmut.On("P-…")`) compiled only into
  mutation builds.

### Outcome of a read after P2.1

| | Absent | Failed |
|---|---|---|
| **Pinned** | denied, exit 77 | denied, exit 77 |
| **Unpinned** | runs classifier-only, audited `classifier`; denied 77 if the read requires confinement | denied, exit 77 |

### Labels (exact strings)

| Condition on this run | Label |
|---|---|
| Pinned `net=deny`, no effective network, the run reached `X` with no unmet clause | `read-only (kernel)` (until P7.1: `kernel-jailed (read-only label not enabled in this build)`) |
| Strict run with network from pin `net=allow` or a signed grant | `kernel-jailed, network open — not read-only` |
| Unpinned, no effective network, profile applied | `classifier-only (jail available; pin to claim)` |
| Daemon-read verb, any pin state | `daemon read, limited verbs: <binary> (not kernel read-only)` |
| Unpinned and Absent | `classifier-only` |
| Pinned with any failure, any Failed, a damaged pin, or an unmet clause on a strict run | `reads denied (jail unavailable)` |

All label strings come from one pure function, `confine.Label`, so every interface reports the
same contract.

### Test-system rules

These apply to every step in this work item. [TESTING.md](TESTING.md) has the commands and the
details.

- **Mutation-proof rule.** Every protection has a registry entry, a hook at its site, a direct
  leg, and an effect leg where an effect can be shown; otherwise an abort leg or a directly
  verified state leg with its control. Each protection has a mutation set in which removing it
  turns its leg red. A meta-test keeps registry IDs and hooks one-to-one. A protection is
  registered, hooked and mutation-proof in the step where its legs land, and is never claimed
  before then.
- **Leg shape.** Build the fixture outside the jail's scratch space. Run an unjailed control that
  must show the effect; a control that cannot show it fails the leg, it never skips. Then run the
  jailed attempt and assert both the absence of the effect and the errno class.
- **Multi-wall rule.** Where several walls stop the same effect, the effect is proven by
  removing all of them; removing one wall must trip its self-check (an abort) or leave the
  effect blocked by the others. Each set runs at the native Landlock ABI and at forced ABI 1.
- **Proof cases.** Each leg runs through the proof API (`newProof`/`RunCase`, `runJailed`,
  `Finish`) with a declared completion mode and evidence obligations (`control:`, `jailed:`,
  `observe:`). A finished case prints exactly one `PROOF-COMPLETE` line. Omissions use
  declared codes (`PROOF-OMITTED`); accepted residuals use `PROOF-RESIDUAL` and must name a
  documented residual. Observers are health-checked and their windows sealed before a verdict.
  The case manifest (`legCases`) lists every case the jail targets must produce.
- **Judging.** A mutation build passes a red leg and reports its markers; the judge accepts a
  case only if the leg and package pass, `go test` exits 0 and the marker set is exact. Any other
  failure is an infrastructure failure, never a detection.
- **Lanes.** Non-root (`make test-jail`) and root (`make test-jail-root`), each at native ABI and
  ABI 1. CI mode (`SSHGATE_JAIL_CI=1`) allows only lane omissions. The phase-end gate is the
  union of the non-root and root CI-mode mutation runs on a disposable runner or VM: every
  registered set red in at least one lane where its legs ran, every case complete, and no
  omission left in the union.
- **Release binaries carry no mutation hooks.** `TestDistGateHasNoMutationBuild` checks the
  committed gate, and the build check below checks a fresh one.
- **Fidelity.** `make test-fidelity-smoke` (and from P6.1 `make test-fidelity`) compares jailed
  and unjailed output of representative reads. Every difference must match a declared category
  in `tests/testdata/fidelity-expected*.txt`, and a declared difference that disappears also
  fails.

**Per-step acceptance (every P-step):** `make vet`, `make test`, `make test-jail`,
`make test-jail-root`, `make test-fidelity-smoke`, and
`make test-jail-mutate MUTATE=<IDs this step added or touched>`. A set reported `NOT-RUN` in a
per-step run (its red legs are root-only or CI-only) is named in the commit message and must be
red in the phase-end run.

**Phase-end acceptance (end of each phase):** the full mutation union above, the independent
review of the phase's code against this plan, and:

```sh
SSHGATE_JAIL_CI=1 make test-jail-mutate              # non-root lane, disposable runner
sudo env SSHGATE_JAIL_CI=1 make test-jail-mutate     # root lane, same runner
make selftest-testjail selftest-jailmut
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$TMP/gate" ./src/gate/cmd/sshgate-gate
file "$TMP/gate" | grep -q 'statically linked'
! go version -m "$TMP/gate" | grep -Eq 'jail_mutation|jailmut'
make verify-repro
```

Invariants that no step may break: one profile (an unknown `Spec` field or profile is rejected);
setup failures never run the command, and nothing that reached `X` is retried; signed writes and
admin verbs are untouched by any jail decision; the gate stays stateless; redaction stays at the
gate boundary; static pure-Go build (`CGO_ENABLED=0`, no new third-party module); no policy from
the environment; the signed wire stays v1 with only additive fields an older gate rejects;
`linux/amd64` only.

### Phase 2: gate wiring

**P2.1 — The `jail` pin, setup-failure classification, and network from the pin.**
Status: open.

- *Goal:* replace the interim probe and the `jail-floor` pin with "the attempt is the probe";
  make network a host permission for unsigned reads.
- *Deliverables:*
  - The `jail` pin parser: at most 4 KiB, `key=value` lines, `#` comments; `lstat` (no symlink),
    regular file, owned by the gate's uid, not group- or world-writable; an unknown or
    duplicate key, a missing required key or a bad value makes it damaged. A damaged pin denies
    reads (77) and never affects signed writes or admin verbs. A leftover `jail-floor` file is
    ignored, with one note from doctor.
  - `confine.ReadHostFacts` and `confine.ClassifySetupFailure(stage, errno, facts)`: `clone`
    `EPERM`/`EINVAL` (or `ENOSPC` with `user.max_user_namespaces == 0`), mount-stage
    `EPERM`/`EACCES`, `setattr` `ENOSYS`, missing `/dev/shm`, Landlock `ENOSYS`/`EOPNOTSUPP` and
    seccomp unavailability are Absent. Cover failures, `nsverify`, `selfcheck`, `report`,
    `exec`, `spec` and `cwd` failures, and any other errno are Failed.
  - `execRead` attempts the jail and applies the outcome table above. The requires-confinement
    flag is computed once and passed to both the plain and the daemon-read branch; in this step
    it comes from a pin with `net=allow` (and a test-only force).
  - `Spec.Strict = validPin || requiresConfinement`; `Spec.AcceptFS` comes only from the pin;
    `Spec.Net` comes from the pin. **Unsigned reads lose network unless the host is pinned
    `net=allow`.** When a jailed read without network fails and its command is a network tool
    (`curl`, `wget`, `dig`, `ssh`, `git`, …), the gate prints one hint line on stderr.
  - Audit fields on executed reads: `enforcement`, `profile`, `pinned`, `landlock_abi`, `net`,
    `accept_fs`, `requires_confinement`, `cwd_reset`, and `label_clause_unmet` (unpinned runs
    without required confinement only); denials record `deny_reason` (for example
    `jail:absent:setattr:ENOSYS`, `pin:damaged`, `confine:required`). The `rung` field goes.
  - Delete `rung.go`, `jail-floor`, `Detect` and its helpers, and the interim mapping; every
    deleted test is replaced by a test of the new code.
- *Acceptance:* protections `P-G-CONFINE-REQUIRED`, `P-G-STRICT` and `P-G-NET-STRICT` are
  registered and mutation-proof (`U-ExecReadConfineRequired`, `U-SpecStrictSources`, the forced
  network and forced-uncoverable unmet-FUSE legs with their no-network twins); the
  classification table has a unit test per row; `G-NSDROP-MNT`, `G-FAULT` and `G-FAULT-ABSENT`
  pass; a placement test forces the jail unavailable and shows that a signed write,
  `SSHGATE_REVOKE` and a valid signed `SSHGATE_UPDATE` still run; INET legs show no socket
  under `net=deny` and a connection under `net=allow`.
- *Depends:* Phase 1.
- *Release note:* any release containing P2.1 states that unsigned reads lost network and how
  to restore it (P5.2 wording).

**P2.2 — `SSHGATE_JAIL`, `gate doctor`, and the label function.** Status: open.

- *Goal:* let operators and the MCP see host capability, and pin a host after a full rehearsal.
- *Deliverables:*
  - `SSHGATE_JAIL`: an unsigned, unaudited verb handled before the public-key load, so Tier-1
    hosts answer. It runs a jail attempt with `:` and prints one JSON line:
    `v`, `profile`, `enforcement` (`kernel|classifier|unavailable`, host capability only, never
    `lane2`), `pinned`, `net`, `landlock_abi`, `label`, `net_grants`, `reason`, `unmet`,
    `accept_fs`, `core_pattern`. No agent-controlled byte executes.
  - `gate doctor [--json] [--pin --net=allow|deny [--accept-fs=network[,autofs]]]`, rewritten:
    feature probes with their errnos; a rehearsal that runs the real jail through
    `__jailselftest` (which refuses to run unless `NoNewPrivs: 1` and seccomp mode 2) against
    doctor-made fixtures (canary file, FIFO, Unix and TCP listeners, a child process, a `/tmp`
    canary), with every effect checked from outside; a report with features, rehearsal,
    pin state, label, mounts and their classes, block-device chains, `core_pattern`, module
    facts (information only) and advice. `--pin` writes the pin atomically at `0600` only if
    every rehearsal check passed in strict mode, and is idempotent.
  - `ExecOpts.Seal` (`PR_SET_DUMPABLE(0)` immediately after the jailed child starts).
  - `confine.KernelLabelEnabled = false` and `confine.Label(state, effectiveNet, enabled)`.
    While the switch is off, `doctor --pin` still writes the pin and reports
    `kernel-jailed (read-only label not enabled in this build)`.
  - The exit-code header comment in the gate's `main.go`.
- *Acceptance:* `P-G-SELFTEST-JAILED`, `P-G-JAILVERB-NOEXEC` and `P-G-LABEL-SWITCH` registered and
  mutation-proof; the gate half of `U-LabelContract` asserts every label string at both switch
  values, that nothing emits `read-only (kernel)` while the switch is off, and that any non-empty
  `unmet` never yields it; `gate doctor --json` reports
  `classifier-only (jail available; pin to claim)` before `--pin`;
  `SSH_ORIGINAL_COMMAND=SSHGATE_JAIL gate` prints exactly one JSON line.
- *Depends:* P2.1.

### Phase 3: daemon-read verbs inside the jail

**P3.0 — Characterise the daemon-read verbs.** Status: open.

- *Goal:* evidence for the grammar and fidelity expectations before the verbs move.
- *Deliverables:* throwaway probes, kept out of the repository, on a development host and the
  matrix distros: the installed clients and retained verbs, including loader and NSS behaviour;
  `docker info` executing plugin candidates; every retained verb (`docker`
  `version`/`ps`/`inspect`/`logs`/`images`/`stats`/`top`, all `systemctl` verbs) producing the
  same output under a Landlock ruleset with `EXECUTE` only on the binary and its interpreter,
  while a plugin exec gets `EACCES`; loader, re-exec and `memfd` execution routes.
- *Acceptance:* findings recorded in the P3.1 commit message. A retained verb whose output
  changes is dropped or declared `L2-NOEXEC`. A `memfd_create`/`memfd_secret` deny for these
  verbs is adopted only if no retained verb calls them.
- *Depends:* Phase 2.

**P3.1 — Grammar, canonical argv, identity checks and endpoint pinning.** Status: open.

- *Deliverables:* a typed grammar per verb (typed flags and positional counts, values at most 128
  bytes, never starting with `-`, each flag at most once) producing a canonical argv;
  `FuzzLane2Parse` (the parse is idempotent on its own output and accepts only grammar tokens);
  `docker info` removed; binary and interpreter (`PT_INTERP`) identity checks, path-component
  checks and a refusal of `DT_RPATH`/`DT_RUNPATH`, all as hygiene (the gate trusts the installed
  client's dependency closure and does not certify it); endpoint pinning: `docker` gets
  `--host=unix://<socket>` (`/run/docker.sock` owned by root, or the pin's `docker_socket` owned
  by the gate's uid); `systemctl` gets `--no-pager --no-ask-password` and the system bus (plus
  `/run/systemd/private` for a root SSH user), each a root-owned socket; `--user`, `--host`,
  `--machine`, `--root`, `--image`, `--global`, `--context` and `-c` are never accepted. The
  verbs still run unjailed in this step.
- *Acceptance:* `P-L2-INTERP` and `P-L2-ADMIT` registered and mutation-proof with
  `U-Lane2ELFSearchTags` and the three `G-L2-ADMIT` fixtures; the fuzz target runs in
  `make test`.
- *Depends:* P3.0.

**P3.2 — Daemon-read verbs run inside `ro-v1`.** Status: open.

- *Deliverables:* `Spec.Lane2` with the canonical argv on fd 3; a closed environment
  (`PATH=/usr/bin:/bin LANG=C SYSTEMD_COLORS=0 TERM=dumb TMPDIR=/dev/shm` plus the pinned empty
  docker config); Unix-socket access only to the pinned sockets (Landlock `RESOLVE_UNIX` from
  ABI 9); `EXECUTE` granted only on the checked binary and its interpreter; network off; the
  exact daemon-read label in every pin state; the `memfd` deny if P3.0 adopted it, with its own
  leg; fidelity rows for `systemctl status <unit>` and `docker ps`.
- *Acceptance:* `P-L2-EXEC-NARROW` (`G-LANE2-PLUGIN-NOEXEC`) registered and mutation-proof;
  loader, re-exec and `memfd` characterisation legs record their outcomes;
  `make test-fidelity-smoke` includes the daemon-read rows.
- *Depends:* P3.1.

### Phase 4: the per-read network permission

**P4.1 — Wire review, no code.** Status: open.

- *Goal:* settle the two wire additions before any code: the signed `Net` field and the unsigned
  `SSHGATE_READ1` envelope.
- *Deliverables:* a critique pass and an independent review of: `SigPayload.Net`
  (`json:"net,omitempty"`, after `Reveal`; a payload with `net=false` is byte-identical to v1;
  an older gate rejects `net` through its strict decoder, exit 65; no protocol-version bump; the
  hosted signer refuses `Net` like reveal); and the envelope `SSHGATE_READ1 <flags> <cmd>`
  (flags from the closed set `{confined}`; an empty, unknown or duplicate flag is refused 77;
  an older gate classifies the line as a write and denies it 77; unsigned only; it never grants
  network and never authorises a write). A command prefix such as `SSHGATE_NET` was rejected: an
  older gate would run it as a signed, unconfined write.
- *Acceptance:* the review is GO, and any change it makes is written into P4.2–P4.4 here.
- *Depends:* Phase 3.

**P4.2 — Gate: signed network and the envelope.** Status: open.

- *Deliverables:* `SigPayload.Net` with goldens; `VerifySigned` returns `Verified{Cmd, Reveal,
  Net}`; a network grant on an admin verb, a write or an unknown command is denied 77
  (`gate: network grant covers reads only`); a network-granted read runs jailed and strict with
  network; the envelope parser runs before the public-key load (Tier-1 handles it), sends an
  inner read to `execRead` with confinement required, denies an inner write or unknown 77, and
  denies an envelope inside a signed command 77.
- *Acceptance:* `TestEncodeSigned_Golden` unchanged, `TestEncodeSigned_NetGolden`,
  `TestDecodeV1RejectsNet`; `P-G-ENVELOPE` registered with `U-EnvelopeParse`; the
  `P-G-CONFINE-REQUIRED` effect leg through the real signed path; `G-NET-NO-FALLBACK`,
  `G-NET-LANE2-ABSENT`, `G-ENVELOPE-OLD-GATE`, `G-ENVELOPE-NEW-GATE`, `G-ENVELOPE-ABSENT`,
  `G-NET-UNMET` and `G-ENVELOPE-UNMET` with their unpinned no-network twins.
- *Depends:* P4.1.

**P4.3 — Signer.** Status: open.

- *Deliverables:* `Net` in the sign request and `CommandReq`; `signAll` copies it into the
  payload; `HandleSignRequest` rejects `Net` on admin verbs; `matchGrant` never auto-signs a
  network read (`if c.Reveal || c.Net || isAdminVerb(c.Cmd)`); the hosted signer refuses `Net`
  before any HTTP call; the Telegram card shows
  `🌐 READ WITH NETWORK on <alias>: may connect anywhere, including services on <alias> itself
  that can change state.` followed by the reason, and the approve button reads
  `✓ Approve READ WITH NETWORK`.
- *Acceptance:* `TestMatchGrantNeverAutoSignsNet`, `TestHostedRefusesNet` and
  `TestApprovalMessageNetBanner` pass; the `matchGrant` guard and the hosted refusal have
  source-patch mutation legs.
- *Depends:* P4.2.

**P4.4 — MCP: the `network` request.** Status: open.

- *Deliverables:* `run` gains `network` (one read only; a reason is required;
  `run_batch` refuses it). A cached `SSHGATE_JAIL` capability per alias, invalidated by a
  successful `update_gate`. One routing table: a network read on a `net=allow` host is sent in
  the `SSHGATE_READ1 confined` envelope; on any other host it is signed with `Net=true`;
  reveal plus network is always one signed request carrying both; a network read with no
  usable signer is refused before anything is sent. New refusals: `network_needs_reason`,
  `network_not_permitted`, `network_unsupported_signer`, `network_unsupported_gate`,
  `network_grant_read_only`, `network_requires_confinement`. No refusal falls back to an
  ordinary read.
- *Acceptance:* the full MCP → signer → gate path is tested with a stale capability cache and
  with the jail becoming unavailable between the capability probe and execution; the named
  cases `M-NET-CACHED-OLD-GATE` (against the committed release gate), `M-NET-PIN-REMOVED-ABSENT`
  and `M-NET-LANE2-ABSENT`, each with its mutation and its expect-green twin, and
  `P-M-REVEAL-NET` with its legs. No network-requested command runs unconfined on any
  interleaving.
- *Depends:* P4.3.

### Phase 5: provisioning and docs

**P5.1 — Provisioning and capability reporting.** Status: open.

- *Deliverables:*
  - `sshgate add` runs `gate doctor --pin --net=<deny|allow> --json` on the fresh bootstrap
    connection, before the forced command is installed, for both tiers. On the idempotent path
    (the host is already gated) it uses `SSHGATE_JAIL` instead, because a `doctor` command sent
    through the forced command would be denied as an unsigned write.
  - `--read-only` on a host without the profile is refused unless `--accept-classifier-only`.
  - The registry's `enforcement` field becomes a capability snapshot
    `{enforcement, pinned, net, label, label_clause_unmet, probed_at}` copied from `SSHGATE_JAIL`,
    with `probed_at` in UTC RFC 3339. A missing or incomplete snapshot reads `unknown`; a label is
    never reconstructed from `enforcement`.
  - `status` and `ping` refresh the snapshot through `SSHGATE_JAIL`. `list_servers` and `status`
    show the stored label with `as of <probed_at>`, and state the signer tier separately as a
    write statement. A failed refresh keeps the old timestamp and reports the failure.
  - Every read's tool result reports `Enforcement: "unknown"`; `HostCapability` carries the
    snapshot, never presented as this command's enforcement.
- *Acceptance:* the MCP half of `U-LabelContract` across `status`, `ping` and `list_servers`;
  `U-RunEnforcementUnknown`; `P-M-ENFORCEMENT-UNKNOWN` registered; provisioning tests for both
  tiers and the idempotent path.
- *Depends:* Phase 4.

**P5.2 — Docs and instructions.** Status: open.

- *Deliverables:* rewrite the MCP server instructions (network is off by default; `network=true`
  needs a reason and an approval; what each label means); the read-jail lines in `AGENTS.md`,
  `README.md` and `ROADMAP.md`; the kernel-confinement section of `THREAT-MODEL.md`, which
  becomes the Phase-1/2 contract plus the residual list; `update_gate`'s result and hint, which
  say that the update turns off network for unsigned reads and how to restore it; the Ubuntu
  24.04 AppArmor user-namespace profile (documentation only). Everything stays generic: no hosts,
  names or paths.
- *Acceptance:* every statement about the jail matches the built code and the label table; the
  docs claim nothing the label switch does not yet allow.
- *Depends:* P5.1.

**P5.3 — Per-command enforcement result.** Status: deferred.

- Reporting how each individual read ran (a gate-written trailer requested through an envelope
  flag) is specified but out of scope for this work item. It needs its own critique and review
  before code, and no other step depends on it. Until then every read reports `unknown` and the
  authoritative per-command record is the gate's audit line.

### Phase 6: matrix and fidelity

**P6.0 — Remaining characterisation probes.** Status: open.

- *Deliverables:* throwaway probes on disposable VMs, results recorded in the commit message:
  block-device transport classification against a software iSCSI LUN and an NVMe/TCP namespace
  (both must classify `network` and be covered without `accept_fs=network`); an XFS
  external-log fixture with direct and loop/nbd/network `logdev=` variants and an outside
  backing-I/O observer; module autoload through binfmt on a kernel below 6.14 (information
  only); a socket `core_pattern` receiver on a kernel 6.17 or newer, recording that the full
  core reaches it (not covered by the label).
- *Acceptance:* each probe's verdict is recorded; a result that contradicts the read-safe list or
  the backing classifier changes the code first.
- *Depends:* Phase 5.

**P6.1 — Full fidelity.** Status: open.

- *Deliverables:* `make test-fidelity` and `tests/testdata/fidelity-expected.txt`, extending the
  smoke target (which stays a subset): the classifier corpus read rows plus the diagnostic set
  (`ps aux`, `top -bn1`, `ss`, `ip`, `df`, `journalctl`, `/tmp` reads, git in `/tmp`, `sqlite3`,
  `getent`, `id`, `who`, the daemon-read verbs), at native ABI and ABI 1, non-root and root.
- *Acceptance:* every difference matches a declared category; Go CLIs (`docker`, `kubectl`)
  are characterised below Landlock ABI 6.
- *Depends:* P6.0.

**P6.2 — VM matrix and CI lanes.** Status: open.

- *Deliverables:* runs on Ubuntu 22.04, Ubuntu 24.04 with and without the AppArmor user-namespace
  profile, Debian 12, RHEL 9 and Amazon Linux 2023. Capable configurations run `test-jail`,
  `test-jail-root`, `test-fidelity` and `doctor --json`. Configurations that intentionally lack
  the profile run a new `make test-jail-expect-absent` (doctor reports Absent with the expected
  reason, an unpinned read runs classifier-only, pinning is refused or a supplied pin denies
  reads, and network-requested reads are denied before `X`). Expected capability is declared per
  configuration and lane before the run. The jail CI workflow gains a root job, a mutation job
  (path-filtered on the jail and gate packages) and a fidelity job, all in CI mode.
- *Acceptance:* a recorded distro/configuration/lane → label table. No distro is documented as
  read-only before this step is done.
- *Depends:* P6.1.

### Phase 7: turn the label on

**P7.1 — Enable `read-only (kernel)`.** Status: open.

- *Preconditions:* P6.2 green on every matrix configuration; the full mutation union green at
  native ABI and ABI 1, non-root and root; the review of every retained read-safe filesystem
  type for the positive no-delegation criterion is complete, and any type that fails has left
  the list; an independent review of the whole read path is GO, with the label contract, the
  residual list and the not-covered list as review targets.
- *Deliverables:* `confine.KernelLabelEnabled = true` (the only step that sets it); the full
  matrix re-run; `THREAT-MODEL.md`, `README.md` and the MCP instructions publish the contract
  below with its not-covered list.
- *Acceptance:* `U-LabelContract`'s enabled-state cases are the live ones and pass; the matrix
  is green after the switch.
- *Depends:* P6.2.

### The contract P7.1 publishes

A read on a host labelled `read-only (kernel)`:

- **Files:** cannot change file contents, metadata or directories on any reachable filesystem,
  except its private `/dev/shm`; cannot open device nodes other than the six re-bound ones, or
  write any of them except `/dev/null`; cannot write or resize an existing host FIFO. Mounts of
  filesystem types not on the reviewed read-safe list are hidden unless the pin's `accept_fs`
  opts network filesystems or `autofs` in.
- **Local daemons:** cannot contact them over sockets of any family or through filesystems that
  forward to a daemon; host System V/POSIX IPC and kernel keyrings are inaccessible.
- **Other processes:** cannot signal, trace or retune a process outside the jail, or read its
  memory, file descriptors or environment.
- **Kernel settings:** cannot change mounts, namespaces or sysctls, or use any capability in the
  initial user namespace.
- **Network:** cannot open an IPv4/IPv6 socket unless approved, and an approval removes the label.

Not covered, and stated on the same page: kernel bugs; module autoload; crash dumps to a socket
`core_pattern` handler; page cache and shared machine resources (including CPU-timer accounting
on other processes); shared file locks; FIFO drain by reading; filesystem housekeeping a read can
trigger; exposure of a hidden mount by something outside the read; root-registered fixed
`binfmt_misc` interpreters; abstract socket name squatting; automount with `accept_fs=autofs`;
driver-specific proc and sysfs side effects; notification events and kernel log lines; data the
SSH user can already read; declared fidelity losses; best-effort cleanup of descendants; audit
and output stalls on a stalled filesystem; the daemon-read verbs (own label); classifier-only and
unpinned hosts; signed writes, which run unconfined by design.

---

## Work item 2: Approval lifecycle (#76 approval-assist, #65 async approval)

**Definition.** Every write, and every reveal, grant request, server revoke, gate update and
transfer, carries a reason the agent supplies. The request becomes a durable approval record
held by the signer. The approver sees a review card: the exact commands with secrets
display-redacted (hidden-byte counts and the SHA-256 of the exact bytes shown), the route facts
labelled as requester-supplied, the reason, and an advisory AI assessment of whether the
commands match the reason. The assessment never changes what is signed, and a failed or late
assessment shows as unavailable. The signer signs when the approved request is claimed for
execution (sign-at-approval), so signatures stay short-lived while a pending request can live
longer. A synchronous call waits for the approval and returns `approval_pending`, having run
nothing, if it does not come in time. On Linux, an asynchronous call hands the job to a
user-level executor service and returns at once; the agent collects results with
`await_approvals` and `list_pending_approvals`. Operators can list, cancel and deny-all pending
requests. The local Telegram signer and the hosted signer serve the same records.

**Decided behaviour that engineers must preserve:**

- A synchronous request is refused before any prompt above 32 steps, any command over 4 KiB,
  or 24 KiB in total (`request_too_large`).
- A synchronous write whose approval has not arrived after about 5 minutes returns
  `approval_pending`; approving the card later does not run it, and the card says so.
- Standing grants become per-uid and host-bound. A write approved under a grant is signed only
  when claimed; a grant revoked or expired before the claim stops it. Grants requested by older
  (v1) clients no longer auto-sign; every v1 sign request prompts.
- A command that cannot be displayed faithfully is refused (`request_unrenderable`), never shown
  fully hidden.
- Upgrade order: signer and hosted signer first, then the MCP. A new MCP in front of an older
  signer fails writes with `signer_incompatible`.
- Hosted admins can cancel and deny-all but cannot approve or vote.
- One signer per approvals directory and one executor per job directory, each on a local
  filesystem.

**Acceptance for every sub-phase:**

```sh
make vet
go vet -tags integration ./...
make test
make build
make verify-no-sqlite-local verify-no-humanauth-local
make verify-gate-closure verify-mcp-closure verify-lifecycle-closure   # from A1a on
GOOS=darwin GOARCH=arm64 go build -o /dev/null ./src/mcp/cmd/sshgate-mcp
GOOS=darwin GOARCH=arm64 go build -o /dev/null ./src/signer/cmd/sshgate-signer-telegram
```

plus the frozen wire and golden selectors (local socket and envelope goldens, `sigwire`, the
hosted wire-frozen and ratchet tests, the MCP tool-registration and denial-shape tests), which
must stay unchanged except where a sub-phase names the change. The gate's bytes must not change:
no new package enters the gate's dependency closure, and the reproducible gate build hash equals
the baseline recorded in A0. Tests are not concurrency-safe: run one test process at a time, and
only one runner owns the Docker-backed integration suite.

**Acceptance at the end of each phase:** the above, `make preflight`, and an independent review
of the phase. These sub-phases are high-stakes and get a focused review of their own: A1a,
A1b and A5 together (schema, state core, wire); A2 and A3 together (display fidelity); A6; A7;
A9; A10 and A11 together (the hosted trust boundary); B0; C2.

**Design rules.** Approval state is write-once facts with derived views: the process that owns
a store has one commit function and one reconciler for it, views are pure functions, time-based
closures (expiry, closed claim windows, erased signature material) are committed as facts before
any answer depends on them, and held authority ends at the earlier of a wall-clock and an
elapsed-time bound. A step that adds a durable record type, a second writer for a fact, or a
clock-held state needs a design change in this file first.

### Phase A: contract, engines and synchronous migration

Sub-phases, in dependency order. A sub-phase starts when everything in its *Depends* column is
merged; sub-phases with no dependency between them may run in parallel.

| ID | Deliverable | Depends |
|---|---|---|
| A0 | Re-ground on the merged #22 code; record the gate build hash and dependency closures as the baseline | Work item 1 |
| A1a | `src/approvalplan`: plan and draft types, validators, bounds, IDs and storage keys, canonical hashes, record schemas, reason validation; closure-check Makefile targets | A0 |
| A1b | The pure state core (`View`, `Apply`, `Next`, `Decide`, `EffectivePolicy`, `GrantLive`, `JobView`, `JobNext`, the claim answer, the notify planner) with its property and model test harness | A1a |
| A2 | `src/redact` span API; `RedactSpans(...).redacted == RedactString(...)` on every corpus | A0 |
| A3 | `src/approvalreview`: review snapshots, neutralized text, the Telegram part packer, the hosted view model | A1a, A2 |
| A4 | `pkg/signerkit/assist`: assessor interface, fail-closed provider input, deadline-bound runner, bounded pool, OpenAI-compatible provider | A1a, A2 |
| A5 | `src/approvalwire` and the MCP approval client: six local socket kinds and the hosted `/v2/approvals` routes, with a closed error-code set | A1a |
| A6 | The lifecycle engine over a memory store: single writer, reconciler, startup, orderly stop | A1b, A4 |
| A7 | The local signer: v2 kinds, peer credentials, legacy (v1) adapter, v2 grants; v1 sign never spends a grant | A5, A6 |
| A8 | The Telegram notifier reconciler: review cards, decision cards, challenges, startup order | A3, A4, A6, A7 |
| A9 | Hosted migration 7 and the v2 row store | A1a, A1b |
| A10 | Hosted v2 machine plane, engine, redactor, assist and worker | A1b, A3, A4, A5, A6, A9 |
| A11 | Hosted human plane and reference app: redacted rendering, session-bound vote challenges, eligibility | A3, A4, A10 |
| A12 | The local signer's stateless proxy to a hosted signer | A7, A8, A10, A11 |
| A13a | `src/mcp/jobplan`, phase-aware SSH execution, `registry.ReadCurrent` | A1a, A1b |
| A13b | MCP synchronous migration: every write path uses the approval client and carries a reason; nine new denial classes; docs and skills updated for the reason | A5, A7, A12, A13a |

*Phase A done when:* every write tool requires a reason and runs through v2 records with
sign-at-claim on both the local and hosted signer; the integration suite passes with a
scripted notifier; no signed command or signature appears in any error or log on any signed
path; the tool count is still eleven.

### Phase B: durable local store

| ID | Deliverable | Depends |
|---|---|---|
| B0 | `internal/securestate`: `ListNames`, `Remove`, `RemoveOrphanTemps` (additive) | A0 (may run during Phase A) |
| B1 | One securestate file per approval record; exclusive directory ownership lock; startup over the file store | Phase A, B0 |
| B2 | The restart matrix, shutdown that leaves records untouched, and the `/renotify <handle>` admin command | B1 |

*Phase B done when:* a pending record with a delivered card survives a signer restart and stays
votable through the same card; an interrupted send is resent only by `/renotify`; a second signer
on the same approvals directory refuses to start.

### Phase C: asynchronous execution

| ID | Deliverable | Depends |
|---|---|---|
| C1 | `src/executorwire` and the executor core: `exec_submit`/`get`/`await`/`list`, a socket restricted to the user's own uid, the job store, admission, the submit window | Phase B |
| C2 | The executor job engine (`JobNext`): one actor per job, claim before signed steps, step checks, reports, retention | C1 |
| C3 | MCP async: the `async: true` option (reads ignore it), the `await_approvals` and `list_pending_approvals` tools (thirteen tools), the executor probe in `status`, the `executor_unavailable` refusal, and the thirteen-tool docs sweep | C1; merges after C2 |
| C4 | Packaging: `sshgate-executor` as a systemd user unit, install and uninstall scripts run by the user, Linux-only release build, install docs | C1 |
| C5 | Async integration and end-to-end tests: approval leads to execution, await returns the stored result, killing the executor mid-run reports `indeterminate` | C2, C3 |

*Phase C done when:* an async call returns once its approval card is sent; the agent can collect
the result after approval; macOS and bundle installs without an executor get
`executor_unavailable`.

### Phase D: queue operations and finish

| ID | Deliverable | Depends |
|---|---|---|
| D1a | In-memory deny-all and cancel snapshots bound to the listed items; execution-report display states | Phase C |
| D1b | Telegram `/pending`, `/deny_all` (with confirmation) and `/cancel <handle>`, each restricted to the allowed user in a private chat | D1a |
| D2 | Hosted admin cancel and deny-all, v2 pending pagination, client-reported execution views | Phase C |
| D3 | Retention and storage policy confirmed end to end; queue metrics in `status` and hosted logs; THREAT-MODEL additions (grants, client-reported results, requester-supplied route facts); design, testing and roadmap docs | D1b, D2 |

*Work item 2 done when:* D3 is done and the final review of the whole work item is GO.

---

## Work item 3: Signature terminal (#81)

**Definition.** A transparent, gated SSH terminal. An operator, or any terminal-capable agent,
uses an ordinary SSH client with a gate-routed key. Reads run as they do through the MCP, inside
the read jail. A command that needs a signature does not run; the gate prints a challenge that
commits to the exact command and the host. The user signs the challenge with the signer, which
applies its normal approval, pastes the signature back, and the gate verifies it exactly as it
verifies any signed write before running the command. The terminal adds a new way to deliver a
signature, not a new trust path: the per-write signature verified on the host stays the boundary.

**Constraints from existing decisions.** The gate must never wrap a live `/bin/sh`: persistent
shell state, `eval`, history and interactive-program escapes would turn per-command gating into
an arms race (see #25 in ROADMAP). Today's forced-command line pins `no-pty` and that pin is
golden-tested, so terminal access needs its own key line or its own design for PTY handling.

**Build steps.**

**T0 — Design (first).** Status: open. Decide and write into this file: the session model (the
gate reads each line, parses it to argv and classifies it itself, as #25 describes, or another
model that preserves per-command gating); the challenge format and how it binds the command,
the host fingerprint and an expiry, reusing the existing signed payload rather than a new
signature scheme; how the user obtains the signature (a signer command or approval surface) and
how the pasted signature is accepted; the key-line and PTY policy; how the read-jail label is
shown in the session; and how this relates to #23 (interactive prompt forwarding) and #25. The
design gets a critique pass and an independent review. *Done when* the review is GO and T1–T5
below are rewritten as concrete steps.

**T1 — Gate session mode** (line reader, argv classification, reads through the jail, a write
answered with a challenge). **T2 — Challenge and signature exchange** in the gate, verified
through `VerifySigned`. **T3 — Signing surface** for a pasted challenge on the local and hosted
signer, with the normal approval. **T4 — Provisioning** of the terminal key line through the
human-only CLI. **T5 — Tests and docs**: a write without a valid signature never runs; a
signature for one command or host does not run another; reads in the session carry the same
jail guarantees as MCP reads; THREAT-MODEL and README describe the terminal. Status of each:
open.

*Depends:* Work item 2.

---

## Work item 4: Hosted signer as a remote MCP server

**Definition.** The hosted signer is reachable as a remote MCP server by any MCP client. For
clients that cannot hold keys, the server holds the SSH client key and runs SSH on their behalf.
The process that holds SSH keys and runs SSH, and the signer that holds the gate-signing key,
run as separate processes under separate users. Every target's gate still verifies every write:
the remote MCP never becomes a way around per-write signatures. Two ways of reaching targets
are supported:

- **Plain `authorized_keys`**, as today: the server's SSH key is pinned to the gate's forced
  command on each target.
- **OpenSSH certificates**: targets trust an SSH certificate authority (`TrustedUserCAKeys`
  with principals) and the certificate forces the gate as its command. The SSH CA key is a
  separate key from the gate-signing key. MCP clients receive short-lived read certificates;
  writes are still individually signed requests verified by the gate.

It is packaged so it can be published to MCP registries and installed as an MCP server.

**Build steps.**

**H0 — Key custody design (first).** Status: open. Decide and write into this file: where the
SSH client key, the SSH CA key and the gate-signing key live; which process and user holds each;
how each is generated, rotated and revoked; whether each is held behind a `crypto.Signer` that
can be backed by a KMS or HSM; how MCP clients authenticate to the server and how a client's
identity maps to SSH principals and to approval records; certificate lifetimes; and how
provisioning installs the CA trust and principals in the same human-only step that installs the
gate. Critique pass and independent review. *Done when* the review is GO and H1–H6 are rewritten
as concrete steps.

**H1 — Process and user split:** an SSH runner and the signer as separate services and users,
with a narrow interface between them. **H2 — Remote MCP transport** with client authentication,
exposing the agent tool surface (provisioning stays off it). **H3 — Server-held SSH key mode**
for clients that cannot hold keys. **H4 — Certificate mode:** CA key, short-lived read
certificates, provisioning of `TrustedUserCAKeys` and principals with the gate as the forced
command; plain `authorized_keys` keeps working. **H5 — Packaging and publication** as an MCP
server (`server.json`, registry metadata, install docs). **H6 — Tests and docs:** a write
through the remote MCP without an approved signature never runs; a read certificate never
authorises a write; a compromised MCP client cannot obtain the gate-signing key; THREAT-MODEL
and approval-architecture describe the new tier. Status of each: open.

*Depends:* Work item 3, and the hosted signer's release gates in ROADMAP.

---

## Work item 5: Secret injection

**Definition.** A command refers to a secret by name instead of by value. The gate looks the
secret up in an encrypted store on the target host, supplies the value to the command when it
executes, and redacts that value from the command's output. The agent never holds the value: it
does not appear in the request, the approval, the agent's output or the logs.

**Build steps.**

**S0 — Design (first).** Status: open. Decide and write into this file: the reference syntax and
how the classifier and the approval card show a reference; how the value reaches the command
(environment, file descriptor or file) and what other processes on the host can observe; which
commands may use secrets (signed writes only, or reads too) and how that interacts with the read
jail; how the on-host store is encrypted and where its key lives; how secrets are added, rotated
and removed (for example over the existing end-to-end encrypted `transfer`); exact-value
redaction of injected secrets in every output sink; and the audit record. README currently says
SSHGate is not a secret manager, so the design also states the new scope. Critique pass and
independent review. *Done when* the review is GO and S1–S4 are rewritten as concrete steps.

**S1 — On-host encrypted store** and its management verbs. **S2 — Injection at exec** in the
gate. **S3 — Redaction** of injected values across every sink. **S4 — Tests and docs:** an
injected value never reaches the agent through output, errors, approvals or logs; a reference
to a missing secret fails closed; THREAT-MODEL states what injection does and does not protect.
Status of each: open.

*Depends:* Work item 4.
