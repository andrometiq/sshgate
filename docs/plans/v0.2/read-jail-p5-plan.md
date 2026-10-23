# Read jail (#22) Phase 5 plan

**Status (2026-10-23): plan v3. Parked: a third critique found 2 major and 2 minor issues, and owner questions O1-O5 (listed in the plan) must be answered before it is revised and built.**

Findings of the third critique, to fold into plan v4:

1. **Major: rotation lacks the busy-guard prerequisite.** §5 brings rotation into the ownership protocol, but the binary-support proof covers only fresh provisioning and preservation repair. Today's rotation re-uploads the gate and signer key and can roll back after a key-generation or verification failure. With an older, guardless binary kept in place, `VERSION` stays available during rotation, so recovery could register an installation before a rollback. Fix: rotation keeps the existing gate binary and signer key and does not use the re-upload path. While ownership is held, prove the existing binary implements the busy guard before re-locking authorization or generating keys. An unsupported binary needs a separate operator-approved update, and the refusal reports any surviving full-shell access. Add unsupported-rotation and recovery-during-rotation cases to the functional and real-SSH manifests.
2. **Major: the ownership protocol lacks mutation proof for several protections.** §7 adds only "unowned cleanup" and "VERSION busy bypass" rows. Fix: register separate mutation variants for exclusive acquisition, stale-state revalidation, mutating-operation ownership, conditional authorization restoration, premature release, and rollback after committed insertion, plus the guard-support admission from finding 1. Name the exact direct and effect-or-state leaves, markers and controls. Drop the claim that the two existing rows prove the concurrency remedy.
3. **Minor: documentation timing.** State that D-owned edits needed by `TestDocsReadJailLabels` land before or with I1 acceptance. The AppArmor recipe and final documentation audit stay at D1.
4. **Minor: a wrong citation** in the closing rules (step 12's paragraph). Cite the repository `AGENTS.md` for preflight and `docs/BUILD-PLAN.md` for the review and publishing rules.

Owner questions (detail in §3 below):

- **O1:** allow an explicit, genuine-absent classifier fallback for fresh provisioning, or require pinning everywhere?
- **O2:** allow unavailable or unknown recovery for signed repair when there is affirmative Tier-2 evidence?
- **O3:** keep the narrowly defined duplicate-key preservation repair, or require manual repair?
- **O4:** approve the concrete schemas, examples and compatibility rules once P5.0 prepares them.
- **O5:** authorize the scoped disposable-host AppArmor experiment, then separately approve its validated publication recipe. O5 is not a prerequisite for the other lanes.

Building also needs Phase 4 reviewed and integrated (the plan's B5 step). Citations below are to the baseline the plan names; re-anchor them before building.

---

**Phase 5 — provisioning, capability reporting, and documentation**

Phase 5 lands a shared capability/storage foundation, three implementation lanes, then integration and documentation. Its central rule remains: **a host capability observation never establishes how a particular command ran**. Every materialized read result reports command enforcement as `unknown`; P5.3 remains deferred. (`docs/BUILD-PLAN.md:640`, `docs/BUILD-PLAN.md:673`.)

**Evidence convention.** Repository citations refer to committed baseline `65e0916fff6c93b7c6b0c655504f3c0ce5e9c72d`, excluding concurrent uncommitted Phase-4 changes in this checkout. `docs/BUILD-PLAN.md` line numbers refer to `main` at that time. Earlier plan revisions, the Phase 4 lane plan and the critiques are in the internal review notes, which are not in this repository. Phase-4 behavior described by its plan remains a dependency contract until verified at B5.

All new implementations, tests, mutation drivers and targets below are **proposed deliverables**, not claims that they already exist or pass. This revision used read-only inspection; no files or git state were changed, and no builds or tests were run.

**Changelog — critique pass 2**

All four findings are accepted; none is disputed.

| Finding | v3 change |
|---|---|
| **Major — concurrent provisioning ownership** | Added account-wide remote ownership, post-acquisition revalidation, attempt-specific state, conditional rollback and uncertainty handling. Added a narrow VERSION busy guard to prevent recovery registering an installation still subject to rollback. Shared rotation/re-lock callers join the protocol. Added same-alias/different-alias barrier tests, recovery-during-install acceptance and preservation of existing pin bytes. |
| **Minor — unused recovery materials** | Connection credentials and path detection precede installation-material loading. Already-gated recovery requires neither staged gate bytes nor a local signer public key. Added missing-material and requested/observed-tier mismatch cases. |
| **Minor — operational documentation omitted** | Added `commands/status.md` and `skills/debugging-remote-servers/SKILL.md` to D’s ownership, documentation inventory and I1’s documentation audit. |
| **Minor — integration can pass through skips** | Added an I-owned strict integration target, exact mandatory test manifest, declared fixture expectations, process/package validation and negative judge self-tests. I2 and I3 use this target instead of bare `make test-integration`. |

The nine critique-1 remedies remain part of this complete plan; their retained mapping appears at the end.

**1. Goals and boundaries**

1. Fresh human provisioning rehearses and pins the jail before installing the forced command, on both tiers. Already-gated recovery uses `SSHGATE_JAIL`, never doctor through the forced command. (`docs/BUILD-PLAN.md:628`.)
2. Store complete, timestamped capability observations. Preserve the last successful observation when refresh fails; describe write tier separately. (`docs/BUILD-PLAN.md:633`.)
3. Every materialized read result—including batch rows, reveal reads and network reads—reports `enforcement:"unknown"`, with host capability represented separately. (`docs/BUILD-PLAN.md:640`, `docs/BUILD-PLAN.md:675`.)
4. Explain network permissions, classifier fallback, daemon exceptions, migration behavior and the disabled label consistently across executable instructions, onboarding and operational documentation. (`docs/BUILD-PLAN.md:649`; `commands/status.md:25`; `skills/debugging-remote-servers/SKILL.md:97`.)
5. Extend the existing batch-level denial to recognized read-jail refusals, including partial batches. (`docs/BUILD-PLAN.md:171`; `src/mcp/tools/run_batch.go:75`.)
6. Ensure cooperating provisioning attempts cannot overwrite or roll back one another’s remote installation, including attempts using different aliases for the same account. The existing shared staging and rollback paths require this additional contract. (`src/mcp/tools/add_server.go:235`, `src/mcp/tools/add_server.go:313`; `src/mcp/tools/provision.go:416`.)

Outside Phase 5:

- Per-command enforcement trailers or new read envelopes: P5.3 remains deferred. (`docs/BUILD-PLAN.md:673`.)
- Full distro/fidelity expansion and permanent root/mutation/fidelity CI jobs: P6.1–P6.2. (`docs/BUILD-PLAN.md:695`, `docs/BUILD-PLAN.md:705`.)
- Enabling the kernel read-only label: P7.1 alone owns that switch. (`docs/BUILD-PLAN.md:728`; `src/gate/confine/label.go:8`.)
- Signer protocol changes, new agent provisioning tools, automatic AppArmor installation and distribution-binary replacement. Provisioning stays human-only; the profile deliverable is documentation; distribution artifacts retain their dedicated release writer. (`src/mcp/server.go:212`; `docs/BUILD-PLAN.md:667`; `Makefile:81`.)

The provisioning VERSION busy guard in §5 is an explicit, narrow gate-path addition. It changes VERSION’s failure behavior during an unfinished provisioning transaction; it adds no verb, successful-response field, signed payload or per-command enforcement report. The existing VERSION, empty-liveness and capability branches are separate. (`src/gate/cmd/sshgate-gate/main.go:164`, `src/gate/cmd/sshgate-gate/main.go:173`, `src/gate/cmd/sshgate-gate/main.go:184`.)

**2. Required BUILD-PLAN amendments**

These amendments accompany their implementation commits. They do not mark unfinished work done. (`docs/BUILD-PLAN.md:13`.)

| Item | Verified discrepancy | Amendment |
|---|---|---|
| Registry field | `Entry` has no existing `enforcement` field. (`src/mcp/registry/servers.go:29`; `docs/BUILD-PLAN.md:633`.) | Specify additive `host_capability` storage and legacy compatibility. |
| Clause-array name | The producer emits `unmet`; the snapshot contract names `label_clause_unmet`. (`src/gate/cmd/sshgate-gate/capability.go:146`; `docs/BUILD-PLAN.md:634`.) | Freeze the mapping without changing the capability wire. |
| Meaning of `net` | Classifier fallback sets it true; unavailable leaves it false independently of pin policy. (`src/gate/cmd/sshgate-gate/capability.go:132`, `src/gate/cmd/sshgate-gate/capability.go:153`, `src/gate/cmd/sshgate-gate/capability.go:158`.) | Describe effective probe networking. Verify explicit recovery policy only from complete `kernel && pinned` observations. |
| Doctor observation | Doctor constructs its capability report before writing the pin. (`src/gate/cmd/sshgate-gate/doctor.go:193`, `src/gate/cmd/sshgate-gate/doctor.go:202`.) | Persist a subsequent forced-session `SSHGATE_JAIL` observation. |
| Fresh fallback | Doctor is required on both tiers, while classifier consent is specified only for Tier-1. (`docs/BUILD-PLAN.md:628`, `docs/BUILD-PLAN.md:632`.) | Record O1 and the complete fresh-admission table. |
| Recovery | Existing aliases are refused before dialing; host tier is reconciled after detection. (`src/mcp/tools/provision.go:240`, `src/mcp/tools/provision.go:320`, `src/mcp/tools/provision.go:385`.) | Preserve same-alias refusal; specify effective tier, classifier consent, unavailable/unknown recovery and legacy-tier handling. |
| Recovery material loading | Gate bytes and requested-tier signer material are loaded before recovery detection. (`src/mcp/tools/provision.go:245`, `src/mcp/tools/provision.go:252`, `src/mcp/tools/provision.go:320`.) | Load installation materials only after choosing a path that uploads them. |
| Remote ownership | Shared staging and destructive rollback have no attempt ownership. (`src/mcp/tools/add_server.go:235`, `src/mcp/tools/add_server.go:295`, `src/mcp/tools/add_server.go:313`.) | Add the account-wide transaction and preservation tables in §5. |
| Recovery during installation | VERSION currently answers without a provisioning-state check, while registration failure can still trigger rollback. (`src/gate/cmd/sshgate-gate/main.go:173`; `src/mcp/tools/provision.go:416`.) | Add the narrow VERSION busy guard, typed probe outcomes, compatibility proof and concurrent-recovery tests. |
| Shared rotation machinery | Rotation reuses setup and rollback. (`src/mcp/tools/provision.go:658`, `src/mcp/tools/provision.go:667`, `src/mcp/tools/provision.go:679`.) | Require rotation/re-lock to join ownership and preserve existing jail policy. |
| Batch denials | Aggregation currently considers write refusals after the execution loop. (`src/mcp/tools/run_batch.go:270`, `src/mcp/tools/run_batch.go:299`.) | Extend the existing batch-level field and preserve first-refusal ordering on partial returns. |
| Persistence | Old timestamps alone do not prevent concurrent-writer loss, replacement-host attachment or delayed reload publication. (`src/mcp/registry/servers.go:114`, `src/mcp/registry/servers.go:295`.) | Add transaction, registration-identity and prior-observation contracts. |
| Older gates | “Older than this release” is too broad; this baseline already builds ordinary jail specifications with deny-by-default networking. (`docs/BUILD-PLAN.md:658`; `src/gate/cmd/sshgate-gate/readjail.go:167`.) | Refer to gates predating that behavior and identify tested compatibility examples. |
| Operational documentation | Status denies capability reporting; debugging gives pin-only network advice and says agents cannot inspect availability. (`commands/status.md:19`, `commands/status.md:25`; `skills/debugging-remote-servers/SKILL.md:97`, `skills/debugging-remote-servers/SKILL.md:140`.) | Include both surfaces in P5.2 ownership and acceptance. |
| Threat model | “Phase-1/2 contract” omits integrated daemon and network behavior. (`docs/BUILD-PLAN.md:664`.) | Publish integrated Phase-1–4 behavior and residuals, with label activation deferred. |
| AppArmor dependency | Documentation requires a profile, while current jail CI relaxes the global restriction. (`docs/BUILD-PLAN.md:667`; `.github/workflows/jail.yml:51`.) | Separate authorized feasibility testing from approval to publish the validated recipe. |
| Docker acceptance | The current target accepts Go’s exit status while helpers may skip unavailable Docker, Compose or startup. (`Makefile:248`; `tests/integration/helpers_test.go:104`, `tests/integration/helpers_test.go:124`, `tests/integration/helpers_test.go:132`.) | Add strict, manifest-checked integration acceptance. |
| Phase-end proof | Two mutation runs do not execute the union checker; root reports are `0600`. (`docs/BUILD-PLAN.md:274`; `scripts/jailmut/harness.go:77`, `scripts/jailmut/harness.go:149`.) | Require explicit baselines, reports and privileged same-host union judging. |

The historical model motivates explicit classifier-only acceptance, but its rung/floor mechanics must not return. Its source is the historical jail model in the internal review notes; the current model has one `ro-v1` profile. (`docs/BUILD-PLAN.md:185`.)

**3. Owner questions**

These are proposed decisions, **not approvals**. Each question has two selectable answers, with the recommendation first. The technical contracts follow in §§4–5.

**O1. Should a new server require a working jail unless you explicitly accept classifier-only reads when system policy prevents the jail?**

- **Recommended:** Allow only that explicit fallback; otherwise require successful pinning.
- **Alternative:** Require successful pinning for every new server.

This resolves fresh admission on both tiers; system-policy absence and other setup failures have different contracts. (`docs/BUILD-PLAN.md:191`, `docs/BUILD-PLAN.md:206`.)

**O2. Should an already-gated server still be recoverable for signed repairs when its read jail cannot be confirmed?**

- **Recommended:** Allow this only when the host confirms that signed writes are supported.
- **Alternative:** Refuse recovery until the read jail can be confirmed.

This resolves the unavailable/unknown recovery exception; host-tier evidence is separate from capability evidence. (`src/mcp/tools/provision.go:385`; `src/gate/cmd/sshgate-gate/capability.go:134`.)

**O3. Should setup repair duplicate SSH keys automatically when it can preserve the existing gate, pin and keys?**

- **Recommended:** Keep the narrowly defined preservation repair.
- **Alternative:** Require manual repair for duplicate-key installations.

This resolves the preservation path and its ownership/rollback contract. Existing setup can rewrite duplicates but its cleanup removes the shared gate directory. (`src/mcp/tools/provision.go:315`; `src/mcp/tools/add_server.go:295`.)

**O4. Should we approve the proposed information shown about each server and command result after reviewing the exact examples?**

- **Recommended:** Approve the proposed fields and compatibility rules.
- **Alternative:** Revise them before implementation.

P5.0 must prepare the concrete schemas and examples before this decision; a field-name list is insufficient. (`docs/BUILD-PLAN.md:31`, `docs/BUILD-PLAN.md:633`.)

**O5. Should we test the scoped AppArmor profile on a disposable server before seeking separate approval to publish it?**

- **Recommended:** Authorize the defined experiment, then review publication separately.
- **Alternative:** Defer the experiment and publication.

The experiment authorization and later publication approval are distinct. Existing globally relaxed CI does not validate the proposed profile. (`docs/BUILD-PLAN.md:667`; `.github/workflows/jail.yml:51`.)

O1–O4 block only their dependent implementation. O5 blocks its experiment and later profile publication/completion; it is **not** a global prerequisite for B1 or P/H/R.

**4. Admission and behavior contracts**

These are proposed contracts subject to the applicable owner decisions.

- **CLI grammar:** add `--net=deny|allow` and `--accept-classifier-only`; retain existing read-only flags. Track explicit `--net` separately from its fresh-install default of deny. Recovery and preservation repair never silently apply that default to an existing pin. (`src/cli/cmd/sshgate/main.go:147`; `docs/BUILD-PLAN.md:181`, `docs/BUILD-PLAN.md:187`.)
- **No provisioning `--accept-fs` flag in P5.** Surface doctor’s refusal and operator remediation; its standalone grammar already handles filesystem acceptance. (`src/gate/cmd/sshgate-gate/doctor.go:53`, `src/gate/cmd/sshgate-gate/doctor.go:246`.)
- **Observation source:** persist the final forced-session response, never doctor’s embedded capability or `pin.label_after`. (`src/gate/cmd/sshgate-gate/doctor.go:287`, `src/gate/cmd/sshgate-gate/doctor.go:304`.)
- **Routing versus reporting:** retain Phase 4’s volatile routing cache and acceptance rules. Never hydrate it from persisted snapshots or tighten its five-required-field parser merely because rich snapshots require more fields.
- **Reachability:** retain liveness and `ping_ms`, with capability errors separate. Keep four workers and one five-second per-server budget shared by liveness and capability work. (`src/mcp/tools/status.go:65`, `src/mcp/tools/status.go:164`.)
- **Label guard:** keep the switch disabled and retain the AST guard. Do not insert the future enabled-label literal into executable instructions or weaken the guard. (`src/gate/confine/label.go:8`; `src/gate/confine/label_test.go:143`, `src/gate/confine/label_test.go:203`.)

**Fresh provisioning, both tiers**

| Evidence | Proposed outcome |
|---|---|
| Successful doctor completion; `rehearsal.passed=true`; `pin.result=written|unchanged`; final capability complete, kernel-enforced, pinned and matching requested networking | Admit with the final observation. |
| Validated unpinned **Absent** classifier fallback without consent | Refuse before finalization. |
| Same genuine fallback with explicit consent | Admit only under O1. Report classifier-only operation, effective networking and that the requested pin policy was not established. Final capability must confirm that accepted state. |
| Kernel operation with unmet clauses or unsuccessful pin admission | Refuse under recommended O1. |
| Failed setup, damaged/legacy pin, unsupported doctor, malformed/missing output, cancellation, transport failure or unrecognized refusal | Refuse; classifier consent does not apply. |
| Staged gate lacks the provisioning busy guard | Refuse before forced-key finalization, irrespective of classifier consent. |
| Doctor admission and final observation disagree | Refuse registration; apply owned rollback or uncertainty handling. |

Exit 77 alone never proves eligible fallback: doctor has several refusal paths and may fail before emitting JSON. (`src/gate/cmd/sshgate-gate/doctor.go:162`, `src/gate/cmd/sshgate-gate/doctor.go:186`, `src/gate/cmd/sshgate-gate/doctor.go:199`.) The guard-support requirement addresses the recovery window identified by VERSION dispatch followed by later registration/rollback. (`src/gate/cmd/sshgate-gate/main.go:173`; `src/mcp/tools/provision.go:405`, `src/mcp/tools/provision.go:416`.)

**Already-gated recovery**

Resolve the effective tier from the host before admission. Preserve the reconciliation note when requested and observed tiers differ. A provisioning-busy response is terminal and is evaluated before this table. (`src/mcp/tools/provision.go:385`; §5’s proposed ownership protocol.)

| Capability/state | Effective Tier-1, `--net` omitted | Effective Tier-2, `--net` omitted | Explicit `--net`, either tier |
|---|---|---|---|
| Complete kernel, valid deny pin | Admit; preserve pin. | Admit; preserve pin. | Admit only `deny`; otherwise refuse with manual advice. |
| Complete kernel, valid allow pin | Admit; preserve pin. | Admit; preserve pin. | Admit only `allow`; otherwise refuse with manual advice. |
| Complete kernel, unpinned, no unmet clauses | Admit with copied “pin to claim” observation. | Same. | Refuse policy verification: no observed valid pin. |
| Complete kernel, unpinned, unmet clauses | Refuse under recommended O2. | Same. | Refuse policy verification. |
| Complete measured classifier, unpinned | Require `--accept-classifier-only`. | Require `--accept-classifier-only`. | Refuse policy verification, even with consent. |
| Complete unavailable; fixture has valid deny pin | Refuse. | O2 signed-repair admission only; retain measured unavailable observation. | Refuse policy verification. |
| Complete unavailable; fixture has valid allow pin | Refuse. | Same repair rule. | Refuse; `net=false` does not prove deny. |
| Complete unavailable with damaged pin or other setup failure | Refuse. | O2 repair admission only; claim neither usable reads nor verified policy. | Refuse policy verification. |
| Unsupported, missing, malformed or incomplete capability | Refuse. | O2 repair admission only; capability remains unknown, without a new successful-observation timestamp. | Refuse policy verification. |

The unavailable allow/deny rows are separate **test fixtures**, not states distinguishable from `net`. The producer sets `pinned` independently and assigns `net` only for kernel/fallback routes. (`src/gate/cmd/sshgate-gate/capability.go:153`, `src/gate/cmd/sshgate-gate/capability.go:158`.)

O2’s repair exception requires affirmative gate liveness and an affirmative host `tier=rw` token. A legacy gate omitting tier does not qualify for that exception. Outside the exception, retain the existing legacy caller-tier fallback and document it rather than silently changing all legacy recovery. (`src/mcp/tools/provision.go:385`, `src/mcp/tools/provision.go:797`.)

Recovery never uploads installation files, runs doctor, generates transfer keys or repins. It requires neither staged gate bytes nor a local signer public key. A registered alias remains refused, and unknown capability must not be described as classifier-only. (`docs/BUILD-PLAN.md:628`; `src/mcp/tools/provision.go:240`, `src/mcp/tools/provision.go:245`; `src/gate/cmd/sshgate-gate/capability.go:134`.)

**5. Frozen implementation contracts**

**Capability representation**

Subject to O4, add `Entry.HostCapability`, JSON key `host_capability`. A complete stored observation contains:

| Field | Contract |
|---|---|
| `enforcement` | Producer value: `kernel`, `classifier` or `unavailable`. |
| `pinned` | Required boolean; explicit false is complete, absence is not. |
| `net` | Required boolean describing effective probe networking. |
| `label` | Nonempty producer label copied verbatim; never reconstructed from tier or enforcement. |
| `label_clause_unmet` | Copy of wire `unmet`; an empty array is complete. |
| `probed_at` | Locally generated UTC RFC3339 observation timestamp, never a remote timestamp. |

The source fields and required snapshot semantics are at `src/gate/cmd/sshgate-gate/capability.go:136`, `src/gate/cmd/sshgate-gate/capability.go:151` and `docs/BUILD-PLAN.md:634`.

Freeze the following in the O4 artifact:

- Tool-facing unknown is exactly `{"enforcement":"unknown"}`: no invented networking, label or fresh timestamp.
- Missing, incomplete or malformed stored snapshots become unknown without discarding valid server identity.
- A successful complete `unavailable` report is a timestamped observation, not a failed refresh.
- Rich decoding requires one response, successful execution, supported version, required field presence/types and bounded printable presentation data. Unknown additive keys remain tolerated.
- Rich completeness remains separate from Phase-4 routing validation.
- Ordinary command stdout/stderr is never parsed as capability metadata.
- Status/ping/list expose complete-or-unknown `host_capability`. Materialized reads expose it separately from literal command `enforcement:"unknown"`.
- `capability_error` is proposed transient, bounded error text for refresh/persistence failure; it is not stored as a successful observation.
- `network_transition_hint` is proposed optional conditional update advice, not a measured transition.
- Generated SDK schemas and text fallbacks handle complete and unknown representations.
- No new per-command batch `denial` field.

These retain v2’s schema contract and Phase-4 parser separation.

**Registry transaction contract**

Current `Add` mutates memory before persistence; `Load` reads before publication; reload records a separately observed hash. These seams matter once status and ping persist snapshots. (`src/mcp/registry/servers.go:114`, `src/mcp/registry/servers.go:184`, `src/mcp/registry/servers.go:255`, `src/mcp/registry/servers.go:295`.)

B1 must provide:

1. One in-process discipline covering read/validation, hash assignment and publication. Delayed successful, failed or missing-file reloads cannot replace newer committed state.
2. A cooperative cross-process lock for all upgraded `Add`, `Remove`, `InsertNew` and capability-update writers.
3. Reload/validation under the writer lock; mutate only the intended entry/field; persist atomically. Corrupt or insecure disk state fails the mutation rather than being overwritten from stale memory.
4. Conditional `UpdateCapability` using both registration identity captured before probing—host, user, port, fingerprint, tier and registration incarnation—and a separate prior-observation token.
5. Rejection of deleted/replaced registrations, changed prior observations and timestamp regression. Timestamp comparison does not replace the token.
6. Final insert-only provisioning, with the absence check inside the transaction. Preserve the winning registration on conflict. The current early check plus replacing `Add` is insufficient. (`src/mcp/tools/provision.go:240`, `src/mcp/tools/provision.go:405`.)
7. Deep copies of snapshot pointers/slices on insertion and getters; preserve legacy-wrapper and warn-once behavior. Existing copies are shallow. (`src/mcp/registry/servers.go:152`, `src/mcp/registry/servers.go:203`, `src/mcp/registry/servers.go:279`, `src/mcp/registry/servers.go:341`.)
8. No SSH while registry locks are held.
9. Refresh/persistence/CAS failure reports the failure without publishing a rejected observation or restamping the old one. Never attach an old host’s probe to its replacement.

P5.0 freezes registration-incarnation representation, observation-token representation, stale-update disposition and provisioning commit/uncertainty outcomes. An uncertain insertion outcome must not trigger an assumed-safe remote rollback. These guarantees cover upgraded cooperating writers; advisory locks cannot serialize old binaries or arbitrary manual edits. (`src/mcp/registry/servers.go:350`.)

**Exclusive remote ownership**

P1 introduces one account-wide provisioning transaction shared by fresh provisioning, preservation repair and rotation/re-lock. It is independent of alias, hostname spelling and local registry path. The need is remote: current setup uploads to common paths, and rollback restores common authorization state and recursively removes the gate directory. (`src/mcp/tools/add_server.go:235`, `src/mcp/tools/add_server.go:242`, `src/mcp/tools/add_server.go:313`.)

Proposed protocol:

1. **Acquire before staging or repair.** Atomically create a fixed private sibling directory, `~/.sshgate-provision.lock`, outside `~/.sshgate-gate`. Use exclusive creation, not `mkdir -p`. The directory is `0700`, belongs to the remote account, and holds a random attempt token plus attempt-specific journal/staging/backup state.
2. **Fail closed on contention or ambiguity.** Existing ownership state, unexpected type/owner/mode, symlinks or inaccessible state refuse the attempt. Never steal, time-expire or automatically delete an existing marker.
3. **Revalidate after acquisition.** Re-read authorization entries, gate-directory identity, pin and key state. Pre-lock observations and an already-authenticated plain connection are not authority to overwrite current state.
4. **Bind mutations to ownership.** Serialize mutations; validate token and directory identity at the operation boundary. Use attempt-specific paths and an exact pre-state manifest. No caller without acknowledged ownership enters shared cleanup.
5. **Keep ownership through completion.** Hold it across staging, rehearsal, finalization, key generation, redial, final capability and confirmed registry insertion—or until scoped rollback is fully completed.
6. **Drain remote operations before release.** A separate ephemeral shell lock is insufficient across `Run`/`Upload` sessions. The implementation must establish completion of all transaction operations before removal of the marker. (`src/mcp/tools/add_server.go:428`, `src/mcp/tools/add_server.go:461`.)
7. **Restore conditionally.** Restore authorization state only if its current identity/content matches the state this attempt wrote. Never restore a reusable shared backup over unrelated changes. Conflicts become explicit uncertainty requiring inspection.
8. **Remove only owned state.** Fresh cleanup may remove the installation it created only while ownership and the recorded identity still match. Preservation repair never removes the existing gate directory.
9. **Keep the marker on uncertainty.** Cancellation, transport loss, an unconfirmed child, uncertain insertion or incomplete cleanup does not establish that rollback completed. Leave the marker/journal and give concrete manual reconciliation advice.
10. **Do not undo a committed registration.** If insertion succeeded but release failed, keep the registration and installation; report registration committed with cleanup pending. Never restore a plain key merely because marker removal failed.

P5.0 freezes the precise journal, ownership checks, operation-completion mechanism and rollback outcomes before P1. The protection covers upgraded cooperating provisioners, including different aliases and different local installations; it does not claim to control old tools or arbitrary manual edits. The retained bootstrap connection’s authority after rewriting makes explicit revalidation necessary. (`src/mcp/tools/provision.go:353`.)

**Prevent recovery from adopting a provisional installation**

A remote mutation lock alone does not close the entire race. After A installs the forced key, B can currently receive VERSION and register another alias while A may still roll back on insertion failure. This is a code-derived interleaving, not an executed reproduction. (`src/gate/cmd/sshgate-gate/main.go:173`; `src/mcp/tools/provision.go:320`, `src/mcp/tools/provision.go:405`, `src/mcp/tools/provision.go:416`.)

P1 therefore adds this narrow guard:

- While the fixed ownership marker exists, or its lookup is ambiguous, `SSHGATE_VERSION` returns exit **75**, empty stdout and the bounded diagnostic **`gate: provisioning in progress or incomplete`**.
- When the marker is absent, VERSION’s successful response remains unchanged.
- Empty-command `SSHGATE_OK` and `SSHGATE_JAIL` remain unchanged, allowing the owner’s final verification while ownership remains held.
- Provisioning and rotation use typed probe outcomes. Busy, transport uncertainty and cancellation never collapse into “plain shell; try fresh setup.” No automatic retry.
- Update VERSION documentation/tests that currently say it never fails. (`src/gate/cmd/sshgate-gate/update.go:248`; `src/mcp/tools/provision.go:774`.)

Before fresh forced-key finalization, prove that the exact staged canonical binary implements the guard: on the still-plain bootstrap connection, with ownership held, invoke it without arguments and with `SSH_ORIGINAL_COMMAND=SSHGATE_VERSION`; require the exact busy outcome. The ordinary entry point reads that variable, so this exercises the same production branch. Unsupported candidates refuse before finalization. (`src/gate/cmd/sshgate-gate/main.go:104`, `src/gate/cmd/sshgate-gate/main.go:164`.)

This is explicitly owned gate work in P1, not an undeclared exception to lane boundaries.

**Remote-state and preservation table**

| State after ownership/revalidation, or verified forced-session detection | Allowed path |
|---|---|
| No installation; validated plain bootstrap access and intended key entries | Fresh staging and O1 admission. |
| Live, already-forced gate with no busy response | Nonmutating recovery under O2; no installation materials loaded. |
| Active, incomplete or ambiguous ownership marker | Refuse; no staging, takeover, recovery registration or shared cleanup. |
| Stale plain connection now sees a completed installation | Release only its own unused transaction state, close the stale connection and redial for nonmutating recovery, or refuse. Never stage from the old observation. |
| Plain plus canonical restricted duplicates for the intended key; safe existing installation; existing binary proves guard support | Narrow O3 preservation repair. |
| Existing gate directory without a completely validated admissible state | Refuse without overwrite or deletion. |
| Duplicate-key repair candidate whose existing binary lacks guard support | Manual repair; do not replace the binary just to qualify. |

For preservation repair:

- Establish actual tier from validated existing host state; preserve it. Apply the recovery admission and explicit-network rules.
- Preserve the gate binary, signer key, transfer keys and **exact pin bytes and metadata**, including `net`, `accept_fs` and `docker_socket`.
- Do not upload a gate or signer key, run doctor, generate transfer keys or repin.
- Change only authorization entries matching the intended key; preserve unrelated entries.
- Require final forced-session liveness/capability and insert-only registration before success.
- Roll back only the attempt’s authorization changes under the conditional-restore rule; never delete the pre-existing installation.

Existing duplicate repair removes matching plain/restricted entries and emits one restricted entry. Ordinary `doctor --pin` reconstructs `net` and `accept_fs`, retaining only an existing `docker_socket`; therefore it is not a preservation operation. (`src/mcp/tools/authorizedkeys.go:55`; `src/gate/cmd/sshgate-gate/doctor.go:83`, `src/gate/cmd/sshgate-gate/doctor.go:89`.)

Rotation/re-lock joins the same ownership protocol because it calls the shared setup and rollback paths. Preserve its host-fingerprint check and dedicated key-rotation semantics. Do not apply fresh default networking or doctor pinning to rotation. Preserve existing pin policy and all material outside the explicitly requested rotation. Release only after confirmed re-lock, key-generation/readback and verification, or completed scoped rollback; uncertain key generation is never retried automatically. (`src/mcp/tools/provision.go:636`, `src/mcp/tools/provision.go:658`, `src/mcp/tools/provision.go:667`, `src/mcp/tools/provision.go:677`.)

**Provisioning sequence**

1. Validate inputs and preserve the early registered-alias refusal.
2. Validate/load connection credentials, intended SSH key identity and host-key configuration.
3. Dial and distinguish live gate, busy/incomplete transaction, confirmed plain bootstrap and uncertain failure. Resolve host tier for recovery.
4. For live-gate recovery, apply O2, obtain the final capability and use `InsertNew`; never load staged gate bytes or a local signer public key.
5. For a plain bootstrap path, acquire account-wide ownership and revalidate remote state.
6. Choose fresh installation, preservation repair or refusal.
7. **Only for an uploading path**, load/validate its installation materials before staging. Missing fresh-install material fails before staging or finalization.
8. Fresh path: stage gate and Tier-2 signer public key; prove busy-guard support; run validated doctor; apply O1; finalize the forced key; preserve fresh Tier-2 transfer-key generation.
9. Preservation path: prove existing-binary guard support and apply the preservation table; no doctor/upload/genkeys.
10. Redial, verify liveness, obtain `SSHGATE_JAIL`, validate the final state and reject cancellation.
11. `InsertNew` with the final observation while remote ownership remains held.
12. Release ownership only after confirmed commit and completed remote operations, or after completed scoped rollback.

This moves material loading past path selection while retaining the current stage/finalize, genkeys, redial and registration ordering where applicable. (`src/mcp/tools/provision.go:245`, `src/mcp/tools/provision.go:320`, `src/mcp/tools/provision.go:353`, `src/mcp/tools/provision.go:375`, `src/mcp/tools/provision.go:405`.)

Preserve typed bootstrap exit status and check cancellation before admission, finalization and insertion. Current `runSSH` flattens `*ssh.ExitError` and has no final cancellation check before success. (`src/mcp/tools/add_server.go:450`, `src/mcp/tools/add_server.go:458`.)

On timeout or lost response:

- Do not retry doctor automatically or claim no pin was written.
- Identify confirmed surviving plain key access as full-shell access.
- Report only confirmed restoration/removal effects and surface cleanup failures.
- Keep ownership on uncertainty; never let another attempt’s cleanup remove the installation.
- Distinguish failed-before-registration, registration-uncertain and registered-but-cleanup-pending outcomes.

The existing rollback wording already establishes the full-shell consequence that must remain explicit. (`src/mcp/tools/provision.go:741`.)

**Read results and partial batches**

Use original command classification and the entry bound to execution. Reveal reads currently route through `runWrite`, so result `Kind` alone cannot determine read metadata. (`src/mcp/tools/run.go:247`.)

For every materialized read result:

- Set command `enforcement` to `"unknown"`.
- Attach the separately qualified stored `host_capability`.
- Cover ordinary, daemon, reveal, signed-network and envelope-network routes.
- Retain unknown enforcement on refused, errored and skipped read rows.
- Add no capability probe, signing request, execution or retry.
- Do not fabricate execution rows for invalid requests or wholly refused batches.

Before execution, initialize every admitted batch row’s command, classification/reason and read metadata. Initialize rows as skipped; clear `skipped` only when attempted. A transport failure leaves trailing rows fully identified and skipped.

Keep the attempted row’s partial stdout/stderr, returned exit information and transport-error context. Text must distinguish “not run” from “attempted; transport failed”; a zero-valued exit field is not proof of success. Current initialization happens inside the loop and a transport error returns immediately. (`src/mcp/tools/run_batch.go:248`, `src/mcp/tools/run_batch.go:251`, `src/mcp/tools/run_batch.go:270`.)

Aggregate refusals incrementally or through a common finalizer before every return:

- Use the existing batch-level `Denial`.
- Recognize read-jail refusal only with exit 77 and the recognized jail diagnostic.
- Preserve the earliest recognized refusal in command order across reads and writes.
- Retain stderr and any “may have started” qualification.
- Preserve `Denied`, stop-on-error defaults, execution order and retry behavior.
- Add no row-level denial schema.

The existing matcher and batch semantics are the anchors. (`src/mcp/tools/run.go:307`, `src/mcp/tools/run.go:317`; `src/mcp/tools/run_batch.go:75`, `src/mcp/tools/run_batch.go:230`, `src/mcp/tools/run_batch.go:299`.)

I1 preserves structured partial SDK output even without a `Denial`, retaining `IsError` and useful text. Partial failures remain outside the convenience live log. Current handlers otherwise discard outputs on those errors. (`src/mcp/server.go:320`, `src/mcp/server.go:385`, `src/mcp/server.go:399`.)

**6. Dependency graph and implementation steps**

`B5` is the integrated, reviewed Phase-4 SHA after G, S, M and Stage I land. This early checkout is not B5. Phase 4 assigns real-producer and cross-component acceptance to Stage I.

```text
Full Phase 4 → B5 → P5.0 → B1
                            |
                    +-------+-------+
                    |       |       |
                  P1→P2     H1      R1
                    |       |       |
                    +-------+-------+
                            |
                            I1
                            |
                            I2 --------------------+
                            |                      |
B5 → authorized A0 experiment → feasibility        |
                            +----------------------+
                            |
                   O5 publication approval
                            |
                            D1
                            |
                            I3
```

A0 can run independently with a source-built gate after its concrete disposable-host scope is authorized. P/H/R do not depend on O5. D1 can draft early; final profile publication depends on integrated evidence and separate approval.

| Step | Deliverables | Dependencies and acceptance |
|---|---|---|
| **P5.0 — freeze contracts** | Record B5; prepare concrete O4 schemas/examples; resolve applicable O1–O4 decisions; freeze admission, ownership, preservation, probe outcomes, token semantics, fixture manifests and BUILD-PLAN amendments. | Full Phase 4. Independent schema/trust-boundary critique. No dependent build with unresolved applicable decisions. O5 excluded from the global gate. |
| **B1 — capability/registry foundation** | Shared decoder/projection, snapshots, deep copies, transactional writers/reloads, conditional refresh, insert-only registration and commit dispositions. | P5.0/O4. Common acceptance A; `go test -race -count=1 ./src/mcp/capability ./src/mcp/registry ./src/mcp/tools`; applicable source mutations. |
| **P1 — provisioning machinery** | Split staging/finalization; exclusive ownership and journal; typed probes/exits/cancellation; narrow gate VERSION guard; support proof; preservation/rotation handling; unified Run/Upload event log; scoped cleanup. No half-wired CLI flag. | B1/O3. A; `go test -race -count=1 ./src/mcp/tools ./src/cli/cmd/sshgate ./src/gate/cmd/sshgate-gate`; provisioning/rotation/guard regressions and new source mutations. |
| **P2 — activate provisioning policy** | Flags/help/output, fresh admission, post-pin observation, material-independent recovery, effective-tier checks, preservation repair, insert-only registration and unsupported-artifact refusal. | P1/O1–O3. A; provisioning package acceptance and mutations. |
| **H1 — host reporting** | Status/ping refresh, independent liveness, retained observations on failure, conditional persistence, stored-only list output. | B1. A; `go test -race -count=1 ./src/mcp/tools ./src/mcp/registry`; reporting mutations. |
| **R1 — result metadata/batch refusals** | Unknown read enforcement, fully initialized partial rows and existing batch-level first-refusal propagation. | B1 and integrated Phase-4 routes. A; `go test -race -count=1 ./src/mcp/tools`; result mutations. |
| **I1 — SDK/presentation/update advice** | Structured error/partial results, matching text, label with “as of”, independent write tier, instructions/descriptions, conditional update hint and documentation contract test. | P2/H1/R1 integrated. A; `go test -race -count=1 ./src/mcp/...`; frozen SDK/update regressions and SDK mutations. |
| **A0 — profile feasibility** | Authorized candidate, attachment/cleanup scope and stock-host restricted/profile/restored evidence through real SSH. | B5 and candidate-test authorization. No P/H/R dependency. |
| **I2 — real-SSH and strict integration** | Real-SSH fixtures/manifests, ownership races, actual registry/SDK, unsupported artifacts, strict Docker acceptance and integrated profile replay. | I1; candidate authorization for profile mode. A; `make test-integration-strict`; all three `test-provision-jail` modes; judge self-tests. |
| **D1 — documentation/profile recipe** | Complete inventory and code-to-claim audit, including operational instructions; exact validated profile recipe. | I1/I2 evidence; O5 publication approval. A; I1-owned documentation test and manual audit. |
| **I3 — phase-end gate** | Full source mutations, independent per-host jail unions, frozen selectors, static/repro checks, strict integration/SSH evidence, release handoff and final reviews. | All required prior acceptance, including D1/O5. Complete P5.1/P5.2 only when earned; retain P5.3 deferred. |

**Exact proposed functional-test inventory**

| Step | Tests |
|---|---|
| B1 | `TestHostCapabilityParse`, `TestHostCapabilitySchema`, `TestCapabilitySnapshotRoundTrip`, `TestCapabilitySnapshotLegacyUnknown`, `TestCapabilitySnapshotDeepCopy`, `TestCapabilityUpdateIdentity`, `TestCapabilityUpdateStaleCAS`, `TestCapabilityUpdatePersistFailure`, `TestCapabilityUpdateConcurrentWriters`, `TestRegistryDelayedReloadCannotOverwriteCommit`, `TestRegistryInsertNewConcurrent` |
| P1 | `TestProvisionDoctorReportParse`, `TestProvisionBootstrapExitStatus`, `TestProvisionBootstrapCancellation`, `TestProvisionStageFinalizeOrder`, `TestProvisionExistingGateState`, `TestProvisionRemoteOwnership`, `TestProvisionRemoteStateRevalidation`, `TestProvisionOwnershipUncertainCompletion`, `TestGateVersionProvisionBusy`, `TestProvisionGuardCompatibility`, `TestRotateXferKeysPreservesJailPolicy`, `TestRotateXferKeysProvisionOwnership` |
| P2 | `TestRunAddJailFlags`, `TestProvisionDoctorBeforeFinalize`, `TestProvisionDoctorRefusalLeavesNoFinalization`, `TestProvisionClassifierAcceptance`, `TestProvisionPostPinCapability`, `TestProvisionIdempotentJailProbe`, `TestProvisionRecoveryWithoutInstallMaterials`, `TestProvisionRecoveryDuringInstall`, `TestProvisionPreserveRepairPin`, `TestProvisionJailFailureRollback`, `TestProvisionAliasClaimRace`, `TestProvisionUnsupportedStagedGate` |
| H1 | `TestStatusCapabilityRefresh`, `TestPingCapabilityRefresh`, `TestCapabilityRefreshFailureKeepsTimestamp`, `TestCapabilityRefreshUnavailableIsObservation`, `TestCapabilityRefreshPersistenceFailure`, `TestListServersStoredCapability`, `TestLabelContractMCP`, `TestCapabilityRefreshAliasChanged` |
| R1 | `TestRunEnforcementUnknown`, `TestRunBatchEnforcementUnknown`, `TestRevealReadEnforcementUnknown`, `TestRunEnforcementUnknownDoesNotProbe`, `TestRunBatchJailDenial`, `TestRunBatchJailDenialPreservesOrdering`, `TestRunBatchPartialFailureMetadata` |
| I1 | `TestCapabilityPresentationSDK`, `TestReadEnforcementUnknownSDK`, `TestReadEnforcementErrorSDK`, `TestRunBatchJailDenialSDK`, `TestRunBatchPartialFailureSDK`, `TestServerInstructionsReadJailContract`, `TestUpdateGateNetworkTransitionHint`, `TestUpdateGateNetworkTransitionHintSDK`, `TestDocsReadJailLabels` |
| I2 | `TestIntegrationStrictJudge`; exact real-SSH and existing Docker test manifests in §9 |

These extend the functional inventory retained from v2 with critique-2 acceptance.

**Required cases**

- **B1 decoding:** explicit false; missing/null/wrong-type fields; empty arrays; missing label; extra keys; wrong version; multiple values/lines; nonzero exit with plausible JSON; oversized output; unknown printable label copied verbatim. Preserve Phase-4 routing acceptance.
- **B1 persistence:** legacy/partial/malformed snapshots without identity loss; failed writes; concurrent instances/processes; deletion/replacement; changed prior token with unchanged registration; timestamp regression; delayed successful/failed/missing reload; warn-once behavior.
- **P2 fresh admission:** both tiers × deny/allow; Absent with/without consent; Failed; damaged/legacy pins; exits 65/70/75/77; malformed/missing doctor output; cancellation racing success; unsupported guard and unsupported doctor independently; no finalization/genkeys/registration after refusal. Doctor’s existing exit distinctions are at `src/gate/cmd/sshgate-gate/doctor.go:162`.
- **P2 recovery:** every §4 row, both effective tiers, requested/actual mismatch, classifier consent, unavailable allow/deny fixtures, unknown capability, explicit match/mismatch/unverifiable policy and missing legacy tier token.
- **Recovery materials:** nonexistent staged bytes and nonexistent local signer key separately and together; requested Tier-2/observed Tier-1 and requested Tier-1/observed Tier-2; zero upload/doctor/genkeys. Fresh missing-material cases fail before staging.
- **P2 rollback:** failures after staging, pinning, key rewrite, generation, redial, final probe and insertion; independent cleanup failure; preservation of unowned state; conditional restore conflict; committed insertion followed by release failure; no automatic retry after uncertainty.
- **Preservation/rotation:** exact existing pin bytes/mode survive success and failure, including nondefault `accept_fs` and `docker_socket`; unrelated keys/files survive; unsupported repair binaries refuse without replacement.
- **H1:** successful unavailable observation versus failed refresh; reachable old gate; unreachable host with stored observation; persistence failure; alias replacement/stale observation; absent, permission-denied and unreachable signer states remain distinct. (`src/mcp/tools/status.go:24`.)
- **R1/I1:** all read routes/capability states; counterfeit command metadata; non-jail exit 77; skipped reads in mixed batches; transport-first failure without denial; actual SDK structured/text agreement.
- **Mandatory three-read regression:** recognized jail refusal → transport failure → never attempted. Assert all command/classification/read metadata; third row skipped; earliest batch denial retained; `Denied=false`; SDK `IsError=true`; useful partial text; exactly two SSH executions; no retry/signing; unchanged partial-live-log behavior.
- **Presentation:** global signer availability never changes every host’s tier or becomes a kernel claim. (`src/mcp/server.go:794`, `src/mcp/server.go:823`.)

**Mandatory ownership schedules**

Use barriers/events, not sleeps:

1. Two attempts for the same remote account both observe absence before acquisition. Run same-alias and different-alias variants, including alternate host spellings.
2. Pause A after acquiring ownership. B must fail without staging or invoking shared cleanup.
3. Let A complete. Assert the winner’s gate, pin, signing/transfer keys and authorization bytes/modes survive; fresh registry reopen retains its entry. No losing attempt restores unrestricted access.
4. Pause B before acquisition until A completes; after acquiring its own unused marker, B must revalidate, close the stale plain connection and recover or refuse.
5. Pause A after forced-key finalization but before insertion. A newly authenticated B must receive VERSION busy and cannot register, including O2 unavailable/unknown recovery cases.
6. Inject owner failure before/after finalization, registry conflict, cancellation, response loss, late remote completion, token mismatch and cleanup failure. Never release ownership while an old operation can still mutate.
7. Exercise rotation versus provisioning/repair contention through their shared production machinery.
8. After confirmed release, a new nonmutating recovery may succeed under O2.

These schedules directly cover the existing shared-path, retained-bootstrap and recovery/rollback seams. (`src/mcp/tools/add_server.go:235`, `src/mcp/tools/add_server.go:428`; `src/mcp/tools/provision.go:353`, `src/mcp/tools/provision.go:416`, `src/mcp/tools/provision.go:658`.)

**Common acceptance A**

Run sequentially on appropriate disposable hosts:

```sh
make vet
make test
make build
make test-jail
sudo make test-jail-root
make test-fidelity-smoke
make selftest-srcmut
```

Run every source mutation added/touched by the step, and jail mutations for changed protection sites. Provisioning integration also retains:

```sh
make test-jail-mutate \
  MUTATE=P-G-PIN-REHEARSAL,P-G-JAILVERB-NOEXEC,P-G-LABEL-SWITCH

sudo make test-jail-mutate \
  MUTATE=P-G-PIN-REHEARSAL,P-G-JAILVERB-NOEXEC,P-G-LABEL-SWITCH
```

These are existing P2.2 protections. Name permitted per-step `NOT-RUN` outcomes and close them in phase-end evidence. (`docs/BUILD-PLAN.md:363`, `docs/BUILD-PLAN.md:265`.)

**7. Protections and exact mutation legs**

Use source-overlay mutations for hook-free MCP code. The narrow non-kernel provisioning VERSION guard also receives source-overlay proof in its gate test binary; it does not introduce a hookless ID into the jail-hook registry. The source harness verifies that production targets are compiled into the selected test binary. (`scripts/srcmut/main.go:244`, `scripts/srcmut/main.go:280`.)

Every row registers both named direct and effect/state leaves in `Red`, each with its exact printed marker, plus the named `Green` control. Leaves are standalone, without descendant subtests. Functional tests supplement these proofs; the harness selects only registered leaves. (`scripts/srcmut/main.go:314`, `scripts/srcmut/main.go:334`.)

Entry names are globally unique: use `p51-` plus protection/variant identity.

| Protection / variant | Direct red leaf → marker | Effect/state red leaf → marker | Green control |
|---|---|---|---|
| `P-M-CAPABILITY-COMPLETE` / incomplete | `TestCapabilityIncompleteSnapshotDirect` → `incomplete-snapshot-claimed-direct` | `TestCapabilityIncompleteSnapshotEffect` → `incomplete-snapshot-claimed` | `TestCapabilityCompleteSnapshotControl` |
| `P-M-CAPABILITY-LABEL` / reconstruct | `TestCapabilityLabelCopiedDirect` → `label-reconstructed-direct` | `TestCapabilityLabelCopiedEffect` → `label-reconstructed` | `TestCapabilityUnknownLabelControl` |
| `P-R-CAPABILITY-IDENTITY` / registration | `TestCapabilityAliasReplacedDirect` → `wrong-host-capability-direct` | `TestCapabilityAliasReplacedEffect` → `wrong-host-capability` | `TestCapabilitySameIdentityControl` |
| `P-R-CAPABILITY-IDENTITY` / stale-observation | `TestCapabilityStaleObservationDirect` → `stale-observation-accepted-direct` | `TestCapabilityStaleObservationEffect` → `stale-observation-overwritten` | `TestCapabilityCurrentObservationControl` |
| `P-R-CAPABILITY-MERGE` / stale-map | `TestCapabilityUpdateLostAliasDirect` → `registry-entry-lost-direct` | `TestCapabilityUpdateLostAliasEffect` → `registry-entry-lost` | `TestCapabilitySingleWriterControl` |
| `P-R-CAPABILITY-MERGE` / stale-publication | `TestRegistryStalePublicationDirect` → `stale-registry-published-direct` | `TestRegistryStalePublicationEffect` → `stale-registry-published` | `TestRegistryFreshPublicationControl` |
| `P-R-PROVISION-INSERT` / replace | `TestProvisionAliasClaimRaceDirect` → `alias-owner-overwritten-direct` | `TestProvisionAliasClaimRaceEffect` → `alias-owner-overwritten` | `TestProvisionDistinctAliasControl` |
| `P-M-PROVISION-OWNERSHIP` / unowned-cleanup | `TestProvisionUnownedCleanupDirect` → `unowned-cleanup-accepted-direct` | `TestProvisionUnownedCleanupEffect` → `foreign-installation-altered` | `TestProvisionOwnedRollbackControl` |
| `P-G-PROVISION-VERSION-BUSY` / bypass | `TestProvisionVersionBusyDirect` → `provision-busy-bypassed-direct` | `TestProvisionVersionBusyEffect` → `provisional-version-published` | `TestProvisionVersionReadyControl` |
| `P-M-CAPABILITY-REFRESH` / failed-stamp | `TestCapabilityFailedRefreshDirect` → `failed-refresh-restamped-direct` | `TestCapabilityFailedRefreshEffect` → `failed-refresh-restamped` | `TestCapabilitySuccessfulRefreshControl` |
| `P-M-PROVISION-PIN` / bypass | `TestProvisionWithoutPinAdmissionDirect` → `finalized-without-pin-admission-direct` | `TestProvisionWithoutPinAdmissionEffect` → `finalized-without-pin-admission` | `TestProvisionPinnedControl` |
| `P-M-PROVISION-CLASSIFIER` / consent | `TestProvisionWithoutClassifierConsentDirect` → `classifier-unaccepted-direct` | `TestProvisionWithoutClassifierConsentEffect` → `classifier-unaccepted` | `TestProvisionClassifierConsentControl` |
| `P-M-PROVISION-CLASSIFIER` / unavailable | `TestProvisionUnavailableAcceptedDirect` → `unavailable-accepted-direct` | `TestProvisionUnavailableAcceptedEffect` → `unavailable-accepted` | `TestProvisionPinnedControl` |
| `P-M-PROVISION-IDEMPOTENT` / mutate | `TestProvisionIdempotentWriteDirect` → `idempotent-mutated-direct` | `TestProvisionIdempotentWriteEffect` → `idempotent-mutated` | `TestProvisionFreshStageControl` |
| `P-M-PROVISION-SNAPSHOT` / pre-pin | `TestProvisionPrePinSnapshotDirect` → `snapshot-not-observed-direct` | `TestProvisionPrePinSnapshotEffect` → `snapshot-not-observed` | `TestProvisionPostPinSnapshotControl` |
| `P-M-ENFORCEMENT-UNKNOWN` / single | `TestRunEnforcementUnknownDirect` → `command-enforcement-claimed-direct` | `TestRunEnforcementUnknownEffect` → `command-enforcement-claimed` | `TestRunEnforcementUnknownWriteControl` |
| `P-M-ENFORCEMENT-UNKNOWN` / batch | `TestRunBatchEnforcementUnknownDirect` → `batch-enforcement-claimed-direct` | `TestRunBatchEnforcementUnknownEffect` → `batch-enforcement-claimed` | `TestRunBatchWriteControl` |
| `P-M-ENFORCEMENT-UNKNOWN` / reveal | `TestRevealReadEnforcementUnknownDirect` → `read-enforcement-missing-direct` | `TestRevealReadEnforcementUnknownEffect` → `read-enforcement-missing` | `TestRevealWriteControl` |
| `P-M-ENFORCEMENT-UNKNOWN` / text | `TestEnforcementTextSDKDirect` → `text-enforcement-claimed-direct` | `TestEnforcementTextSDKEffect` → `text-enforcement-claimed` | `TestWriteTextSDKControl` |
| `P-M-BATCH-JAIL-DENIAL` / drop | `TestRunBatchJailDenialDirect` → `jail-denial-missing-direct` | `TestRunBatchJailDenialEffect` → `jail-denial-missing` | `TestRunBatchNonJail77Control` |

The retained rows come from plan v2; the two ownership rows supply proof for the accepted concurrent-provisioning remedy.

**Mutation sites and observations**

| Variant | Production mutation | Direct observation | Independent effect/state observation |
|---|---|---|---|
| incomplete | Bypass rich completeness rejection. | Incomplete observation is accepted. | Reporting/storage exposes a concrete observation instead of unknown or retained prior state. |
| reconstruct | Derive label from enforcement. | Copied label differs from wire input. | Stored/exposed label differs after the production path. |
| registration | Skip registration identity only. | Replaced registration accepts the update. | Replacement host receives the old host’s observation. |
| stale-observation | Skip prior-token comparison only. | Stale token is accepted under unchanged registration. | Newer observation is overwritten. |
| stale-map | Persist cached map instead of freshly loaded disk state. | Transaction loses an unrelated entry. | Reopened registry confirms disk loss. |
| stale-publication | Bypass publication serialization/generation. | Delayed reader publishes obsolete state. | Later getters expose it after the newer commit. |
| replace | Replace rather than reject an insert conflict. | `InsertNew` incorrectly succeeds. | Reopened registry shows the winning owner overwritten. |
| unowned-cleanup | Bypass the enforcing ownership check in the production cleanup operation. | Wrong/no ownership is accepted. | A controlled stale attempt alters another installation or authorization state. |
| VERSION busy bypass | Remove the production busy guard. | Guard permits VERSION during active ownership. | Full production VERSION dispatch publishes success while the installation remains provisional. |
| failed-stamp | Publish/restamp after refresh failure. | Failed refresh receives successful-update disposition. | Stored/displayed observation or time changes. |
| pin bypass | Bypass doctor admission. | Fresh admission proceeds without required evidence. | Ordered operations/remote state show forced-key finalization. |
| consent | Bypass classifier consent. | Classifier admission succeeds without consent. | Installation/registration exists without acceptance. |
| unavailable | Broaden fallback to Failed/unavailable. | Ineligible state enters fallback admission. | Installation/registration succeeds under that exception. |
| mutate | Route recovery through staging/doctor. | Recovery selects a mutating operation. | Run/Upload events and state prove the mutation. |
| pre-pin | Select doctor’s embedded observation. | Selected snapshot is pre-pin. | Persisted observation differs from final forced-session capability. |
| single/batch/reveal | Substitute host enforcement or omit reveal metadata. | Annotation violates literal unknown. | Full Runner route exposes the wrong result. |
| text | Present host capability as command enforcement. | Formatter loses the distinction. | Actual SDK fallback makes the incorrect claim. |
| drop | Suppress recognized batch jail denial. | First-refusal selection omits it. | Full/partial batch loses the verdict while stderr records refusal. |

For ownership proof, exercise the actual production cleanup operation against independently observed fixture state; a mock’s return value is insufficient. For VERSION proof, compile and execute the production dispatch in the selected gate test binary. Source overlays do not modify a separately built child gate. (`scripts/srcmut/main.go:280`.)

**Stale-observation schedule**

1. A captures registration `R` and prior token `V0`, then waits.
2. B commits under unchanged `R`, advancing to `V1`.
3. Release A with different content and a timestamp equal to or later than B’s, preventing timestamp checks from masking a missing token check.
4. Baseline rejects A with the defined stale disposition; B remains in memory and reopened storage.
5. Removing only the prior-token comparison makes the direct leaf observe acceptance and the state leaf observe overwrite.
6. The control uses current `R`/token and commits successfully in memory and reopened storage.

Use barriers/events, never sleeps or a lock schedule that demands a writer complete while deliberately blocking it.

Freeze literal `old`/`new` patches at each introducing commit. Targets must be compiled into the test binary; old text must occur exactly once at HEAD and the working target must match HEAD. (`scripts/srcmut/main.go:244`, `scripts/srcmut/main.go:280`, `scripts/srcmut/main.go:287`, `scripts/srcmut/main.go:293`.)

Require baseline red/control passes, normal mutated red failures with exact markers and green control passes. Missing tests, skips, unrelated failures, crashes or abnormal termination never count as detection. Emit a marker only after observing its own violation. (`scripts/srcmut/main.go:568`, `scripts/srcmut/main.go:574`, `scripts/srcmut/main.go:589`.)

Claim a protection only when its guard and both proof legs land. An SDK leg owned by I1 defers the claim to I1.

**8. Ownership and merge rules**

All P/H/R lanes start from B1’s reviewed commit based on B5. Each lane contract records exact base SHA, owned/forbidden paths, acceptance commands and proof IDs.

| Owner | Owned paths |
|---|---|
| **B1** | New `src/mcp/capability/**`; `src/mcp/registry/**`; shared-parser delegation in Phase-4 `src/mcp/tools/netcap.go` before the fork; necessary shared Runner preparation; `scripts/srcmut/sets/p51-registry.json`. |
| **P** | CLI `main.go`/tests; `src/mcp/tools/provision.go`, `add_server.go`, new `provision_jail.go` and ownership helpers; provisioning/bootstrap/preservation/rotation tests; `scripts/srcmut/sets/p51-provisioning.json`. **Narrow gate exception:** VERSION branch in `src/gate/cmd/sshgate-gate/main.go`, new `provision_guard.go`/tests, affected VERSION commentary/tests in `update.go`, and `scripts/srcmut/sets/p51-provision-guard.json`. |
| **H** | `status.go`, `ping.go`, `list_servers.go`, `netcap.go`, new `caprefresh.go`; corresponding tests; `scripts/srcmut/sets/p51-reporting.json`. |
| **R** | `run.go`, `run_batch.go`, `netroute.go`, `denial.go`, new result-metadata helper; corresponding tests; `scripts/srcmut/sets/p51-results.json`. |
| **I** | After integration: `src/mcp/server.go`, `src/mcp/tools/update_gate.go`, SDK/advisory tests; new **`src/mcp/docs_read_jail_test.go`, owning `TestDocsReadJailLabels`**; real-SSH and profile fixture machinery; strict-integration driver/manifest/self-tests; integration helper/test/fixture adaptations; Makefile wiring; `scripts/srcmut/sets/p51-sdk.json`. |
| **D** | `AGENTS.md`, `README.md`, `INSTALL.md`, `CHANGELOG.md`, `commands/setup.md`, **`commands/status.md`**, **`skills/debugging-remote-servers/SKILL.md`**, `docs/THREAT-MODEL.md`, `docs/design.md`, `docs/install-step-by-step.md`, `docs/install-generic-mcp.md`, `docs/ROADMAP.md`, `docs/TESTING.md`, `packaging/mcpb/README.md`, and description fields only in `packaging/mcpb/manifest.json`. **Excludes `docs/BUILD-PLAN.md`.** |
| **Orchestrator** | `docs/BUILD-PLAN.md`, git integration, ownership adjustments, local evidence/reviews and earned status changes. |

P/H/R cannot edit one another’s files, I-owned presentation/update files, Makefile, workflows, documentation, signer implementation, signed-wire packages or distribution artifacts. Gate implementation is forbidden except P’s explicitly listed provisioning guard. This amends v2’s blanket gate prohibition for the justified recovery-race fix. (`src/gate/cmd/sshgate-gate/main.go:173`, `src/mcp/tools/provision.go:416`.)

D cannot edit executable code, tests, scripts, service units, workflow behavior, manifest versions or tool names. D may run I1’s documentation test but does not own it.

Any additional shared Runner field lands before the fork or through a serialized foundation follow-up. Shared setup changes must preserve rotation and bring it into ownership. (`src/mcp/tools/provision.go:658`.)

Merge **P → H → R → I1**, with orchestrator-run `make vet` and `make test` after each merge. Reserve overlapping paths against Work-item-2 writers. (`docs/BUILD-PLAN.md:25`.)

**9. Real-SSH, strict integration, AppArmor, documentation and compatibility acceptance**

**Real-SSH fixtures**

Add:

```sh
make test-provision-jail \
  PROVISION_CASE=capable \
  PROVISION_FIXTURE="$phase5_capable_fixture"

make test-provision-jail \
  PROVISION_CASE=absent \
  PROVISION_FIXTURE="$phase5_absent_fixture"

make test-provision-jail \
  PROVISION_CASE=apparmor \
  PROVISION_FIXTURE="$phase5_apparmor_fixture"
```

`PROVISION_CASE` is a closed enum. Descriptors identify disposable VM/test-sshd resources, temporary accounts/keys, declared expected capability and privileges. Missing fixtures/tools/features fail rather than skip. This retains and extends v2’s strict fixture contract.

Validate exact leaf sets from `go test -json`; abbreviated names below share their preceding test prefix.

| Mode | Required leaves |
|---|---|
| capable | `TestProvisionJailOverSSH/Tier1Deny`, `/Tier1Allow`, `/Tier2Deny`, `/Tier2Allow`, `/IdempotentTier1`, `/IdempotentTier2`, `/SnapshotRefresh`, `/ReadResultsUnknown`, `/UnsupportedStagedTier1`, `/UnsupportedStagedTier2`, `/ConcurrentSameAlias`, `/ConcurrentDifferentAliases`, `/StaleBootstrapRevalidation`, `/RecoveryDuringInstall`, `/RecoveryMissingMaterialsTier1`, `/RecoveryMissingMaterialsTier2`, `/PreservationRepair`, `/UnsupportedRepairGate`, `/RotationOwnership` |
| absent | `TestProvisionJailAbsentOverSSH/DefaultRefusedTier1`, `/DefaultRefusedTier2`, `/AcceptedTier1`, `/AcceptedTier2`; amend explicitly if approved O1 differs |
| apparmor | `TestProvisionAppArmorProfile/Restricted`, `/ScopedProfile`, `/Restored` |

Every required leaf runs and passes. If a named case introduces child subtests, freeze and require those exact descendants too; a parent pass is insufficient. Reject missing/skipped leaves and abnormal test/package/process outcomes. Record fixture identity, privilege lane, kernel/ABI, staged-gate hash, source SHA and declared/observed capability.

Capable-host evidence proves:

- Doctor precedes forced-command finalization.
- The pin is `0600` with selected policy.
- Tier-1 has no signer public key and answers capability probes.
- Registry state comes from final forced-session capability.
- Recovery changes no installation/pin files and works without unused local installation materials.
- Preservation repair keeps exact existing pin/key state.
- Concurrent losers cannot remove the winner’s gate/pin/keys, restore unrestricted access or disturb its registry entry.
- Recovery cannot register while installation remains subject to rollback.
- Status/ping refresh and stored-list output agree.
- Actual SDK read enforcement remains unknown.
- Tier-1 write refusal and Tier-2 signed writes remain intact.

Use source-built bytes explicitly staged into temporary test configuration. Production `install-local` instead stages committed distribution bytes. (`Makefile:145`, `Makefile:159`.)

**Strict Docker integration acceptance**

I owns a new target:

```sh
make test-integration-strict \
  INTEGRATION_FIXTURE="$phase5_integration_fixture"
```

It runs the current full integration package set with serialization, race checking, disabled caching and JSON output:

```sh
go test -count=1 -p=1 -race -tags=integration -json \
  ./internal/redteam ./tests/integration/... -timeout=300s
```

The current target serializes those packages because they share a host port, but accepts skip-bearing Go success. (`Makefile:242`, `Makefile:248`.)

The strict driver maintains an exact package/test manifest containing at least these existing tests:

| Required test | Declaration |
|---|---|
| `TestPhase3Provision_Success` | `tests/integration/phase3_test.go:54` |
| `TestPhase3Provision_VerifyFailureRollsBack` | `tests/integration/phase3_test.go:148` |
| `TestPhase3Provision_AliasAlreadyRegistered` | `tests/integration/phase3_test.go:228` |
| `TestPhase3Provision_IdempotentReAdd` | `tests/integration/phase3_test.go:262` |
| `TestPhase3Provision_ReadOnly` | `tests/integration/phase3_test.go:333` |
| `TestPhase3Provision_NoGoroutineLeaks` | `tests/integration/phase3_test.go:429` |
| `TestPhase3SignedWrite_Executes` | `tests/integration/phase3_signed_write_test.go:41` |

Freeze complete package identifiers and required descendants at I2. Do not weaken these regressions to accommodate new admission policy.

Strict acceptance requires:

1. Every required test/descendant has an observed run and passing terminal result.
2. No required test is missing, skipped or represented only by a parent pass.
3. All invoked packages have valid successful terminal results; package skip, compile failure, unexpected failure or missing terminal fails acceptance.
4. The actual `go test` process exits normally with status zero. Timeout, signal, start failure or nonzero exit fails even if prior test events passed.
5. JSON is complete and valid. Truncated/malformed output, an empty run or a required “no tests to run” outcome fails.
6. Capture the producer’s status directly; a successful `tee`/parser cannot conceal its failure.
7. Run the full existing suite; the manifest does not replace it with a few selected tests. Record nonrequired skips without treating them as successful coverage.

In strict mode, missing Compose, unavailable Docker and failed image/container startup are failures. Ordinary contributor runs retain their existing skip behavior. Those skip sites are explicit in `tests/integration/helpers_test.go:104`, `tests/integration/helpers_test.go:124` and `tests/integration/helpers_test.go:132`.

The fixture descriptor declares **pin-capable** or **genuine Absent** before execution:

- Pin-capable fixtures must satisfy normal pinning admission.
- Only a declared and independently validated genuine-Absent fixture may use explicit classifier consent, and only under approved O1.
- Failed, malformed, unknown or unexpectedly incapable fixtures fail; never infer the desired expectation from the result.
- Do not add classifier consent indiscriminately to recover green.
- Record source SHA, gate hash, fixture settings and expected/observed state.
- Docker acceptance never substitutes for native capable-host real-SSH acceptance.

`TestIntegrationStrictJudge` must accept complete valid evidence and reject missing tests, required skips, parent-only success, missing package terminals, malformed/truncated JSON, compile failure, signal/timeout, nonzero producer status and a deliberately masked producer failure. Add `make selftest-integration-strict` to run this judge’s deterministic self-tests.

These requirements replace v2’s undefined “explicit environment contract.”

Existing smoke remains a keyless MCP-startup check, not provisioning evidence. (`Makefile:501`; `scripts/smoke-fresh-install.sh:25`.)

**Unsupported staged-gate negatives**

Exercise both tiers with independently controlled incompatibilities:

- A candidate lacking busy-guard support fails before forced-key finalization.
- A guard-supporting candidate with unsupported/missing/malformed doctor behavior fails doctor admission even with classifier consent. Do not let the earlier guard rejection mask this separate negative.
- No forced-key finalization, transfer generation or registry insertion follows refusal.
- Report surviving full-shell access accurately.
- Verify owned cleanup and expose cleanup failure/uncertainty.
- Never overwrite or remove pre-existing installation state.
- An existing repair binary lacking the guard is refused without replacement.

Provisioning’s staged-binary seam is the local read followed by remote upload. (`src/mcp/tools/provision.go:245`; `src/mcp/tools/add_server.go:242`.)

**Production-artifact release handoff**

Source-built P5 acceptance does **not** establish installed-CLI/staged-artifact compatibility.

Record a release-owner handoff requiring:

1. Distribution production through `make release-gate`, outside P5 changes.
2. Installation through the normal staging path.
3. Acceptance with the **actual installed CLI and normally staged artifact**, on both tiers/both policies, plus recovery and ownership-guard compatibility.
4. Recorded CLI revision, staged/uploaded artifact hash and acceptance evidence.
5. Unsupported-combination behavior matching the negative cases above.

This blocks a release-readiness claim until executed. It authorizes no artifact replacement during P5. (`Makefile:81`, `Makefile:159`.)

**AppArmor feasibility and publication**

A0 presents the exact candidate profile, attachment target, disposable-host install/removal steps and expected effects for experiment authorization. It is not yet validated.

On a stock disposable Ubuntu 24.04 fixture:

1. Verify the restriction remains enabled and establish the restricted baseline.
2. Run existing classifier-fallback tests.
3. Install only the authorized candidate.
4. Confirm the global restriction remains enabled.
5. Exercise doctor rehearsal/pinning, capability reporting, ordinary jailed reads and gate re-execution through actual SSH.
6. Remove the candidate, restore fixture-owned installation/pin changes and reproduce the restricted baseline.

A0 may manually stage a source-built gate. I2 repeats the integrated CLI path. Submit the exact tested recipe and evidence for separate O5 publication approval; substantive profile/attachment changes require renewed validation. This preserves v2’s separation of feasibility and publication.

Retain:

```sh
SSHGATE_REQUIRE_CLAMP_TEST=1 go test -race -count=1 -v \
  -run '^(TestRunReadClampHostRunsClassifierOnly|TestGateBinaryClampHostClassifierOnly)$' \
  ./src/gate/cmd/sshgate-gate/
```

These tests and their mandatory CI invocation exist. Profile feasibility remains unverified until the proposed runs pass. (`src/gate/cmd/sshgate-gate/clamp_test.go:45`, `src/gate/cmd/sshgate-gate/clamp_test.go:59`; `.github/workflows/tests.yml:76`.)

**Documentation inventory**

| Surface | Required changes |
|---|---|
| MCP instructions/descriptions | Effective network policy, reason/approval requirements, observation age, unknown command enforcement, daemon exceptions and refusals. (`src/mcp/server.go:130`.) |
| CLI help/output/setup | Fresh defaults/pinning, classifier exception, recovery without unused local materials, preservation, busy/uncertain ownership, explicit-policy limits and independent write tier. (`src/cli/cmd/sshgate/main.go:147`; `commands/setup.md:344`.) |
| **Status command** | Add exact capability/error output fields; label with “as of”; retained stale observation plus refresh failure; separate liveness/write tier; unknown capability and unknown command enforcement. Remove the assertion that capability cannot be reported. (`commands/status.md:19`, `commands/status.md:25`.) |
| **Debugging skill** | Explain status/ping refresh and stored list observations; remove “you can’t see which one applies” as a capability claim; explain network requests/reasons/approval, allow pins, reveal and daemon exceptions; retain denial/uncertainty no-retry guidance. (`skills/debugging-remote-servers/SKILL.md:97`, `skills/debugging-remote-servers/SKILL.md:128`, `skills/debugging-remote-servers/SKILL.md:140`, `skills/debugging-remote-servers/SKILL.md:144`.) |
| README/AGENTS | Qualified jail/network guarantees, Phase-4 routes, daemon exceptions and uncertainty warnings. (`README.md:29`; `AGENTS.md:104`.) |
| INSTALL/install guides | Remove obsolete planned-network wording; distinguish fresh pinning from manual existing-host work; correct daemon behavior under allow pins; explain recovery/ownership failures. (`INSTALL.md:259`; `docs/install-step-by-step.md:290`, `docs/install-step-by-step.md:333`, `docs/install-step-by-step.md:345`.) |
| Threat model/design | Integrated Phase-1–4 behavior, snapshot limits, grant/replay semantics, daemon residuals, provisioning ownership limits and not-covered list. (`docs/BUILD-PLAN.md:549`, `docs/BUILD-PLAN.md:735`; `docs/THREAT-MODEL.md:199`.) |
| Update result/text/hint | Conditional migration advice separate from measured capability; preserve hash/marker/read-once handling; describe a VERSION busy failure without retrying it. (`src/mcp/tools/update_gate.go:34`, `src/mcp/tools/update_gate.go:117`, `src/mcp/tools/update_gate.go:219`; `src/mcp/server.go:598`.) |
| Generic MCP/MCPB | Correct blanket signer-free/free-read and ping-only-liveness descriptions; preserve names/defaults. (`docs/install-generic-mcp.md:132`; `packaging/mcpb/manifest.json:35`, `packaging/mcpb/manifest.json:45`.) |
| ROADMAP/CHANGELOG/TESTING | Integrated behavior, strict targets/manifests, ownership/compatibility acceptance and release handoff; retain P6/P7 boundaries. (`docs/ROADMAP.md:62`; `docs/BUILD-PLAN.md:705`, `docs/BUILD-PLAN.md:721`.) |
| BUILD-PLAN | Orchestrator alone applies §2 amendments and earned status changes. (`docs/BUILD-PLAN.md:13`.) |

I1’s `TestDocsReadJailLabels` explicitly includes both operational documents. Pair deterministic content checks with a manual code-to-claim audit; word-presence tests alone cannot establish correct instructions.

Freeze these explanatory rules:

- Ordinary jailed reads obtain network through an allow pin or signed network grant.
- Permitted unconfined classifier fallback retains networking.
- Jailed daemon reads have no network, including under allow pins; permitted unconfined fallback retains it.
- Explicit daemon-read network requests are refused.
- Network without reveal on a capable allow-pinned host uses the pin-authorized envelope without signing.
- Reveal plus network remains signed and approved.
- Signed network routes require supported local signing, never standing-grant auto-sign or silent retry/fallback.
- Label prefixes alone establish neither networking nor a command’s enforcement.
- Even a recent host capability observation does not establish command enforcement.
- Refresh failure is shown separately without restamping old observations.

These are integrated dependency contracts and the required snapshot semantics. (`docs/BUILD-PLAN.md:540`, `docs/BUILD-PLAN.md:601`, `docs/BUILD-PLAN.md:639`, `docs/BUILD-PLAN.md:649`.)

The update hint applies to upgrades from behavior predating deny-by-default networking: **unsigned reads that actually run jailed without an allow pin** lose network. Classifier fallback retains it. Do not claim an observed transition, repin or retry. (`docs/BUILD-PLAN.md:664`.)

**Frozen selectors**

Keep signed-wire and signer goldens unchanged:

```sh
go test -race -count=1 \
  -run 'TestEncodeSigned|TestDecodeV1RejectsNet' ./src/sigwire/

go test -race -count=1 \
  -run 'TestEnvelopeGolden|TestSocketGolden|Reveal' \
  ./pkg/signerkit/ ./src/signer/...

go test -race -count=1 \
  -run '^TestWireFrozen_' ./pkg/signerkit/hosted/

go test -race -count=1 \
  -run '^TestSignRequestWireNoNetGolden$' ./src/mcp/sign/
```

Declaration anchors: `src/sigwire/payload_golden_test.go:43`, `src/sigwire/payload_net_test.go:38`, `src/sigwire/payload_net_test.go:107`, `pkg/signerkit/envelope_golden_test.go:201`, `pkg/signerkit/socketrpc_golden_test.go:86`, `pkg/signerkit/hosted/wire_frozen_test.go:36`, `src/mcp/sign/client_net_wire_test.go:32`.

Also retain:

```sh
go test -race -count=1 \
  -run '^TestServe_RegistersExactlyAgentTools$' ./src/mcp/

go test -race -count=1 \
  -run '^(TestNewDenial_ShapePinned|TestDenialForGateExit)$' ./src/mcp/tools/

go test -race -count=1 \
  -run '^(TestDoctor.*|TestJailVerb.*)$' ./src/gate/cmd/sshgate-gate/

go test -race -count=1 \
  -run '^TestLabel' ./src/gate/confine/

go test -race -count=1 \
  -run 'TestProvision_|TestRotateXferKeys_|TestUpdateGate_' ./src/mcp/tools/
```

Preserve tool surface, denial shape, tier reconciliation, duplicate-key safety and full-shell rollback warnings. Extend duplicate repair fixtures for the approved preservation/support contract; do not remove their security assertion. (`src/mcp/server_test.go:262`; `src/mcp/tools/denial_shape_test.go:10`, `src/mcp/tools/denial_shape_test.go:76`; `src/mcp/tools/provision_test.go:541`, `src/mcp/tools/provision_test.go:850`, `src/mcp/tools/provision_test.go:903`.)

At B5, additionally freeze Phase-4 capability/routing selectors and `p43.json`/`p44.json` mutations: parser/cache, routing, no-fallback and real-producer tests.

**10. Phase-end union and completion gate**

Run the full jail union independently on:

- A disposable CI-equivalent runner.
- A disposable VM with native Landlock ABI at least 9.

Judge each root/non-root pair on its producing host. ABI-dependent residual expectations are computed there; do not combine hosts’ reports. (`src/gate/confine/jailmut/harness/residuals.go:12`.)

On each host, use a fresh evidence directory accessible to both privilege lanes:

```sh
SSHGATE_JAIL_CI=1 make test-jail \
  JAIL_BASELINE="$phase5_evidence/nonroot-baseline.json"

SSHGATE_JAIL_CI=1 make test-jail-mutate \
  JAIL_PROOF_LOG="$phase5_evidence/nonroot-baseline.json" \
  MUTATION_REPORT="$phase5_evidence/nonroot.json"

sudo env SSHGATE_JAIL_CI=1 make test-jail-root \
  JAIL_BASELINE="$phase5_evidence/root-baseline.json"

sudo env SSHGATE_JAIL_CI=1 make test-jail-mutate \
  JAIL_PROOF_LOG="$phase5_evidence/root-baseline.json" \
  MUTATION_REPORT="$phase5_evidence/root.json"

sudo make test-jail-mutate \
  MUTATION_UNION="$phase5_evidence/nonroot.json,$phase5_evidence/root.json"
```

The final invocation is privileged because root reports are `0600`. Union judging checks both protection and proof-case coverage. (`scripts/jailmut/harness.go:80`, `scripts/jailmut/harness.go:90`, `scripts/jailmut/harness.go:97`, `scripts/jailmut/harness.go:149`.)

Then run on the integrated tree:

```sh
make vet
make test
make build
make test-srcmut
make selftest-testjail selftest-jailmut selftest-srcmut
make selftest-integration-strict
make test-fidelity-smoke

make test-integration-strict \
  INTEGRATION_FIXTURE="$phase5_integration_fixture"

make smoke

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o "$phase5_evidence/gate" \
  ./src/gate/cmd/sshgate-gate

file "$phase5_evidence/gate" | grep -q 'statically linked'
go run ./scripts/jailmut -check-binary "$phase5_evidence/gate"
make verify-repro

GOOS=darwin GOARCH=arm64 \
  go build -o /dev/null ./src/mcp/cmd/sshgate-mcp

GOOS=darwin GOARCH=arm64 \
  go build -o /dev/null ./src/cli/cmd/sshgate
```

Run all frozen selectors and all three real-SSH modes. The binary checker fails when metadata cannot be read; failure must not masquerade as absence of mutation settings. (`scripts/jailmut/harness.go:44`.)

Before completion:

1. Confirm every source-mutation entry ran both direct/effect leaves and green controls.
2. Confirm both independent jail unions passed without undeclared omissions.
3. Confirm every required strict Docker and real-SSH leaf passed, including ownership races, missing recovery materials and independently exercised unsupported guard/doctor negatives.
4. Confirm strict-judge negative self-tests reject skips and abnormal evidence.
5. Confirm preservation/rotation evidence retains existing pin policy and that stale/uncertain transactions cannot trigger destructive cleanup.
6. Confirm both operational documents are included in I1’s test and D’s claim audit.
7. Confirm O5 publication approval refers to the exact validated profile/recipe.
8. Record the installed-CLI/artifact release handoff without claiming it ran.
9. Review the full diff against amended BUILD-PLAN, schemas, admission/ownership rules, residuals and documentation.
10. Obtain independent high-effort verification; fix blocking findings and re-review.
11. Run one fresh final scope check against the original request and actual evidence.
12. Mark P5.1/P5.2 done only in the commits completing their acceptance; keep P5.3 deferred.

Per-step review and same-commit status updates remain required. PII review and `make preflight` precede any separately authorized push; Phase 5 authorizes no push, tag, release or deployment. (`docs/BUILD-PLAN.md:13`, `docs/BUILD-PLAN.md:25`, `docs/BUILD-PLAN.md:35`.)

**11. Principal risks and stop conditions**

| Risk | Required response |
|---|---|
| Rehearsal and final capability disagree | Reject fresh admission and use owned rollback/uncertainty handling; doctor reports before pin writing. (`src/gate/cmd/sshgate-gate/doctor.go:193`, `src/gate/cmd/sshgate-gate/doctor.go:202`.) |
| Lost doctor/upload response or late child | No retry or claim of absent effects; retain ownership until completion is established, otherwise require reconciliation. (`src/mcp/tools/add_server.go:428`, `src/mcp/tools/add_server.go:440`.) |
| Concurrent attempt removes the winner | Account-wide ownership, post-lock revalidation and identity-bound cleanup; prove both alias schedules. (`src/mcp/tools/add_server.go:235`, `src/mcp/tools/add_server.go:313`.) |
| Recovery adopts a provisional install | VERSION busy guard and terminal typed outcome; no registration until the owner releases after commit/rollback. (`src/gate/cmd/sshgate-gate/main.go:173`; `src/mcp/tools/provision.go:416`.) |
| Rotation bypasses ownership | All shared setup/rollback callers join the protocol; preserve explicit rotation semantics and pin bytes. (`src/mcp/tools/provision.go:658`, `src/mcp/tools/provision.go:667`.) |
| Recovery requires unused local materials | Detect/reconcile recovery before installation-material reads; prove absent-file cases. (`src/mcp/tools/provision.go:245`, `src/mcp/tools/provision.go:320`.) |
| Unavailable capability is mistaken for deny policy | Explicit policy verification requires complete `kernel && pinned`. (`src/gate/cmd/sshgate-gate/capability.go:153`, `src/gate/cmd/sshgate-gate/capability.go:158`.) |
| Refresh overwrites a replacement/newer observation | Independent registration and observation-token guards, separate mutations and reopened-state proof. (`src/mcp/registry/servers.go:114`, `src/mcp/registry/servers.go:295`.) |
| Partial results imply successful execution | Initialize all rows, retain transport context/skipped status and preserve earlier refusals before return. (`src/mcp/tools/run_batch.go:248`, `src/mcp/tools/run_batch.go:270`, `src/mcp/tools/run_batch.go:299`.) |
| Legacy recovery gains a fabricated claim | Distinguish unknown from measured classifier/unavailable and apply O2. (`src/gate/cmd/sshgate-gate/capability.go:134`.) |
| Repair repins or conceals unrestricted access | Preserve exact existing pin/key state, condition authorization restoration and retain explicit full-shell remediation. (`src/gate/cmd/sshgate-gate/doctor.go:89`; `src/mcp/tools/provision.go:741`.) |
| Reporting changes routing | Preserve Phase-4 cache/routing/no-retry acceptance; persisted snapshots never authorize execution. |
| Documentation enables/manufactures the label | Preserve disabled switch, literal guard and copied-label contract. (`src/gate/confine/label.go:8`; `src/gate/confine/label_test.go:143`.) |
| Operational instructions contradict the API | Audit status command and debugging skill alongside schemas and built routes. (`commands/status.md:25`; `skills/debugging-remote-servers/SKILL.md:140`.) |
| Docker skips or smoke hide missing acceptance | Strict manifests, process/package checks, judge self-tests and native SSH evidence. (`Makefile:248`, `Makefile:501`; `tests/integration/helpers_test.go:104`, `tests/integration/helpers_test.go:132`.) |
| Relaxed CI is mistaken for scoped-profile validation | Require stock restriction/profile/restoration evidence. (`.github/workflows/jail.yml:51`.) |
| Source-built success is called production compatibility | Keep the separately executed installed-CLI/staged-artifact handoff. (`Makefile:159`.) |
| Three fix rounds expose the wrong subsystem model | Stop patching, document the mechanism and redesign. (`docs/BUILD-PLAN.md:33`.) |

**Retained critique-1 remedies**

All nine remain accepted and incorporated.

| Finding | Retained requirement |
|---|---|
| Recovery pin inference | Complete pinned-kernel evidence for explicit policy; both-tier consent; separate unavailable allow/deny fixtures; unknown and legacy-tier cases. |
| Partial batch rows | Initialize all rows; mark trailing rows skipped; retain earliest refusal and the mandatory three-read Runner/SDK regression. |
| AppArmor dependency cycle | O5 outside the global gate; independently authorized A0, integrated I2 replay and separate publication approval. |
| Unreadable root report | Privileged same-host union invocation. |
| Incomplete mutation proof | Exact direct/effect leaves and markers, controls and unchanged-registration stale-observation schedule. |
| Documentation ownership | BUILD-PLAN excluded from D; `TestDocsReadJailLabels` owned by I1. |
| Artifact compatibility | Independent unsupported-artifact negatives and actual installed-CLI/staged-artifact release handoff. |
| Unnecessary row denial | Existing batch-level denial retained; no row-level schema. |
| Citations | Baseline-qualified evidence, correct source-overlay anchors, fully qualified historical model and verified frozen selectors. |