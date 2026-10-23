# Read jail (#22) Phases 6-7 plan

**Status (2026-10-23): plan v3, reviewed GO. Depends on Phase 5 being complete.**

Citations below are to the baseline the plan names; re-anchor them before building.

---

**Proposed and open. Keep the label disabled through Phase 6. Enable it only after the complete matrix, both mutation unions, retained-filesystem review, and independent whole-read-path review pass. Phase 7 includes the switch-proof transition, consumer checks, release artifact preparation, and the complete enabled-state matrix.** These are the scheduled activation prerequisites. (`docs/BUILD-PLAN.md:721`, `docs/BUILD-PLAN.md:723`, `docs/BUILD-PLAN.md:728`)

Source anchors retain v2’s pinned revisions; the critique-2 changes were checked against those sources. Repository citations are relative to SSHGate and refer to the revisions below, not concurrent working-tree edits:

- Code at `65e0916fff6c93b7c6b0c655504f3c0ce5e9c72d`, excluding concurrent working-tree edits.
- The requested main `docs/BUILD-PLAN.md` at `1069ff49f6481b04b04280a71149a11ad3316d43`.
- The Phase 3 and Phase 4 lane plans, plan v2, its two critiques, and the historical jail model. These are in the internal review notes, not in this repository.

All new files, targets, tests, receipt fields, and implementation contracts below are **proposed**, unless explicitly identified as existing. They have not been implemented or run by this lane. Both critique-2 findings are accepted, with no disputes. All eleven critique-1 corrections remain requirements. This is a complete replacement plan, not evidence that implementation or acceptance has run.

**1. Scope and entry conditions**

| Phase | Required outcome |
|---|---|
| P6.0 | Resolve transport, XFS, module-autoload, and socket-core characterizations; correct contradictory enforcement before proceeding. |
| P6.1 | Account for every classifier-corpus READ occurrence and the complete diagnostic set, with witnessed controls, correct execution routes, and exact fidelity expectations. |
| P6.2 | Demonstrate the declared behavior of every distro/configuration/privilege cell, including intentionally Absent cells; enforce those expectations in CI. |
| P7.1 | Enable the existing contract, prove the enabled production path and consumers, repeat the matrix, and prepare release bytes matching the tested candidate. |

These outcomes implement the scheduled deliverables. (`docs/BUILD-PLAN.md:682`, `docs/BUILD-PLAN.md:695`, `docs/BUILD-PLAN.md:705`, `docs/BUILD-PLAN.md:721`)

Entry conditions:

- **Phase 4 includes G, S, M, and Stage I.** Its real-producer, real-signer, stale-cache, source-mutation, and phase-end obligations remain required. Treat the Phase 4 lane plan (internal review notes) and the Phase 4 section of `docs/BUILD-PLAN.md` as the integration contract; re-anchor its implementation locations after integration.
- **Phase 5 must be complete.** P6.0 depends on it. Capability snapshots, timestamped labels, per-read `Enforcement:"unknown"`, provisioning behavior, and updated instructions must exist before P6/P7 consumer acceptance. Their absence on this early branch is not a P6 implementation defect. (`docs/BUILD-PLAN.md:625`, `docs/BUILD-PLAN.md:633`, `docs/BUILD-PLAN.md:640`, `docs/BUILD-PLAN.md:693`)
- Preserve one profile, stateless execution, confinement-required refusal, no retry after `X`, redaction, signed-write/admin independence, additive v1 wire compatibility, and the static Linux/amd64 gate boundary. No new third-party module is required. (`docs/BUILD-PLAN.md:284`)
- Use the historical jail model (internal review notes) as rationale, particularly for visible host `/tmp` and `/var/tmp`. Its old rung architecture and open-cell inventory are not current defect evidence.

Before implementation forks, the orchestrator records an immutable integrated `BASE`, relevant source-tree digest, gate build identity, exact selectors, configuration contracts, and file ownership. Re-anchor baseline-dependent citations and test roots then; do not start lanes from a moving branch.

**2. BUILD-PLAN corrections to fold before implementation**

| Existing wording or omission | Required correction |
|---|---|
| Distribution coverage omits ABI transitions. | Carry forward actual ABI 5, ABI 6, and ABI ≥9 configurations; daemon-read characterization at ABI 5/6; Debian Docker provisioning; and RPM-family interpreter/RUNPATH evidence. |
| Transport probes “both must classify `network`.” | For a block filesystem on iSCSI/NVMe-TCP, assert `Class:"block", Backing:"network"`. `Class:"network"` identifies network filesystem types. (`src/gate/confine/describe_linux.go:48`) |
| XFS direct external-log expectations are unspecified. | Preserve covering of every `logdev=` and `rtdev=` mount, including direct auxiliary devices and `accept_fs=network`. (`src/gate/confine/fstypes_linux.go:249`, `src/gate/confine/mounts_test.go:263`) |
| “Classifier corpus read rows” has no execution contract. | Freeze occurrence accounting, fixture substitutions, bounded protocols, one owner, and the intended ordinary/daemon route. The corpus contains interactive, following, network, daemon, fixture-dependent, and nonzero-exit commands. (`tests/testdata/classifier-corpus.txt:8`, `tests/testdata/classifier-corpus.txt:10`, `tests/testdata/classifier-corpus.txt:25`, `tests/testdata/classifier-corpus.txt:42`, `tests/testdata/classifier-corpus.txt:54`) |
| “Every registered set red” overstates union requirements. | Require each eligible leg’s declared outcome, complete proof-case coverage, and a red set per protection per ABI. Some multi-wall sets deliberately remain green. (`src/gate/confine/jailmut/harness/coverage.go:35`, `src/gate/confine/jailmut/harness/coverage.go:86`, `docs/TESTING.md:740`) |
| Phase-end commands do not join baseline and mutation evidence. | Preserve successful baseline JSON plus `.status`, import it into lane reports, and run `MUTATION_UNION` with sufficient privilege on the producing host. Define verified export of root-owned evidence. (`Makefile:210`, `scripts/jailmut/harness.go:80`, `scripts/jailmut/harness.go:134`, `scripts/jailmut/harness.go:149`) |
| Raw mutation evidence is assumed recoverable by the outer runner. | Extend P6.0-1 to both nested mutation runners and their self-tests: retain unique per-leg/per-entry raw events, stderr, statuses, and receipt hashes before judgment, including failures; preserve existing mutation judgments. (`scripts/jailmut/harness.go:251`, `scripts/srcmut/main.go:212`, `scripts/srcmut/main.go:328`) |
| Mandatory diagnostics are assumed to be classifier READs. | Explicitly account for non-READ `pidof` and SQLite rows through required direct-confinement diagnostics at native ABI/ABI1 and both privileges, with source-derived executable identities. Keep product routing for READ corpus and daemon rows; do not expand the classifier. (`src/gate/confine/fidelity_smoke_e2e_test.go:67`, `src/gate/confine/fidelity_smoke_e2e_test.go:71`, `src/classify/classifier.go:364`, `src/classify/classifier.go:445`, `docs/BUILD-PLAN.md:699`) |
| One generic union appears sufficient. | Require independently passing CI-host and ABI≥9-host unions. Registry expectations depend on the producing host’s ABI and probe results. (`src/gate/confine/phase3_registry_test.go:54`.) |
| Filesystem inventory and completed review are conflated. | Separate an early schema/coverage check from a mandatory activation closure check. Unresolved rows may exist during review; no unresolved retained type may pass closure. (`docs/BUILD-PLAN.md:723`.) |
| P7.1 appears to be only a constant change. | Migrate disabled-state assertions, the switch mutation, independent controls, live expectations, consumers, and documentation together. (`src/gate/confine/label_test.go:138`, `src/gate/cmd/sshgate-gate/capability_test.go:314`, `src/gate/cmd/sshgate-gate/phase22_e2e_test.go:198`, `src/gate/confine/label.go:85`) |
| Fresh local builds are treated as release-candidate execution. | Add a test-harness-only candidate path/hash contract. Final native production checks execute the verified candidate bytes without rebuilding or falling back. Record source-derived and mutation binaries separately. (`src/gate/cmd/sshgate-gate/gate_jail_e2e_test.go:38`, `src/gate/cmd/sshgate-gate/phase22_e2e_test.go:241`, `Makefile:21`, `Makefile:109`) |
| Old-gate compatibility depends on mutable dist bytes. | Preserve an immutable checksum-pinned legacy fixture before replacing `dist/gate`. Keep release-candidate and legacy execution identities separate. (`Makefile:145`.) |
| Documentation sweep omits packaging metadata and label-producer constraints. | Update MCPB descriptions as well as instructions/help. Reuse label constants in Go instructions without weakening the single-producer AST guard; cross-build clients afterward. (`packaging/mcpb/manifest.json:35`, `packaging/mcpb/manifest.json:49`, `src/gate/confine/label_test.go:143`, `Makefile:452`) |

Reconcile stale phase statuses and summaries when P3/P4 integration actually lands. Do not mark assumed integration complete in advance. (`docs/BUILD-PLAN.md:13`, `docs/BUILD-PLAN.md:54`, `docs/BUILD-PLAN.md:78`)

**3. Dependency graph and ownership**

Proposed dependency graph:

```text
P4 complete + P5 complete
          |
       P6.0-1
       freeze schemas, provisioning inputs, inventory;
       implement status-preserving outer and nested mutation runners
          |
          +---------------- filesystem source review ----------------+
          |                                                        |
       P6.0-2 characterization probes                              |
          |                                                        |
       P6.0-3 resolve findings / reviewed conditional corrections    |
          |                                                        |
       P6.1-1 freeze shared helpers and occurrence ownership        |
          |                                                        |
          +------ F: ordinary corpus / diagnostics -----+           |
          +------ D: daemon corpus / supplemental CLI --+           |
          +------ A: expected-Absent -------------------+           |
          +------ C: receipts / collection -------------+           |
          +------ M: consumer contract -----------------+           |
                                                       |           |
                                                   integration     |
                                                       |           |
                                                   P6.2 matrix     |
                                                       |           |
                        closure evidence + any required reruns <----+
                                                       |
                           P6 complete + closure + whole-path GO
                                                       |
                                                   P7.1-1
                                                       |
                                                   P7.1-2a
                                            switch-proof preparation
                                                       |
                                                   P7.1-2b
                                                   activation
                                                       |
                                                   P7.1-3
                                     candidate + complete enabled matrix
```

Record permitted internal overlap in BUILD-PLAN’s `Depends` lines before forks. P6.2 acceptance remains dependent on full P6.1 acceptance. Filesystem removals or enforcement changes invalidate affected downstream evidence and require reruns before activation. (`docs/BUILD-PLAN.md:8`, `docs/BUILD-PLAN.md:13`, `docs/BUILD-PLAN.md:717`, `docs/BUILD-PLAN.md:723`)

The following are proposed exact ownership paths. Brace lists enumerate files, not wildcard ownership.

| Owner | Exclusive paths |
|---|---|
| Early shared harness, before forks | `internal/fidelity/{manifest.go,manifest_test.go,compare.go,compare_test.go,execute.go,execute_test.go,smoke.go}`; `internal/gatecandidate/{candidate.go,candidate_test.go}`; `scripts/jailmatrix/{main.go,manifest.go,manifest_test.go,events.go,events_test.go,provision.go,provision_test.go,closure.go,closure_test.go}` |
| Shared manifests, orchestrator only | `tests/testdata/{p60-probes.json,jail-matrix.json,jail-provision-inputs.json,readsafe-review-inventory.json,readsafe-closure-fixtures.json,fidelity-occurrences.json,fidelity-smoke.json,kernel-label-release-state.json}` |
| F | `src/gate/cmd/sshgate-gate/{fidelity_full_e2e_test.go,fidelity_full_fixture_test.go}`; `src/gate/confine/fidelity_full_diagnostics_e2e_test.go`; `tests/testdata/{fidelity-ordinary.json,fidelity-diagnostics.json,fidelity-expected.txt}` |
| D | `src/gate/cmd/sshgate-gate/{fidelity_full_daemon_e2e_test.go,fidelity_go_cli_e2e_test.go,fidelity_daemon_fixture_test.go}`; `tests/testdata/{fidelity-daemon.json,fidelity-expected-daemon.txt}` |
| A | `src/gate/cmd/sshgate-gate/{expect_absent_e2e_test.go,expect_absent_fixture_test.go}` |
| C | `scripts/jailmatrix/{receipt.go,receipt_test.go,collect.go,collect_test.go}` |
| M | `src/mcp/tools/label_matrix_e2e_test.go` |
| Filesystem reviewers | Read-only source findings returned to the orchestrator; no concurrent edits to shared inventory or closure artifacts |
| P6.0-1 orchestrator — evidence retention, before forks | `scripts/jailmut/{harness.go,harness_test.go,testjail_test.go}`; `scripts/srcmut/{main.go,srcmut_test.go,regression_test.go}`; Makefile runner and self-test wiring. This includes nested runtime-leg and source-entry execution, not only the outer matrix wrapper. |
| Orchestrator/integrator | Makefile, workflows, documentation, packaging text, shared proof registries/manifests, candidate-helper adoption in existing tests, conditional production corrections, final switch, legacy fixture, generated release artifacts |

The early shared step also extracts existing smoke definitions from `src/gate/confine/fidelity_smoke_e2e_test.go` and `src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go`; those files are frozen before F/D fork. Their current execution paths differ, so extraction must preserve their assertions while making route ownership explicit. Shared smoke IDs must map to full-suite rows, including the mandatory direct-confinement diagnostics owned by F. (`src/gate/confine/fidelity_smoke_e2e_test.go:134`, `src/gate/confine/hardening_e2e_test.go:97`, `src/gate/confine/testmain_test.go:20`, `src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:73`)

F/D/A/C/M may build concurrently only after shared contracts are frozen. C adds receipt/collection implementation; changes to frozen schemas, dispatch, or helpers return to the integrator. Any additional path requires an explicit ownership amendment before editing.

All build lanes forbid production signer/wire changes, existing golden changes, architecture expansion, and hand-editing `dist/gate`. Conditional enforcement corrections get a separate reviewed contract and one production writer. (`docs/BUILD-PLAN.md:284`, `AGENTS.md:161`.)

Integrate one lane at a time. Serialize root fixture runs on a shared VM. Transport, XFS, and global-kernel-setting probes may overlap only on separate disposable guests. Existing root fixtures create users, mounts, and loop devices. (`docs/TESTING.md:630`)

**4. Common acceptance, provisioning, and evidence**

Every implementation commit receives common acceptance on a prepared capable reference host:

```sh
make vet
make test
make test-jail
sudo make test-jail-root
make test-fidelity-smoke
```

After P6.1 lands, also run:

```sh
SSHGATE_JAIL_CI=1 make test-fidelity
sudo env SSHGATE_JAIL_CI=1 make test-fidelity
```

For runtime protections added or touched, run both privilege lanes with the step’s explicit mutation filter. Record every `NOT-RUN`; phase-end coverage must resolve required omissions. Test-tooling changes receive adversarial harness tests rather than artificial runtime protection IDs. (`docs/BUILD-PLAN.md:232`, `docs/BUILD-PLAN.md:265`, `src/gate/confine/protections_test.go:113`)

**Provisioning contract**

P6.0-1 freezes a reviewed input manifest and narrowly scoped Debian-family and RPM-family provisioning recipes, proposed as `scripts/jailmatrix/provision-debian.sh` and `scripts/jailmatrix/provision-rpm.sh`.

For each configuration, require:

- Authenticated image provenance and an independently trusted expected digest or signature, verified **before boot**.
- Signed package-repository metadata, scoped repository trust keys, and recorded package/version inputs.
- Downloaded clients verified against trusted expected hashes or signatures **before installation or execution**.
- Container fixtures pinned by digest and verified before running.
- Defined toolchain versions, root toolchain locations, and root command-search paths. Root acceptance must not silently select a different `go`, compiler, or helper.
- Disposable guests with test-only keys, credentials, sockets, users, and services. Do not expose operator credentials, production sockets, or host service sockets.
- Verification failure stops before the affected image, package, client, or container is installed or executed.

Receipts record verification results and expected identities, not merely hashes measured after execution. Preserve existing CI safeguards: `contents: read`, SHA-pinned actions, and `persist-credentials: false`. This adds an acceptance constraint; it does not allege an existing insecure downloader. (`.github/workflows/jail.yml:20`, `.github/workflows/jail.yml:29`, `.github/workflows/jail.yml:34`.)

Proposed self-tests include `TestProvisioningRejectsUnverifiedInput` and `TestProvisioningStopsBeforeExecution`.

**Receipt contract**

Each receipt records:

- Source SHA, relevant source-tree digest, and intended release state.
- Configuration ID and manifest digest; authenticated image identity; kernel build/configuration; actual Landlock ABI.
- Root/non-root lane, relevant LSM/sysctl values, and executable/profile attachment identities.
- Client/toolchain versions, fixture witnesses, and cleanup outcome.
- Executable role and hash: release candidate, source-built production binary, guarded test binary, mutant, or legacy fixture.
- Native versus forced ABI, mutation set, registry/case-manifest fingerprints, and relevant memfd probe results.
- Exact commands/selectors, raw JSON events, stderr, process/logger/validator statuses, final verdict, baseline `.status`, fidelity reports, doctor/capability output, mutation reports, and host-local union verdict.
- A digest-bound artifact index covering every nested runtime leg and each source-mutation entry’s baseline and mutated execution: unique relative paths, byte sizes, hashes of raw events/stderr/status files, and links to the resulting judgment. Missing evidence is explicit failure, never an invented success status.
- For direct-confinement diagnostics, the row ID, declared route and classifier result, native/forced ABI, privilege, source revision/build inputs, source-derived test/helper executable hash, and external client identity. These rows never carry the release-candidate execution role.

The current mutation report contains privilege/CI flags, outcomes, and proofs; provenance therefore belongs in an outer receipt without changing the proof wire. (`src/gate/confine/jailmut/harness/coverage.go:10`)

**Failure-preserving outer and nested runners**

The orchestrator lands all runner changes in **P6.0-1, before scratch probes and before F/D/A/C/M fork**. Existing `jail-runner` deletes its temporary directory and exports baseline JSON only on success. Runtime mutation execution buffers child JSON/stderr and deletes its temporary status directory; source mutations also buffer output and remove temporary evidence. An outer wrapper cannot recover those discarded streams. (`Makefile:187`, `Makefile:211`, `scripts/jailmut/harness.go:255`, `scripts/jailmut/harness.go:263`, `scripts/srcmut/main.go:212`, `scripts/srcmut/main.go:328`)

The revised outer baseline/probe runner must:

1. Create a unique directory for every invocation and refuse reuse.
2. Preserve raw JSON, stderr, child exit status, logger status, validator status, and final target verdict on success and failure.
3. Validate actual package/test execution against frozen selectors: required roots and leaves must run and pass; zero matches, skips, truncated events, missing completions, and unexpected selection fail.
4. Record the **final verdict after** JSON, selector, manifest, persistence, and export checks. The existing status write precedes manifest validation and must not be retained as the final-success rule. (`Makefile:209`, `Makefile:210`)
5. Publish a successful importable baseline and its success `.status` only after all required checks and copies succeed. Keep failed raw evidence separate from that success-only interface.
6. Preserve earlier failures even if later invocations pass. Missing final status or failed evidence export fails collection.

Add self-tests for zero matches, skipped tests, malformed/truncated JSON, child failure, logger failure, successful tests followed by validator/export failure, and a later pass following an earlier failure. Preserve the existing independent process/logger status discipline. (`Makefile:191`, `Makefile:193`, `Makefile:203`, `Makefile:206`)

**Nested mutation retention, also mandatory in P6.0-1**

1. The orchestrator updates `scripts/jailmut/harness.go` and its self-tests, and `scripts/srcmut/main.go` and its self-tests, under the exclusive ownership above. Freeze their evidence-directory inputs and pass them explicitly through Makefile/matrix dispatch, including sudo. Phase acceptance must fail if nested persistence is disabled or its evidence root is missing.
2. Allocate a fresh invocation directory and distinct retained directories for every runtime `(mutation set, ABI, privilege, leg, attempt)` and every source-mutation `(entry, baseline-or-mutated, attempt)`. Bind configuration and source identity in the parent receipt. Refuse reuse; no later attempt may overwrite an earlier failure. Separate disposable build/overlay scratch from retained evidence so cleanup cannot remove the latter.
3. Persist raw JSON/stdout, stderr, launcher status, child status, timeout/signal facts, and capture/persistence status **before** invoking the existing judgment routine. Retain available partial streams and explicit missing-status/start/build/deadline errors on every early failure. Source-entry baseline and mutant evidence remain distinct; if baseline failure prevents the mutant from running, record that fact and fail the entry.
4. Judge the persisted, unchanged bytes using each harness’s existing semantics. Runtime mutation requires child exit 0 and passing package/test events with the declared finalized proof; a red outcome comes from the proof’s expected markers, not a failing Go test. Source mutation requires a passing unmutated baseline, the declared mutated red leaves failing with their exact markers, passing green controls, and matching launcher/child statuses. Do not replace either judgment with the other or with a generic exit-code check. Preserve runtime completion modes and union eligibility; setup failure, panic, timeout, malformed/missing events, or exit 1 alone never establish detection. (`scripts/jailmut/harness.go:277`, `src/gate/confine/jailmut/harness/judge.go:30`, `src/gate/confine/jailmut/harness/judge.go:88`, `src/gate/confine/jailmut/harness/coverage.go:25`, `scripts/srcmut/main.go:369`, `scripts/srcmut/main.go:440`)
5. Persist judgment results and final invocation verdict after validation and persistence checks. Receipt hashes cover raw events, stderr, all status artifacts, and judgments, including failed attempts. Evidence-write/close/hash/export failure fails acceptance even if mutation judgment would otherwise succeed. Missing final status fails collection. Preserve the success-only checked report and baseline interfaces; failed evidence must not masquerade as an importable successful report. (`src/gate/confine/jailmut/harness/coverage.go:8`, `scripts/jailmut/harness.go:144`)
6. Keep retained files through runner cleanup, failed judgment, and later retries; §9’s private privileged export includes these nested artifacts. The collector verifies every indexed digest and rejects omissions or substitutions without regenerating evidence from summary reports.

Add proposed runtime tests `TestHarnessEvidenceRetention`, `TestHarnessEvidenceIsolation`, and `TestHarnessEvidencePersistenceFailure` in `scripts/jailmut/harness_test.go`; add `TestSourceMutationEvidenceRetention`, `TestSourceMutationEvidenceIsolation`, and `TestSourceMutationEvidencePersistenceFailure` in `scripts/srcmut/srcmut_test.go`, extending existing regression fixtures where needed. Cover successful expected-red/green runs, failed baseline, undetected mutation, malformed/truncated events, missing child status, build/start/timeout errors, persistence/export failure, cleanup, and an earlier failure followed by a later pass. Assert retained byte/hash identity and unchanged judgment outcomes. Existing fixture suites are the semantic regression baseline. (`scripts/jailmut/harness_test.go:19`, `scripts/jailmut/harness_test.go:61`, `scripts/srcmut/srcmut_test.go:31`, `scripts/srcmut/regression_test.go:15`)

Wire all new roots into `selftest-jailmut`, `selftest-srcmut`, and outer-runner/collector acceptance, with exact selection checked at BASE freeze. The current runtime self-test target filters names, while source self-tests select whole packages; neither may silently omit the new retention checks. (`Makefile:234`, `Makefile:521`)

**Candidate execution contract**

Add test-harness-only inputs:

```text
GATE_TEST_MODE=source|candidate
GATE_CANDIDATE_PATH=<absolute path>
GATE_CANDIDATE_SHA256=<independently frozen expected digest>
```

In candidate mode:

- Both path and expected digest are mandatory.
- Verify bytes before staging; stage the same bytes at the configuration’s declared executable/profile path; verify the staged and executed identity.
- Missing input, wrong hash, changed bytes, or an unsuitable artifact fails before gate execution.
- Never rebuild a replacement or fall back to a source-built gate.
- Keep these inputs in test tooling; they are not production gate policy variables.
- Enumerate every production-binary build site at integrated `BASE` and migrate native candidate checks to the shared helper. Existing checks currently invoke ordinary local `go build`, which differs from the release recipe. (`src/gate/cmd/sshgate-gate/gate_jail_e2e_test.go:38`, `src/gate/cmd/sshgate-gate/phase22_e2e_test.go:241`, `Makefile:21`, `Makefile:109`)

Forced-ABI, forced-Absent, forced-unmet, mutation checks, and mandatory direct-confinement diagnostics continue using guarded/source-derived test executables, with separate hashes and roles. Direct diagnostics use source-derived executables at native ABI as well as ABI1 and remain mandatory in the final candidate matrix. They must never claim to execute the release candidate. Legacy compatibility cases use only the separately pinned legacy fixture.

Add `TestCandidateRejectsWrongHash`, `TestCandidateRequiresCompleteInputs`, and `TestCandidateNoRebuildOrFallback`. Ordinary compilation of test harnesses remains permitted; candidate selection itself cannot compile a substitute gate.

**5. P6.0 — characterization and conditional corrections**

| Step | Deliverable | Proposed acceptance |
|---|---|---|
| **P6.0-1** | Freeze probe/matrix/provisioning schemas, fixture ownership, expected observations, cleanup, and retained-filesystem inventory; implement outer-runner and nested runtime/source-mutation evidence retention, with receipt hashes and preserved judgments. | `TestMatrixManifest`, `TestP60ProbeManifest`, `TestReadSafeReviewInventory`, provisioning/outer-runner self-tests, both mutation-retention self-test suites; common acceptance. The inventory test permits explicit unresolved dispositions. |
| **P6.0-2** | Execute required characterization families on designated disposable guests; preserve detailed evidence and sanitized verdicts. | Exact execution of `TestP60BlockTransport`, `TestP60XFSExternalLog`, `TestP60BinfmtAutoload`, and `TestP60SocketCore` on their declared configurations. |
| **P6.0-3** | Resolve every finding. Correct contradictions before fidelity, or record that no correction was needed. | Existing backing tests; correction-specific permanent proofs, runner integration, targeted mutation acceptance, and common acceptance. |

P6.0 remains dependent on Phase 5. Informational probes receive no invented prevention claim or protection ID. (`docs/BUILD-PLAN.md:682`, `docs/BUILD-PLAN.md:691`, `docs/BUILD-PLAN.md:693`)

| Probe | Fixture and required observations |
|---|---|
| **iSCSI and NVMe-TCP** | Disposable target/initiator fixtures and direct-storage control. Record sysfs chains, transport metadata, mountinfo, and filesystem/journal shape. Assert `Class:block`, `Backing:network`; cover without acceptance and admit under the existing `accept_fs=network` policy. Verify jail visibility as well as classification. Choose a filesystem whose journal check does not decide the case first. (`src/gate/confine/describe_linux.go:55`, `src/gate/confine/fstypes_linux.go:143`, `src/gate/confine/fstypes_linux.go:162`, `src/gate/confine/fstypes_linux.go:217`, `src/gate/confine/fstypes_linux.go:276`) |
| **XFS auxiliary devices** | Direct data device with separate direct, loop, nbd, and network `logdev=` cases. Record actual mounted options. All remain covered, including with `accept_fs=network`. Include direct/unresolved `rtdev=` variants. (`src/gate/confine/fstypes_linux.go:249`, `src/gate/confine/mounts_test.go:263`) |
| **XFS backing I/O** | An outside observer with a health check and sealed windows. The unjailed control must produce the backing activity under test; exclude unrelated activity and require no corresponding delegated activity from the covered attempt. A cached/no-I/O control is inconclusive and fails. Existing loop-visibility evidence does not substitute for this observer. (`src/gate/confine/cover_registry_test.go:62`, `src/gate/confine/root_cover_e2e_test.go:16`, `docs/BUILD-PLAN.md:238`) |
| **binfmt autoload** | A designated kernel **below 6.14**; record cold/warm module state, trigger, helper/module observation, and control. Informational only. The existing socket-diagnostic autoload leg exercises a different trigger. (`docs/BUILD-PLAN.md:688`, `src/gate/confine/filter_m1_module_test.go:52`) |
| **Socket core handler** | A designated kernel **6.17 or newer**, dedicated receiver, and crashing fixture containing a memory nonce. Verify complete stream reception and nonce presence against an unjailed control; restore settings. Existing file/pipe crash legs do not satisfy this probe. An unexpected result requires investigation and correction of the residual statement. (`docs/BUILD-PLAN.md:689`, `src/gate/confine/proof_m2_crash_observer_test.go:70`, `src/gate/confine/crash_e2e_test.go:37`) |

Run scratch probes through the proposed common runner, for example:

```sh
go run ./scripts/jailmatrix run \
  --config "$MATRIX_CONFIG" \
  --probe p60-block-transport \
  --evidence "$E/p60-block-transport" \
  -- go -C "$P60_PROBE_DIR" test -json -count=1 \
     -run '^TestP60BlockTransport$' .
```

The frozen probe manifest supplies the expected package, root, and exact leaves. The runner must observe their `run` and `pass` events, reject zero matches and skips, preserve child status independently, and retain failure evidence. Separate manifest entries invoke the other three tests. An incompatible-kernel probe cannot become an accepted skip. This applies the workload-validation rule already required by P4.

**Conditional backing-correction contract**

A contradictory probe first produces a correction-specific reviewed contract naming:

- Exact production checks and mutation hooks.
- Existing protection identity, normally `P-BACKING`.
- Exact mutation sets, per-ABI markers, direct/effect/abort legs, green twins, completion modes, and evidence obligations.
- Exact test roots, leaves, proof-manifest entries, and baseline-runner changes.
- Required fixtures and eligibility for every privilege/ABI lane.

Possible new leg names are `U-BackingTransportObserved`, `U-XFSAuxCovered`, `L-BACKING-ISCSI`, `L-BACKING-NVME-TCP`, `L-BACKING-XFS-LOG`, and `L-BACKING-XFS-RT`. They are candidates for a correction contract, not pre-approved registrations.

Intact enforcement must retain the required cover and block the witnessed effect. The mutation removes the actual changed check and exposes the declared effect. Direct storage, explicitly accepted network backing, and unrelated covers supply green controls. Where another wall blocks the effect, register the necessary multi-wall set and its single-wall cases. Infrastructure errors never count as detection. (`src/gate/confine/cover_registry_test.go:82`, `docs/BUILD-PLAN.md:238`, `docs/BUILD-PLAN.md:241`)

Hooks, registry, proof cases, tests, and runner integration land **in the same correction commit**. If introduced, explicitly select `TestPhase6BackingTables` and require completion of `TestJailMatrixPhase6Backing`; do not assume the existing baseline selector discovers new table roots. (`Makefile:200`, `Makefile:206`)

The registry currently selects root/non-root/CI eligibility, not arbitrary matrix configurations. Every newly registered eligible effect fixture must therefore be provisioned on **both union hosts**, and on the per-step reference host where required. A scratch-VM result cannot replace a permanent leg; unavailable transport/XFS fixtures cannot become skips. (`src/gate/confine/jailmut/harness/registry.go:145`, `src/gate/confine/jailmut/harness/coverage.go:75`)

Correction acceptance includes:

```sh
go test -json -race -count=1 ./src/gate/confine \
  -run '^(TestReadSafeFstypesLiteral|TestBackingLiterals|TestBackingClass|TestBackingChains|TestBackingSCSITransports|TestBackingUnknownAncestorAndBrokenDriver|TestBackingOptionalMetadataErrors)$'

make test-jail-mutate MUTATE=P-BACKING,P-COVERS,P-SELFCHECK-MOUNTS
sudo make test-jail-mutate MUTATE=P-BACKING,P-COVERS,P-SELFCHECK-MOUNTS
```

The table invocation goes through the common JSON validator. These are existing test roots; the filter selects registered sets and does not create a combined mutation set. (`src/gate/confine/mounts_test.go:120`, `src/gate/confine/mounts_test.go:133`, `src/gate/confine/mounts_test.go:141`, `src/gate/confine/mounts_test.go:209`, `src/gate/confine/mounts_test.go:286`, `src/gate/confine/mounts_test.go:309`, `src/gate/confine/mounts_test.go:410`, `scripts/jailmut/harness.go:154`)

**6. Filesystem review — early inventory, mandatory closure**

Review every retained type individually:

```text
ext2 ext3 ext4 xfs btrfs vfat msdos exfat iso9660 squashfs
tmpfs ramfs devtmpfs devpts proc sysfs cgroup cgroup2 pstore
binfmt_misc fusectl nsfs selinuxfs
```

This is the current 23-type inventory, independently frozen by a literal test. (`src/gate/confine/fstypes_linux.go:16`, `src/gate/confine/mounts_test.go:120`)

Each review row contains:

- Kernel/source revision and configuration/provider scope.
- Reachable read, metadata, ioctl, mmap, and fsync operations and callbacks.
- Retained references and delegation to another filesystem, userspace, or host-driven network transport.
- Actual walls against mutators, with source anchors.
- Applicable **already accepted** residuals.
- Disposition: retained, removed, or unresolved.
- Review completion evidence, runtime evidence where applicable, and fidelity consequences.

Review filesystem type and backing separately: external journals, XFS auxiliaries, and the btrfs device union have distinct checks. (`src/gate/confine/fstypes_linux.go:216`)

The criterion is qualified by accepted residuals; it does not claim that reads have no physical side effects. Extensible proc, sysfs, and cgroup-provider coverage remains an explicit source-review obligation. List equality and successful probes cannot establish that criterion.

Two separate gates apply:

| Gate | Timing and rule |
|---|---|
| **`TestReadSafeReviewInventory`** | P6.0-1. Validate schema, complete inventory accounting, unique rows, required scope fields, and valid disposition values. Explicitly unresolved rows are permitted. This proves accounting, not safety. |
| **Release closure check** | Before P7.1-1. Require completed reviewed dispositions for every retained type; reject unresolved retained rows, missing evidence, stale scope/source/list identities, and “removed” types still present in code. |

Implement the closure validator with synthetic fixtures and adversarial tests, proposed as `TestReadSafeReviewClosure`. The real release gate is proposed as:

```sh
make check-readsafe-closure \
  READSAFE_CLOSURE="$CLOSURE_BUNDLE" \
  READSAFE_CLOSURE_SHA256="$CLOSURE_SHA256"
```

CI receives the real closure bundle as a versioned, immutable artifact from the reviewed release workflow. Its expected digest and provenance are explicit release inputs. The sanitized bundle includes dispositions, source/list digests, kernel/provider/configuration scope, evidence references, and completed independent review outcomes. Detailed operator notes remain local; CI must not depend on a reviewer’s local path. Missing or unverifiable closure evidence blocks activation. The validator checks evidence completeness and binding; it does not replace the substantive source review. (`AGENTS.md:150`, `docs/BUILD-PLAN.md:723`)

A failing type is removed before activation. Update its literal inventory, protections, proof cases, fidelity expectations, and affected configuration contracts together. Invalidate and regenerate affected fidelity, matrix, and mutation receipts; reopen affected source-review conclusions. P7.1-1 accepts only current evidence after those changes. If removal makes a required configuration unusable, keep activation blocked pending a concrete redesign or owner ruling. (`docs/BUILD-PLAN.md:723`)

**7. P6.1 — full fidelity**

| Step | Deliverable | Proposed tests |
|---|---|---|
| **P6.1-1 — shared contract** | Closed row schema, corpus and mandatory-diagnostic accounting, ordinary/daemon/direct-confinement routes, channel/exit comparison, narrow validators, bounded execution, shared smoke inventory, candidate integration, failure-preserving reporting. | `TestFidelityManifestValidation`, `TestFidelityCorpusAccounting`, `TestFidelityDiagnosticAccounting`, `TestFidelityRoutePreserved`, `TestFidelityComparatorRejectsCorruption`, `TestFidelityExpectedDifferenceDisappeared`, `TestFidelitySmokeSubset` |
| **P6.1-2 — F** | All ordinary-route corpus occurrences and assigned READ diagnostics, plus the mandatory non-READ direct-confinement diagnostic inventory. | `TestFidelityFull/{native,abi1}/<occurrence-id>`, `TestFidelityDirectDiagnostics/{native,abi1}/<diagnostic-id>` |
| **P6.1-3 — D** | All daemon-route corpus occurrences, supplemental grammar cases, and separately identified Go-client workloads. | `TestFidelityFullDaemonRead/{native,abi1}/<row-id>`, `TestFidelityGoCLI/{native,abi1}/{docker,kubectl}`, `TestFidelityDaemonGrammarCoverage` |
| **Integration** | `make test-fidelity`; combined smoke/full accounting, including direct diagnostics; required roots and leaves enforced at native ABI/ABI1 in both privilege lanes. | `TestFidelityTargetStatusCapture` and common acceptance |

The existing smoke assertions remain the baseline: process/socket visibility, host `/tmp`, Git, SQLite, journal, NSS/identity, native ABI, ABI1, and declared losses. (`src/gate/confine/fidelity_smoke_e2e_test.go:35`, `src/gate/confine/fidelity_smoke_e2e_test.go:63`, `tests/testdata/fidelity-expected-smoke.txt:1`)

**One occurrence manifest**

`tests/testdata/fidelity-occurrences.json` accounts for every READ occurrence exactly once. Each entry declares:

- Unique occurrence ID, source ordinal/line, exact source command, and digest.
- Exactly one owner: F for ordinary corpus occurrences, D for daemon corpus occurrences.
- Explicit intended route: ordinary or daemon.
- Fixture adaptation, rendered command, cwd, environment, stdin, and network permission.
- Independent expected control exit, stdout/stderr shapes, and required identity/nonce witnesses.
- Completion and bounded-teardown protocol.
- Comparator/projection, narrowly scoped expected difference, and applicable privilege/configuration cells.

Reject missing, duplicate, multiply owned, or silently excluded occurrences. Command digest alone is insufficient because separate corpus lines contain identical commands. (`tests/testdata/classifier-corpus.txt:138`, `tests/testdata/classifier-corpus.txt:166`)

Validate that every adapted **corpus READ command and READ diagnostic** remains READ-classified and retains its intended ordinary/daemon routing behavior. Native product fidelity goes through the gate route; final native product checks execute the candidate. Forced-ABI product rows use the guarded gate test path. Direct confinement-layer execution cannot substitute for these product-route requirements. The separately declared non-READ diagnostic route below is mandatory for its own rows. Existing ordinary smoke calls confinement directly, whereas daemon smoke invokes gate routing and checks its audit. (`src/gate/confine/fidelity_smoke_e2e_test.go:134`, `src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:73`)

Read-classified commands outside retained lane2 grammar stay on the ordinary route. Do not adapt them into admitted daemon verbs or call their socket denial a daemon-fidelity pass. Supplemental grammar and Go-client rows have distinct IDs and do not acquire second ownership of corpus occurrences. (`tests/testdata/classifier-corpus.txt:56`, `src/gate/cmd/sshgate-gate/lane2grammar.go:158`)

**Mandatory direct-confinement diagnostics**

`pidof` and `sqlite3` appear in the existing smoke inventory and execute directly through `runP12`; they are absent from the READ allowlist, whose unknown heads become WRITE. SQLite is also explicitly required by P6.1. Their absence from the corpus READ manifest must not omit them from full fidelity. (`src/gate/confine/fidelity_smoke_e2e_test.go:35`, `src/gate/confine/fidelity_smoke_e2e_test.go:67`, `src/gate/confine/fidelity_smoke_e2e_test.go:71`, `src/gate/confine/fidelity_smoke_e2e_test.go:134`, `src/classify/classifier.go:364`, `src/classify/classifier.go:445`, `src/classify/classifier.go:561`, `docs/BUILD-PLAN.md:699`)

F owns `tests/testdata/fidelity-diagnostics.json` and `src/gate/confine/fidelity_full_diagnostics_e2e_test.go`. The manifest explicitly assigns `route:direct-confinement` and stable diagnostic IDs to both existing `pidof` modes and SQLite smoke/read-query cases. Shared accounting maps every mandatory diagnostic and smoke row to exactly one full-suite owner and route; READ diagnostics remain in the ordinary or daemon product manifests. Direct diagnostic IDs cannot satisfy corpus occurrence counts or daemon grammar coverage.

For each direct diagnostic:

- Record source smoke/spec anchors, exact adapted command, expected classifier result, fixture and control witnesses, cwd/environment/stdin, independent channel/exit expectations, expected-difference category, teardown protocol, and required cells. Preserve the expected WRITE classification of these commands; do not add allowlist entries, rephrase them into READ commands, sign them as writes, or treat a signature denial as diagnostic fidelity.
- Execute the real confinement layer with `ProfileROv1`, network denied, and native ABI/forced ABI1, in **both root and non-root lanes on every capable configuration**, before and after label activation. Natural-Absent cells use §8’s explicit absence contract; they cannot claim completed diagnostic fidelity.
- Use a separately identified source-derived test/helper executable for both ABI variants. Record its source revision, build inputs, executable hash, client identity, privilege, actual ABI and any forced ABI. In candidate mode these diagnostics remain source-derived evidence tied to the candidate’s source revision; they must never be reported as executions of candidate gate bytes or introduce a production bypass.
- Preserve the held-process witness for `pidof` argv matching and the executable-mode expected loss, including the independent `/proc/<pid>/exe` denial check. Preserve SQLite `.tables` smoke coverage and add committed nonempty data with a query-result nonce; any required write failure needs its own exact expected result and unchanged-data witness. Matching empty output or failure to reach the query is not success. (`src/gate/confine/fidelity_smoke_e2e_test.go:48`, `src/gate/confine/fidelity_smoke_e2e_test.go:138`, `src/gate/confine/fidelity_smoke_e2e_test.go:191`)
- Require the same raw evidence, separate stdout/stderr/exit comparison, bounded teardown, and narrowly validated expected differences as product-route fidelity.

`TestFidelityDiagnosticAccounting` and `TestFidelityRoutePreserved` reject omitted/duplicate diagnostic IDs, loss of either `pidof` mode or SQLite coverage, wrong privilege/ABI coverage, classifier expansion, direct execution substituted for a product READ/daemon row, and signature-denial or candidate-identity substitution. `TestFidelitySmokeSubset` proves these required rows remain represented. Wire `TestFidelityDirectDiagnostics/{native,abi1}/<diagnostic-id>` into `make test-fidelity`, matrix selectors, receipts and final candidate collection; omission is failure, not a supplemental skip.

**Required fixtures**

| Family | Required coverage |
|---|---|
| Text/files/pipelines | Seeded files for cat/head/tail/grep/awk/sed/sort/uniq/diff/find; preserve semantics when substituting paths. Declare legitimate nonzero diff/search exits. |
| Interactive/following | Noninteractive pager input; producer nonce for following reads; separately recorded bounded cancellation. Timeout before the witness is failure. |
| Processes | Held identifiable processes, stable identity columns, and required PIDs. Never normalize away the owned-process witness. |
| Socket inventory | Held IPv4/IPv6 listening and established sockets; stable endpoint identities and specific permitted detail losses. |
| `/tmp`, `/var/tmp`, home | Nonempty canaries, relative reads, visible host files, and private scratch behavior. |
| Git | Nonempty history/worktree/stash/config fixtures so rows exercise content. |
| SQLite | Mandatory direct-confinement route; `.tables`, committed nonempty data, witnessed read queries, and exact declared failures where writes are required. |
| Journal/accounting/NSS | Bounded journal evidence and meaningful account/session fixtures; matching empty output is insufficient. |
| Network clients | Disposable local DNS/HTTP/TLS and other required endpoints; no-network negatives and authorized-network positive twins; no public-service dependency. |
| Ordinary daemon consumers outside lane2 | Correct ordinary route and precise expected failure where socket denial prevents execution. |

These families follow the corpus and diagnostic set. The existing corpus helper drops network and following commands and therefore cannot provide full accounting unchanged. (`tests/testdata/classifier-corpus.txt:7`, `tests/testdata/classifier-corpus.txt:42`, `tests/testdata/classifier-corpus.txt:51`, `tests/testdata/classifier-corpus.txt:63`, `docs/BUILD-PLAN.md:697`, `src/gate/confine/jail_e2e_test.go:1477`, `src/gate/confine/jail_e2e_test.go:1505`)

Compare stdout, stderr, and exit independently. Existing smoke combines control channels and generally requires zero; full fidelity needs explicit channel/exit contracts. Each expected-difference validator must reject unrelated damage and fail when the declared difference disappears. (`src/gate/confine/fidelity_smoke_e2e_test.go:128`, `src/gate/confine/fidelity_smoke_e2e_test.go:163`, `src/gate/confine/fidelity_smoke_e2e_test.go:237`)

Comparator sabotage tests must reject missing identities, matching empty/error outputs without witnesses, dropped stderr, changed exits, extra differences, disappearing expected differences, missing/duplicate rows, and normalization that removes the field under test.

**Daemon and Go-client coverage**

The retained grammar contains **eight systemctl verbs and seven Docker verbs**. Docker’s verbs are `ps`, `inspect`, `logs`, `images`, `version`, `stats`, and `top`. Derive coverage from the grammar inventory and fail when any admitted verb or required flag class lacks a case. (`src/gate/cmd/sshgate-gate/lane2grammar.go:158`, `src/gate/cmd/sshgate-gate/lane2grammar.go:171`)

Use installed clients and seeded units, containers, images, logs, and processes. Current daemon smoke covers status/show and ps/version; equality alone cannot prove complete or nonempty coverage. (`src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:22`, `src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:38`, `src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:49`)

For Go clients:

- Record CLI and available Go build metadata.
- Preserve the inherited Docker workload: logs from a 50 MiB fixture and `stats --no-stream -a`.
- Exercise substantive kubectl responses against a disposable local endpoint, using its ordinary route.
- Test network denial and authorized network separately.
- Require deadlines, completion witnesses, and clean teardown.
- Preserve signal restrictions; hangs or output loss become compatibility findings.

The below-ABI6 signal filter and P3’s substantive Docker workload motivate this coverage. Actual ABI5/6 characterization remains required in the matrix. (`src/gate/confine/seccomp_args_linux.go:204`.)

Fidelity adds compatibility evidence. If a finding requires production enforcement changes, return it to the owning protection, close the correction, and regenerate affected mutation and matrix evidence.

**8. P6.2 — expected absence, matrix, consumers, and CI**

| Step | Deliverable | Proposed tests |
|---|---|---|
| **P6.2-1A** | Natural-host expected-Absent target using production behavior. | `TestJailExpectAbsent/{doctor,unsigned,pin-deny,pin-allow,envelope-confined,envelope-net,signed-net}`, `TestAbsentTargetStatusCapture` |
| **P6.2-1C** | Strict receipts, complete lane/diagnostic accounting, nested mutation artifact hashes, verified collection, and local-union aggregation. | `TestMatrixReceiptRejectsMismatch`, `TestMatrixReceiptRequiresEveryLane`, `TestMatrixReceiptRejectsUnexpectedAbsent`, `TestMatrixReceiptRequiresBaselineStatus`, `TestMatrixReceiptRequiresNestedEvidence`, `TestMatrixReceiptRequiresDirectDiagnostics`, `TestMatrixRootEvidenceExport` |
| **P6.2-1M** | One reusable consumer contract suite. | `TestLabelSDKContract/{status,ping,list_servers,run,run_batch}/{fresh,stale,missing,old-gate}` |
| **P6.2-2** | Integrated targets, selectors, AppArmor proof, CI jobs, provisioning, and failure-artifact collection. | `TestMatrixAppArmorProfileCoverage`, `TestMatrixRequiredSelectors`, `TestMatrixPathFilterCoverage`, runner/target self-tests |
| **P6.2-3** | Complete configuration/lane receipts and label table; both independent phase-end unions. | All applicable targets, full fidelity, frozen regressions, closure-related reruns, and phase-end acceptance |

Proposed targets:

```sh
make test-jail-expect-absent MATRIX_CONFIG=<id> MATRIX_EVIDENCE="$E"
make test-jail-matrix MATRIX_CONFIG=<id> MATRIX_EVIDENCE="$E"
make selftest-fidelity
make selftest-jailmatrix
```

`MATRIX_CONFIG` controls test expectations and evidence selection only; it must not become a production policy input.

**Expected-Absent behavior**

For each predeclared Absent privilege/configuration cell:

1. `doctor --json` reports the expected stage/errno/class and host facts. Exit zero alone is insufficient because doctor can successfully report an unavailable jail. (`src/gate/cmd/sshgate-gate/doctor.go:162`, `src/gate/cmd/sshgate-gate/doctor.go:193`)
2. A witnessed unsigned, unpinned ordinary read executes once through classifier-only fallback, with expected audit/network facts.
3. `doctor --pin` refuses; no new pin appears and an existing pin remains byte-identical. Do not require the entire directory to remain unchanged because doctor acquires a lock. (`src/gate/cmd/sshgate-gate/doctor.go:184`, `src/gate/cmd/sshgate-gate/doctor.go:199`)
4. Supplied valid deny/allow pins refuse reads under the declared absent condition.
5. Unsigned confinement envelopes and valid Tier-2 signed network reads do not execute the inner command. Require denial identity, audit, and independently controlled no-execution/network witnesses.
6. MCP network requests refuse without fallback/retry, preserving Phase-4 stale-capability guarantees.
7. Tier-1 requests requiring signing remain locally refused; do not invent a Tier-1 signing path.

Use natural host absence for production-binary checks. Forced absence belongs only in guarded test binaries. Existing clamp tests cover ordinary unpinned fallback for a particular `clone:EACCES` condition and are not the full target. (`src/gate/cmd/sshgate-gate/clamp_test.go:30`, `src/gate/cmd/sshgate-gate/clamp_test.go:59`.)

Declare each expected reason before acceptance from reviewed configuration evidence. Arbitrary setup failure cannot count as Absent; classification is a closed stage/errno/fact table. (`src/gate/confine/classify.go:39`, `src/gate/confine/classify.go:68`)

**Required configurations**

| Configuration | Additional requirement |
|---|---|
| Ubuntu 22.04 | Exact image, kernel, LSM, backing, and independent root/non-root expectations. |
| Ubuntu 24.04, stock restriction, no exception | Preserve restriction; exercise declared Absent lanes without assuming identical root/non-root outcomes. |
| Ubuntu 24.04, operator profile | Restriction remains enabled; separately prove production and helper/test executable attachment. |
| Debian 12 | Working Docker daemon, required non-root access, daemon rows, and client admission evidence. |
| RHEL 9 | Actual client/interpreter/RUNPATH shapes and exact capability expectations. |
| Amazon Linux 2023 | Same configuration and client-shape evidence. |
| Actual ABI 5 | Native transition coverage plus forced ABI1. |
| Actual ABI 6 | Native signal-scope transition coverage plus forced ABI1. |
| Actual ABI ≥9 | Native Unix-socket pin enforcement and its independent phase-end union. |

The distribution families are scheduled; ABI additions are inherited P3 obligations. Exact image IDs, native ABIs, and expected reasons remain unverified by this planning lane and must be frozen before acceptance. Forced ABI1 on a newer kernel does not replace actual ABI5/6 coverage. (`docs/BUILD-PLAN.md:707`.)

For each capable privilege/configuration cell, run jail proofs and full fidelity—including mandatory direct-confinement diagnostics—at native ABI and forced ABI1, required mutations, native production doctor/pin/capability checks, and applicable consumer checks. Forced variants use separate guarded executables. An Absent cell runs the explicit absence target instead of pretending to pass a capable suite. (`docs/BUILD-PLAN.md:697`, `docs/BUILD-PLAN.md:707`)

**AppArmor proof**

`TestMatrixAppArmorProfileCoverage` must:

- Keep the restriction enabled before and after execution.
- Declare production-gate and test/helper attachment paths separately.
- Observe the executed subject after exec, using a readiness/hold witness and executable identity.
- Read the subject’s `/proc/<pid>/attr/current`, or have an executed helper report its own profile.
- Keep production gate code free of test-policy overrides; a controlled FIFO read may hold it for outside observation.
- Assert an unprofiled copy’s refusal only where that cell declares absence.
- Fail unreadable profile state, missing readiness, identity mismatch, or cleanup timeout.

Reading only the launcher’s profile or disabling the restriction does not prove attachment. Existing tests build real gates at temporary paths, while the current CI workflow globally relaxes the restriction. (`docs/TESTING.md:621`, `src/gate/cmd/sshgate-gate/phase22_e2e_test.go:237`, `.github/workflows/jail.yml:51`)

**Consumer contract**

Use **one** `TestLabelSDKContract` suite before and after activation, with an independent intended release-state expectation. Cover fresh, stale, missing, and old-gate snapshots across all five tools. Failed refresh retains the old timestamp and reports failure; no label may be reconstructed from `enforcement`. Every read result remains `Enforcement:"unknown"` with a separate host snapshot. Rerun P5’s `P-M-ENFORCEMENT-UNKNOWN` source mutation. (`docs/BUILD-PLAN.md:633`, `docs/BUILD-PLAN.md:640`, `docs/BUILD-PLAN.md:642`)

Do not add a duplicate `TestEnabledLabelSDKContract`. Separate tests are justified only for additional candidate-byte or production-execution behavior.

**CI integration**

Expose capable, root, mutation-union, fidelity, and expected-Absent results independently. The existing workflow has one non-root jail job, relaxes the restriction, and invokes `test-jail`. (`.github/workflows/jail.yml:23`, `.github/workflows/jail.yml:51`, `.github/workflows/jail.yml:94`)

Run each union’s root and non-root lanes within the same disposable guest/kernel lifecycle. Central CI aggregates locally judged, provenance-bound verdicts; it does not regenerate a registry on another host to judge heterogeneous reports.

Path filters include the gate’s transitive imports, executor, classifier/redactor/wire packages, P4 MCP/signer integration tests, harnesses, fixtures/goldens, Makefile, and workflows. The release verifier documents why a literal `src/gate/**` filter is insufficient. (`.github/workflows/verify-gate.yml:17`)

Provision systemd, Docker daemon/client, other clients, C compiler, FUSE, filesystem/transport tooling, loop devices, sufficient CPUs, and required capabilities through the verified recipes. Missing fixtures on a capable host are infrastructure failure. Collect preserved failure evidence even when an earlier step fails. (`docs/TESTING.md:619`, `docs/TESTING.md:630`, `src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:24`)

**9. Frozen selectors and phase-end acceptance**

Freeze these existing selectors without weakening assertions. Submit the invocations through the common JSON runner, which verifies the enumerated roots/leaves rather than accepting shell exit alone:

```sh
go test -json -race -count=1 ./src/sigwire \
  -run '^(TestEncodeSigned_Golden|TestEncodeSigned_NetGolden|TestEncodeSigned_RevealNetGolden)$'

go test -json -race -count=1 ./pkg/signerkit \
  -run '^(TestEnvelopeGolden_.*|TestSocketGolden_.*)$'

go test -json -race -count=1 ./pkg/signerkit/hosted \
  -run '^TestWireFrozen_.*$'

go test -json -race -count=1 ./src/mcp/sign \
  -run '^TestSignRequestWireNoNetGolden$'

go test -json -race -count=1 ./src/gate/cmd/sshgate-gate \
  -run '^(TestGateClassifyUnchanged|TestLane2CanonicalArgvGolden)$'

go test -json -race -count=1 ./src/classify \
  -run '^(TestClassify_Corpus|TestClassify_FPCorpus)$'
```

These roots exist at the verified baseline. Expand wildcard families to exact expected tests when freezing `BASE`. (`src/sigwire/payload_golden_test.go:43`, `src/sigwire/payload_net_test.go:38`, `pkg/signerkit/envelope_golden_test.go:201`, `pkg/signerkit/socketrpc_golden_test.go:86`, `pkg/signerkit/hosted/wire_frozen_test.go:36`, `src/mcp/sign/client_net_wire_test.go:32`, `src/gate/cmd/sshgate-gate/classify_invariant_test.go:20`, `src/gate/cmd/sshgate-gate/lane2_endpoint_test.go:209`, `src/classify/classifier_test.go:16`, `src/classify/classifier_test.go:162`)

Also freeze integrated P4 G/S/M/Stage-I selectors, every `p43`/`p44` source-mutation entry, P5 label/enforcement/provisioning selectors, and every required P6/P7 root and manifest leaf. Missing or non-leaf workloads fail validation.

Run the following sequence **twice**: once on the designated capable CI host and once on the ABI≥9 host. Use fresh evidence directories and the verified root toolchain environment:

```sh
SSHGATE_JAIL_CI=1 make test-jail \
  JAIL_BASELINE="$E/nonroot-baseline.json"

SSHGATE_JAIL_CI=1 make test-jail-mutate \
  JAIL_PROOF_LOG="$E/nonroot-baseline.json" \
  MUTATION_REPORT="$E/nonroot.json"

sudo env SSHGATE_JAIL_CI=1 make test-jail-root \
  JAIL_BASELINE="$E/root-baseline.json"

sudo env SSHGATE_JAIL_CI=1 make test-jail-mutate \
  JAIL_PROOF_LOG="$E/root-baseline.json" \
  MUTATION_REPORT="$E/root.json"

sudo env SSHGATE_JAIL_CI=1 make test-jail-mutate \
  MUTATION_UNION="$E/nonroot.json,$E/root.json"

make selftest-testjail selftest-jailmut selftest-srcmut
make selftest-fidelity selftest-jailmatrix
make test-srcmut

SSHGATE_JAIL_CI=1 make test-fidelity
sudo env SSHGATE_JAIL_CI=1 make test-fidelity
```

The matrix runner preserves each command’s status/output under unique invocation paths and explicitly supplies retained evidence roots to both nested mutation runners. Receipts hash and index every runtime leg and each source entry’s baseline/mutant raw events, stderr, statuses and judgment, including failed attempts. Preserve each baseline’s `.status`. Validate matching source/configuration identities and registry fingerprints before accepting the pair. The union requires one root and one non-root CI report and checks both mutation outcomes and proof-case coverage. (`src/gate/confine/jailmut/harness/coverage.go:35`, `scripts/jailmut/harness.go:90`, `scripts/jailmut/harness.go:97`)

The union must run privileged: reports are created with mode `0600`, and union mode opens them directly. (`scripts/jailmut/harness.go:80`, `scripts/jailmut/harness.go:149`)

After local judgment, the proposed collector performs privileged export of the exact receipt-listed root artifacts into a fresh collector-owned directory, mode `0700`, with files mode `0600`. It verifies copied bytes against original digests, preserves originals, includes nested runtime-leg and source-entry raw evidence, failure traces and final statuses, and refuses missing, substituted, or incomplete artifacts. It must not make the originals broadly readable or depend on pre-existing permissive files. Central collection verifies exported hashes and the local-union receipt; it does not rerun union judgment elsewhere.

Retain the static-build and reproducibility gate:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -o "$E/gate-source-check" ./src/gate/cmd/sshgate-gate

file "$E/gate-source-check" | grep -q 'statically linked'
go run ./scripts/jailmut -check-binary "$E/gate-source-check"
make verify-repro
make verify-no-sqlite-local verify-no-humanauth-local
```

Record that executable as a source-derived check, not the release candidate. Final candidate checks additionally inspect the actual candidate bytes. These gates supplement runtime acceptance. (`docs/BUILD-PLAN.md:271`, `Makefile:111`, `Makefile:288`, `Makefile:306`)

**10. P7.1 — switch transition and enabled behavior**

| Step | Deliverable | Acceptance |
|---|---|---|
| **P7.1-1 — close prerequisites** | Current P6 receipts, both unions, completed filesystem closure, and independent whole-read-path GO against contract/residuals. | Closure/receipt validation, frozen regressions, all blocking review findings resolved. |
| **P7.1-2a — prepare proof** | Mutation effective in either switch state; independent controls and live expectations migrated while production remains disabled. | Existing label tables/proof legs, proposed `TestKernelLabelReleaseState`, targeted mutations in both lanes. |
| **P7.1-2b — activate** | The only step setting `KernelLabelEnabled=true`; enabled live assertions and documentation expectations. | `TestGateBinaryEnabledLabelContract`, shared `TestLabelSDKContract`, existing label proofs, common acceptance. |
| **P7.1-3 — final candidate** | Immutable legacy fixture, generated candidate, complete enabled matrix/unions, publication-ready contract and verified artifacts. | All P6 acceptance again, candidate-mode native checks, separate guarded/mutation checks, legacy compatibility, reproducibility/preflight. |

Activation cannot precede closure merely because code or tests are ready. (`docs/BUILD-PLAN.md:723`, `docs/BUILD-PLAN.md:728`)

**Switch-proof transition**

Retain protection `P-G-LABEL-SWITCH`, direct leg `U-LabelContract`, live leg `G-JAILVERB-LABEL`, and marker identity `EFFECT:label` / rendered `MUTATION-EFFECT label`. (`src/gate/confine/phase2_registry_test.go:69`, `src/gate/confine/proof_cases_phase2_test.go:46`)

Change the mutation from “force enabled” to **invert the supplied switch**. The current `enabled || hook` becomes inert once production is enabled. (`src/gate/confine/label.go:85`)

Migrate together:

- Test both explicit switch values and the live compiled policy.
- Replace the unconditional `!KernelLabelEnabled` obligation with an independently declared intended release-state check.
- Use literal/table expected labels as controls; mutated `Label` calls are attempts, not control oracles.
- Make the live leg detect disagreement with intended policy, rather than any occurrence of the enabled label.
- Derive claim eligibility independently from checked facts, not a second call to mutated `Label`.
- Preserve exact completion and marker obligations.

The existing direct control calls the mutated function, and the live leg derives `claimable` the same way. Those controls must change with inversion. (`src/gate/cmd/sshgate-gate/capability_test.go:314`, `src/gate/cmd/sshgate-gate/phase22_e2e_test.go:201`)

Preserve `TestLabelTable`, `TestLabelNeverClaimsReadOnlyWrongly`, `TestLabelCallersPassTheSwitch`, and string-contract coverage in `TestLabelStringsMatchBuildPlan`. Replace only the temporary disabled-state assertion; update hardcoded doctor/capability expectations in the same transition. (`src/gate/confine/label_test.go:18`, `src/gate/confine/label_test.go:70`, `src/gate/confine/label_test.go:120`, `src/gate/confine/label_test.go:138`, `src/gate/cmd/sshgate-gate/doctor_test.go:312`, `src/gate/cmd/sshgate-gate/phase22_e2e_test.go:435`)

Targeted acceptance, using the common JSON validator for test invocations:

```sh
go test -json -race -count=1 ./src/gate/confine \
  -run '^(TestLabelTable|TestLabelNeverClaimsReadOnlyWrongly|TestLabelStringsMatchBuildPlan|TestLabelCallersPassTheSwitch|TestKernelLabelReleaseState)$'

go test -json -race -count=1 ./src/gate/cmd/sshgate-gate \
  -run '^TestPhase2Tables$/^(native|abi1)$/^U-LabelContract$'

make test-jail-mutate MUTATE=P-G-LABEL-SWITCH
sudo make test-jail-mutate MUTATE=P-G-LABEL-SWITCH
```

The direct leg resides under `TestPhase2Tables`; the live leg resides under `TestJailMatrixPhase2` and remains required by common/mutation acceptance. (`src/gate/cmd/sshgate-gate/readjail_test.go:211`, `src/gate/cmd/sshgate-gate/phase2_e2e_test.go:26`)

**Capability observations**

`doctor` and `SSHGATE_JAIL` observe the host’s unsigned `:` probe. That probe has no per-command signed grant, and doctor embeds its capability result. These interfaces cannot prove how a particular signed-network or daemon command executed. (`src/gate/cmd/sshgate-gate/capability.go:18`, `src/gate/cmd/sshgate-gate/capability.go:55`, `src/gate/cmd/sshgate-gate/doctor.go:287`)

Check both interfaces against applicable native observations:

| Capability state | Expected enabled label |
|---|---|
| Valid deny pin; successful strict `ro-v1`; no unmet clause; no effective network | `read-only (kernel)` |
| Unpinned successful ordinary kernel probe; no effective network; **no unmet clauses** | `classifier-only (jail available; pin to claim)` |
| Unpinned kernel probe with unmet clauses | `classifier-only` |
| Valid allow pin; successful strict networked probe | `kernel-jailed, network open — not read-only` |
| Damaged pin, failed setup, pinned Absent, or strict unmet clause | `reads denied (jail unavailable)` |
| Unpinned Absent probe | `classifier-only` |

These are existing label rules. Guarded forced scenarios supplement native evidence and are identified separately. (`src/gate/confine/label.go:49`, `src/gate/confine/label.go:71`, `src/gate/confine/label.go:89`)

**Command-execution assertions**

Use audit records plus independent execution/network/socket witnesses:

| Command scenario | Required evidence |
|---|---|
| Ordinary strict deny-pin read | Actual kernel confinement, no effective network, required output/fixture witness, and no replay. |
| Signed network read or pin-authorized network envelope | Required confinement and authorized network behavior; positive listener witness and audit facts. A capability snapshot is not its execution result. |
| Damaged pin or setup failure | Correct refusal and no inner-command witness. |
| Unpinned Absent ordinary read | One classifier fallback with expected audit/network behavior. |
| Required-confinement read on an Absent host | Refusal before inner execution; no fallback/retry. |
| Retained daemon read | Actual daemon route, correct admitted client/socket, jailed network denial, and meaningful daemon result. Test permitted natural fallback separately. |

The ordinary and daemon audit paths are distinct, and daemon confinement explicitly disables network. Phase 4 supplies the signed-network/envelope and stale-cache guarantees. (`src/gate/cmd/sshgate-gate/readjail.go:143`, `src/gate/cmd/sshgate-gate/readjail.go:205`, `src/gate/cmd/sshgate-gate/readjail.go:222`.)

Keep dedicated daemon-label string coverage in `Label` tests. Do not invent a command-label field in capability APIs or MCP results. Per-command tool `Enforcement` remains `"unknown"`; the authoritative command record remains the gate audit. (`src/gate/confine/label.go:53`, `docs/BUILD-PLAN.md:640`, `docs/BUILD-PLAN.md:673`)

**11. Artifacts, final matrix, and publication content**

Before replacing `dist/gate`, preserve the pre-network legacy bytes as a checksum-verified immutable fixture under proposed `tests/testdata/gate-legacy/`, with origin commit and digest metadata. Redirect old-gate cases to it without changing their identities or assertions. Tests must neither download old artifacts nor rely on shallow-history availability. P4 currently binds those cases to mutable dist bytes.

Add `TestLegacyGateFixtureDigest` and `TestLegacyGateFixtureRejectsNetworkWire`. Release-artifact identity checks may be named `TestReleaseGateLabelContract`, but must reuse the shared execution/consumer contracts rather than duplicate their matrices.

Generate candidate bytes only with:

```sh
make release-gate
make verify-dist
make verify-repro
make preflight
```

Freeze the resulting candidate digest and source/build provenance before the final matrix. Installation stages committed dist bytes, so source-only validation cannot establish installed behavior. (`Makefile:81`, `Makefile:109`, `Makefile:145`, `scripts/install.sh:65`)

For each final native production cell:

```sh
make test-jail-matrix \
  MATRIX_CONFIG="$MATRIX_CONFIG" \
  MATRIX_EVIDENCE="$E" \
  GATE_TEST_MODE=candidate \
  GATE_CANDIDATE_PATH="$CANDIDATE" \
  GATE_CANDIDATE_SHA256="$CANDIDATE_SHA256"
```

The integrated matrix target passes those inputs explicitly into both privilege lanes and every native production helper. Candidate mode must execute the verified staged bytes; forced, mutation, and mandatory direct-confinement diagnostic rows remain separately identified source-derived checks. Legacy rows remain separately identified legacy executions. Any relevant source, artifact, configuration, or review-scope change invalidates affected receipts and requires regeneration before P7 completion.

Run the complete enabled matrix and both host-local unions again. Require candidate hash verification, AppArmor attachment evidence where applicable, shared SDK contract acceptance, closed filesystem evidence, whole-path GO, and artifact/source consistency. The release verifier rebuilds the artifact and rejects tracked dist drift. (`docs/BUILD-PLAN.md:728`, `.github/workflows/verify-gate.yml:44`)

**Publication contract**

Publish the complete contract and not-covered list together in README, THREAT-MODEL, MCP instructions, and relevant packaging/help text. Include accepted filesystem opt-ins, network permissions, timestamped host capabilities, daemon distinctions, and declared fidelity losses. Reuse label constants in Go instructions and retain the AST guard; cross-build Darwin clients after shared-constant dependency changes. MCPB arm64 clients do not expand the remote gate’s amd64-only boundary. (`docs/BUILD-PLAN.md:735`, `docs/BUILD-PLAN.md:752`, `src/gate/confine/label_test.go:143`, `Makefile:33`, `Makefile:452`)

The published contract must retain these points:

- **Files:** a labelled read cannot change contents, metadata, or directories on reachable filesystems except its private `/dev/shm`; cannot open device nodes other than the six rebound ones or write any except `/dev/null`; cannot write or resize an existing host FIFO. Unreviewed filesystem types remain hidden unless explicit `accept_fs` policy opts network filesystems or autofs in.
- **Local daemons:** ordinary labelled reads cannot contact them through sockets or delegating filesystems; host System V/POSIX IPC and kernel keyrings remain inaccessible.
- **Other processes:** cannot signal, trace, retune, or read another process’s memory, file descriptors, or environment outside the jail.
- **Kernel settings:** cannot change mounts, namespaces, or sysctls, or exercise capabilities in the initial user namespace.
- **Network:** cannot open IPv4/IPv6 sockets without permission; an approved networked execution does not receive the kernel-read-only label.

These are the scheduled publication claims, subject to completed activation prerequisites. (`docs/BUILD-PLAN.md:737`)

Retain the complete not-covered list on the same page:

> Kernel bugs; module autoload; crash dumps to a socket `core_pattern` handler; page cache and shared machine resources, including CPU-timer accounting on other processes; shared file locks; FIFO drain by reading; filesystem housekeeping triggered by reads; exposure of a hidden mount by something outside the read; root-registered fixed `binfmt_misc` interpreters; abstract socket name squatting; automount with `accept_fs=autofs`; driver-specific proc and sysfs side effects; notification events and kernel log lines; data the SSH user can already read; declared fidelity losses; best-effort cleanup of descendants; audit and output stalls on a stalled filesystem; daemon-read verbs with their own label; classifier-only and unpinned hosts; and signed writes, which run unconfined by design.

(`docs/BUILD-PLAN.md:752`)

Artifact preparation does not authorize pushing, tagging, release publication, or deployment. Those remain separate explicitly authorized actions.

**12. Owner questions**

None now. Both critique-2 edits and the retained critique-1 corrections require no owner decision.

If filesystem/provider review cannot establish the existing contract, keep activation blocked while preparing reviewed removal or redesign. Only a concrete proposal for a narrower guarantee or additional residual raises an owner question; include its consequences and evidence. Present that decision here as one plain-language question with exactly two tap answers: the recommended answer first and one alternative. Do not ask the owner to approve an unspecified future exception.

No silent scope reduction, broader trust assumption, or unreviewed runtime restriction is permitted. The label function checks run/profile/ABI facts rather than a distro/kernel allowlist. (`docs/BUILD-PLAN.md:723`, `src/gate/confine/label.go:71`.)

Wire/schema changes and irreversible rollout are outside this plan; a finding requiring them returns to a separate reviewed proposal. (`docs/BUILD-PLAN.md:31`, `docs/BUILD-PLAN.md:284`)

**13. Risks and completion rule**

| Risk | Required handling |
|---|---|
| Incomplete extensible-provider review | Block activation; runtime success cannot substitute for positive source review. |
| Distro label hides kernel, LSM, backing, or privilege differences | Freeze configuration-level expectations; unexpected absence fails. (`docs/BUILD-PLAN.md:707`, `src/gate/confine/classify.go:68`) |
| Fidelity passes on empty results or matching errors | Independent witnesses, declared exits, separate channels, and adversarial comparators. (`src/gate/cmd/sshgate-gate/fidelity_daemon_e2e_test.go:49`) |
| Forced ABI1 masks real ABI5/6 behavior | Retain actual transition kernels and signal restrictions. (`src/gate/confine/seccomp_args_linux.go:204`.) |
| Fixture interference or inadequate observers | Serialize shared-host runs, isolate global-setting probes, and fail missing controls or cleanup. (`docs/TESTING.md:630`, `docs/BUILD-PLAN.md:238`) |
| Stale or heterogeneous reports satisfy acceptance | Bind identities and judge each union on its producing host. (`scripts/jailmut/harness.go:73`, `src/gate/confine/phase3_registry_test.go:54`) |
| Snapshot presented as command enforcement | Keep timestamped host capabilities separate from per-command unknown; use audit/witnesses for execution. (`docs/BUILD-PLAN.md:633`, `docs/BUILD-PLAN.md:673`) |
| Locally rebuilt gate presented as release evidence | Candidate mode has no rebuild/fallback; record each executable role and hash separately. (`src/gate/cmd/sshgate-gate/gate_jail_e2e_test.go:38`, `Makefile:109`) |
| Dist refresh destroys legacy-case meaning | Freeze and verify legacy bytes before replacement. |
| Failed raw evidence appears successful or disappears inside a mutation runner | Persist nested raw events/statuses before judgment; retain failures and hash every artifact; final verdict follows validation/export; importable success marker is published last. (`Makefile:209`, `Makefile:210`, `Makefile:211`, `scripts/jailmut/harness.go:251`, `scripts/srcmut/main.go:328`) |
| Non-READ diagnostics disappear from fidelity or pass on signature denial | Mandatory direct-confinement diagnostic accounting, both privileges/ABIs, source-derived identity, and meaningful controls; preserve product routing and classifier scope. (`src/gate/confine/fidelity_smoke_e2e_test.go:67`, `src/gate/confine/fidelity_smoke_e2e_test.go:71`, `src/classify/classifier.go:364`, `docs/BUILD-PLAN.md:699`) |

P7 is complete only when the enabled candidate’s entire matrix and both unions pass, filesystem and whole-read-path reviews are closed, consumer/documentation contracts agree, and release artifact bytes are verified. (`docs/BUILD-PLAN.md:723`, `docs/BUILD-PLAN.md:728`, `docs/BUILD-PLAN.md:731`)

This lane changed no files or Git state and ran no builds, tests, VM probes, or release actions. The commands and tests above define proposed implementation acceptance.

**Changelog against critique pass 2**

| Finding | Change |
|---|---|
| **1 — Minor: nested mutation evidence is discarded** | §§2–5 explicitly assign both runners and their self-tests to P6.0-1’s orchestrator; require unique per-leg/per-entry directories, persistence before unchanged judgment, failure retention, and raw-event/status hashes. §§8–9 enforce nested collection and private export. |
| **2 — Minor: mandatory non-READ diagnostics need explicit accounting** | §§3–4 and 7–11 require F-owned direct-confinement `pidof`/SQLite rows at native ABI/ABI1 and both privileges, with separate source-derived identity and strict accounting. Product READ/daemon routing and the classifier remain unchanged; signature denial cannot pass fidelity. |

All eleven critique-1 corrections remain in the plan. No critique-2 finding is disputed; no owner question is pending.