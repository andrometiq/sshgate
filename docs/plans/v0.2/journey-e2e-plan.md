Add **`make test-journey`**: a required GitHub Actions job that drives installed binaries through MCP, substitutes a local Telegram Bot API service for phone taps, and verifies remote effects. Build the synchronous journey now; extend it as WI2 lands.

Inspection baseline: main `1fd2bd2bf91da2f78e296562b00c40f1f27973f6`. This is a plan; no files, git state, or services were changed.

**1. Architecture and installation**

```text
Go MCP client ──stdio──> sshgate-mcp
                            │
                            ├──Unix socket──> sshgate-signer-telegram
                            │                         ↕ HTTP / callbacks
                            │                  fake-telegram process
                            │
                            └──SSH──> target A / target B
                                         sshd → forced-command gate
```

After WI2, add the real `sshgate-executor`, running as the MCP user. The existing integration test already exercises Telegram and SSH, but constructs its signer and `tools.Runner` in-process; the new suite must cross the executable and MCP transport boundaries. [phase2_test.go:5](tests/integration/phase2_test.go:5), [phase2_test.go:390](tests/integration/phase2_test.go:390)

- **Controller:** disposable Ubuntu 24.04 systemd container, with separate operator and `sshgatesigner` users. Run the actual installer and generated systemd unit. Use a private cgroup namespace and temporary runtime directories; prove this fixture boots before building the scenarios. No `systemctl` shim. The installer requires systemd and creates the separate-user service. [install.sh:50](scripts/install.sh:50), [install.sh:173](scripts/install.sh:173)
- **Targets:** two independent sshd containers with separate homes, host keys and volumes. Use a dedicated journey Compose file with pinned images, unique project names and no fixed host ports. The existing fixture uses one container, `latest`, and port 2222, so reusing it unchanged would create collisions. [docker-compose.yml:1](tests/integration/docker-compose.yml:1)
- **Client:** use the already-pinned Go MCP SDK over the subprocess’s stdin/stdout; keep stderr separate. Exercise initialization, `tools/list`, and `tools/call`, decoding structured results. Never call `Runner` directly. [go.mod:12](go.mod:12), [main.go:106](src/mcp/cmd/sshgate-mcp/main.go:106), [server_alltools_test.go:125](src/mcp/server_alltools_test.go:125)
- **Observers:** fixture administration may inspect files, hashes, permissions and audits through `docker exec`. All journey operations go through the documented CLI or MCP.

Installation sequence:

1. Clone the tested commit from the runner’s local checkout into the controller’s fresh operator home. Run **`make install-local`**, establish the documented PATH, then start MCP before creating any SSH key. The local clone substitutes only for the README’s GitHub download. [README.md:39](README.md:39)
2. Run **`sshgate pubkey`**; simulate the operator’s paste into target A; run **`sshgate add web1 user@target-a --read-only`**. Test the README diagnosis and Tier-1 refusal. [README.md:54](README.md:54)
3. Drive **`sudo ./scripts/install.sh`** through a PTY, supplying synthetic user ID/token. Before its first start, install a fixture-only systemd drop-in setting `SSHGATE_TELEGRAM_API_URL=http://127.0.0.1:<port>`. This override already exists; localhost HTTP is explicitly supported. Inject `/start` through Telegram polling, rather than pre-writing the chat store. [install.sh:242](scripts/install.sh:242), [main.go:554](src/signer/cmd/sshgate-signer-telegram/main.go:554), [telegram.go:205](src/signer/backend/telegram.go:205)
4. Start a fresh operator login process to activate group membership. Follow the documented manual Tier-1 de-provision/re-add sequence; add target B at Tier 2. Assert transfer registration succeeded: `sshgate add` can return zero even when registration failed. [install-step-by-step.md:264](docs/install-step-by-step.md:264), [install-step-by-step.md:418](docs/install-step-by-step.md:418), [main.go:226](src/cli/cmd/sshgate/main.go:226)

**Test both gate identities explicitly.** `install-local` copies the committed `dist/gate` binary, although it also builds a development gate. First run an installation check using those untouched installed bytes. Then run the full candidate journey on fresh target state, provisioning with the existing `SSHGATE_GATE_BIN` override pointing to the newly built gate. Record both hashes and build metadata. At release acceptance, run the full journey using the published gate too. Never overwrite `dist/gate` to make a PR test pass. [Makefile:152](Makefile:152), [main.go:282](src/cli/cmd/sshgate/main.go:282)

The generic MCP-client path is documented; proprietary plugin installation/relaunch and the outside tester’s cold install remain distinct coverage. The owner explicitly retained the outside tester. [README.md:146](README.md:146), [WI2-WAVE3-PLAN.md:553](docs/plans/v0.2/wave3-lanes.md:553)

**2. Fake Telegram service**

Build `tests/journey/cmd/fake-telegram`, adapting the existing fake’s protocol coverage: `getMe`, `getUpdates`, `sendMessage`, both edit methods and `answerCallbackQuery`. [phase2_test.go:131](tests/integration/phase2_test.go:131)

Give it a separate controller-only administration endpoint:

| Policy | Behaviour |
|---|---|
| `approve_now` | Tap the actual rendered Approve button after card delivery. |
| `approve_after_sync_wait` | Wait for the MCP call’s terminal response, then inject the saved callback. |
| `deny` | Tap the rendered Deny button once. |
| `never` | Deliver no decision. |
| `hold/release` | Barrier used for delayed success and restart scenarios. |

Callbacks must carry the exact chat, message ID, user ID and opaque button data emitted by the signer. Support multipart reviews by identifying the actionable card, not the first message. Current callbacks already bind to the originating message. [telegram.go:517](src/signer/backend/telegram.go:517)

Retain an event transcript, model update offsets and acknowledgement, and support deliberate duplicate delivery. Unknown API methods fail the test. Capture edits—including markup—and callback answers; do not have the fake manufacture terminal card states. Disable external assessment providers.

**3. Journey tests and required evidence**

Use a small fixture HTTP service on target A: `enabled=0` produces HTTP 503 and an explanatory log; changing its configuration to `enabled=1` produces HTTP 200 with `ok\n`. This gives diagnosis and repair an observable purpose.

| Test | Exact assertions | Availability |
|---|---|---|
| **Fresh install** | MCP initializes without a key; tool names match the current public surface and omit provisioning. CLI creates a 0600 SSH key; remote authorized key becomes restricted/forced-command; deployed gate hash equals the selected artifact. Tier-1 has no `gate.pub`. | Now |
| **Useful diagnosis** | MCP reads configuration/logs and runs `df -h`/`ps`; configuration contains `enabled=0`, log identifies that condition, observer sees HTTP 503. Zero approval cards. Tier-1 write returns `read_only_server`; destination marker remains absent. A direct unsigned SSH write independently exits 77. | Now |
| **Approve immediately** | Before tap: marker absent. After tap: exact marker bytes, stdout `approved\n`, stderr empty, exit 0, `approved=true`, `auth_mode=human`. One decision card, Approved edit, one matching approved signer audit and one signed gate execution. | Now |
| **Approve a late fix** | Hold approval until 240 seconds after card delivery. Until then: configuration unchanged, HTTP 503, execution counter absent. Approve a two-command `run_batch`; configuration becomes `enabled=1`, health becomes 200/`ok\n`, counter contains exactly one line, returned outputs match exactly. One approval covers both commands; two gate execution records. | Now |
| **Deny** | Result is `approval_denied`, non-retryable; Denied edit and denied signer audit; no marker and no gate execution for that command. Re-delivering its callback causes no effect or new decision. | Now |
| **Never / tap after expiry** | Two independent requests reach terminal `approval_timeout`; neither executes. Both cards receive expiry edits. Inject a saved Approve callback only after its call returns and expiry is established: callback is refused, file remains absent, no approved/mint record appears. | Now; strengthen with OQ1 records |
| **Signer restart while pending** | On main, characterize fail-closed behaviour: stop with an unanswered card, restart, tap the old card; no write or automatic resubmission. After WI2 B, require durable pending/card identity across restart. With async installed, the same card approves the same job, which executes once and yields its result. | Safety case now; durable success after B/C |
| **Async late approval and collection** | `run(async:true)` returns its request ID before any tap. Keep it pending beyond 300 seconds, approve, collect via `await_approvals`; assert exact stdout/stderr, exit code and target bytes. Restart MCP, collect again, obtain identical result bytes and a one-line execution counter. Final card identifies the client-reported execution outcome. | After C2–C4; final display after D1a |
| **Async reveal refusal** | `run(async:true,reveal:true)` fails validation before any card, executor job or SSH execution; advice points to synchronous reveal. Include batch input rejection without adding reveal support to batches. | After C3/OQ2 |
| **Two-server secret transfer** | Seed a synthetic binary secret out of band. One SECRET TRANSFER decision produces destination content with identical size/hash and mode 0600; source remains unchanged. MCP returns matching transfer ID/count and human auth only. Both gate legs and signer audit correlate to that transfer. Sentinel plaintext is absent from MCP transcript, cards, journals and audits. A denied transfer leaves destination absent. | Now |

The current output, denial and audit contracts support these assertions. Gate audit defaults to metadata without raw output; distinguish signer decisions from actual gate execution. [run.go:32](src/mcp/tools/run.go:32), [denial.go:74](src/mcp/tools/denial.go:74), [audit.go:174](src/gate/audit.go:174), [audit.go:74](src/gate/audit.go:74)

Transfer returns metadata only, uses one approval for two host-bound legs, and records the transfer ID in the signer audit. [transfer.go:29](src/mcp/tools/transfer.go:29), [transfer.go:62](src/mcp/tools/transfer.go:62), [daemon.go:1274](pkg/signerkit/daemon.go:1274)

**Jail coverage:** the required journey targets deliberately exercise unpinned classifier fallback. Use a target seccomp profile that reliably refuses creation of user namespaces, then assert `gate doctor` and the actual read audit agree: `enforcement=classifier`, `pinned=false`, nonempty `jail_absent`. Any unexplained setup failure or exit 77 fails the journey. Do not label this a jail pass. Kernel proof remains in the existing dedicated jail workflow; ordinary integration containers already lack that guarantee. [readjail.go:142](src/gate/cmd/sshgate-gate/readjail.go:142), [audit.go:237](src/gate/audit.go:237), [E2E-TEST-STRATEGY.md:63](docs/E2E-TEST-STRATEGY.md:63)

**4. WI2 integration rules**

- **OQ1 wins:** synchronous requests request 300-second validity and expire with the wait. Assert frozen expiry, terminal timeout and rejected late tap. Do not preserve the older “card remains pending for 24 hours” expectation. [WI2-WAVE3-PLAN.md:531](docs/plans/v0.2/wave3-lanes.md:531)
- **OQ2 wins:** replace the older async-reveal success scenarios with refusal tests. The conflicting C5 expectations must be corrected in the same integration change. [WI2-WAVE3-PLAN.md:538](docs/plans/v0.2/wave3-lanes.md:538), [BUILD-PLAN-76-65.md:2191](docs/plans/v0.2/approval-lifecycle-spec.md:2191)
- B adds delivered-card persistence; C adds executor installation, async submission and result collection. Use C5 for the full journey extension rather than building a second competing async harness. [BUILD-PLAN.md:797](docs/BUILD-PLAN.md:797), [WI2-WAVE3-PLAN.md:397](docs/plans/v0.2/wave3-lanes.md:397)
- Each merged phase adds mandatory tests. Missing functionality must fail once scheduled; do not discover it dynamically and skip.

**5. CI and local execution**

Add a `journey` job to `.github/workflows/tests.yml`: every PR and push to main, no path filters, Ubuntu 24.04, read-only repository permissions, no secrets, no `pull_request_target`. Retain the existing unit job. Update its comments that currently exclude Docker tests and incorrectly group the keyless startup smoke with privileged installation tests. [tests.yml:13](.github/workflows/tests.yml:13), [smoke-fresh-install.sh:16](scripts/smoke-fresh-install.sh:16)

- **Preparation:** acquire pinned images, the `go.mod` toolchain and modules. Cache modules/build results by OS, architecture, toolchain and `go.sum`; cache image layers by fixture inputs. Never cache installed state, keys, registries or approval journals.
- **Execution:** all containers join a Docker `internal` network; fake Telegram uses controller loopback. No published ports, external DNS, real Telegram or external model calls. Set offline Go dependency/toolchain behaviour after preparation. Cold dependency acquisition is explicitly outside the isolated test phase.
- **Budget:** target ≤12 minutes warm; 20-minute test timeout, 30-minute job timeout initially. Keep the real five-minute approval window. Run late-success, never and post-expiry cases as independent concurrent requests within one window; run disruptive restart tests separately. Existing production deadlines are five minutes plus transport slack, so the old integration timeout of 300 seconds is insufficient. [timeouts.go:17](src/sigwire/timeouts.go:17), [Makefile:250](Makefile:250)
- **Flakes:** health/barrier polling with deadlines; no blind startup sleeps, tight boundary taps or automatic test reruns. Missing Docker/systemd is failure. Require the complete scenario manifest with zero skips; existing helpers currently skip infrastructure failures. [helpers_test.go:104](tests/integration/helpers_test.go:104)
- **Failure artifacts:** bounded MCP transcript, fake API events/card edits, service journals, gate/signer audits, scenario timeline, doctor output, image digests and binary hashes/build metadata. Exclude keys, token files, raw journals containing outputs and secret fixtures. Collect before teardown; always remove containers/volumes.
- **Targets:** `make test-journey` runs the same disposable fixture locally. Add it to `make e2e`; retain `test-integration` and `smoke`. [Makefile:496](Makefile:496)

**6. Builder lanes and commits**

First schedule this owner-requested work in `docs/BUILD-PLAN.md`; changes to order/scope belong there. [BUILD-PLAN.md:8](docs/BUILD-PLAN.md:8)

| Lane | Owns; small commits | Acceptance |
|---|---|---|
| **J0 — coordinator contract** | Build-plan entry; `tests/journey/README.md` with process, artifact and fake-control contracts. Base: inspected main SHA. | Review against this plan and OQ1/OQ2. |
| **J1 — fake service** | `tests/journey/faketg/**`, `tests/journey/cmd/fake-telegram/**`. Commit protocol first, policies/replay second. | `go test -race ./tests/journey/faketg/...`; API transcript and callback-binding tests. |
| **J2 — disposable rig** | `tests/journey/fixtures/**`, `rig_test.go`, `mcp_test.go`, `scripts/test-journey.sh`. Commit systemd/network feasibility first; literal installation and MCP transport second. | Script selecting `TestJourneyRig`: real service active, key isolation, offline networking, two SSH hosts, cleanup. |
| **J3 — main scenarios** | `tests/journey/sync_test.go`, `transfer_test.go`, fixture health service. Commit approval/diagnosis cases, then timing/restart safety, then transfer. Depends J1/J2. | Focused scenario runs; full journey twice during acceptance to establish stability. |
| **J4 — CI integration** | `Makefile`, `.github/workflows/tests.yml`, `docs/E2E-TEST-STRATEGY.md`, relevant testing documentation. Depends J3. | `make test-journey`, `make smoke`, `make vet`, `make test`, then `make e2e`. |
| **J5 — WI2/C5 extension** | `tests/journey/async_test.go`, durable restart cases and explicit v2 expectation updates. Separate commits for OQ1 migration, B recovery, C async/OQ2, final card reporting. | Full journey using real executor and installed services; WI2 phase acceptance. |

J1 and J2 can proceed independently after J0; the coordinator records each dependency’s merged SHA before dispatch. Builders stay within owned files and do not modify production approval/gate logic or `dist/gate`. Coordinate J4’s Makefile/docs ownership with WI2 C4/C3, whose existing contracts already own those files. [WI2-WAVE3-PLAN.md:396](docs/plans/v0.2/wave3-lanes.md:396), [WI2-WAVE3-PLAN.md:410](docs/plans/v0.2/wave3-lanes.md:410)