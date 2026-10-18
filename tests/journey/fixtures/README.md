# Journey fixture

Run from an amd64 Linux host with Docker Compose and cgroup v2:

```sh
JOURNEY_ALLOW_PRIVILEGED=1 scripts/test-journey.sh -run TestJourneyRig
```

The default base is `ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac`.
Override it with `JOURNEY_UBUNTU_IMAGE`; floating image tags are rejected.
Preparation installs Ubuntu packages,
stages the exact go.mod toolchain, vendors dependencies, and bundles HEAD from the local checkout.
The controller clones that bundle into a fresh operator home. Uncommitted production changes are
not installed: commit the candidate before acceptance. The host test files themselves run from
the working tree. No repository git state is changed by the script.

All runtime containers use the same locally built image, an internal network, no published ports,
and no upstream DNS. The controller is privileged to boot actual systemd, with a private cgroup
namespace and temporary /run and /run/lock. **Privileged Docker exposes host devices:**
controller root (including the passwordless-sudo operator) can read or modify host disks.
Private cgroups, internal networking and absent bind mounts do not isolate host secrets.
The script prints this warning and refuses before Docker access unless `CI=true` (the
GitHub disposable runner) or `JOURNEY_ALLOW_PRIVILEGED=1` explicitly accepts the risk.
Use a disposable VM with no secrets; never opt in on a persistent developer host or set
`CI=true` merely to bypass this guard. Never mount the host cgroup tree or Docker socket.

A non-privileged controller with private cgroups, runtime tmpfs mounts and Docker's read-only
cgroup v2 mount has not been validated: Docker execution was unavailable during the fix review.
The guarded privileged configuration is retained pending a real boot and installer test of
that alternative; no reduced-capability isolation claim is made.

Target homes are separate named volumes; host keys are generated separately at startup. Targets deny user-namespace creation via seccomp and deliberately exercise classifier
fallback, not the jail guarantee. Go toolchain and module downloads are disabled during execution.

The installer creates sshgatesigner; the fixture does not replace its generated service unit.
Only a drop-in redirects Telegram to loopback. The PTY supplies synthetic user 424242 and token
123456:journey_fixture_only without writing terminal output to artifacts. Every operator command
and MCP launch uses a new login, activating the installer's supplementary group change.

## Fake-process contract (J1 integration)

Preparation builds `tests/journey/cmd/fake-telegram` by default. To substitute a compatible
amd64 Linux executable or launcher, set `JOURNEY_FAKE_TELEGRAM_BIN`. The image contains Python 3
and bash. `JOURNEY_FAKE_TELEGRAM_ARGS_JSON` optionally appends an argument array without shell
evaluation. The executable runs as the `journey-fake-telegram` system unit with
`--api 127.0.0.1:18080 --admin 127.0.0.1:18081 --user-id 424242`.

`TestJourneyRig` POSTs `/start` with `{"chat_id":424242}` to the admin API before installing the
signer. It waits for the signer to persist that chat through real `getUpdates` processing; the
fixture never writes the chat store. It then POSTs `/policy` with `{"policy":"approve_now"}`
for web2 transfer enrollment, verifies CLI enrollment success, restores `hold`, and checks the
fake transcript for API failures. Approval uses the actual rendered button and callback identity.

## Helpers and acceptance

`newJourneyRig` starts the containers, checks systemd and network isolation, clones HEAD and runs
`make install-local`. `rig.mcp` initializes the real installed stdio MCP process; `assertTools`
checks the eleven-tool surface and `call` decodes structured content even when `IsError=true`.
Transport/protocol failures abort; callers must assert success or the expected refusal explicitly.
`addReadOnly` creates the SSH key via the CLI, simulates pasting its public half, provisions web1, and verifies the untouched
published gate hash: `dist/gate` = installed artifact = deployed gate. `installSigner` drives the
PTY and verifies signer key isolation, then adds web2 and requires transfer-enrollment success rather than trusting the CLI exit status alone.
J3 owns Tier-1 diagnosis, manual re-tiering/fresh candidate state, and the full scenario assertions.
The fixture logs both published and candidate gate hashes/build metadata without replacing dist.

Cleanup is registered before container startup and repeated by the shell EXIT/INT/TERM trap;
containers, volumes, temporary preparation files and the per-run image are removed. An image
that was never built is tolerated; listing/removal failures or an image remaining after removal
fail the run. Infrastructure failures are fatal, including unavailable Docker and systemd. Go tests run under the shared lane
lock (`JOURNEY_TEST_LOCK`, default `${XDG_CACHE_HOME:-$HOME/.cache}/sshgate-lanes/test.lock`).
Failure diagnostics here are container status only; J3's artifact collector must redact and
bound protocol/card/audit evidence before retaining it. No raw credentials or journals are dumped.

Without Docker, run `python3 tests/journey/fixtures/check-runner.py` for the privileged guard
and cleanup failure matrix, and `go vet -tags journey ./tests/journey/...` to compile/check the
Go fixture and its in-memory MCP refusal regression. These do not prove the rig boots.

## Main-line scenarios (J3)

`TestJourneyMain` diagnoses the disabled HTTP fixture through MCP, checks Tier-1 and
unsigned-SSH refusal, then follows the documented human re-tier procedure for web1.
It installs the candidate gate on web1 through the CLI and on web2 through
`update_gate`, verifying both hashes. Immediate approval, denial/replay, restart
refusal and binary transfer exercise the real signer. Late batch approval at 240
seconds and two independent expiry requests share one five-minute window.

Each target starts `health.py` on loopback port 8080. Its user-owned
`/home/user/health.conf` initially contains `enabled=0\n`: requests return 503
and append `unhealthy: enabled=0` to `health.log`. Setting it to `enabled=1\n`
returns 200 with `ok\n`; the service rereads the file on each request.
Observer commands use Docker exec for health, file metadata and audits. Repairs and
transfers use MCP; only fixture seeding, lifecycle controls and documented human
provisioning run outside MCP.

Set `JOURNEY_ARTIFACT_DIR` to retain bounded, timestamped MCP results, Telegram
events and gate/signer audits in `main-evidence.json` before teardown. Secret
fixtures and raw journals are never retained; transfer checks scan the synthetic
sentinel in MCP results, cards, audits, live logs and service journals before
saving evidence. Missing infrastructure fails rather than skips. Compile-only
validation with `go vet -tags journey ./tests/journey/...` does not execute these
Docker scenarios.
