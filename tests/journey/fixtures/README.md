# Journey fixture

Run from an amd64 Linux host with Docker Compose and cgroup v2:

```sh
scripts/test-journey.sh -run TestJourneyRig
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
namespace and temporary /run. Use a disposable runner, never mount the host cgroup tree or Docker
socket into it. Target homes are separate named volumes; host keys are generated separately at
startup. Targets deny user-namespace creation via seccomp and deliberately exercise classifier
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
checks the eleven-tool surface and `call` decodes structured content. `addReadOnly` creates the
SSH key via the CLI, simulates pasting its public half, provisions web1, and verifies the untouched
published gate hash. `installSigner` drives the PTY and verifies signer key isolation, then adds
web2 and requires transfer-enrollment success rather than trusting the CLI exit status alone.
J3 owns Tier-1 diagnosis, manual re-tiering/fresh candidate state, and the full scenario assertions.
The fixture logs both published and candidate gate hashes/build metadata without replacing dist.

Cleanup is registered before container startup and repeated by the shell EXIT/INT/TERM trap;
containers, volumes, temporary preparation files and the per-run image are removed. Infrastructure
failures are fatal, including unavailable Docker and systemd. Go tests run under the shared lane
lock (`JOURNEY_TEST_LOCK`, default `${XDG_CACHE_HOME:-$HOME/.cache}/sshgate-lanes/test.lock`).
Failure diagnostics here are container status only; J3's artifact collector must redact and
bound protocol/card/audit evidence before retaining it. No raw credentials or journals are dumped.
