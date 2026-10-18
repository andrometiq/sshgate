# Journey fixture

Run from an amd64 Linux host with Docker Compose and cgroup v2:

```sh
JOURNEY_UBUNTU_IMAGE=ubuntu:24.04@sha256:<reviewed-manifest-digest> \
  scripts/test-journey.sh -run TestJourneyRig
```

The base image digest is required explicitly; floating image tags are rejected. The sandbox
used to build this fixture could not reach Docker or the image registry, so no unverified digest
is supplied. Pin the reviewed value in the CI caller. Preparation installs Ubuntu packages,
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

By default preparation builds `tests/journey/cmd/fake-telegram`. Until J1 is available, set
`JOURNEY_FAKE_TELEGRAM_BIN` to an amd64 Linux executable or executable launcher script. The image
contains Python 3 and bash. `JOURNEY_FAKE_TELEGRAM_ARGS_JSON` optionally supplies an argument array;
no shell evaluation is performed. The executable runs as the `journey-fake-telegram` system unit.
It must bind the Bot API to `127.0.0.1:18080` and any admin API to `127.0.0.1:18081`.

For `TestJourneyRig`, the fake must enqueue a private `/start` update for user/chat 424242 through
`getUpdates` and approve the actual transfer-enrollment button for web2. It must support the real
Bot API methods used by the signer. A fake that merely returns getMe succeeds at readiness but
cannot satisfy enrollment. Do not pre-write the signer's chat store. J1's policy/admin interface
must be connected to this contract when the lanes integrate; this lane does not invent that API.

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
lock. Failure diagnostics here are container status only; J3's artifact collector must redact and
bound protocol/card/audit evidence before retaining it. No raw credentials or journals are dumped.
