#!/usr/bin/env bash
# Preparation may use the network. The test phase uses only an internal Docker network.
set -euo pipefail
cd "$(dirname "$0")/.."
cat >&2 <<'WARNING'
WARNING: Journey runs a privileged controller with passwordless sudo. It can access
host devices and read or modify host disks, despite private cgroups and no bind mounts.
Use only a disposable runner with no secrets. Outside CI, read this warning and set
JOURNEY_ALLOW_PRIVILEGED=1 to accept this risk. Never use a persistent developer host.
WARNING
if [[ "${CI:-}" != true && "${JOURNEY_ALLOW_PRIVILEGED:-}" != 1 ]]; then
    echo 'Refusing privileged journey; use a disposable runner and explicitly opt in.' >&2
    exit 1
fi
docker info >/dev/null
docker compose version >/dev/null
[[ "$(uname -m)" = x86_64 ]] || { echo "Journey requires an amd64 runner (published gate architecture)" >&2; exit 1; }
: "${JOURNEY_UBUNTU_IMAGE:=ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac}"
[[ "$JOURNEY_UBUNTU_IMAGE" =~ ^ubuntu:24\.04@sha256:[a-f0-9]{64}$ ]] || { echo 'Ubuntu image must be pinned by digest' >&2; exit 1; }
prep=$(mktemp -d)
export JOURNEY_PROJECT="journey-$(date +%s)-$$-$RANDOM"
export JOURNEY_IMAGE="sshgate-journey:${JOURNEY_PROJECT}"
export JOURNEY_COMPOSE_FILE="$PWD/tests/journey/fixtures/compose.yml"
cleanup() {
    result=$?
    trap - EXIT
    docker compose -p "$JOURNEY_PROJECT" -f "$JOURNEY_COMPOSE_FILE" down --volumes --remove-orphans --timeout 10 || result=1
    # Listing distinguishes a never-built image from a daemon/inspection failure.
    if images=$(docker image ls --quiet --filter "reference=$JOURNEY_IMAGE"); then
        if [[ -n "$images" ]]; then
            docker image rm "$JOURNEY_IMAGE" || result=1
        fi
        if remaining=$(docker image ls --quiet --filter "reference=$JOURNEY_IMAGE"); then
            if [[ -n "$remaining" ]]; then
                echo "Journey image remains after cleanup: $JOURNEY_IMAGE" >&2
                result=1
            fi
        else
            result=1
        fi
    else
        result=1
    fi
    chmod -R u+w "$prep" 2>/dev/null || true
    rm -rf "$prep"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export JOURNEY_COMMIT
JOURNEY_COMMIT=$(git rev-parse HEAD)
git bundle create "$prep/source.bundle" HEAD
# Dependencies/toolchain are staged before the offline phase; installed state is never cached.
toolchain=$(awk '$1 == "toolchain" {print $2}' go.mod)
[[ -n "$toolchain" ]]
GOTOOLCHAIN="$toolchain" go mod download
GOTOOLCHAIN="$toolchain" go mod vendor -o "$prep/vendor"
cp -a "$(GOTOOLCHAIN="$toolchain" go env GOROOT)" "$prep/go"
cp -a tests/journey/fixtures "$prep/fixtures"
if [[ -n "${JOURNEY_FAKE_TELEGRAM_BIN:-}" ]]; then
    cp "$JOURNEY_FAKE_TELEGRAM_BIN" "$prep/fake-telegram"
else
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN="$toolchain" go build -buildvcs=false -o "$prep/fake-telegram" ./tests/journey/cmd/fake-telegram
fi
chmod 0755 "$prep/fake-telegram"
docker build --platform linux/amd64 --build-arg "UBUNTU_IMAGE=$JOURNEY_UBUNTU_IMAGE" -t "$JOURNEY_IMAGE" -f tests/journey/fixtures/Dockerfile "$prep"
export PATH="$prep/go/bin:$PATH"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
# The shared lock also serializes this lane with the project's other Go test processes.
test_lock="${JOURNEY_TEST_LOCK:-${XDG_CACHE_HOME:-$HOME/.cache}/sshgate-lanes/test.lock}"
mkdir -p "$(dirname "$test_lock")"
flock "$test_lock" go test -race -timeout 30m -tags journey -count=1 ./tests/journey/... "$@"
