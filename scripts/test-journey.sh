#!/usr/bin/env bash
# Preparation may use the network. The test phase uses only an internal Docker network.
set -euo pipefail
cd "$(dirname "$0")/.."
docker info >/dev/null
docker compose version >/dev/null
[[ "$(uname -m)" = x86_64 ]] || { echo "Journey requires an amd64 runner (published gate architecture)" >&2; exit 1; }
: "${JOURNEY_UBUNTU_IMAGE:?Set to ubuntu:24.04@sha256:<reviewed image digest>}"
[[ "$JOURNEY_UBUNTU_IMAGE" =~ ^ubuntu:24\.04@sha256:[a-f0-9]{64}$ ]] || { echo 'Ubuntu image must be pinned by digest' >&2; exit 1; }
prep=$(mktemp -d)
export JOURNEY_PROJECT="journey-$(date +%s)-$$-$RANDOM"
export JOURNEY_IMAGE="sshgate-journey:${JOURNEY_PROJECT}"
export JOURNEY_COMPOSE_FILE="$PWD/tests/journey/fixtures/compose.yml"
cleanup() {
    result=$?
    trap - EXIT
    docker compose -p "$JOURNEY_PROJECT" -f "$JOURNEY_COMPOSE_FILE" down --volumes --remove-orphans --timeout 10 || result=1
    docker image rm "$JOURNEY_IMAGE" >/dev/null 2>&1 || true
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
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN="$toolchain" go build -o "$prep/fake-telegram" ./tests/journey/cmd/fake-telegram
fi
chmod 0755 "$prep/fake-telegram"
docker build --platform linux/amd64 --build-arg "UBUNTU_IMAGE=$JOURNEY_UBUNTU_IMAGE" -t "$JOURNEY_IMAGE" -f tests/journey/fixtures/Dockerfile "$prep"
export PATH="$prep/go/bin:$PATH"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
# The shared lock also serializes this lane with the project's other Go test processes.
flock /home/karthi/.cache/sshgate-lanes/test.lock go test -race -timeout 30m -tags journey -count=1 ./tests/journey/... "$@"
