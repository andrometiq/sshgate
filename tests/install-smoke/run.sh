#!/usr/bin/env bash
# Disposable real-systemd lifecycle coverage; never operates the host's units.
set -euo pipefail
[[ ${INSTALL_SMOKE_ALLOW_PRIVILEGED:-} == 1 ]] || {
    echo 'Refusing privileged smoke: set INSTALL_SMOKE_ALLOW_PRIVILEGED=1' >&2
    exit 1
}
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
staging=$(mktemp -d)
container=''
image=sshgate-install-smoke:$$
# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup() {
    if [[ -n $container ]]; then docker rm -f "$container" >/dev/null || true; fi
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf -- "$staging"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$staging/scripts" "$staging/packaging/systemd"
cp "$repo/scripts/"{install,uninstall}-executor.sh "$staging/scripts/"
cp "$repo/packaging/systemd/sshgate-executor.service" "$staging/packaging/systemd/"
cp "$repo/tests/install-smoke/Dockerfile" "$staging/"
(cd "$repo" && CGO_ENABLED=0 GOOS=linux go build -buildvcs=false -o "$staging/sshgate-executor" ./src/executor/cmd/sshgate-executor)
docker build -t "$image" "$staging"
container=$(docker run -d --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$image")
ready=false
for ((attempt=0; attempt<60; attempt++)); do
    if docker exec "$container" systemctl is-active --quiet user@1001.service; then ready=true; break; fi
    sleep 1
done
$ready || { echo 'FAIL user manager startup' >&2; docker logs "$container"; exit 1; }
failed=0
run_case() {
    local name=$1
    if docker exec -i --user smoke \
        -e HOME=/home/smoke -e XDG_RUNTIME_DIR=/run/user/1001 \
        -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus \
        -e SMOKE_RECORD=/home/smoke/.config/sshgate/executor/j-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
        "$container" bash -se; then
        printf 'PASS %s\n' "$name"
    else
        printf 'FAIL %s\n' "$name" >&2
        failed=1
        docker exec "$container" journalctl --no-pager -n 40 || true
    fi
}
run_case install <<'CASE'
# The normal setup creates this data root before the optional executor install.
mkdir -p -m 700 "$HOME/.config/sshgate"
/opt/sshgate/scripts/install-executor.sh
systemctl --user is-enabled --quiet sshgate-executor.service
systemctl --user is-active --quiet sshgate-executor.service
# Wait for the real executor to bind its socket, not merely for systemd to fork it.
for ((i=0; i<50; i++)); do
    [[ ! -S $XDG_RUNTIME_DIR/sshgate/executor.sock ]] || break
    sleep .1
done
[[ -S $XDG_RUNTIME_DIR/sshgate/executor.sock ]]
mkdir -p "$HOME/.config/sshgate/executor"
# A valid job filename with corrupt content is retained as quarantine evidence.
umask 077
printf 'retained\n' > "$SMOKE_RECORD"
CASE
run_case reinstall <<'CASE'
before=$(systemctl --user show -p InvocationID --value sshgate-executor.service)
[[ -n $before ]]
/opt/sshgate/scripts/install-executor.sh
after=$(systemctl --user show -p InvocationID --value sshgate-executor.service)
[[ -n $after && $before != "$after" ]]
systemctl --user is-active --quiet sshgate-executor.service
CASE
run_case uninstall <<'CASE'
pid=$(systemctl --user show -p MainPID --value sshgate-executor.service)
[[ $pid -gt 0 ]]
/opt/sshgate/scripts/uninstall-executor.sh
[[ ! -e /proc/$pid ]]
[[ $(systemctl --user show -p ActiveState --value sshgate-executor.service) == inactive ]]
if systemctl --user is-enabled --quiet sshgate-executor.service; then exit 1; fi
[[ ! -e $HOME/.config/systemd/user/sshgate-executor.service ]]
[[ ! -L $HOME/.config/systemd/user/default.target.wants/sshgate-executor.service ]]
[[ -x /usr/local/bin/sshgate-executor ]]
[[ $(cat "$SMOKE_RECORD") == retained ]]
CASE
run_case deleted-unit-uninstall <<'CASE'
/opt/sshgate/scripts/install-executor.sh
pid=$(systemctl --user show -p MainPID --value sshgate-executor.service)
[[ $pid -gt 0 ]]
rm "$HOME/.config/systemd/user/sshgate-executor.service"
/opt/sshgate/scripts/uninstall-executor.sh
[[ ! -e /proc/$pid ]]
[[ $(systemctl --user show -p ActiveState --value sshgate-executor.service) == inactive ]]
if systemctl --user is-enabled --quiet sshgate-executor.service; then exit 1; fi
[[ ! -L $HOME/.config/systemd/user/default.target.wants/sshgate-executor.service ]]
[[ $(cat "$SMOKE_RECORD") == retained ]]
CASE
run_case conflict-refusal <<'CASE'
conflict=$HOME/.config/systemd/user.control/sshgate-executor.service
mkdir -p "$(dirname "$conflict")"
printf '[Service]\nExecStart=/bin/sleep infinity\n' > "$conflict"
before=$(sha256sum "$conflict")
# Do not reload here: each script must refresh the manager before checking conflicts.
if output=$(/opt/sshgate/scripts/install-executor.sh 2>&1); then echo "$output"; exit 1; fi
[[ $output == *"$conflict"* ]]
if output=$(/opt/sshgate/scripts/uninstall-executor.sh 2>&1); then echo "$output"; exit 1; fi
[[ $output == *"$conflict"* ]]
[[ $(sha256sum "$conflict") == "$before" ]]
[[ ! -e $HOME/.config/systemd/user/sshgate-executor.service ]]
[[ ! -L $HOME/.config/systemd/user/default.target.wants/sshgate-executor.service ]]
CASE
exit "$failed"
