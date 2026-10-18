#!/usr/bin/env bash
# Job records are retained so removal never destroys stored results.
set -euo pipefail

fail() { echo "uninstall-executor: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail 'run as your login user, without sudo'
[[ $(uname -s) == Linux ]] || fail 'the executor requires Linux and systemd --user'
dry_run=false
case $# in
    0) ;;
    1) [[ $1 == --dry-run ]] || fail "usage: $0 [--dry-run]"; dry_run=true ;;
    *) fail "usage: $0 [--dry-run]" ;;
esac
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
[[ $config_home == /* ]] || fail 'XDG_CONFIG_HOME must be absolute'
unit=$config_home/systemd/user/sshgate-executor.service
if $dry_run; then
    printf 'Would disable --now sshgate-executor.service, remove %s, and daemon-reload.\n' "$unit"
    printf 'Binary and job records under %s/sshgate/executor are retained.\n' "$config_home"
    exit 0
fi
command -v systemctl >/dev/null || fail 'systemctl is required'
if [[ -e $unit || -L $unit ]]; then
    systemctl --user disable --now sshgate-executor.service
    rm -- "$unit"
    systemctl --user daemon-reload
fi
printf 'Executor unit removed; binary and job records retained.\n'
