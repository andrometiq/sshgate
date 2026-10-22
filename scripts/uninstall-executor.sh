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
if $dry_run; then
    printf 'Would stop and disable sshgate-executor.service, remove its unit from the user manager configuration directory, and daemon-reload.\n'
    printf 'Binary and job records under %s/sshgate/executor are retained.\n' "$config_home"
    exit 0
fi
command -v systemctl >/dev/null || fail 'systemctl is required'
unit_paths=$(systemctl --user show -p UnitPath --value)
# systemd double-quotes entries with spaces and backslash-escapes other special
# characters. Only the quoting is decoded here, so escaped entries are refused.
[[ $unit_paths != *\\* && $unit_paths != *\'* ]] || fail 'user manager unit path contains unsupported backslashes or single quotes; remove the unit by hand'
decoded=$(xargs -r -n1 printf '%s\n' <<< "$unit_paths") || fail 'could not parse the user manager unit path'
mapfile -t paths <<< "$decoded"
unit_dir=''
for path in "${paths[@]}"; do
    if [[ $path == /*/systemd/user.control && $path != /run/* ]]; then
        unit_dir=${path%.control}
        break
    fi
done
[[ -n $unit_dir ]] || fail 'user manager has no persistent systemd/user.control directory'
unit=$unit_dir/sshgate-executor.service
systemctl --user daemon-reload
loaded_unit=$(systemctl --user show --property=FragmentPath --value sshgate-executor.service)
owned_unit=$(realpath -m -- "$unit")
[[ -z $loaded_unit || $(realpath -m -- "$loaded_unit") == "$owned_unit" ]] || fail "manager already loads $loaded_unit instead of $unit; remove it before retrying"
# A deleted unit file does not mean its process has stopped.
if ! systemctl --user stop sshgate-executor.service; then
    load_state=$(systemctl --user show --property=LoadState --value sshgate-executor.service)
    active_state=$(systemctl --user show --property=ActiveState --value sshgate-executor.service)
    [[ $load_state == not-found && $active_state == inactive ]] || fail 'could not stop executor'
fi
systemctl --user disable sshgate-executor.service || true
# disable can fail when the source file was deleted by hand.
for directory in "$unit_dir/"*.target.wants; do
    [[ -d $directory && ! -L $directory ]] || continue
    link=$directory/sshgate-executor.service
    [[ -L $link ]] || continue
    target=$(readlink -- "$link")
    [[ $target == /* ]] || target=$directory/$target
    if [[ $(realpath -m -- "$target") == "$owned_unit" ]]; then
        rm -- "$link"
    fi
done
if [[ -f $unit && ! -L $unit ]]; then rm -- "$unit"; fi
systemctl --user daemon-reload
systemctl --user reset-failed sshgate-executor.service 2>/dev/null || true
printf 'Executor unit removed; binary and job records retained.\n'
