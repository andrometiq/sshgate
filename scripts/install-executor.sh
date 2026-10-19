#!/usr/bin/env bash
# Run as the operator, never from the root signer installer.
set -euo pipefail

fail() { echo "install-executor: $*" >&2; exit 1; }
[[ $EUID -ne 0 ]] || fail 'run as your login user, without sudo'
[[ $(uname -s) == Linux ]] || fail 'the executor requires Linux and systemd --user'
dry_run=false
binary=''
while (( $# )); do
    case $1 in
        --dry-run) dry_run=true; shift ;;
        --binary)
            (( $# >= 2 )) || fail '--binary needs a path'
            binary=$2; shift 2 ;;
        *) fail "unknown argument: $1 (usage: $0 [--dry-run] [--binary PATH])" ;;
    esac
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
if [[ -z $binary ]]; then
    binary=$(command -v sshgate-executor) || fail 'install sshgate-executor on PATH, or pass --binary PATH'
fi
[[ -f $binary && -x $binary ]] || fail "not an executable file: $binary"
IFS= read -r -d '' binary < <(realpath -ze -- "$binary")
[[ $binary != *[\"\'\$\\]* ]] || fail 'systemd executable paths must not contain quotes, $ or backslashes'
config_home=${XDG_CONFIG_HOME:-$HOME/.config}
[[ $config_home == /* ]] || fail 'XDG_CONFIG_HOME must be absolute'

# Quote systemd strings and escape specifiers.
quote_unit() {
    local value=$1
    [[ $value != *[[:cntrl:]]* ]] || fail 'paths must not contain control characters'
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//%/%%}
    printf '"%s"' "$value"
}
exec_path=$(quote_unit "$binary")
config_env=$(quote_unit "XDG_CONFIG_HOME=$config_home")
render_unit() {
    local line
    while IFS= read -r line; do
        case $line in
            ExecStart=*) printf 'ExecStart=%s\n' "$exec_path" ;;
            Environment=*) printf 'Environment=%s\n' "$config_env" ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < "$repo/packaging/systemd/sshgate-executor.service"
}
if $dry_run; then
    render_unit
    printf '\n# Would install in the user manager configuration directory, enable and restart sshgate-executor.service\n'
    exit 0
fi
command -v systemctl >/dev/null || fail 'systemctl is required'
unit_paths=$(systemctl --user show -p UnitPath --value)
# systemd double-quotes entries with spaces and backslash-escapes other special
# characters. Only the quoting is decoded here, so escaped entries are refused.
[[ $unit_paths != *\\* && $unit_paths != *\'* ]] || fail 'user manager unit path contains unsupported backslashes or single quotes; install the unit by hand'
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
[[ ! -L $unit ]] || fail "destination is a symlink: $unit"
loaded_unit=$(systemctl --user show --property=FragmentPath --value sshgate-executor.service)
[[ -z $loaded_unit || $loaded_unit -ef $unit ]] || fail "manager already loads $loaded_unit instead of $unit"
[[ ! -e $unit || -f $unit ]] || fail "destination is not a regular file: $unit"
umask 077
mkdir -p -- "$unit_dir"
temporary=$(mktemp "$unit_dir/.sshgate-executor.XXXXXX")
backup=''
trap 'rm -f -- "$temporary"; if [[ -n $backup ]]; then rm -f -- "$backup"; fi' EXIT
render_unit > "$temporary"
if [[ -f $unit ]]; then
    backup=$(mktemp "$unit_dir/.sshgate-executor.backup.XXXXXX")
    cp -p -- "$unit" "$backup"
fi
if ! cmp -s -- "$temporary" "$unit"; then
    mv -f -- "$temporary" "$unit"
fi
systemctl --user daemon-reload
loaded_unit=$(systemctl --user show --property=FragmentPath --value sshgate-executor.service) || loaded_unit=''
if [[ ! $loaded_unit -ef $unit ]]; then
    if [[ -n $backup ]]; then
        mv -f -- "$backup" "$unit"
    else
        rm -f -- "$unit"
    fi
    systemctl --user daemon-reload
    fail "configuration-root mismatch: manager does not load $unit; previous unit restored"
fi
systemctl --user enable sshgate-executor.service
systemctl --user restart sshgate-executor.service
printf 'Installed %s\n' "$unit"
