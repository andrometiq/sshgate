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
unit_dir=$config_home/systemd/user
unit=$unit_dir/sshgate-executor.service

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
    printf '\n# Would write %s, daemon-reload, and enable --now sshgate-executor.service\n' "$unit"
    exit 0
fi
command -v systemctl >/dev/null || fail 'systemctl is required'
umask 077
mkdir -p -- "$unit_dir"
temporary=$(mktemp "$unit_dir/.sshgate-executor.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
render_unit > "$temporary"
mv -f -- "$temporary" "$unit"
systemctl --user daemon-reload
systemctl --user enable --now sshgate-executor.service
printf 'Installed %s\n' "$unit"
