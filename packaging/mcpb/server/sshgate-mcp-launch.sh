#!/bin/sh
# SSHGate MCPB launcher.
#
# MCPB's platform_overrides key on OS only (linux/darwin/win32) — there is no
# architecture selector in the manifest spec. So the bundle ships one binary per
# OS+arch under server/bin/ and this launcher execs the one matching the host's
# `uname -s`/`uname -m`. It forwards argv and inherits the environment (including
# SSHGATE_SIGNER_SOCK, which the manifest sets from user_config), so it is a thin
# shim: exactly equivalent to running sshgate-mcp directly on the right arch.
set -eu

dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
esac

bin="$dir/bin/sshgate-mcp-$os-$arch"
if [ ! -x "$bin" ]; then
	echo "sshgate-mcp: no bundled binary for $os/$arch (looked for $bin)" >&2
	echo "sshgate-mcp: this MCPB bundle targets linux/darwin on amd64/arm64." >&2
	exit 1
fi

exec "$bin" "$@"
