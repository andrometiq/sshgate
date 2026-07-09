#!/usr/bin/env bash
# install.sh — single-entry SSHGate installer (v1.1).
#
# One idempotent pass that:
#   1. Creates the `sshgatesigner` system user (if missing).
#   2. Creates the /var/lib/sshgatesigner/ skeleton (idempotent).
#   3. Adds the invoking user ($SUDO_USER) to the `sshgatesigner` group.
#   4. Copies binaries to /usr/local.
#   5. Writes the hardened systemd unit (overwrites every run — the unit
#      is the source of truth).
#   6. Runs `sshgate-signer-telegram --init` if the signing key is missing.
#   7. Configures the Telegram approval backend in the SAME pass: prompts for
#      the numeric Telegram user_id, appends the [backend.telegram] block, and
#      flips the backend type from "stub" to "telegram" — so one run reaches
#      both the user_id and the token prompt (no hand-edit + second pass).
#   8. Prompts for the Telegram bot token now that the backend is selected
#      and no token file exists yet (echo off).
#   9. Enables + starts the unit and asserts it came up.
#
# Run from anywhere; the script resolves its repo root from $0. Expects:
#
#     <repo>/bin/sshgate-mcp
#     <repo>/bin/sshgate-signer-telegram
#     <repo>/dist/gate/sshgate-gate-linux-amd64  (committed, CI-verified — §11)
#
# Build them first with `make install-local` (the canonical command used
# throughout the install docs; it runs `make build` plus stages binaries
# onto your PATH and the gate cross-binary into ~/.config/sshgate/bin/).
#
#     sudo ./scripts/install.sh
#
# Idempotent: re-running upgrades the binaries in place, restarts the
# daemon, and repairs permissions on the state dir.
#
# Exit codes (per cli.md §2):
#   0  success
#   1  generic runtime failure
#   66 input file missing  (EX_NOINPUT)
#   77 not root            (EX_NOPERM)
#   78 misconfigured       (EX_CONFIG)
set -euo pipefail

log() { printf '[install] %s\n' "$*" >&2; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    printf '[install] ERROR: must run as root (try: sudo %s)\n' "$0" >&2
    exit 77
fi

# systemd guard: the signer runs as a systemd unit. Fail clean up front
# (before any filesystem/user changes) rather than half-installing on a
# host without systemd.
if ! command -v systemctl >/dev/null 2>&1; then
    printf '[install] ERROR: systemctl not found; SSHGate'\''s signer requires systemd. Aborting before making changes.\n' >&2
    exit 78
fi

# Resolve repo root from this script's location so the operator can
# invoke install.sh from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SSHGATE_MCP_BIN="$REPO_ROOT/bin/sshgate-mcp"
SIGNER_BIN="$REPO_ROOT/bin/sshgate-signer-telegram"
# Ship the COMMITTED, CI-verified gate (verified release channel, §11) — NOT a
# locally-rebuilt bin/ copy, which would be a second, unverified gate outside
# the channel (MED-3). This is the same published artifact update_gate pushes.
GATE_BIN="$REPO_ROOT/dist/gate/sshgate-gate-linux-amd64"

# Probe binaries before touching the system (plugin.md §8.5 — external
# tools probed with a clear error). We check sshgate-mcp too so a fresh
# install doesn't half-succeed and leave the operator wondering why the
# MCP server isn't there.
for bin in "$SSHGATE_MCP_BIN" "$SIGNER_BIN"; do
    if [ ! -f "$bin" ]; then
        printf '[install] ERROR: %s not found; run `make install-local` in your clone first\n' "$bin" >&2
        exit 66
    fi
done
# The gate gets its own message: it is the COMMITTED, CI-verified artifact
# (verified release channel, §11) — `make install-local` COPIES it but cannot
# recreate it, so pointing there would bounce the operator through a command
# that cannot fix the problem.
if [ ! -f "$GATE_BIN" ]; then
    printf '[install] ERROR: %s not found; it is the committed, CI-verified artifact — restore it with `git checkout -- dist/gate/` (or a fresh clone), or rebuild it with `make release-gate`\n' "$GATE_BIN" >&2
    exit 66
fi
if [ ! -x "$SIGNER_BIN" ]; then
    printf '[install] ERROR: %s not executable\n' "$SIGNER_BIN" >&2
    exit 66
fi

SIGNER_HOME="/var/lib/sshgatesigner"
SIGNER_RUN="/run/sshgatesigner"

# Step 1: create the system user (idempotent).
if getent passwd sshgatesigner >/dev/null 2>&1; then
    log "user sshgatesigner exists; skipping useradd"
else
    log "creating system user sshgatesigner"
    # Probe for nologin — its path varies across distros (Debian/RedHat
    # use /usr/sbin, others /sbin or /usr/bin). Fall back to /bin/false
    # so useradd never fails on a missing nologin.
    NOLOGIN="$(command -v nologin || true)"
    for c in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin; do
        [ -x "$c" ] && NOLOGIN="$c" && break
    done
    [ -n "$NOLOGIN" ] || NOLOGIN=/bin/false
    useradd \
        --system \
        --shell "$NOLOGIN" \
        --home-dir "$SIGNER_HOME" \
        --create-home \
        sshgatesigner
fi

# Step 2: create the state-dir skeleton (idempotent — also repairs
# perms on a re-run, so a half-broken state can be recovered).
log "ensuring $SIGNER_HOME skeleton exists"
mkdir -p \
    "$SIGNER_HOME/keys" \
    "$SIGNER_HOME/tokens" \
    "$SIGNER_HOME/config" \
    "$SIGNER_HOME/log" \
    "$SIGNER_HOME/bin"

chown -R sshgatesigner:sshgatesigner "$SIGNER_HOME"
# 0750 (not 0700) so members of the sshgatesigner group can traverse into
# the home — the design point is that $SUDO_USER (added to the
# sshgatesigner group below) reads the audit log and peer.json without
# sudo. 0700 would force every status probe back through sudo.
chmod 0750 "$SIGNER_HOME"
# Keys and tokens hold the signing material and bot token. Same mode
# as the parent; the keystore enforces 0600 on the key file itself
# (src/signer/keystore.go rejects looser modes on load), so this
# directory mode protects against listing rather than reading.
chmod 0750 "$SIGNER_HOME/keys" "$SIGNER_HOME/tokens"

# Step 3: runtime dir for the unix socket. Volatile (lost on reboot),
# but the unit's RuntimeDirectory=sshgatesigner recreates it on every
# start. We create it now so a CLI run before the unit is enabled
# still works.
log "ensuring $SIGNER_RUN exists"
mkdir -p "$SIGNER_RUN"
chown sshgatesigner:sshgatesigner "$SIGNER_RUN"
chmod 0750 "$SIGNER_RUN"

# Step 4: add the invoking user to the sshgatesigner group so they can stat
# the runtime dir, read the audit log, etc., without sudo.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    if id -nG "$SUDO_USER" 2>/dev/null | tr ' ' '\n' | grep -qx sshgatesigner; then
        log "$SUDO_USER already in sshgatesigner group; skipping"
    else
        log "adding $SUDO_USER to sshgatesigner group"
        usermod -aG sshgatesigner "$SUDO_USER"
        log "you may need to log out and back in (or run 'newgrp sshgatesigner') for group membership to take effect"
    fi
fi

# Step 5: install binaries.
log "installing sshgate-signer-telegram -> /usr/local/bin/sshgate-signer-telegram"
install -m 0755 -o root -g root "$SIGNER_BIN" /usr/local/bin/sshgate-signer-telegram

log "installing sshgate-gate-linux-amd64 -> /usr/local/share/sshgate/sshgate-gate-linux-amd64"
mkdir -p /usr/local/share/sshgate
install -m 0755 -o root -g root "$GATE_BIN" /usr/local/share/sshgate/sshgate-gate-linux-amd64

# Step 6: write the systemd unit. Always overwrite — the unit is the
# source of truth, not whatever a previous install or hand-edit left.
UNIT_PATH=/etc/systemd/system/sshgate-signer-telegram.service
log "writing systemd unit -> $UNIT_PATH"
cat >"$UNIT_PATH" <<'UNIT'
[Unit]
Description=SSHGate signing daemon (sshgate-signer-telegram)
After=network.target

[Service]
Type=simple
User=sshgatesigner
Group=sshgatesigner
ExecStart=/usr/local/bin/sshgate-signer-telegram --config /var/lib/sshgatesigner/config/config.toml
Restart=on-failure
RestartSec=10
RuntimeDirectory=sshgatesigner
RuntimeDirectoryMode=0750
# Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/sshgatesigner /run/sshgatesigner
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictNamespaces=yes
SystemCallArchitectures=native
# Restrict syscalls to the curated service-class allowlist.
# Covers ordinary daemon needs (read/write/socket/poll/etc.)
# while rejecting ptrace, kexec_load, init_module, swapon and
# other kernel-attack syscalls. @system-service is the standard
# baseline for hardened units (systemd.exec(5)).
SystemCallFilter=@system-service

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$UNIT_PATH"

log "systemctl daemon-reload"
systemctl daemon-reload

# Step 7: initialise key material + skeleton config if missing.
CONFIG_PATH="$SIGNER_HOME/config/config.toml"
KEY_PATH="$SIGNER_HOME/keys/gate.key"
if [ ! -f "$KEY_PATH" ]; then
    log "running sshgate-signer-telegram --init (no signing key at $KEY_PATH)"
    sudo -u sshgatesigner /usr/local/bin/sshgate-signer-telegram --init --config "$CONFIG_PATH"
else
    log "signing key already present; skipping --init"
fi

# Step 7b: configure the Telegram approval backend in this SAME pass
# (single-pass install). Step 7's `--init` writes a `type = "stub"` config;
# historically the operator then had to hand-edit this root-owned TOML —
# append a [backend.telegram] block and flip the type with a separate
# tee/sed — and run install.sh a SECOND time before the token prompt below
# would fire. We fold that here: prompt once for the numeric Telegram
# user_id, append the [backend.telegram] block, and flip the backend type to
# "telegram", all as root and idempotently. Step 8 then prompts for the bot
# token in the same run, so ONE `sudo install.sh` reaches both prompts.
if [ -f "$CONFIG_PATH" ]; then
    if grep -Eq '^[[:space:]]*type[[:space:]]*=[[:space:]]*"telegram"' "$CONFIG_PATH"; then
        log "config already selects the telegram backend; skipping backend config"
    elif grep -Eq '^[[:space:]]*type[[:space:]]*=[[:space:]]*"stub"' "$CONFIG_PATH"; then
        # Only auto-configure a pristine stub config. A config that is neither
        # stub nor telegram (e.g. a hand-customised or hosted backend) is left
        # untouched — we never rewrite an operator's own config.
        if [ -t 0 ]; then
            # Idempotence: if a previous partial run already appended a
            # [backend.telegram] block (block present but type still "stub"),
            # do NOT append a duplicate — fall through to the type flip below.
            if grep -Eq '^[[:space:]]*\[backend\.telegram\][[:space:]]*$' "$CONFIG_PATH"; then
                log "[backend.telegram] block already present; not appending a duplicate"
            else
                printf '\n' >&2
                printf '[install] Configure the Telegram approval backend.\n' >&2
                printf '[install] Find your numeric Telegram user_id by messaging @userinfobot on\n' >&2
                printf '[install] Telegram — it replies with an "Id:" line. That number is your\n' >&2
                printf '[install] allowed_user_id (the only account whose taps can approve writes).\n' >&2
                TG_USER_ID=""
                attempt=0
                while [ "$attempt" -lt 3 ]; do
                    attempt=$((attempt + 1))
                    printf '[install] Telegram user_id (numeric), or press Enter to skip: ' >&2
                    IFS= read -r TG_USER_ID_INPUT || TG_USER_ID_INPUT=""
                    if [ -z "$TG_USER_ID_INPUT" ]; then
                        TG_USER_ID=""
                        break
                    fi
                    # Validate shape before writing it into the TOML (mirrors
                    # setup.md's ^[0-9]+$ check). A bad value never reaches disk.
                    if printf '%s' "$TG_USER_ID_INPUT" | grep -Eq '^[0-9]+$'; then
                        TG_USER_ID="$TG_USER_ID_INPUT"
                        break
                    fi
                    printf '[install] not a positive integer; try again.\n' >&2
                    TG_USER_ID=""
                done
                if [ -n "$TG_USER_ID" ]; then
                    # Append the [backend.telegram] block as root, pointing at
                    # the token + chatstore paths under the signer home. This is
                    # exactly the block the old hand-edit produced; the leading
                    # blank line separates it from the [backend] table above.
                    cat >>"$CONFIG_PATH" <<TGBLOCK

[backend.telegram]
token_path      = "$SIGNER_HOME/tokens/telegram.token"
allowed_user_id = $TG_USER_ID
chatstore_path  = "$SIGNER_HOME/config/peer.json"
TGBLOCK
                    log "appended [backend.telegram] block (allowed_user_id=$TG_USER_ID)"
                else
                    log "no user_id entered; leaving backend type = \"stub\" (re-run install.sh to configure telegram)"
                fi
            fi
            # Flip stub -> telegram only once a [backend.telegram] block exists
            # (either just appended, or recovered from a partial prior run).
            if grep -Eq '^[[:space:]]*\[backend\.telegram\][[:space:]]*$' "$CONFIG_PATH"; then
                sed -i 's/^type = "stub"$/type = "telegram"/' "$CONFIG_PATH"
                log 'set backend type = "telegram"'
            fi
        else
            # Non-TTY: cannot prompt safely. Leave the stub config in place and
            # print exactly how to configure telegram, then re-run.
            log "no TTY on stdin; leaving backend type = \"stub\""
            log "to enable telegram: append a [backend.telegram] block to $CONFIG_PATH"
            log "  (token_path=$SIGNER_HOME/tokens/telegram.token, allowed_user_id=<your id>,"
            log "   chatstore_path=$SIGNER_HOME/config/peer.json), flip type to \"telegram\", and re-run"
        fi
    else
        log "backend type is neither stub nor telegram; leaving config untouched"
    fi
fi

# Step 8: prompt for the Telegram bot token if the config selects the
# telegram backend and no token file exists yet. Echo is disabled
# (read -rs) so the token never lands in shell history or scrollback.
TOKEN_PATH="$SIGNER_HOME/tokens/telegram.token"
if [ -f "$CONFIG_PATH" ] && grep -Eq '^[[:space:]]*type[[:space:]]*=[[:space:]]*"telegram"' "$CONFIG_PATH"; then
    if [ -f "$TOKEN_PATH" ]; then
        log "telegram bot token already present at $TOKEN_PATH; skipping prompt"
    else
        # Need a TTY on stdin to prompt safely; if not interactive, tell
        # the user how to drop the token in by hand and continue (the
        # daemon will fail to start, which is the correct loud failure).
        if [ -t 0 ]; then
            printf '\n'
            printf '[install] backend.type = "telegram" but no token at %s.\n' "$TOKEN_PATH" >&2
            printf '[install] Paste the BotFather token (input hidden), or press Enter to skip: ' >&2
            IFS= read -rs TOKEN_VALUE || TOKEN_VALUE=""
            printf '\n' >&2
            if [ -n "$TOKEN_VALUE" ]; then
                # Validate shape: <digits>:<base64-ish>. Refuse garbage so
                # we don't write something useless to disk.
                if printf '%s' "$TOKEN_VALUE" | grep -Eq '^[0-9]+:[A-Za-z0-9_-]+$'; then
                    printf '%s' "$TOKEN_VALUE" | install -m 0600 -o sshgatesigner -g sshgatesigner /dev/stdin "$TOKEN_PATH"
                    log "wrote $TOKEN_PATH (mode 0600, owner sshgatesigner)"
                    unset TOKEN_VALUE
                else
                    unset TOKEN_VALUE
                    printf '[install] ERROR: token did not match expected shape <digits>:<chars>; not written\n' >&2
                    exit 78
                fi
            else
                log "skipped token entry; place it manually before the daemon will start"
            fi
        else
            log "no TTY on stdin; skipping bot-token prompt"
            log "drop the token at $TOKEN_PATH (mode 0600 sshgatesigner:sshgatesigner) and re-run"
        fi
    fi
fi

# Step 9: enable + (re)start. Use --now so a fresh install starts the
# daemon in one shot; if it was already running, restart picks up the
# new binary.
log "systemctl enable --now sshgate-signer-telegram"
systemctl enable --now sshgate-signer-telegram

# If the unit was already active we want the new binary loaded — issue
# a restart so the installed binary actually replaces the running one.
# (`enable --now` is a no-op on an already-active unit.)
if systemctl is-active --quiet sshgate-signer-telegram; then
    log "systemctl restart sshgate-signer-telegram (pick up new binary)"
    systemctl restart sshgate-signer-telegram
fi

# Give the unit a beat to either come up or fail visibly.
sleep 1
if ! systemctl is-active --quiet sshgate-signer-telegram; then
    printf '[install] ERROR: sshgate-signer-telegram failed to start; check: journalctl -u sshgate-signer-telegram -n 50\n' >&2
    exit 1
fi

log "sshgate-signer-telegram is active"

# Step 10: stage gate.pub into the invoking user's MCP distribution
# path so `sshgate add` (read-write) can find it without a manual copy.
# `sshgate add` reads ~/.config/sshgate/pubkey-distrib/gate.pub (audit B6).
PUBKEY_SRC="$SIGNER_HOME/keys/gate.pub"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ -f "$PUBKEY_SRC" ]; then
    USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [ -n "$USER_HOME" ]; then
        # Assumes the default ~/.config location; an operator who runs SSHGate
        # with a custom $XDG_CONFIG_HOME must stage gate.pub there manually
        # (sudo scrubs XDG_CONFIG_HOME, so install.sh cannot see it).
        # `sshgate add`'s read-only fallback fails safe if the path mismatches.
        DISTRIB_DIR="$USER_HOME/.config/sshgate/pubkey-distrib"
        # Derive the user's real primary group — it is NOT always a
        # per-user group named after the user (that's a Debian/RedHat
        # convention; on Arch the primary group is `users`), so `-g
        # "$SUDO_USER"` fails "install: invalid group" there.
        USER_GROUP="$(id -gn "$SUDO_USER")"
        log "staging gate.pub -> $DISTRIB_DIR/gate.pub (owner $SUDO_USER)"
        # Non-fatal: a staging hiccup must never abort an already-successful
        # daemon install. Warn and continue (the operator can copy it by hand).
        install -d -m 0755 -o "$SUDO_USER" -g "$USER_GROUP" "$DISTRIB_DIR" \
            || log "WARN: could not stage gate.pub to $DISTRIB_DIR; copy it manually (see docs)"
        install -m 0644 -o "$SUDO_USER" -g "$USER_GROUP" "$PUBKEY_SRC" "$DISTRIB_DIR/gate.pub" \
            || log "WARN: could not stage gate.pub to $DISTRIB_DIR; copy it manually (see docs)"
        # Normalize ownership of the user-owned sshgate subtree with the
        # corrected group. Guarded to ONLY the sshgate subtree — never the
        # whole ~/.config.
        chown "$SUDO_USER:$USER_GROUP" "$USER_HOME/.config/sshgate" "$DISTRIB_DIR" 2>/dev/null || true
    fi
fi

log "done"

# Final, unmissable banner: usermod -aG above does NOT activate the new
# group for the user's already-running shell or Claude Code session. The
# running MCP server inherited the stale group set, so every write will
# fail with permission denied on the signer socket until the user logs
# out and back in AND relaunches Claude Code. `newgrp` in a side terminal
# is NOT enough — it doesn't touch the already-running Claude Code process.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    printf '\n' >&2
    printf '========================================================================\n' >&2
    printf '  ACTION REQUIRED before writes will work:\n' >&2
    printf '\n' >&2
    printf '    1. LOG OUT and LOG BACK IN  (a new login shell, not `newgrp`)\n' >&2
    printf '    2. RELAUNCH Claude Code\n' >&2
    printf '    3. RESUME: in the new session run  /sshgate:status  then\n' >&2
    printf '       /sshgate:setup  — setup re-probes on-disk state, detects the\n' >&2
    printf '       tier, and continues from here (this is the durable breadcrumb;\n' >&2
    printf '       an agent driving the install loses its context on the relaunch).\n' >&2
    printf '\n' >&2
    printf '  Why: %s was added to the sshgatesigner group, but the\n' "$SUDO_USER" >&2
    printf '  currently-running shell and Claude Code (and its MCP server) still\n' >&2
    printf '  hold the OLD group set. Until you re-login AND relaunch Claude Code,\n' >&2
    printf '  EVERY write will fail with "permission denied" on the signer socket.\n' >&2
    printf '  `newgrp sshgatesigner` in a side terminal is NOT enough.\n' >&2
    printf '========================================================================\n' >&2
fi
