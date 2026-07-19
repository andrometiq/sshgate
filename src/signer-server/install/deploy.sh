#!/usr/bin/env bash
# deploy.sh — VPS-side install script for the hosted SSHGate signer.
#
# Idempotent. Run as a user with sudo on a fresh-ish Linux box:
#
#   git clone <sshgate repo>
#   cd sshgate/src/signer-server
#   sudo ./install/deploy.sh
#
# What it does (in order):
#   1. Verifies Go toolchain is present (the daemon is built from source —
#      no pre-built binary is committed; this mirrors v1's plugin install).
#   2. Creates a dedicated `sshgate-signer-server` system user (no shell, no
#      home directory).
#   3. Creates /var/lib/sshgate-signer-server (owned by the user) for the
#      SQLite DB.
#   4. Creates /etc/sshgate-signer-server with a 0700 keys/ subdir, generates
#      the bearer token and Ed25519 signing keypair without overwriting either,
#      and bootstraps the first TOTP operator into SQLite.
#   5. Builds the binary with `go build` and installs it at
#      /usr/local/bin/sshgate-signer-server.
#   6. Renders the systemd unit (with placeholder substitution from the
#      template) at /etc/systemd/system/sshgate-signer-server.service.
#   7. Enables + starts the service.
#   8. Prints the API key path + a quick smoke test (curl /healthz).
#
# What it does NOT do:
#   - Provision TLS. The server listens on 127.0.0.1:8443 (plain HTTP);
#     operators need a reverse proxy (Caddy/nginx) for public traffic.
#   - Configure log shipping or metrics.
#
# Re-running this script is safe: existing user/dir/file/unit are
# detected and left alone (or upgraded in place for the binary + unit).

set -euo pipefail
umask 077

# ----- Configurable knobs (override via env) -----
SERVICE_USER="${SIGNER_SERVER_USER:-sshgate-signer-server}"
INSTALL_DIR="${SIGNER_SERVER_INSTALL_DIR:-/usr/local/bin}"
STATE_DIR="${SIGNER_SERVER_STATE_DIR:-/var/lib/sshgate-signer-server}"
CONFIG_DIR="${SIGNER_SERVER_CONFIG_DIR:-/etc/sshgate-signer-server}"
KEYS_DIR="${SIGNER_SERVER_KEYS_DIR:-${CONFIG_DIR}/keys}"
API_KEY_FILE="${SIGNER_SERVER_API_KEY_FILE:-${KEYS_DIR}/api-key.txt}"
DB_PATH="${SIGNER_SERVER_DB:-${STATE_DIR}/state.db}"
LISTEN_ADDR="${SIGNER_SERVER_ADDR:-127.0.0.1:8443}"
SIGNING_KEY_FILE="${SIGNER_SERVER_SIGNING_KEY_FILE:-${KEYS_DIR}/signing-key.ed25519}"
SIGNING_PUBLIC_KEY_FILE="${SIGNER_SERVER_SIGNING_PUBLIC_KEY_FILE:-${KEYS_DIR}/signing-key.ed25519.pub}"
RP_ID="${SIGNER_SERVER_RP_ID:-}"
RP_ORIGIN="${SIGNER_SERVER_RP_ORIGIN:-}"
RP_DISPLAY_NAME="${SIGNER_SERVER_RP_DISPLAY_NAME:-SSHGate Signer}"
SESSION_TTL="${SIGNER_SERVER_SESSION_TTL:-1h}"
REQUIRE_STEP_UP="${SIGNER_SERVER_REQUIRE_STEP_UP:-true}"
DENY_VETO="${SIGNER_SERVER_DENY_VETO:-true}"
ALLOW_SELF_APPROVE="${SIGNER_SERVER_ALLOW_SELF_APPROVE:-false}"
BOOTSTRAP_OPERATOR="${SIGNER_SERVER_BOOTSTRAP_OPERATOR:-}"
BOOTSTRAP_OPERATORS="${SIGNER_SERVER_BOOTSTRAP_OPERATORS:-${BOOTSTRAP_OPERATOR}}"
MACHINE_CLIENT_ID="${SIGNER_SERVER_MACHINE_CLIENT_ID:-}"
REQUIRED_APPROVALS="${SIGNER_SERVER_REQUIRED_APPROVALS:-1}"
TRUST_PROXY_HEADERS="${SIGNER_SERVER_TRUST_PROXY_HEADERS:-true}"
UNIT_PATH="/etc/systemd/system/sshgate-signer-server.service"

# ----- Helpers -----
log() { printf '[deploy] %s\n' "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }
need_sudo() { [[ $EUID -eq 0 ]] || fail "run as root (or via sudo)"; }
refuse_symlink() { [[ ! -L "$1" ]] || fail "refusing symbolic-link path: $1"; }

# Discover the repo root: this script lives at <repo>/src/signer-server/install/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${PKG_DIR}/../.." && pwd)"

# ----- Pre-flight -----
need_sudo
command -v go >/dev/null 2>&1 || fail "go toolchain not found; install Go 1.22+ first"
command -v systemctl >/dev/null 2>&1 || fail "systemctl not found; this script targets systemd hosts"
command -v openssl >/dev/null 2>&1 || fail "openssl not found; needed for API key generation"
command -v runuser >/dev/null 2>&1 || fail "runuser not found; needed to initialize secrets as the service account"
[[ -n "${RP_ID}" ]] || fail "set SIGNER_SERVER_RP_ID to the public WebAuthn domain (for example signer.example.com)"
[[ -n "${RP_ORIGIN}" ]] || fail "set SIGNER_SERVER_RP_ORIGIN to the exact public HTTPS origin (for example https://signer.example.com)"
[[ -n "${MACHINE_CLIENT_ID}" ]] || fail "set SIGNER_SERVER_MACHINE_CLIENT_ID to the bootstrapped operator represented by this bearer credential"
[[ "${REQUIRED_APPROVALS}" =~ ^[1-9][0-9]*$ ]] || fail "SIGNER_SERVER_REQUIRED_APPROVALS must be a positive integer"
for setting in REQUIRE_STEP_UP DENY_VETO ALLOW_SELF_APPROVE TRUST_PROXY_HEADERS; do
  value="${!setting}"
  [[ "${value}" == true || "${value}" == false ]] || fail "${setting} must be true or false"
done
[[ -n "${BOOTSTRAP_OPERATORS}" ]] || fail "set SIGNER_SERVER_BOOTSTRAP_OPERATORS to a comma-separated operator roster (for example alice,bob)"
IFS=',' read -r -a configured_bootstrap_names <<< "${BOOTSTRAP_OPERATORS}"
declare -A bootstrap_seen=()
bootstrap_count=0
machine_in_roster=false
for raw_name in "${configured_bootstrap_names[@]}"; do
  name="${raw_name//[[:space:]]/}"
  [[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$ ]] || fail "invalid bootstrap operator name: ${name}"
  if [[ -z "${bootstrap_seen[${name}]+x}" ]]; then
    bootstrap_seen["${name}"]=1
    bootstrap_count=$((bootstrap_count + 1))
  fi
  [[ "${name}" != "${MACHINE_CLIENT_ID}" ]] || machine_in_roster=true
done
[[ "${machine_in_roster}" == true ]] || fail "SIGNER_SERVER_MACHINE_CLIENT_ID must appear in SIGNER_SERVER_BOOTSTRAP_OPERATORS"
eligible_count="${bootstrap_count}"
if [[ "${ALLOW_SELF_APPROVE}" == false ]]; then
  eligible_count=$((eligible_count - 1))
fi
(( REQUIRED_APPROVALS <= eligible_count )) || fail "required approvals ${REQUIRED_APPROVALS} exceed eligible bootstrapped operators ${eligible_count}"

# ----- 1. user -----
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  log "creating system user '${SERVICE_USER}'"
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
else
  log "user '${SERVICE_USER}' already exists"
fi

# ----- 2. directories -----
log "ensuring state dir ${STATE_DIR} (owned by ${SERVICE_USER})"
refuse_symlink "${STATE_DIR}"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${STATE_DIR}"

log "ensuring config dirs ${CONFIG_DIR} + ${KEYS_DIR}"
refuse_symlink "${CONFIG_DIR}"
refuse_symlink "${KEYS_DIR}"
install -d -m 0755 "${CONFIG_DIR}"
install -d -m 0750 -o root -g "${SERVICE_USER}" "${KEYS_DIR}"

# ----- 3. API key (single bearer token for v2.0) -----
refuse_symlink "${API_KEY_FILE}"
if [[ ! -e "${API_KEY_FILE}" ]]; then
	log "generating bearer API key at ${API_KEY_FILE}"
	API_TMP_DIR="$(mktemp -d /tmp/sshgate-signer-server-api.XXXXXX)"
	openssl rand -base64 32 > "${API_TMP_DIR}/api-key"
	install -m 0600 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${API_TMP_DIR}/api-key" "${API_KEY_FILE}"
	rm -rf -- "${API_TMP_DIR}"
else
	[[ -f "${API_KEY_FILE}" && -s "${API_KEY_FILE}" ]] || fail "API key path exists but is not a non-empty regular file: ${API_KEY_FILE}"
	log "API key already present at ${API_KEY_FILE}; leaving it alone"
fi
refuse_symlink "${API_KEY_FILE}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${API_KEY_FILE}"
chmod 0600 "${API_KEY_FILE}"

# ----- 4. build the binary -----
log "building sshgate-signer-server from ${REPO_ROOT}"
(
  cd "${REPO_ROOT}"
  VERSION="$(cat VERSION)"
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o "${INSTALL_DIR}/sshgate-signer-server" \
    ./src/signer-server/cmd/sshgate-signer-server
)
chmod 0755 "${INSTALL_DIR}/sshgate-signer-server"
log "installed binary at ${INSTALL_DIR}/sshgate-signer-server"

# ----- 5. signing key + first operator -----
refuse_symlink "${SIGNING_KEY_FILE}"
refuse_symlink "${SIGNING_PUBLIC_KEY_FILE}"
if [[ -e "${SIGNING_KEY_FILE}" || -e "${SIGNING_PUBLIC_KEY_FILE}" ]]; then
	[[ -f "${SIGNING_KEY_FILE}" && -f "${SIGNING_PUBLIC_KEY_FILE}" ]] || \
		fail "signing keypair is incomplete; refusing to generate over one existing half"
	log "signing keypair already present; leaving it alone"
else
	log "generating signing keypair in a service-private staging directory"
	KEY_TMP_DIR="$(mktemp -d /tmp/sshgate-signer-server-keygen.XXXXXX)"
	"${INSTALL_DIR}/sshgate-signer-server" \
		--init-signing-key \
		--signing-key-file "${KEY_TMP_DIR}/signing-key.ed25519" \
		--signing-public-key-file "${KEY_TMP_DIR}/signing-key.ed25519.pub"
	install -m 0600 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${KEY_TMP_DIR}/signing-key.ed25519" "${SIGNING_KEY_FILE}"
	install -m 0644 -o "${SERVICE_USER}" -g "${SERVICE_USER}" "${KEY_TMP_DIR}/signing-key.ed25519.pub" "${SIGNING_PUBLIC_KEY_FILE}"
	rm -rf -- "${KEY_TMP_DIR}"
fi
refuse_symlink "${SIGNING_KEY_FILE}"
refuse_symlink "${SIGNING_PUBLIC_KEY_FILE}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${SIGNING_KEY_FILE}" "${SIGNING_PUBLIC_KEY_FILE}"
chmod 0600 "${SIGNING_KEY_FILE}"
chmod 0644 "${SIGNING_PUBLIC_KEY_FILE}"

refuse_symlink "${DB_PATH}"
if [[ -e "${DB_PATH}" ]]; then
	[[ -f "${DB_PATH}" ]] || fail "database path exists but is not a regular file: ${DB_PATH}"
	# Upgrade legacy scaffold databases without a root-following chmod: the
	# service identity can tighten only files it already owns.
	runuser -u "${SERVICE_USER}" -- chmod 0600 -- "${DB_PATH}" || fail "database must be owned by ${SERVICE_USER}: ${DB_PATH}"
fi
for sidecar in "${DB_PATH}-wal" "${DB_PATH}-shm"; do
	refuse_symlink "${sidecar}"
	if [[ -e "${sidecar}" ]]; then
		[[ -f "${sidecar}" ]] || fail "database sidecar is not a regular file: ${sidecar}"
		runuser -u "${SERVICE_USER}" -- chmod 0600 -- "${sidecar}" || fail "database sidecar must be owned by ${SERVICE_USER}: ${sidecar}"
	fi
done

for raw_name in "${configured_bootstrap_names[@]}"; do
	name="${raw_name//[[:space:]]/}"
	[[ -n "${name}" ]] || continue
	artifact="${STATE_DIR}/bootstrap-${name}.txt"
	refuse_symlink "${artifact}"
	log "ensuring bootstrap operator '${name}' (one-time secret artifact: ${artifact})"
	runuser -u "${SERVICE_USER}" -- "${INSTALL_DIR}/sshgate-signer-server" \
		--bootstrap-operator "${name}" \
		--bootstrap-output-file "${artifact}" \
		--db "${DB_PATH}" \
		--rp-id "${RP_ID}" \
		--rp-origin "${RP_ORIGIN}" \
		--rp-display-name "${RP_DISPLAY_NAME}" \
		--session-ttl "${SESSION_TTL}"
done

# ----- 6. systemd unit -----
log "rendering systemd unit at ${UNIT_PATH}"
TEMPLATE="${SCRIPT_DIR}/sshgate-signer-server.service"
[[ -f "${TEMPLATE}" ]] || fail "systemd unit template missing at ${TEMPLATE}"

# Simple sed substitution; the template uses __FOO__ placeholders that
# don't appear in any legitimate systemd directive.
sed \
  -e "s#__BIN__#${INSTALL_DIR}/sshgate-signer-server#g" \
  -e "s#__USER__#${SERVICE_USER}#g" \
  -e "s#__API_KEY_FILE__#${API_KEY_FILE}#g" \
  -e "s#__SIGNING_KEY_FILE__#${SIGNING_KEY_FILE}#g" \
  -e "s#__DB_PATH__#${DB_PATH}#g" \
  -e "s#__LISTEN_ADDR__#${LISTEN_ADDR}#g" \
  -e "s#__RP_ID__#${RP_ID}#g" \
  -e "s#__RP_ORIGIN__#${RP_ORIGIN}#g" \
  -e "s#__RP_DISPLAY_NAME__#${RP_DISPLAY_NAME}#g" \
  -e "s#__SESSION_TTL__#${SESSION_TTL}#g" \
  -e "s#__REQUIRE_STEP_UP__#${REQUIRE_STEP_UP}#g" \
  -e "s#__DENY_VETO__#${DENY_VETO}#g" \
	-e "s#__ALLOW_SELF_APPROVE__#${ALLOW_SELF_APPROVE}#g" \
	-e "s#__MACHINE_CLIENT_ID__#${MACHINE_CLIENT_ID}#g" \
	-e "s#__REQUIRED_APPROVALS__#${REQUIRED_APPROVALS}#g" \
	-e "s#__TRUST_PROXY_HEADERS__#${TRUST_PROXY_HEADERS}#g" \
  -e "s#__STATE_DIR__#${STATE_DIR}#g" \
  -e "s#__INSTALL_DIR__#${PKG_DIR}#g" \
  "${TEMPLATE}" > "${UNIT_PATH}"

systemctl daemon-reload
systemctl enable sshgate-signer-server.service >/dev/null
systemctl restart sshgate-signer-server.service
log "service enabled + (re)started"

# ----- 7. smoke test -----
sleep 1
if command -v curl >/dev/null 2>&1; then
  log "smoke test: GET ${LISTEN_ADDR}/healthz"
  if curl -fsS "http://${LISTEN_ADDR}/healthz"; then
    log "smoke test passed"
  else
    log "smoke test FAILED — check 'journalctl -u sshgate-signer-server -n 50'"
    exit 1
  fi
fi

log "done."
log ""
log "API key (give this to laptop clients):"
log "  ${API_KEY_FILE}"
log "Gate trust public key:"
log "  ${SIGNING_PUBLIC_KEY_FILE}"
log "Bootstrap artifacts (read once, enroll, then securely remove):"
for raw_name in "${configured_bootstrap_names[@]}"; do
  name="${raw_name//[[:space:]]/}"
  [[ ! -f "${STATE_DIR}/bootstrap-${name}.txt" ]] || log "  ${STATE_DIR}/bootstrap-${name}.txt"
done
log ""
log "Next: stand up a reverse proxy (Caddy/nginx) terminating TLS on 443"
log "      and forwarding to ${LISTEN_ADDR}. The server speaks plain HTTP;"
log "      it expects TLS to be handled upstream."
