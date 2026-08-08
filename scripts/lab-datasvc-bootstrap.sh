#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# lab-datasvc-bootstrap.sh — Bootstrap shared PostgreSQL + MinIO on a Debian
# VM for the cfg-lab controller HA epic (#3090, story #3124).
# Idempotent. Re-run safe. Never rotates an existing role/user password.
#
# Usage:
#   sudo bash lab-datasvc-bootstrap.sh
#
# On first run this prints the generated PostgreSQL role password and MinIO
# access/secret key ONCE to stdout. Capture them into an OS keychain
# immediately — nothing is written to disk in cleartext, and a re-run will
# not reprint them (see step 3 and step 5 for the idempotency check).
#
# See: docs/testing/controller-ha-real-cluster-runbook.md

set -euo pipefail

PG_DB="cfgms"
PG_ROLE="cfgms"
PG_LISTEN_SUBNET="192.168.234.0/24"
PG_TLS_DIR="${CFGMS_LAB_DATASVC_TLS_DIR:-/etc/postgresql/tls}"
PG_CA_KEY="${PG_TLS_DIR}/ca.key"
PG_CA_CERT="${PG_TLS_DIR}/ca.pem"
PG_SERVER_KEY="${PG_TLS_DIR}/server.key"
PG_SERVER_CERT="${PG_TLS_DIR}/server.pem"

MINIO_USER="minio-server"
MINIO_DATA_DIR="/var/lib/minio/data"
MINIO_CONFIG_DIR="/etc/minio"
MINIO_ENV_FILE="${MINIO_CONFIG_DIR}/minio.env"
MINIO_BUCKET="cfgms-installer-blobs"
MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001

log() { echo "[bootstrap] $*"; }

# ── Provisioning functions ────────────────────────────────────────────────────
#
# Defined before any side effect so that scripts/lab-datasvc-bootstrap_test.sh
# (and the test's PostgreSQL container fixture) can source this file and
# exercise the exact logic that runs on the lab VM, rather than a re-implemented
# copy that can drift from it. See the sourcing guard below.

# generate_tls_certs <tls_dir> <server_ip> <server_fqdn> [key_bits]
#
# Generates the self-managed CA and the PostgreSQL server cert in <tls_dir>.
# Idempotent: an existing ca.pem / server.pem is never regenerated or rotated,
# so a re-run does not invalidate the sslrootcert already distributed to
# controller nodes. The server SAN covers <server_ip> and <server_fqdn> so
# sslmode=verify-full succeeds by either address form.
generate_tls_certs() {
    local tls_dir="$1" server_ip="$2" server_fqdn="$3" key_bits="${4:-4096}"
    # CA/server private keys are written by `openssl genrsa -out` before the
    # explicit chmod 600 below lands; without this, a caller-inherited
    # permissive umask (e.g. 022) leaves the key at its umask-derived default
    # mode for that window. Restored at the end of the function so it does not
    # affect permissions of files created later in the script.
    local old_umask
    old_umask="$(umask)"
    umask 077

    mkdir -p "$tls_dir"

    if [[ ! -f "${tls_dir}/ca.pem" ]]; then
        openssl genrsa -out "${tls_dir}/ca.key" "$key_bits" 2>/dev/null
        openssl req -new -x509 -days 3650 \
            -key "${tls_dir}/ca.key" \
            -subj "/CN=cfgms-lab-datasvc-pg-ca/O=cfgms-lab" \
            -out "${tls_dir}/ca.pem" 2>/dev/null
        chmod 600 "${tls_dir}/ca.key"
        chmod 644 "${tls_dir}/ca.pem"
    fi

    if [[ ! -f "${tls_dir}/server.pem" ]]; then
        openssl genrsa -out "${tls_dir}/server.key" "$key_bits" 2>/dev/null

        cat > "${tls_dir}/server.ext" <<EXTEOF
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:${server_ip},DNS:${server_fqdn}
EXTEOF

        openssl req -new \
            -key "${tls_dir}/server.key" \
            -subj "/CN=${server_fqdn}/O=cfgms-lab" \
            -out "${tls_dir}/server.csr" 2>/dev/null

        openssl x509 -req -days 3650 \
            -in "${tls_dir}/server.csr" \
            -CA "${tls_dir}/ca.pem" \
            -CAkey "${tls_dir}/ca.key" \
            -CAcreateserial \
            -extfile "${tls_dir}/server.ext" \
            -out "${tls_dir}/server.pem" 2>/dev/null

        chmod 600 "${tls_dir}/server.key"
        chmod 644 "${tls_dir}/server.pem"
        rm -f "${tls_dir}/server.csr" "${tls_dir}/server.ext" "${tls_dir}/ca.srl"
    fi

    umask "$old_umask"
}

# apply_pg_conf_tls <postgresql_conf> <cert_path> <key_path>
#
# Turns TLS on and points PostgreSQL at the generated cert/key.
# Uses sed-replace, never append-if-absent: Debian's pg_createcluster writes
# UNCOMMENTED snakeoil defaults (ssl = on, ssl_cert_file =
# '/etc/ssl/certs/ssl-cert-snakeoil.pem') into postgresql.conf, so an
# append-if-absent guard would find the keys present, skip the append, and leave
# the server serving the snakeoil cert — which is not signed by the CA this
# script generates, breaking every verify-full client while the run still
# reports success.
apply_pg_conf_tls() {
    local pg_conf="$1" cert_path="$2" key_path="$3"

    if grep -q "^#\?ssl =" "$pg_conf" 2>/dev/null; then
        sed -i "s/^#\?ssl =.*/ssl = on/" "$pg_conf"
    else
        echo "ssl = on" >> "$pg_conf"
    fi

    if grep -q "^#\?ssl_cert_file" "$pg_conf" 2>/dev/null; then
        sed -i "s|^#\?ssl_cert_file.*|ssl_cert_file = '${cert_path}'|" "$pg_conf"
    else
        echo "ssl_cert_file = '${cert_path}'" >> "$pg_conf"
    fi

    if grep -q "^#\?ssl_key_file" "$pg_conf" 2>/dev/null; then
        sed -i "s|^#\?ssl_key_file.*|ssl_key_file = '${key_path}'|" "$pg_conf"
    else
        echo "ssl_key_file = '${key_path}'" >> "$pg_conf"
    fi
}

# apply_pg_hba_tls <pg_hba_conf> <subnet> <auth_method>
#
# Writes the TLS-enforcing host-based auth rules for <subnet>:
#   hostnossl … reject      — a client connecting with sslmode=disable is
#                             refused outright instead of getting a cleartext
#                             session across the lab LAN
#   hostssl   … <auth>      — TLS-only, with the given auth method
#
# A plain `host` rule matches BOTH SSL and non-SSL connections, so the `host …
# scram-sha-256` rule written by story #3124 (before server TLS existed) is
# upgraded in place rather than left alongside the new rules — leaving it would
# make the TLS machinery optional and silently downgradable.
apply_pg_hba_tls() {
    local pg_hba="$1" subnet="$2" auth="$3"
    local subnet_re="${subnet//./\\.}"
    local nossl_line="hostnossl all           all             ${subnet}        reject"
    local ssl_line="hostssl all             all             ${subnet}        ${auth}"

    [[ -f "$pg_hba" ]] || touch "$pg_hba"

    # `^host` followed by whitespace matches only the plaintext-capable form —
    # `hostssl` / `hostnossl` have no whitespace after `host`, so they are left
    # untouched and re-application stays idempotent.
    sed -i -E "s|^host[[:space:]]+all[[:space:]]+all[[:space:]]+${subnet_re}[[:space:]]+.*|${ssl_line}|" "$pg_hba"

    grep -qF -- "$nossl_line" "$pg_hba" || echo "$nossl_line" >> "$pg_hba"
    grep -qF -- "$ssl_line" "$pg_hba" || echo "$ssl_line" >> "$pg_hba"
}

# Sourcing guard: when this file is sourced (by the test suite or by the test's
# container fixture) stop here — only the constants and functions above are
# wanted. When executed, run the bootstrap steps below.
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    return 0
fi

# ── Step 1: Pre-flight ────────────────────────────────────────────────────────

log "Step 1: Pre-flight checks"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Error: must be run as root (sudo bash $(basename "$0"))" >&2
    exit 1
fi

if ! grep -qi "debian" /etc/os-release 2>/dev/null; then
    echo "Error: this script targets Debian. Detected OS:" >&2
    grep PRETTY_NAME /etc/os-release 2>/dev/null || echo "  (unknown)" >&2
    exit 1
fi

log "Pre-flight checks passed."

# ── Step 2: PostgreSQL install ────────────────────────────────────────────────

log "Step 2: PostgreSQL install (idempotent)"

if ! command -v psql &>/dev/null; then
    apt-get -qq update -y
    apt-get -qq install -y postgresql postgresql-contrib
    log "PostgreSQL installed."
else
    log "PostgreSQL already installed."
fi

PG_VERSION="$(psql -V | grep -oE '[0-9]+' | head -1)"
PG_CONF_DIR="/etc/postgresql/${PG_VERSION}/main"
PG_CONF="${PG_CONF_DIR}/postgresql.conf"
PG_HBA="${PG_CONF_DIR}/pg_hba.conf"

# Listen on all interfaces so cluster-node hosts on the lab LAN can reach it.
if ! grep -q "^listen_addresses = '\*'" "$PG_CONF" 2>/dev/null; then
    sed -i "s/^#\?listen_addresses.*/listen_addresses = '*'/" "$PG_CONF"
    log "Set listen_addresses = '*' in $PG_CONF"
else
    log "listen_addresses already set to '*'."
fi

# TLS-only access for the lab subnet: hostssl for authenticated TLS sessions,
# hostnossl … reject so a sslmode=disable client is refused rather than served
# in cleartext. Any plaintext-capable `host` rule from story #3124 is upgraded.
apply_pg_hba_tls "$PG_HBA" "$PG_LISTEN_SUBNET" "scram-sha-256"
log "pg_hba.conf: hostssl (scram-sha-256) + hostnossl reject applied for ${PG_LISTEN_SUBNET}."

systemctl enable postgresql &>/dev/null || true

# ── Step 2.5: PostgreSQL TLS certificate provisioning ─────────────────────────

log "Step 2.5: PostgreSQL TLS certificate provisioning"

# SAN covers the VM's LAN IP and hostname so verify-full connections work from
# controller nodes on the same subnet. generate_tls_certs is idempotent: an
# existing CA or server cert is never regenerated or rotated.
PG_VM_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
PG_FQDN="$(hostname -f 2>/dev/null || hostname)"

if [[ -f "$PG_CA_CERT" ]]; then
    log "TLS CA already present — not rotating: ${PG_CA_CERT}"
fi
if [[ -f "$PG_SERVER_CERT" ]]; then
    log "TLS server cert already present — not rotating: ${PG_SERVER_CERT}"
fi

generate_tls_certs "$PG_TLS_DIR" "$PG_VM_IP" "$PG_FQDN" 4096

log "TLS material in place (CA: ${PG_CA_CERT}, server cert SAN: IP:${PG_VM_IP}, DNS:${PG_FQDN})."

# CA key must not be readable by the postgres runtime account — only root needs
# it (for re-signing future server certs). The postgres user needs the server
# cert + key only.
chown root:root "$PG_TLS_DIR" "$PG_CA_KEY" "$PG_CA_CERT"
chown root:postgres "$PG_SERVER_KEY" "$PG_SERVER_CERT"
chmod 755 "$PG_TLS_DIR"   # world-traversable so postgres can reach its files
chmod 600 "$PG_CA_KEY"    # CA private key: root-only
chmod 644 "$PG_CA_CERT"   # CA cert: world-readable (distributed as sslrootcert)
chmod 640 "$PG_SERVER_KEY" # server key: postgres-readable, others denied
chmod 644 "$PG_SERVER_CERT" # server cert: world-readable

# Configure postgresql.conf to enable TLS and point at the generated cert/key.
apply_pg_conf_tls "$PG_CONF" "$PG_SERVER_CERT" "$PG_SERVER_KEY"

systemctl restart postgresql

# Verify against the running server rather than trusting the edit: Debian ships
# uncommented snakeoil cert paths, and any config-file surprise must fail the
# run loudly instead of leaving a server that serves an untrusted cert while the
# bootstrap reports TLS as configured.
PG_LIVE_SSL="$(sudo -u postgres psql -tAc "SHOW ssl" 2>/dev/null || echo "unknown")"
PG_LIVE_CERT="$(sudo -u postgres psql -tAc "SHOW ssl_cert_file" 2>/dev/null || echo "unknown")"
PG_LIVE_KEY="$(sudo -u postgres psql -tAc "SHOW ssl_key_file" 2>/dev/null || echo "unknown")"

if [[ "$PG_LIVE_SSL" != "on" || "$PG_LIVE_CERT" != "$PG_SERVER_CERT" || "$PG_LIVE_KEY" != "$PG_SERVER_KEY" ]]; then
    echo "Error: PostgreSQL did not come up with the generated TLS material." >&2
    echo "  ssl           = ${PG_LIVE_SSL} (expected: on)" >&2
    echo "  ssl_cert_file = ${PG_LIVE_CERT} (expected: ${PG_SERVER_CERT})" >&2
    echo "  ssl_key_file  = ${PG_LIVE_KEY} (expected: ${PG_SERVER_KEY})" >&2
    echo "  Check ${PG_CONF} for a later override and re-run." >&2
    exit 1
fi

log "PostgreSQL (re)started; verified live: ssl=${PG_LIVE_SSL}, cert=${PG_LIVE_CERT}, key=${PG_LIVE_KEY}"

# ── Step 3: PostgreSQL role + database ────────────────────────────────────────

log "Step 3: PostgreSQL role + database"

PG_ROLE_EXISTS="$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_ROLE}'")"
PG_PASSWORD_PRINTED=false

if [[ "$PG_ROLE_EXISTS" != "1" ]]; then
    PG_PASSWORD="$(openssl rand -base64 24)"
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
        "CREATE ROLE ${PG_ROLE} WITH LOGIN PASSWORD '${PG_PASSWORD}';"
    log "Created role ${PG_ROLE} (non-superuser, LOGIN only)."
    PG_PASSWORD_PRINTED=true
else
    log "Role ${PG_ROLE} already exists — password NOT rotated."
fi

PG_DB_EXISTS="$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'")"
if [[ "$PG_DB_EXISTS" != "1" ]]; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c \
        "CREATE DATABASE ${PG_DB} OWNER ${PG_ROLE};"
    log "Created database ${PG_DB} (owner ${PG_ROLE})."
else
    log "Database ${PG_DB} already exists."
fi

# ── Step 4: MinIO install ─────────────────────────────────────────────────────

log "Step 4: MinIO install (idempotent)"

if ! id "$MINIO_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$MINIO_USER"
    log "Created ${MINIO_USER} system user."
fi

mkdir -p "$MINIO_DATA_DIR" "$MINIO_CONFIG_DIR"
chown -R "${MINIO_USER}:${MINIO_USER}" "$MINIO_DATA_DIR"

if [[ ! -x /usr/local/bin/minio ]]; then
    curl -fsSL https://dl.min.io/server/minio/release/linux-amd64/minio \
        -o /usr/local/bin/minio
    chmod +x /usr/local/bin/minio
    log "MinIO server binary installed to /usr/local/bin/minio."
else
    log "MinIO server binary already present."
fi

if [[ ! -x /usr/local/bin/mc ]]; then
    curl -fsSL https://dl.min.io/client/mc/release/linux-amd64/mc \
        -o /usr/local/bin/mc
    chmod +x /usr/local/bin/mc
    log "MinIO client (mc) installed to /usr/local/bin/mc."
else
    log "MinIO client already present."
fi

# ── Step 5: MinIO credentials + service ───────────────────────────────────────

log "Step 5: MinIO credentials + service"

MINIO_PASSWORD_PRINTED=false

if [[ ! -f "$MINIO_ENV_FILE" ]]; then
    MINIO_ROOT_USER="cfgms-lab-datasvc"
    MINIO_ROOT_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-32)"

    cat > "$MINIO_ENV_FILE" <<EOF
MINIO_ROOT_USER=${MINIO_ROOT_USER}
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
MINIO_VOLUMES="${MINIO_DATA_DIR}"
MINIO_OPTS="--address :${MINIO_API_PORT} --console-address :${MINIO_CONSOLE_PORT}"
EOF
    chown root:"$MINIO_USER" "$MINIO_ENV_FILE"
    chmod 640 "$MINIO_ENV_FILE"
    log "Generated MinIO root credentials in ${MINIO_ENV_FILE} (root:group-readable only)."
    MINIO_PASSWORD_PRINTED=true
else
    log "MinIO env file already exists — credentials NOT rotated."
    # shellcheck disable=SC1090
    source "$MINIO_ENV_FILE"
fi

cat > /etc/systemd/system/minio.service <<EOF
[Unit]
Description=MinIO (cfgms-lab-datasvc installer blob store)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${MINIO_USER}
Group=${MINIO_USER}
EnvironmentFile=${MINIO_ENV_FILE}
ExecStart=/usr/local/bin/minio server \$MINIO_VOLUMES \$MINIO_OPTS
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable minio &>/dev/null || true
if systemctl is-active --quiet minio; then
    systemctl restart minio
else
    systemctl start minio
fi
log "MinIO service (re)started, listening on :${MINIO_API_PORT} (API) / :${MINIO_CONSOLE_PORT} (console)."

# ── Step 6: MinIO bucket ──────────────────────────────────────────────────────

log "Step 6: MinIO bucket"

# shellcheck disable=SC1090
source "$MINIO_ENV_FILE"

RETRIES=12
for ((i = 1; i <= RETRIES; i++)); do
    if /usr/local/bin/mc alias set local "http://127.0.0.1:${MINIO_API_PORT}" \
        "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" &>/dev/null; then
        break
    fi
    if [[ $i -eq $RETRIES ]]; then
        echo "Error: MinIO did not become ready after $((RETRIES * 5))s." >&2
        exit 1
    fi
    log "  Waiting for MinIO API... (${i}/${RETRIES})"
    sleep 5
done

if ! /usr/local/bin/mc ls "local/${MINIO_BUCKET}" &>/dev/null; then
    /usr/local/bin/mc mb "local/${MINIO_BUCKET}"
    log "Created bucket ${MINIO_BUCKET}."
else
    log "Bucket ${MINIO_BUCKET} already exists."
fi

# ── Step 7: Final output ──────────────────────────────────────────────────────

PG_VM_IP_OUT="$(hostname -I 2>/dev/null | awk '{print $1}')"

echo ""
echo "=========================================="
echo " cfg-lab data-services bootstrap complete"
echo "=========================================="
echo ""
echo "PostgreSQL: db=${PG_DB} role=${PG_ROLE} port=5432 (TLS-only: hostssl + hostnossl reject for ${PG_LISTEN_SUBNET})"
echo "  TLS CA cert: ${PG_CA_CERT}"
echo "  Copy it to each controller node, e.g.:"
echo "    scp ${PG_VM_IP_OUT}:${PG_CA_CERT} /etc/cfgms/datasvc-ca.pem"
echo "  Connection string (sslmode=verify-full, path as seen on the controller node):"
echo "    postgres://cfgms:<password>@${PG_VM_IP_OUT}:5432/cfgms?sslmode=verify-full&sslrootcert=/etc/cfgms/datasvc-ca.pem"
echo "  Use the raw dsn string config path (not the keyword-builder) to pass sslrootcert — see story #3127."
echo "MinIO:      endpoint_url=http://${PG_VM_IP_OUT}:${MINIO_API_PORT} bucket=${MINIO_BUCKET}"
echo ""

if [[ "$PG_PASSWORD_PRINTED" == "true" ]]; then
    echo "PostgreSQL role password (ONE-TIME PRINT — store now, not repeated on re-run):"
    echo "  ${PG_PASSWORD}"
    echo ""
fi

if [[ "$MINIO_PASSWORD_PRINTED" == "true" ]]; then
    echo "MinIO root credentials (ONE-TIME PRINT — store now, not repeated on re-run):"
    echo "  access key: ${MINIO_ROOT_USER}"
    echo "  secret key: ${MINIO_ROOT_PASSWORD}"
    echo ""
fi

echo "Store both in an OS-native keychain immediately, e.g. from the operator workstation:"
echo "  Windows: cmdkey /generic:cfgms-lab-datasvc-postgres /user:${PG_ROLE} /pass:<password>"
echo "           cmdkey /generic:cfgms-lab-datasvc-minio /user:<access-key> /pass:<secret-key>"
echo "  Linux:   secret-tool store --label='cfgms-lab-datasvc postgres' service cfgms-lab-datasvc credential postgres"
echo "  macOS:   security add-generic-password -s cfgms-lab-datasvc -a postgres -w '<password>'"
echo ""
echo "Never commit these values to a file in the repository."
echo ""
