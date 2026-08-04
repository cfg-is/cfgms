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

MINIO_USER="minio-server"
MINIO_DATA_DIR="/var/lib/minio/data"
MINIO_CONFIG_DIR="/etc/minio"
MINIO_ENV_FILE="${MINIO_CONFIG_DIR}/minio.env"
MINIO_BUCKET="cfgms-installer-blobs"
MINIO_API_PORT=9000
MINIO_CONSOLE_PORT=9001

log() { echo "[bootstrap] $*"; }

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

HBA_LINE="host    all             all             ${PG_LISTEN_SUBNET}        scram-sha-256"
if ! grep -qF "$HBA_LINE" "$PG_HBA" 2>/dev/null; then
    echo "$HBA_LINE" >> "$PG_HBA"
    log "Added pg_hba.conf entry for ${PG_LISTEN_SUBNET}."
else
    log "pg_hba.conf entry for ${PG_LISTEN_SUBNET} already present."
fi

systemctl enable postgresql &>/dev/null || true
systemctl restart postgresql
log "PostgreSQL configured and (re)started."

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

echo ""
echo "=========================================="
echo " cfg-lab data-services bootstrap complete"
echo "=========================================="
echo ""
echo "PostgreSQL: db=${PG_DB} role=${PG_ROLE} port=5432"
echo "MinIO:      endpoint_url=http://$(hostname -I | awk '{print $1}'):${MINIO_API_PORT} bucket=${MINIO_BUCKET}"
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
