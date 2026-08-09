#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# tier1-bootstrap.sh — Bootstrap a Tier 1 CFGMS controller on Debian 12.
# Idempotent. Re-run safe.
#
# Usage:
#   sudo bash tier1-bootstrap.sh --hostname=ctrl.cfgms.lab [options]
#
# Flags:
#   --hostname HOST         Controller hostname for cert SAN (required)
#   --version TAG           Release tag to install (default: latest tagged release)
#   --binary-path PATH      Local binary path instead of downloading (air-gapped)
#   --config PATH           Alternate controller.cfg template (default: generated)
#   --skip-tenant-seed      Skip tenant tree seeding (step 7)
#   --skip-smoke            Skip smoke test (step 8)
#
# Test isolation:
#   CFGMS_INSTALL_PREFIX=/tmp/test bash tier1-bootstrap.sh --hostname=test-host
#   All write paths are prefixed. Binary must be pre-populated at
#   $CFGMS_INSTALL_PREFIX/usr/local/bin/cfgms-controller (and cfg).
#   System calls (apt, useradd, chown, systemctl) are skipped.
#
# See: docs/operations/tier1-controller-bringup.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${CFGMS_INSTALL_PREFIX:-}"

# ── Argument parsing ──────────────────────────────────────────────────────────

HOSTNAME_FLAG=""
VERSION_FLAG=""
BINARY_PATH=""
CONFIG_OVERRIDE=""
SKIP_TENANT_SEED=false
SKIP_SMOKE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname=*)       HOSTNAME_FLAG="${1#*=}"; shift ;;
        --hostname)         HOSTNAME_FLAG="$2"; shift 2 ;;
        --version=*)        VERSION_FLAG="${1#*=}"; shift ;;
        --version)          VERSION_FLAG="$2"; shift 2 ;;
        --binary-path=*)    BINARY_PATH="${1#*=}"; shift ;;
        --binary-path)      BINARY_PATH="$2"; shift 2 ;;
        --config=*)         CONFIG_OVERRIDE="${1#*=}"; shift ;;
        --config)           CONFIG_OVERRIDE="$2"; shift 2 ;;
        --skip-tenant-seed) SKIP_TENANT_SEED=true; shift ;;
        --skip-smoke)       SKIP_SMOKE=true; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$HOSTNAME_FLAG" ]]; then
    echo "Usage: sudo bash tier1-bootstrap.sh --hostname=<hostname> [options]" >&2
    echo "" >&2
    echo "  --hostname HOST         Controller hostname for cert SAN (required)" >&2
    echo "  --version TAG           Release tag (default: latest tagged release)" >&2
    echo "  --binary-path PATH      Local binary path (air-gapped install)" >&2
    echo "  --config PATH           Alternate controller.cfg template" >&2
    echo "  --skip-tenant-seed      Skip tenant tree seeding" >&2
    echo "  --skip-smoke            Skip smoke test" >&2
    exit 1
fi

# ── Path helpers ──────────────────────────────────────────────────────────────

# All write paths use CFGMS_INSTALL_PREFIX when set (test isolation).
CFGMS_BIN_DIR="${INSTALL_PREFIX}/usr/local/bin"
CFGMS_ETC_DIR="${INSTALL_PREFIX}/etc/cfgms"
CFGMS_DATA_DIR="${INSTALL_PREFIX}/var/lib/cfgms"
CFGMS_LOG_DIR="${INSTALL_PREFIX}/var/log/cfgms"
CFGMS_SYSTEMD_DIR="${INSTALL_PREFIX}/etc/systemd/system"
CONTROLLER_BIN="${CFGMS_BIN_DIR}/cfgms-controller"
CFG_BIN="${CFGMS_BIN_DIR}/cfg"
CONTROLLER_CFG="${CFGMS_ETC_DIR}/controller.cfg"
CONTROLLER_SERVICE="${CFGMS_SYSTEMD_DIR}/cfgms-controller.service"
ADMIN_BUNDLE="${CFGMS_ETC_DIR}/admin.bundle.yaml"
INIT_MARKER="${CFGMS_ETC_DIR}/.admin-bundle-issued"
SECRETS_KEY_FILE="${CFGMS_ETC_DIR}/secrets.key"

log() { echo "[bootstrap] $*"; }

# ── Step 1: Pre-flight ────────────────────────────────────────────────────────

log "Step 1: Pre-flight checks"

if [[ -z "$INSTALL_PREFIX" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: must be run as root (sudo bash $(basename "$0") --hostname=...)" >&2
        exit 1
    fi

    if ! grep -qi "debian" /etc/os-release 2>/dev/null; then
        echo "Error: this script targets Debian 12. Detected OS:" >&2
        grep PRETTY_NAME /etc/os-release 2>/dev/null || echo "  (unknown)" >&2
        exit 1
    fi

    if ss -tlnp 2>/dev/null | grep -q ':9080 '; then
        echo "Error: port 9080 is already in use." >&2
        echo "  Find the process: ss -tlnp | grep ':9080'" >&2
        exit 1
    fi
fi

log "Pre-flight checks passed."

# ── Step 2: OS baseline ───────────────────────────────────────────────────────

log "Step 2: OS baseline (idempotent)"

if [[ -z "$INSTALL_PREFIX" ]]; then
    if command -v apt-get &>/dev/null; then
        apt-get -qq update -y
        apt-get -qq install -y git curl openssl
    fi

    if ! id cfgms &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin cfgms
        log "Created cfgms system user."
    else
        log "cfgms user already exists."
    fi
fi

mkdir -p \
    "${CFGMS_ETC_DIR}" \
    "${CFGMS_DATA_DIR}/storage" \
    "${CFGMS_DATA_DIR}/certs/ca" \
    "${CFGMS_LOG_DIR}" \
    "${CFGMS_BIN_DIR}" \
    "${CFGMS_SYSTEMD_DIR}"

if [[ -z "$INSTALL_PREFIX" ]]; then
    chown cfgms:cfgms "${CFGMS_ETC_DIR}"
    chown -R cfgms:cfgms "${CFGMS_DATA_DIR}" "${CFGMS_LOG_DIR}"
    chmod 750 "${CFGMS_DATA_DIR}"
    chmod 750 "${CFGMS_LOG_DIR}"
    chmod 750 "${CFGMS_ETC_DIR}"
fi

log "Directory layout ready."

if [[ ! -f "$SECRETS_KEY_FILE" ]]; then
    umask 077
    openssl rand -out "$SECRETS_KEY_FILE" 32
    log "Generated external secret-encryption key."
fi
chmod 0600 "$SECRETS_KEY_FILE"
if [[ -z "$INSTALL_PREFIX" ]]; then
    chown cfgms:cfgms "$SECRETS_KEY_FILE"
fi

# ── Step 3: Binary fetch ──────────────────────────────────────────────────────

log "Step 3: Binary fetch"

if [[ -x "$CONTROLLER_BIN" ]]; then
    log "Binary already present at $CONTROLLER_BIN — skipping download."
elif [[ -n "$BINARY_PATH" ]]; then
    cp "$BINARY_PATH" "$CONTROLLER_BIN"
    chmod +x "$CONTROLLER_BIN"
    log "Installed binary from $BINARY_PATH"
elif [[ -n "$INSTALL_PREFIX" ]]; then
    echo "Error: test isolation requires cfgms-controller pre-populated at $CONTROLLER_BIN" >&2
    exit 1
else
    # Resolve version from latest tagged release (never develop tip).
    if [[ -z "$VERSION_FLAG" ]]; then
        if command -v gh &>/dev/null; then
            VERSION_FLAG="$(gh release view --repo cfg-is/cfgms --json tagName -q .tagName 2>/dev/null || true)"
        fi
        if [[ -z "$VERSION_FLAG" ]]; then
            VERSION_FLAG="$(curl -fsSL https://api.github.com/repos/cfg-is/cfgms/releases/latest \
                | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' 2>/dev/null | head -1 || true)"
        fi
        if [[ -z "$VERSION_FLAG" ]]; then
            echo "Error: could not determine latest release tag." >&2
            echo "  Pass --version <tag> or check network connectivity." >&2
            exit 1
        fi
    fi
    if [[ ! "$VERSION_FLAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?$ ]]; then
        echo "Error: release version is not a canonical semantic version." >&2
        exit 1
    fi
    if [[ "$VERSION_FLAG" == *-* ]]; then
        IFS='.' read -r -a prerelease_parts <<< "${VERSION_FLAG#*-}"
        for identifier in "${prerelease_parts[@]}"; do
            if [[ "$identifier" =~ ^[0-9]+$ && ${#identifier} -gt 1 && "$identifier" == 0* ]]; then
                echo "Error: release version is not canonical semantic versioning." >&2
                exit 1
            fi
        done
    fi
    log "Installing cfgms-controller version $VERSION_FLAG"

    ARCH="amd64"
    if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
        ARCH="arm64"
    fi
    TARBALL_URL="https://github.com/cfg-is/cfgms/releases/download/${VERSION_FLAG}/cfgms-linux-${ARCH}.tar.gz"
    BUNDLE_URL="${TARBALL_URL}.sigstore.json"

    TMPTAR="$(mktemp /tmp/cfgms-XXXXXX.tar.gz)"
    TMPBUNDLE="$(mktemp /tmp/cfgms-XXXXXX.sigstore.json)"
    cleanup_tar() { rm -f "$TMPTAR" "$TMPBUNDLE"; }
    trap cleanup_tar EXIT INT TERM

    curl -fsSL "$TARBALL_URL" -o "$TMPTAR"
    curl -fsSL "$BUNDLE_URL" -o "$TMPBUNDLE"

    VERIFY_SCRIPT="$SCRIPT_DIR/verify-release-artifact.sh"
    if [[ ! -f "$VERIFY_SCRIPT" ]]; then
        echo "Error: release verifier not found at $VERIFY_SCRIPT." >&2
        echo "  Run the bootstrap from a complete CFGMS source checkout." >&2
        exit 1
    fi
    bash "$VERIFY_SCRIPT" "$TMPTAR" "$TMPBUNDLE" "$VERSION_FLAG"

    # Extract only the fixed top-level names after repository-bound
    # signature/attestation succeeds. Refuse unexpected archive layouts.
    if ! tar -tzf "$TMPTAR" cfgms-controller >/dev/null 2>&1; then
        echo "Error: signed archive does not contain top-level cfgms-controller." >&2
        exit 1
    fi
    tar -xzf "$TMPTAR" -C "$CFGMS_BIN_DIR" cfgms-controller
    chmod +x "$CONTROLLER_BIN"

    # Extract cfg CLI binary if present in the tarball.
    if tar -tzf "$TMPTAR" cfg >/dev/null 2>&1; then
        tar -xzf "$TMPTAR" -C "$CFGMS_BIN_DIR" cfg
        chmod +x "$CFG_BIN"
        log "cfg CLI installed from tarball."
    fi

    rm -f "$TMPTAR" "$TMPBUNDLE"
    trap - EXIT INT TERM
    log "Binary installed to $CONTROLLER_BIN"
fi

# Locate cfg CLI for tenant seeding (may have been installed separately or from tarball).
if [[ ! -x "$CFG_BIN" ]]; then
    CFG_IN_PATH="$(command -v cfg 2>/dev/null || true)"
    if [[ -n "$CFG_IN_PATH" ]]; then
        CFG_BIN="$CFG_IN_PATH"
        log "Using cfg from PATH: $CFG_BIN"
    else
        log "Warning: cfg CLI not found at $CFGMS_BIN_DIR/cfg or in PATH."
        log "  Tenant seeding will be skipped unless --skip-tenant-seed is passed."
        if [[ "$SKIP_TENANT_SEED" != "true" ]]; then
            echo "Error: cfg CLI required for tenant seeding. Install it or pass --skip-tenant-seed." >&2
            exit 1
        fi
    fi
fi

# ── Step 4: Config ────────────────────────────────────────────────────────────

log "Step 4: Config"

if [[ -f "$CONTROLLER_CFG" ]]; then
    log "Config already exists at $CONTROLLER_CFG — skipping generation."
else
    if [[ -n "$CONFIG_OVERRIDE" ]]; then
        cp "$CONFIG_OVERRIDE" "$CONTROLLER_CFG"
        log "Config installed from override: $CONFIG_OVERRIDE"
    else
        cat > "$CONTROLLER_CFG" <<EOF
# CFGMS Controller Configuration
# Generated by tier1-bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Hostname: ${HOSTNAME_FLAG}

security_profile: "public-beta"
execution:
  require_signed_adhoc: true

listen_addr: "0.0.0.0:9080"
metrics_listen_addr: "127.0.0.1:9090"
external_url: "https://${HOSTNAME_FLAG}:9080"
data_dir: "/var/lib/cfgms"

certificate:
  enable_cert_management: true
  ca_path: "/var/lib/cfgms/certs/ca"
  renewal_threshold_days: 30
  server_cert_validity_days: 365
  client_cert_validity_days: 365
  server:
    common_name: "${HOSTNAME_FLAG}"
    dns_names:
      - "${HOSTNAME_FLAG}"
      - "localhost"
    ip_addresses:
      - "127.0.0.1"
    organization: "CFGMS Tier 1"

storage:
  flatfile_root: "/var/lib/cfgms/storage"
  sqlite_path: "/var/lib/cfgms/cfgms.db"

logging:
  level: "info"
  provider: "file"
  config:
    directory: "/var/log/cfgms"
    max_file_size: 10485760
    max_files: 5

transport:
  listen_addr: "0.0.0.0:4433"
  external_address: "${HOSTNAME_FLAG}"
  use_cert_manager: true
  max_connections: 50000
  keepalive_period: "30s"
  idle_timeout: "5m"
EOF
        log "Config rendered to $CONTROLLER_CFG"
    fi
    if [[ -z "$INSTALL_PREFIX" ]]; then
        chown cfgms:cfgms "$CONTROLLER_CFG"
        chmod 640 "$CONTROLLER_CFG"
    fi
fi

# ── Step 5: Init ──────────────────────────────────────────────────────────────

log "Step 5: Controller init"

if [[ -f "$INIT_MARKER" ]]; then
    log "Init marker found at $INIT_MARKER — controller already initialized, skipping."
else
    if [[ -z "$INSTALL_PREFIX" ]]; then
        runuser --user cfgms -- env CFGMS_SECRETS_KEY_FILE="$SECRETS_KEY_FILE" \
            "$CONTROLLER_BIN" --init --config "$CONTROLLER_CFG"
    else
        CFGMS_SECRETS_KEY_FILE="$SECRETS_KEY_FILE" \
            "$CONTROLLER_BIN" --init --config "$CONTROLLER_CFG"
    fi
fi

# ── Step 6: Systemd ───────────────────────────────────────────────────────────

log "Step 6: Systemd service"

cat > "$CONTROLLER_SERVICE" <<EOF
[Unit]
Description=CFGMS Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-controller --config /etc/cfgms/controller.cfg
LoadCredential=cfgms-secrets-key:/etc/cfgms/secrets.key
Environment=CFGMS_SECRETS_KEY_FILE=%d/cfgms-secrets-key
Environment=CFGMS_SECURITY_PROFILE=public-beta
Environment=CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC=true
Restart=on-failure
RestartSec=5
User=cfgms
Group=cfgms
WorkingDirectory=/var/lib/cfgms
UMask=0077
ConfigurationDirectory=cfgms
ConfigurationDirectoryMode=0750
StateDirectory=cfgms
StateDirectoryMode=0750
LogsDirectory=cfgms
LogsDirectoryMode=0750
RuntimeDirectory=cfgms
RuntimeDirectoryMode=0750
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
InaccessiblePaths=/etc/cfgms/secrets.key
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
ProcSubset=pid
ReadWritePaths=/var/lib/cfgms /var/log/cfgms
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
KeyringMode=private
PrivateMounts=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitNOFILE=65536
TasksMax=512
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cfgms-controller

[Install]
WantedBy=multi-user.target
EOF

if [[ -z "$INSTALL_PREFIX" ]]; then
    systemctl daemon-reload
    systemctl enable cfgms-controller 2>/dev/null || true
    if systemctl is-active --quiet cfgms-controller 2>/dev/null; then
        log "cfgms-controller service already running."
    else
        systemctl start cfgms-controller
        log "cfgms-controller service started."
    fi
else
    log "Test isolation: systemd unit written to $CONTROLLER_SERVICE (not loaded)."
fi

# ── Step 7: Tenant seed ───────────────────────────────────────────────────────

if [[ "$SKIP_TENANT_SEED" == "true" ]]; then
    log "Step 7: Tenant seeding skipped (--skip-tenant-seed)."
else
    log "Step 7: Tenant seed"

    if [[ -z "$INSTALL_PREFIX" ]]; then
        # Wait for the REST API to accept connections before seeding.
        RETRIES=12
        for ((i = 1; i <= RETRIES; i++)); do
            if curl --fail --silent --show-error \
                --cacert "${CFGMS_DATA_DIR}/certs/ca/ca.crt" \
                "https://localhost:9080/api/v1/health" &>/dev/null; then
                break
            fi
            if [[ $i -eq $RETRIES ]]; then
                echo "Error: controller REST API did not become ready after $((RETRIES * 5))s." >&2
                exit 1
            fi
            log "  Waiting for controller REST API... (${i}/${RETRIES})"
            sleep 5
        done
    fi

    _seed_tenant() {
        local tenant_id="$1"
        local parent_flag="${2:-}"
        local args=(tenant create "--tenant-id=${tenant_id}")
        if [[ -n "$parent_flag" ]]; then
            args+=("--parent=${parent_flag}")
        fi
        if [[ -n "$INSTALL_PREFIX" ]]; then
            CFGMS_ADMIN_BUNDLE="$ADMIN_BUNDLE" "$CFG_BIN" "${args[@]}" 2>/dev/null \
                && log "  Tenant ${tenant_id}: created." \
                || log "  Tenant ${tenant_id}: already exists (idempotent)."
        else
            CFGMS_ADMIN_BUNDLE="$ADMIN_BUNDLE" "$CFG_BIN" "${args[@]}" \
                && log "  Tenant ${tenant_id}: created." \
                || log "  Tenant ${tenant_id}: already exists (idempotent)."
        fi
    }

    _seed_tenant "team-root"
    _seed_tenant "agent-test" "team-root"
    _seed_tenant "infra-hyperv" "team-root"

    log "Tenant seeding complete."
fi

# ── Step 8: Smoke test ────────────────────────────────────────────────────────

if [[ "$SKIP_SMOKE" == "true" ]]; then
    log "Step 8: Smoke test skipped (--skip-smoke)."
else
    log "Step 8: Smoke test"

    SMOKE_SCRIPT="${SCRIPT_DIR}/tier1-smoke-test.sh"
    if [[ ! -f "$SMOKE_SCRIPT" ]]; then
        echo "Error: tier1-smoke-test.sh not found at $SMOKE_SCRIPT" >&2
        echo "  Copy it alongside tier1-bootstrap.sh and retry." >&2
        exit 1
    fi

    if [[ -n "$INSTALL_PREFIX" ]]; then
        log "Test isolation: smoke test skipped (no live controller in test mode)."
    else
        CFGMS_ADMIN_BUNDLE="$ADMIN_BUNDLE" bash "$SMOKE_SCRIPT"
    fi
fi

# ── Step 9: Final output ──────────────────────────────────────────────────────

DISPLAY_HOST="$(hostname -f 2>/dev/null || echo "${HOSTNAME_FLAG}")"

echo ""
echo "=========================================="
echo " Tier 1 Controller Bootstrap Complete"
echo "=========================================="
echo ""
echo "Admin bundle:  ${ADMIN_BUNDLE}"
echo ""
echo "To copy the admin bundle to your workstation:"
echo "  scp ${DISPLAY_HOST}:${ADMIN_BUNDLE} /tmp/admin.bundle.yaml"
echo ""
echo "Then store it in your OS keychain:"
echo "  Linux:  secret-tool store --label='CFGMS Admin Bundle' service cfgms bundle admin < /tmp/admin.bundle.yaml"
echo "  macOS:  security add-generic-password -s cfgms -a admin -w \"\$(cat /tmp/admin.bundle.yaml)\""
echo "  Then:   rm /tmp/admin.bundle.yaml"
echo ""
echo "Load the bundle in future sessions:"
echo "  source scripts/cfgms-bundle-load"
echo ""
echo "See docs/operations/tier1-controller-bringup.md for the full runbook."
echo ""
