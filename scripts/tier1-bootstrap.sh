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
#   --allow-host-key        Seal the root key to this node's disk-resident host
#                           key instead of its TPM2. Explicit opt-in; warns loudly.
#   --skip-tenant-seed      Skip tenant tree seeding (step 7)
#   --skip-smoke            Skip smoke test (step 8)
#
# Root key at rest (ADR-030, story #3462):
#   The SOPS root key is generated and sealed in a single pipeline —
#   `openssl rand 32 | systemd-creds encrypt --with-key=tpm2 - secrets.key.cred`
#   — so the plaintext exists only in that pipe and is never written to a file,
#   temporary or otherwise. The unit loads the sealed blob with
#   LoadCredentialEncrypted=, and systemd exposes the decrypted key on a
#   per-invocation tmpfs under /run/credentials/ before privilege drop.
#
#   No temporary file is used, on tmpfs or anywhere else: /tmp is a directory on
#   the root filesystem on Debian and Ubuntu, and `shred` does not reliably
#   destroy overwritten data on ext4/XFS/btrfs or on wear-levelled and
#   thin-provisioned disks — so "write then shred" would put the root key on
#   persistent storage with no dependable way to remove it.
#
#   A node with no usable TPM2 fails provisioning unless the operator opts in
#   with --allow-host-key (env: CFGMS_BOOTSTRAP_ALLOW_HOST_KEY=1).
#   `--with-key=auto` is never used: it downgrades to the disk-resident host key
#   with no signal to the operator. Re-running the script MIGRATES an existing
#   controller by sealing its current cleartext /etc/cfgms/secrets.key and then
#   removing it.
#
# Admin bundle at rest (Issue #4342):
#   The same argument applies to the admin credential `--init` issues: once
#   written to persistent storage, `shred` cannot dependably erase it either, so
#   the fix is to never write it there — not to write-then-shred. The
#   controller.cfg in force is made to point admin_bundle_path at this script's
#   own tmpfs-backed directory, /run/cfgms-admin-bundle, and Step 4 FAILS THE
#   RUN if it points anywhere else — including at a config an operator supplied
#   with --config, and including a config written by an older version of this
#   script that predates the key (the key is appended to it). The bundle is
#   printed to this script's stdout exactly once (Step 9) — the operator's only
#   copy — and a trap removes it on every exit path (success, a later step's
#   failure, or a signal). Every other byte produced by the run — this script's
#   own messages AND the stdout of every child it spawns — goes to stderr, so
#   that `ssh ... 'sudo bash tier1-bootstrap.sh ...' > admin.bundle.yaml`
#   captures nothing but the bundle. That is enforced structurally (fd 1 is
#   pointed at stderr for the whole script and the caller's stdout kept on
#   fd 3), not by remembering `>&2` at each call site. Re-running an
#   already-initialized controller does not re-issue or re-print it: the
#   issuance marker at /etc/cfgms/.admin-bundle-issued (now written by this
#   script, not by --init) gates it, and steps 7-8 skip rather than use a stale
#   credential. A controller provisioned by an earlier version of this script
#   has the bundle sitting in cleartext at /etc/cfgms/admin.bundle.yaml
#   indefinitely; the cleanup trap removes it on every run — including runs that
#   fail after it was armed — so an existing deployment converges without a
#   manual step.
#
#   This script never `rm -rf`s a directory it did not create. The bundle
#   directory is validated to be its own dedicated path under /run before
#   anything is removed from it, only the bundle file itself is deleted, and the
#   directory is reclaimed with `rmdir`, which refuses to touch a non-empty
#   directory. An earlier revision re-derived the directory from
#   admin_bundle_path and `rm -rf`'d whatever that resolved to, which destroyed
#   /etc/cfgms — sealed root key included — for a config pointing the bundle
#   there.
#
# Test isolation:
#   CFGMS_INSTALL_PREFIX=/tmp/test bash tier1-bootstrap.sh --hostname=test-host
#   All write paths are prefixed. Binary must be pre-populated at
#   $CFGMS_INSTALL_PREFIX/usr/local/bin/cfgms-controller (and cfg).
#   System calls (apt, useradd, chown, systemctl) are skipped.
#   CFGMS_SYSTEMD_CREDS_BIN overrides the `systemd-creds` executable and
#   CFGMS_BOOTSTRAP_TPM2_PROBE overrides the TPM2 detection command.
#
# See: docs/operations/tier1-controller-bringup.md

set -euo pipefail

# stdout is reserved, for the whole run, for the admin bundle printed in Step 9
# (Issue #4342). Reserving it per-statement does not hold: this script's own
# `log`/`warn`/`die` honour it, but the CHILDREN it runs do not — `cfgms-controller
# --init` prints its completion banner, `cfg tenant create` prints "tenant
# created: <id>" three times, and tier1-smoke-test.sh prints "[PASS] ..." and a
# result line, all on stdout. Those ~10 lines landed ahead of the bundle in
# `ssh host 'sudo bash tier1-bootstrap.sh ...' > admin.bundle.yaml`, corrupting
# the operator's ONLY copy of a live admin credential that this script will not
# re-issue.
#
# So the reservation is made structural instead of per-call-site: the caller's
# real stdout is saved on fd 3 and fd 1 is pointed at stderr for the rest of the
# script. Anything this script or any process it spawns writes to fd 1 goes to
# stderr, and the single `>&3` in Step 9 is the only path to the caller's stdout
# — including for children added later, which cannot reintroduce the leak.
# Command substitutions, pipelines and `> file` redirections establish their own
# fd 1 and are unaffected.
exec 3>&1 1>&2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${CFGMS_INSTALL_PREFIX:-}"

# ── Argument parsing ──────────────────────────────────────────────────────────

HOSTNAME_FLAG=""
VERSION_FLAG=""
BINARY_PATH=""
CONFIG_OVERRIDE=""
SKIP_TENANT_SEED=false
SKIP_SMOKE=false
ALLOW_HOST_KEY="${CFGMS_BOOTSTRAP_ALLOW_HOST_KEY:-0}"
SYSTEMD_CREDS_BIN="${CFGMS_SYSTEMD_CREDS_BIN:-systemd-creds}"
TPM2_PROBE="${CFGMS_BOOTSTRAP_TPM2_PROBE:-systemd-analyze has-tpm2 -q}"

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
        --allow-host-key)   ALLOW_HOST_KEY=1; shift ;;
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
    echo "  --allow-host-key        Seal the root key to disk instead of the TPM2" >&2
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

# Admin bundle: tmpfs only, never persistent storage. See "Admin bundle at
# rest" above. This directory is dedicated to this script — it is the only
# directory the script creates, writes the bundle into, and removes from, and
# Step 4 refuses to run if the controller.cfg in force names any other location.
ADMIN_BUNDLE_DIR="${INSTALL_PREFIX}/run/cfgms-admin-bundle"
ADMIN_BUNDLE="${ADMIN_BUNDLE_DIR}/admin.bundle.yaml"

INIT_MARKER="${CFGMS_ETC_DIR}/.admin-bundle-issued"
BOOTSTRAP_RECORD="${CFGMS_ETC_DIR}/.bootstrap-record"

# Legacy cleartext admin bundle path from before this script stopped leaving it
# on persistent storage (Issue #4342). Opportunistically removed every run.
LEGACY_ADMIN_BUNDLE="${CFGMS_ETC_DIR}/admin.bundle.yaml"

# Legacy cleartext path. Read (to migrate it) and then removed. Never written.
LEGACY_SECRETS_KEY_FILE="${CFGMS_ETC_DIR}/secrets.key"

# Sealed root key. `systemd-creds encrypt` output, decryptable only by this
# node's TPM2 (or, under --allow-host-key, its host key).
SECRETS_KEY_CRED="${CFGMS_ETC_DIR}/secrets.key.cred"
SECRETS_KEY_CRED_ID="cfgms-secrets-key"

# All status output goes to stderr — stdout is reserved for the admin bundle
# printed in Step 9, so `command > admin.bundle.yaml` captures only the bundle.
log() { echo "[bootstrap] $*" >&2; }
warn() { echo "[bootstrap] WARNING: $*" >&2; }
die() { echo "[bootstrap] Error: $*" >&2; exit 1; }

# ── Credential sealing ────────────────────────────────────────────────────────

# select_key_mode decides what `systemd-creds encrypt --with-key=` is given, and
# fails provisioning rather than silently downgrading. `--with-key=auto` is
# never used: it falls back to the host key in
# /var/lib/systemd/credential.secret whenever no TPM2 is present, with no signal
# to the operator — and that file sits on the same disk as the sealed blob, so a
# stolen image yields both halves (ADR-030, Decision 1).
KEY_MODE=""
select_key_mode() {
    if [[ "$ALLOW_HOST_KEY" == "1" ]]; then
        KEY_MODE="host"
        warn "--allow-host-key: sealing the root key with the HOST KEY, not a TPM."
        warn "  The unsealing key is /var/lib/systemd/credential.secret on this host's own"
        warn "  disk, so a stolen disk image or VM snapshot yields the plaintext root key."
        warn "  Recorded as key_mode: host in ${BOOTSTRAP_RECORD}."
        return 0
    fi

    if $TPM2_PROBE >/dev/null 2>&1; then
        KEY_MODE="tpm2"
        return 0
    fi

    die "no usable TPM2 on this host — refusing to seal the root key to disk silently.
  The SOPS root key is sealed to the TPM2 by default so a stolen disk image or
  VM snapshot cannot yield it. This host reports no usable TPM2
  (probe: ${TPM2_PROBE}).
  Either enable a TPM2, or accept disk-bound sealing explicitly by re-running
  with --allow-host-key (env: CFGMS_BOOTSTRAP_ALLOW_HOST_KEY=1).
  See docs/architecture/decisions/030-controller-secret-material-at-rest.md"
}

# provision_secrets_key generates and seals the SOPS root key in a single
# pipeline, or migrates an existing cleartext key into a sealed blob.
#
# The generated plaintext exists ONLY in the pipe between openssl and
# systemd-creds — there is deliberately no intermediate file to shred. A node
# that cannot seal its key fails here, loudly, leaving no key material behind
# for a later run to adopt as if it were valid.
provision_secrets_key() {
    if [[ -f "$SECRETS_KEY_CRED" ]]; then
        log "Root key already sealed at ${SECRETS_KEY_CRED} — skipping."
        return 0
    fi

    if [[ -f "$LEGACY_SECRETS_KEY_FILE" ]]; then
        # Migration. The existing key must be preserved exactly: this controller's
        # stored secrets are already encrypted under it, and generating a new one
        # would leave a node that starts cleanly and cannot read its own data.
        if ! (umask 077 && "$SYSTEMD_CREDS_BIN" encrypt --name="$SECRETS_KEY_CRED_ID" \
                --with-key="$KEY_MODE" "$LEGACY_SECRETS_KEY_FILE" "$SECRETS_KEY_CRED"); then
            rm -f "$SECRETS_KEY_CRED"
            die "failed to seal the existing root key with --with-key=${KEY_MODE}; nothing was changed."
        fi
        log "Migrated the existing root key from ${LEGACY_SECRETS_KEY_FILE} to a sealed credential."
    else
        if ! (umask 077 && openssl rand 32 | "$SYSTEMD_CREDS_BIN" encrypt \
                --name="$SECRETS_KEY_CRED_ID" --with-key="$KEY_MODE" - "$SECRETS_KEY_CRED"); then
            rm -f "$SECRETS_KEY_CRED"
            die "failed to generate and seal the root key with --with-key=${KEY_MODE}."
        fi
        log "Generated and sealed the external secret-encryption key (key_mode=${KEY_MODE})."
    fi

    chmod 0400 "$SECRETS_KEY_CRED"
    if [[ -z "$INSTALL_PREFIX" ]]; then
        chown root:root "$SECRETS_KEY_CRED"
    fi

    {
        echo "# Written by tier1-bootstrap.sh — do not edit."
        echo "hostname: ${HOSTNAME_FLAG}"
        echo "key_mode: ${KEY_MODE}"
        echo "sealed_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$BOOTSTRAP_RECORD"
    chmod 0640 "$BOOTSTRAP_RECORD"

    if [[ -f "$LEGACY_SECRETS_KEY_FILE" ]]; then
        rm -f "$LEGACY_SECRETS_KEY_FILE"
        log "Removed legacy cleartext ${LEGACY_SECRETS_KEY_FILE} (superseded by the sealed credential)."
    fi
}

# unseal_secrets_key decrypts the sealed root key for the one-shot `--init` run,
# which happens outside systemd and so has no credentials directory of its own.
unseal_secrets_key() {
    local dest="$1"
    if ! (umask 077 && "$SYSTEMD_CREDS_BIN" decrypt --name="$SECRETS_KEY_CRED_ID" "$SECRETS_KEY_CRED" "$dest"); then
        rm -f "$dest"
        die "failed to unseal the root key from ${SECRETS_KEY_CRED}."
    fi
    chmod 0400 "$dest"
}

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

select_key_mode
provision_secrets_key

# ── Step 3: Binary fetch ──────────────────────────────────────────────────────

log "Step 3: Binary fetch"

if [[ -x "$CONTROLLER_BIN" ]]; then
    log "Binary already present at $CONTROLLER_BIN — skipping download."
elif [[ -n "$BINARY_PATH" ]]; then
    cp "$BINARY_PATH" "$CONTROLLER_BIN"
    chmod 0755 "$CONTROLLER_BIN"
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
    chmod 0755 "$CONTROLLER_BIN"

    # Extract cfg CLI binary if present in the tarball.
    if tar -tzf "$TMPTAR" cfg >/dev/null 2>&1; then
        tar -xzf "$TMPTAR" -C "$CFGMS_BIN_DIR" cfg
        chmod 0755 "$CFG_BIN"
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
    # A config written before this script stopped leaving the admin bundle on
    # persistent storage (Issue #4342) has no admin_bundle_path at all, and the
    # controller then falls back to its own default — /etc/cfgms/admin.bundle.yaml
    # (features/controller/initialization/bundle_marker.go). Appending the key is
    # what makes an already-provisioned host converge; without it `--init` writes
    # the full admin cert and key to persistent storage and this run aborts with
    # that file left behind. Same append the --config branch below does.
    if ! grep -q '^admin_bundle_path:' "$CONTROLLER_CFG"; then
        echo "admin_bundle_path: \"${ADMIN_BUNDLE}\"" >> "$CONTROLLER_CFG"
        log "  Existing config predates admin_bundle_path — appended ${ADMIN_BUNDLE}."
    fi
else
    if [[ -n "$CONFIG_OVERRIDE" ]]; then
        cp "$CONFIG_OVERRIDE" "$CONTROLLER_CFG"
        log "Config installed from override: $CONFIG_OVERRIDE"
        if ! grep -q '^admin_bundle_path:' "$CONTROLLER_CFG"; then
            echo "admin_bundle_path: \"${ADMIN_BUNDLE}\"" >> "$CONTROLLER_CFG"
        fi
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
admin_bundle_path: "${ADMIN_BUNDLE}"

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

# The config actually in force (generated, overridden, or pre-existing from an
# earlier run) is the source of truth for where --init will write the admin
# bundle, so read it back rather than trust the default above — and then hold it
# to that default rather than following it wherever it points. The value is
# operator-controlled: this script creates, writes to and deletes from the
# directory it names, so anything other than its own dedicated tmpfs directory
# fails the run. Accepting a value under /etc/cfgms or /var/lib/cfgms would mean
# deleting the sealed root key, the CA, or the stored config.
CONFIGURED_ADMIN_BUNDLE="$(sed -n 's/^admin_bundle_path:[[:space:]]*//p' "$CONTROLLER_CFG" | head -1)"
CONFIGURED_ADMIN_BUNDLE="${CONFIGURED_ADMIN_BUNDLE%$'\r'}"
CONFIGURED_ADMIN_BUNDLE="${CONFIGURED_ADMIN_BUNDLE#[\"\']}"
CONFIGURED_ADMIN_BUNDLE="${CONFIGURED_ADMIN_BUNDLE%[\"\']}"

if grep -q '^admin_bundle_path:' "$CONTROLLER_CFG" && [[ -z "$CONFIGURED_ADMIN_BUNDLE" ]]; then
    die "admin_bundle_path in ${CONTROLLER_CFG} is present but empty or unparseable.
  Set it to \"${ADMIN_BUNDLE}\" or remove the key and re-run."
fi

if [[ -n "$CONFIGURED_ADMIN_BUNDLE" && "$CONFIGURED_ADMIN_BUNDLE" != "$ADMIN_BUNDLE" ]]; then
    die "admin_bundle_path in ${CONTROLLER_CFG} is ${CONFIGURED_ADMIN_BUNDLE}.
  This script issues the admin bundle only into its own dedicated tmpfs
  directory, ${ADMIN_BUNDLE_DIR}, which it creates and removes; it will not
  create files in — or delete files from — a directory an operator chose,
  because that directory may be /etc/cfgms or /var/lib/cfgms and hold the
  sealed root key, the CA, or this very config.
  Set admin_bundle_path to \"${ADMIN_BUNDLE}\", or drop the key and let this
  script write it. To issue the bundle somewhere else, run
  'cfgms-controller --init --config ...' yourself and take responsibility for
  capturing and removing the credential
  (docs/operations/tier1-controller-bringup.md §9, Step 5)."
fi

# The directory must be one this script owns outright. A symlink here would let
# every removal below land somewhere else entirely.
if [[ -L "$ADMIN_BUNDLE_DIR" ]]; then
    die "${ADMIN_BUNDLE_DIR} is a symlink — refusing to issue the admin bundle through it."
fi

# ── Credential cleanup trap ───────────────────────────────────────────────────
#
# Armed here, before anything is issued, and stays armed for the REST of the
# script so every cleartext credential this run can produce is removed on every
# exit path it can take: success, any later step's failure, or a signal. It runs
# on a run that skips issuance entirely too — that is what converges a host
# provisioned by an older version of this script, whose bundle is still sitting
# at ${LEGACY_ADMIN_BUNDLE}.
#
# Nothing here is `rm -rf` against an operator-controlled path: the bundle and
# the legacy bundle are single files, INIT_CRED_DIR is a path this script
# itself created, and the bundle directory is reclaimed with rmdir, which fails
# rather than delete a directory that unexpectedly has something else in it.
INIT_CRED_DIR=""
cleanup_credential_material() {
    if [[ -e "$LEGACY_ADMIN_BUNDLE" ]]; then
        rm -f "$LEGACY_ADMIN_BUNDLE"
        log "Removed legacy cleartext admin bundle at ${LEGACY_ADMIN_BUNDLE}."
    fi
    if [[ -n "$INIT_CRED_DIR" && -d "$INIT_CRED_DIR" ]]; then
        rm -rf "$INIT_CRED_DIR"
    fi
    rm -f "$ADMIN_BUNDLE"
    if [[ -d "$ADMIN_BUNDLE_DIR" ]] && ! rmdir "$ADMIN_BUNDLE_DIR" 2>/dev/null; then
        warn "left ${ADMIN_BUNDLE_DIR} in place: it is not empty. Inspect it — the admin"
        warn "  bundle itself was removed, but something else is in that directory."
    fi
}
trap cleanup_credential_material EXIT INT TERM

# ── Step 5: Init ──────────────────────────────────────────────────────────────

log "Step 5: Controller init"

FRESH_BUNDLE_ISSUED=false

if [[ -f "$INIT_MARKER" ]]; then
    log "Init marker found at $INIT_MARKER — controller already initialized, skipping."
else
    # `--init` runs from this script, outside systemd, so it has no credentials
    # directory. The sealed key is unsealed into a short-lived directory on
    # tmpfs — asserted to be tmpfs, never assumed, because /tmp is a directory
    # on the root filesystem on Debian and Ubuntu and `shred` cannot reliably
    # undo a write there (ADR-030). The admin bundle --init issues lands in a
    # second tmpfs-backed directory for the identical reason — see "Admin
    # bundle at rest" above.
    if [[ -z "$INSTALL_PREFIX" ]]; then
        RUNTIME_FSTYPE="$(findmnt -no FSTYPE --target /run 2>/dev/null || true)"
        if [[ "$RUNTIME_FSTYPE" != "tmpfs" ]]; then
            die "/run is ${RUNTIME_FSTYPE:-unknown}, not tmpfs — refusing to unseal the root key onto persistent storage."
        fi
        INIT_CRED_DIR="$(mktemp -d /run/cfgms-init-creds-XXXXXX)"
    else
        INIT_CRED_DIR="${INSTALL_PREFIX}/run/cfgms-init-creds"
        mkdir -p "$INIT_CRED_DIR"
    fi
    chmod 0700 "$INIT_CRED_DIR"

    # Both directories are tmpfs-only, start to finish. The directory is created
    # if absent and only the bundle FILE is removed — a stale one from a run
    # that died between issuance and cleanup. Step 4 already proved this is the
    # script's own dedicated directory and armed the trap that removes the
    # bundle again on exit.
    mkdir -p "$ADMIN_BUNDLE_DIR"
    chmod 0700 "$ADMIN_BUNDLE_DIR"
    rm -f "$ADMIN_BUNDLE"

    unseal_secrets_key "${INIT_CRED_DIR}/${SECRETS_KEY_CRED_ID}"

    if [[ -z "$INSTALL_PREFIX" ]]; then
        chown -R cfgms:cfgms "$INIT_CRED_DIR"
        chown cfgms:cfgms "$ADMIN_BUNDLE_DIR"
        # `--init` prints a completion banner (CA fingerprint, storage provider)
        # on stdout. It is operator information, not bundle content, so it is
        # sent to stderr explicitly here as well as by the fd swap at the top of
        # the script — the invariant is stated at the call site that would
        # otherwise violate it.
        runuser --user cfgms -- env "CFGMS_SECRETS_KEY_FILE=${INIT_CRED_DIR}/${SECRETS_KEY_CRED_ID}" \
            "$CONTROLLER_BIN" --init --config "$CONTROLLER_CFG" >&2
    else
        CFGMS_SECRETS_KEY_FILE="${INIT_CRED_DIR}/${SECRETS_KEY_CRED_ID}" \
            "$CONTROLLER_BIN" --init --config "$CONTROLLER_CFG" >&2
    fi

    # The unsealed root key is consumed the moment --init returns; remove it
    # now instead of waiting for script exit. The Step 4 trap stays armed — the
    # admin bundle it also covers is still needed by steps 7 and 8.
    rm -rf "$INIT_CRED_DIR"

    if [[ ! -f "$ADMIN_BUNDLE" ]]; then
        die "controller --init did not produce an admin bundle at $ADMIN_BUNDLE."
    fi

    # Script-owned issuance marker (Issue #4342): --init no longer writes the
    # bundle anywhere this script would find a co-located marker (the bundle
    # lives on tmpfs now), so this script records issuance itself. Its
    # presence is what step 5 checks above, and what steps 7-9 use to tell a
    # fresh issuance from a re-run.
    {
        echo "# Written by tier1-bootstrap.sh — do not edit."
        echo "issued_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$INIT_MARKER"
    chmod 0640 "$INIT_MARKER"

    FRESH_BUNDLE_ISSUED=true
    log "Controller initialized; admin bundle issued (kept on tmpfs only, never persistent storage)."
fi

# Opportunistic migration (Issue #4342) — a controller provisioned by an earlier
# version of this script has the admin bundle sitting in cleartext at
# ${LEGACY_ADMIN_BUNDLE} indefinitely — is handled by cleanup_credential_material
# (Step 4), not here: doing it inline removed the legacy copy only on runs that
# reached this line, leaving it on disk exactly when a step in between failed.
# Plain rm, not shred: shred cannot dependably erase overwritten data on
# ext4/XFS/btrfs or thin-provisioned disks either (see "Admin bundle at rest"
# above) — the fix is to stop creating the durable copy, not to try harder to
# erase it after the fact. The legacy path can never be this run's own bundle:
# Step 4 fails the run unless admin_bundle_path is the tmpfs path.

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
LoadCredentialEncrypted=cfgms-secrets-key:/etc/cfgms/secrets.key.cred
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
InaccessiblePaths=/etc/cfgms/secrets.key.cred
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
elif [[ "$FRESH_BUNDLE_ISSUED" != "true" ]]; then
    log "Step 7: Tenant seeding skipped — controller was already initialized and no admin"
    log "  credential is available this run (Issue #4342: it is never kept past issuance)."
    log "  Tenants were seeded during the initial bootstrap; use your own retained"
    log "  credential with 'cfg tenant create' if you need to seed additional ones."
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
        # `cfg tenant create` prints "tenant created: <id>" on stdout; this
        # script reports the outcome itself via log(), so the child's stdout is
        # sent to stderr. `>&2` precedes `2>/dev/null` so fd 1 is duplicated
        # from the still-live stderr before fd 2 is discarded.
        if [[ -n "$INSTALL_PREFIX" ]]; then
            CFGMS_ADMIN_BUNDLE="$ADMIN_BUNDLE" "$CFG_BIN" "${args[@]}" >&2 2>/dev/null \
                && log "  Tenant ${tenant_id}: created." \
                || log "  Tenant ${tenant_id}: already exists (idempotent)."
        else
            CFGMS_ADMIN_BUNDLE="$ADMIN_BUNDLE" "$CFG_BIN" "${args[@]}" >&2 \
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
elif [[ "$FRESH_BUNDLE_ISSUED" != "true" ]]; then
    log "Step 8: Smoke test skipped — controller was already initialized and no admin"
    log "  credential is available this run (Issue #4342: it is never kept past issuance)."
    log "  Run tier1-smoke-test.sh manually with your own retained credential if needed."
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
        # The smoke test prints "[PASS] ..." lines and a result summary on
        # stdout; they are not bundle content (and are not valid YAML), so they
        # go to stderr. A non-zero exit still propagates under `set -e`.
        CFGMS_ADMIN_BUNDLE="$ADMIN_BUNDLE" bash "$SMOKE_SCRIPT" >&2
    fi
fi

# ── Step 9: Final output ──────────────────────────────────────────────────────
#
# The admin bundle is never written to persistent storage (Step 5). It is
# printed to the caller's stdout below, and ONLY there — every other message
# produced by this run, this section's own banner and the output of every child
# process (`controller --init`, `cfg tenant create`, tier1-smoke-test.sh)
# included, goes to stderr, because fd 1 was pointed at stderr for the whole
# script at the top and the caller's stdout kept on fd 3. So
# `ssh ... 'sudo bash tier1-bootstrap.sh ...' > admin.bundle.yaml` captures
# exactly the bundle and nothing else.

DISPLAY_HOST="$(hostname -f 2>/dev/null || echo "${HOSTNAME_FLAG}")"
EXTERNAL_URL="https://${HOSTNAME_FLAG}:9080"

{
    echo ""
    echo "=========================================="
    echo " Tier 1 Controller Bootstrap Complete"
    echo "=========================================="
    echo ""

    if [[ "$FRESH_BUNDLE_ISSUED" == "true" ]]; then
        echo "Admin bundle: issued for this run and printed to stdout, below — that is"
        echo "the only copy. It is never written to disk on ${DISPLAY_HOST}."
        echo ""
        echo "On your workstation:"
        echo "  1. Capture the bundle printed on stdout to a file, e.g. admin.bundle.yaml."
        echo "     If you ran this over ssh, redirect stdout directly so nothing but the"
        echo "     bundle lands in the file:"
        echo "       ssh ${DISPLAY_HOST} 'sudo bash tier1-bootstrap.sh --hostname=${HOSTNAME_FLAG} ...' > admin.bundle.yaml"
        echo "  2. cfg connect --bundle admin.bundle.yaml --url ${EXTERNAL_URL}"
        echo "     Stores a session token in your OS keychain and the credential itself"
        echo "     SOPS-encrypted under your user config directory — cfg's normal"
        echo "     stateless invoke-and-exit model, not a new mechanism."
        echo "  3. rm admin.bundle.yaml — cfg connect no longer needs the plaintext copy."
        echo "  4. Reconnect in future sessions with: cfg connect ${HOSTNAME_FLAG}"
        echo ""
        echo "If you did not capture the bundle above, do not re-run this script — it"
        echo "will find the issuance marker at ${INIT_MARKER} and skip re-issuing."
        echo "Regenerate instead: cfgms-controller bootstrap-admin --regenerate"
        echo "(then revoke the old serial: cfgms-controller bootstrap-admin --revoke <serial>)."
    else
        echo "Admin bundle: already issued in an earlier run (marker: ${INIT_MARKER})."
        echo "This run did not re-issue or re-expose it."
    fi

    echo ""
    echo "See docs/operations/tier1-controller-bringup.md for the full runbook."
    echo ""
} >&2

if [[ "$FRESH_BUNDLE_ISSUED" == "true" ]]; then
    # fd 3 is the caller's real stdout, saved before fd 1 was pointed at stderr
    # at the top of the script. This is the only write to it in the entire run.
    cat "$ADMIN_BUNDLE" >&3
fi
