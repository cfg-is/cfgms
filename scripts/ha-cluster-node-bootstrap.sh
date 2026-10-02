#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# ha-cluster-node-bootstrap.sh — Bootstrap one of the two *new* nodes joining
# the cfg-lab controller HA cluster (epic #3090, story #3130). Idempotent.
# Re-run safe. Only the 2 new nodes use this script — the Tier-1 controller
# gets its cluster-mode config change directly (it already has a controller
# install from tier1-bootstrap.sh); see docs/testing/controller-ha-real-cluster-runbook.md.
#
# Usage:
#   sudo bash ha-cluster-node-bootstrap.sh \
#     --hostname=cfgms-ha-node2.lab.cfg.is \
#     --node-id=cfgms-ha-node2.lab.cfg.is \
#     --cluster-nodes=cfgms-ctrl-01.lab.cfg.is:9443,cfgms-ha-node2.lab.cfg.is:9443,cfgms-ha-node3.lab.cfg.is:9443 \
#     --vault-address=http://192.168.234.105:8200 \
#     --vault-key-path=root/cluster-ca \
#     [options]
#
# --node-id MUST be an FQDN (or otherwise fully cross-host-resolvable name),
# not a bare hostname: pkg/ha uses the node-id string directly as the raft
# peer's DIAL TARGET (address = "<node-id>:<port>", see pkg/ha/manager.go),
# and reuses it as the expected mTLS peer-certificate Common Name. It must
# also be byte-identical to how every OTHER node's --cluster-nodes list
# refers to this node — a mismatch breaks both raft peer-ID hashing and mTLS
# CN verification. FQDNs were chosen over bare hostnames here because they are
# proven resolvable cluster-wide (already used for SSH to every lab host),
# whereas bare-name resolution depends on each node's DNS search-domain
# configuration, which was not independently verified.
#
# Required secrets are read from the environment, never from CLI args or the
# rendered config file (they would be visible in `ps`/shell history/world-readable
# config otherwise):
#   CFGMS_STORAGE_DB_PASSWORD   Postgres role password (#3124's shared instance)
#   CFGMS_SESSION_HMAC_KEY      Cluster session-token HMAC key (same value on all 3 nodes)
#   CFGMS_SECRETS_KEY_B64       Base64-encoded 32-byte secrets.key (same value on all 3
#                               nodes — see the CFGMS_SECRETS_KEY_B64 note below)
#   OPENBAO_TOKEN or BAO_TOKEN  OpenBao service token for cluster CA vault access
#
# None of those four values is ever written to persistent storage in cleartext,
# and none reaches the service's environment (ADR-030, story #3462). Each is
# sealed at provisioning time with `systemd-creds encrypt` into a `.cred` blob
# next to the unit, and the unit carries a LoadCredentialEncrypted= line per
# secret. systemd decrypts each blob as root before privilege drop and exposes
# it on a per-invocation tmpfs under /run/credentials/, mode 0440, scoped by a
# POSIX ACL and destroyed on stop. The unit environment holds only the resulting
# *paths* (CFGMS_SECRETS_KEY_FILE, CFGMS_STORAGE_DB_PASSWORD_FILE,
# CFGMS_SESSION_HMAC_KEY_FILE, OPENBAO_TOKEN_FILE). This replaces the previous
# /etc/cfgms/ha-secrets.env + EnvironmentFile= delivery, which put three secrets
# into the service environment — readable through /proc/<pid>/environ and
# inherited by every child process — and left them in cleartext on disk.
#
# Key binding:
#   By default each blob is sealed to the node's TPM2, so a stolen disk image or
#   VM snapshot does not yield the plaintext. A node with no usable TPM2 FAILS
#   provisioning unless the operator explicitly opts in to disk-bound sealing
#   with --allow-host-key (env: CFGMS_BOOTSTRAP_ALLOW_HOST_KEY=1), which seals
#   with --with-key=host and warns. `--with-key=auto` is deliberately never
#   used: it silently downgrades to the host key with no signal to the operator.
#   The mode actually used is recorded as `key_mode` in the bootstrap init
#   record (/etc/cfgms/.bootstrap-record) so the cluster's weakest binding is
#   auditable after the fact rather than inferred.
#
# Re-running this script MIGRATES an existing node: it seals the supplied values,
# rewrites the unit without EnvironmentFile=, and removes the legacy cleartext
# /etc/cfgms/ha-secrets.env and /etc/cfgms/secrets.key. Sealing is skipped when a
# .cred file is already present; delete the .cred to re-seal with a new value.
#
# CFGMS_SECRETS_KEY_B64 MUST be identical across all 3 cluster nodes. It is the
# encryption key for the SOPS "database" secrets backend, which persists
# cluster-wide secrets (e.g. the audit HMAC key) as a single shared row in the
# cluster Postgres instance — whichever node's process writes that row first
# encrypts it under its own secrets.key, and every other node must decrypt
# with the SAME key or fail with "secret ciphertext authentication failed" at
# startup (reproduced live during #3130: an earlier version of this script
# generated a fresh random key per node via `openssl rand`, which is wrong for
# cluster mode — only correct for the single-node tier1-bootstrap.sh path).
# Generate the value ONCE for the whole cluster's lifetime:
#   openssl rand -base64 32
# and reuse it for every node's --init, including the Tier-1 controller's
# cutover. Store it in the operator's OS-native keychain immediately (same
# discipline as CFGMS_SESSION_HMAC_KEY) — never in a file on disk.
#
# Flags:
#   --hostname HOST          Node hostname for cert SAN and external_address (required)
#   --node-id ID             CFGMS_NODE_ID for this node, must be unique in the cluster (required)
#   --cluster-nodes LIST     CFGMS_HA_CLUSTER_NODES value: comma-separated node-id:port
#                            for ALL 3 cluster members, identical on every node (required)
#   --postgres-host HOST     #3124's shared Postgres host (default: from PG_HOST env or unset=error)
#   --postgres-db NAME       Shared database name (default: cfgms)
#   --postgres-user NAME     Shared role name (default: cfgms)
#   --s3-endpoint URL        #3124's shared MinIO endpoint_url (required)
#   --s3-bucket NAME         #3124's shared MinIO bucket (default: cfgms-installer-blobs)
#   --vault-address URL      OpenBao server URL for the cluster CA (required)
#   --vault-key-path PATH    OpenBao KV v2 path "tenantID/key-name" for the cluster CA (required)
#   --raft-port PORT         Internal transport port used in --cluster-nodes (default: 9443)
#   --version TAG            Release tag to install (default: latest tagged release)
#   --binary-path PATH       Local binary path instead of downloading (air-gapped)
#   --allow-host-key         Seal credentials to this node's disk-resident host key
#                            instead of its TPM2. Explicit opt-in; warns loudly.
#   --skip-smoke             Skip smoke test (health check)
#
# Test isolation:
#   CFGMS_INSTALL_PREFIX=/tmp/test bash ha-cluster-node-bootstrap.sh --hostname=test-host ...
#   All write paths are prefixed. Binary must be pre-populated at
#   $CFGMS_INSTALL_PREFIX/usr/local/bin/cfgms-controller. System calls
#   (apt, useradd, chown, systemctl) are skipped.
#   CFGMS_SYSTEMD_CREDS_BIN overrides the `systemd-creds` executable and
#   CFGMS_BOOTSTRAP_TPM2_PROBE overrides the TPM2 detection command, so the
#   credential-sealing path is exercised on hosts without systemd.
#
# See: docs/testing/controller-ha-real-cluster-runbook.md, docs/operations/cluster-ca.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PREFIX="${CFGMS_INSTALL_PREFIX:-}"

# ── Argument parsing ──────────────────────────────────────────────────────────

HOSTNAME_FLAG=""
NODE_ID=""
CLUSTER_NODES=""
PG_HOST="${PG_HOST:-}"
PG_DB="cfgms"
PG_USER="cfgms"
S3_ENDPOINT=""
S3_BUCKET="cfgms-installer-blobs"
VAULT_ADDRESS=""
VAULT_KEY_PATH=""
RAFT_PORT="9443"
VERSION_FLAG=""
BINARY_PATH=""
SKIP_SMOKE=false
ALLOW_HOST_KEY="${CFGMS_BOOTSTRAP_ALLOW_HOST_KEY:-0}"
SYSTEMD_CREDS_BIN="${CFGMS_SYSTEMD_CREDS_BIN:-systemd-creds}"
TPM2_PROBE="${CFGMS_BOOTSTRAP_TPM2_PROBE:-systemd-analyze has-tpm2 -q}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hostname=*)       HOSTNAME_FLAG="${1#*=}"; shift ;;
        --hostname)         HOSTNAME_FLAG="$2"; shift 2 ;;
        --node-id=*)        NODE_ID="${1#*=}"; shift ;;
        --node-id)          NODE_ID="$2"; shift 2 ;;
        --cluster-nodes=*)  CLUSTER_NODES="${1#*=}"; shift ;;
        --cluster-nodes)    CLUSTER_NODES="$2"; shift 2 ;;
        --postgres-host=*)  PG_HOST="${1#*=}"; shift ;;
        --postgres-host)    PG_HOST="$2"; shift 2 ;;
        --postgres-db=*)    PG_DB="${1#*=}"; shift ;;
        --postgres-db)      PG_DB="$2"; shift 2 ;;
        --postgres-user=*)  PG_USER="${1#*=}"; shift ;;
        --postgres-user)    PG_USER="$2"; shift 2 ;;
        --s3-endpoint=*)    S3_ENDPOINT="${1#*=}"; shift ;;
        --s3-endpoint)      S3_ENDPOINT="$2"; shift 2 ;;
        --s3-bucket=*)      S3_BUCKET="${1#*=}"; shift ;;
        --s3-bucket)        S3_BUCKET="$2"; shift 2 ;;
        --vault-address=*)  VAULT_ADDRESS="${1#*=}"; shift ;;
        --vault-address)    VAULT_ADDRESS="$2"; shift 2 ;;
        --vault-key-path=*) VAULT_KEY_PATH="${1#*=}"; shift ;;
        --vault-key-path)   VAULT_KEY_PATH="$2"; shift 2 ;;
        --raft-port=*)      RAFT_PORT="${1#*=}"; shift ;;
        --raft-port)        RAFT_PORT="$2"; shift 2 ;;
        --version=*)        VERSION_FLAG="${1#*=}"; shift ;;
        --version)          VERSION_FLAG="$2"; shift 2 ;;
        --binary-path=*)    BINARY_PATH="${1#*=}"; shift ;;
        --binary-path)      BINARY_PATH="$2"; shift 2 ;;
        --allow-host-key)   ALLOW_HOST_KEY=1; shift ;;
        --skip-smoke)       SKIP_SMOKE=true; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

usage() {
    echo "Usage: sudo bash ha-cluster-node-bootstrap.sh --hostname=<host> --node-id=<id> \\" >&2
    echo "         --cluster-nodes=<id:port,id:port,id:port> --s3-endpoint=<url> \\" >&2
    echo "         --vault-address=<url> --vault-key-path=<tenantID/key-name> [options]" >&2
    echo "" >&2
    echo "See the script header for the full flag list and required environment variables" >&2
    echo "(CFGMS_STORAGE_DB_PASSWORD, CFGMS_SESSION_HMAC_KEY, CFGMS_SECRETS_KEY_B64," >&2
    echo "OPENBAO_TOKEN or BAO_TOKEN)." >&2
    exit 1
}

[[ -z "$HOSTNAME_FLAG" ]] && usage
[[ -z "$NODE_ID" ]] && usage
[[ -z "$CLUSTER_NODES" ]] && usage
[[ -z "$S3_ENDPOINT" ]] && usage
[[ -z "$VAULT_ADDRESS" ]] && usage
[[ -z "$VAULT_KEY_PATH" ]] && usage
[[ -z "$PG_HOST" ]] && { echo "Error: --postgres-host is required (or set PG_HOST)." >&2; exit 1; }

# Required secrets are validated unconditionally (pure input check, no side
# effects) so both real runs and CFGMS_INSTALL_PREFIX test isolation exercise
# the same validation logic.
if [[ -z "${CFGMS_STORAGE_DB_PASSWORD:-}" ]]; then
    echo "Error: CFGMS_STORAGE_DB_PASSWORD must be set in the environment." >&2
    exit 1
fi
if [[ -z "${CFGMS_SESSION_HMAC_KEY:-}" ]]; then
    echo "Error: CFGMS_SESSION_HMAC_KEY must be set in the environment (same value on all 3 nodes)." >&2
    exit 1
fi
if [[ -z "${CFGMS_SECRETS_KEY_B64:-}" ]]; then
    echo "Error: CFGMS_SECRETS_KEY_B64 must be set in the environment (same value on all 3 nodes —" >&2
    echo "  see the script header for why; generate ONCE with: openssl rand -base64 32)." >&2
    exit 1
fi
if [[ -z "${OPENBAO_TOKEN:-}" && -z "${BAO_TOKEN:-}" ]]; then
    echo "Error: OPENBAO_TOKEN or BAO_TOKEN must be set in the environment." >&2
    exit 1
fi

# ── Path helpers ──────────────────────────────────────────────────────────────

CFGMS_BIN_DIR="${INSTALL_PREFIX}/usr/local/bin"
CFGMS_ETC_DIR="${INSTALL_PREFIX}/etc/cfgms"
CFGMS_DATA_DIR="${INSTALL_PREFIX}/var/lib/cfgms"
CFGMS_LOG_DIR="${INSTALL_PREFIX}/var/log/cfgms"
CFGMS_SYSTEMD_DIR="${INSTALL_PREFIX}/etc/systemd/system"
CONTROLLER_BIN="${CFGMS_BIN_DIR}/cfgms-controller"
CONTROLLER_CFG="${CFGMS_ETC_DIR}/controller.cfg"
CONTROLLER_SERVICE="${CFGMS_SYSTEMD_DIR}/cfgms-controller.service"
ADMIN_BUNDLE="${CFGMS_ETC_DIR}/admin.bundle.yaml"
INIT_MARKER="${CFGMS_ETC_DIR}/.admin-bundle-issued"
BOOTSTRAP_RECORD="${CFGMS_ETC_DIR}/.bootstrap-record"

# Legacy cleartext paths this script now MIGRATES AWAY FROM. They are read (to
# cross-check the supplied values) and then removed once the sealed equivalents
# exist. Never written.
LEGACY_SECRETS_ENV="${CFGMS_ETC_DIR}/ha-secrets.env"
LEGACY_SECRETS_KEY_FILE="${CFGMS_ETC_DIR}/secrets.key"

# Sealed credential blobs. Each is a `systemd-creds encrypt` output, decryptable
# only by this node's TPM2 (or, under --allow-host-key, this node's host key),
# and is loaded by the unit via LoadCredentialEncrypted=.
SECRETS_KEY_CRED="${CFGMS_ETC_DIR}/secrets.key.cred"
DB_PASSWORD_CRED="${CFGMS_ETC_DIR}/db-password.cred"
SESSION_HMAC_CRED="${CFGMS_ETC_DIR}/session-hmac-key.cred"
OPENBAO_TOKEN_CRED="${CFGMS_ETC_DIR}/openbao-token.cred"

# Credential IDs. These are both the LoadCredentialEncrypted= identifier and the
# name embedded in the sealed blob — systemd rejects a credential whose embedded
# name does not match the ID it is being loaded under, so the two must agree.
SECRETS_KEY_CRED_ID="cfgms-secrets-key"
DB_PASSWORD_CRED_ID="cfgms-db-password"
SESSION_HMAC_CRED_ID="cfgms-session-hmac-key"
OPENBAO_TOKEN_CRED_ID="cfgms-openbao-token"

log() { echo "[ha-node-bootstrap] $*"; }
warn() { echo "[ha-node-bootstrap] WARNING: $*" >&2; }
die() { echo "[ha-node-bootstrap] Error: $*" >&2; exit 1; }

# ── Credential sealing ────────────────────────────────────────────────────────

# select_key_mode decides what `systemd-creds encrypt --with-key=` is given, and
# fails provisioning rather than silently downgrading.
#
# `--with-key=auto` is never used: it falls back to the host key in
# /var/lib/systemd/credential.secret whenever no TPM2 is present, with no signal
# to the operator. That file sits on the same disk as the sealed blob, so a
# stolen VM snapshot yields both halves and the "cannot be recovered from a
# stolen disk image" property is quietly void. Security must not degrade
# silently when a precondition is absent — if the TPM is missing the operator
# has to know and decide (ADR-030, Decision 2).
KEY_MODE=""
select_key_mode() {
    if [[ "$ALLOW_HOST_KEY" == "1" ]]; then
        KEY_MODE="host"
        warn "--allow-host-key: sealing credentials with the HOST KEY, not a TPM."
        warn "  The unsealing key is /var/lib/systemd/credential.secret on this node's own"
        warn "  disk, so a stolen disk image or VM snapshot yields the plaintext secrets."
        warn "  Recorded as key_mode: host in ${BOOTSTRAP_RECORD}."
        return 0
    fi

    if $TPM2_PROBE >/dev/null 2>&1; then
        KEY_MODE="tpm2"
        return 0
    fi

    die "no usable TPM2 on this node — refusing to seal credentials to disk silently.
  Credentials are sealed to the TPM2 by default so a stolen disk image or VM
  snapshot cannot yield the plaintext. This node reports no usable TPM2
  (probe: ${TPM2_PROBE}).
  Either enable a TPM2 (Hyper-V Gen2: enable the vTPM; most hypervisors support
  one), or accept disk-bound sealing explicitly by re-running with
  --allow-host-key (env: CFGMS_BOOTSTRAP_ALLOW_HOST_KEY=1).
  See docs/architecture/decisions/030-controller-secret-material-at-rest.md"
}

# seal_credential <cred-id> <dest-path> — reads the plaintext from stdin and
# writes a sealed blob. The plaintext exists only in the pipe: it is never
# written to a file, temporary or otherwise. A failed seal leaves no partial
# blob behind, so a later run cannot mistake a truncated file for a valid one.
seal_credential() {
    local cred_id="$1" dest="$2"

    if ! (umask 077 && "$SYSTEMD_CREDS_BIN" encrypt --name="$cred_id" --with-key="$KEY_MODE" - "$dest"); then
        rm -f "$dest"
        die "failed to seal credential '${cred_id}' with --with-key=${KEY_MODE}."
    fi
    chmod 0400 "$dest"
    if [[ -z "$INSTALL_PREFIX" ]]; then
        chown root:root "$dest"
    fi
}

# seal_credential_if_absent <cred-id> <dest-path> <plaintext> — idempotent form.
# Re-running the bootstrap must not churn existing credentials; delete the .cred
# file to force a re-seal with a new value.
seal_credential_if_absent() {
    local cred_id="$1" dest="$2" plaintext="$3"

    if [[ -f "$dest" ]]; then
        log "Credential '${cred_id}' already sealed at ${dest} — skipping."
        return 0
    fi
    printf '%s' "$plaintext" | seal_credential "$cred_id" "$dest"
    log "Sealed credential '${cred_id}' to ${dest} (key_mode=${KEY_MODE})."
}

# unseal_credential <cred-id> <src-path> <dest-path> — decrypts a sealed blob to
# a file for the one-shot `--init` run, which happens outside systemd and so has
# no credentials directory of its own.
unseal_credential() {
    local cred_id="$1" src="$2" dest="$3"

    if ! (umask 077 && "$SYSTEMD_CREDS_BIN" decrypt --name="$cred_id" "$src" "$dest"); then
        rm -f "$dest"
        die "failed to unseal credential '${cred_id}' from ${src}."
    fi
    chmod 0400 "$dest"
}

# ── Step 1: Pre-flight ────────────────────────────────────────────────────────

log "Step 1: Pre-flight checks"

if [[ -z "$INSTALL_PREFIX" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        echo "Error: must be run as root (sudo bash $(basename "$0") ...)" >&2
        exit 1
    fi

    if ! grep -qi "debian" /etc/os-release 2>/dev/null; then
        echo "Error: this script targets Debian 12. Detected OS:" >&2
        grep PRETTY_NAME /etc/os-release 2>/dev/null || echo "  (unknown)" >&2
        exit 1
    fi

    # Port 9080 held by THIS node's own cfgms-controller is the normal state of
    # a re-run — the script is documented as idempotent, and the upgrade path
    # (#3462) re-runs it on a live node to seal its credentials and rewrite the
    # unit, which takes effect at the next coordinated restart rather than
    # immediately. Only a FOREIGN listener is an error; refusing on our own
    # service made the in-place upgrade impossible and forced a cluster-wide
    # outage before any preparation could happen.
    if ss -tlnp 2>/dev/null | grep -q ':9080 '; then
        if systemctl is-active --quiet cfgms-controller 2>/dev/null; then
            log "Port 9080 is held by the running cfgms-controller service — continuing (re-run/upgrade)."
        else
            echo "Error: port 9080 is already in use by a process other than cfgms-controller." >&2
            echo "  Find the process: ss -tlnp | grep ':9080'" >&2
            exit 1
        fi
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

# decode_secrets_key writes the decoded 32-byte root key to stdout. It exists so
# the key is only ever a byte stream: it must not pass through a shell variable,
# which would drop the NUL bytes a random key contains.
decode_secrets_key() {
    printf '%s' "$CFGMS_SECRETS_KEY_B64" | base64 -d 2>/dev/null
}

# provision_secrets_key seals the cluster's shared SOPS root key.
#
# It NEVER generates a key. That was the original defect: a node that could not
# obtain the shared key generated a fresh random one, producing a node that
# looked healthy while holding the wrong root of trust — every secret it wrote
# was unreadable by its peers, surfacing much later as "secret ciphertext
# authentication failed" on a different node (reproduced live in #3130). A node
# that cannot obtain the cluster's root key must fail here, loudly, and must
# leave no key material behind for a later run to pick up as if it were valid.
provision_secrets_key() {
    if [[ -f "$SECRETS_KEY_CRED" ]]; then
        log "Root key already sealed at ${SECRETS_KEY_CRED} — skipping."
        return 0
    fi

    if [[ -z "${CFGMS_SECRETS_KEY_B64:-}" ]]; then
        die "cannot obtain the cluster's root key: CFGMS_SECRETS_KEY_B64 is not set.
  This node will NOT generate one — every cluster node must hold the SAME
  32-byte key or peers cannot decrypt each other's secrets (#3130).
  Supply the value generated once for this cluster's lifetime."
    fi

    # The decoded key is a 32-byte BINARY value and is therefore never held in a
    # shell variable: bash command substitution silently discards NUL bytes, so
    # a random key would be truncated — measured short, compared unequal, and
    # sealed wrong. (Observed live: a real key measured 31 bytes.) Every use
    # below re-decodes into a pipe instead.
    local key_bytes
    if ! key_bytes="$(decode_secrets_key | wc -c | tr -d '[:space:]')"; then
        die "cannot obtain the cluster's root key: CFGMS_SECRETS_KEY_B64 is not valid base64.
  No key file has been written. Generate the cluster key once with:
    openssl rand -base64 32"
    fi

    if [[ "$key_bytes" != "32" ]]; then
        die "cannot obtain the cluster's root key: CFGMS_SECRETS_KEY_B64 decodes to ${key_bytes} bytes, expected 32.
  No key file has been written. Generate the cluster key once with:
    openssl rand -base64 32"
    fi

    # Migration guard. Sealing a DIFFERENT key than the one this node's data was
    # already encrypted under is silently destructive — the node starts, then
    # fails to decrypt cluster secrets written under the old key. Refuse rather
    # than seal the wrong root of trust.
    if [[ -f "$LEGACY_SECRETS_KEY_FILE" ]]; then
        if ! decode_secrets_key | cmp -s - "$LEGACY_SECRETS_KEY_FILE"; then
            die "CFGMS_SECRETS_KEY_B64 does not match this node's existing ${LEGACY_SECRETS_KEY_FILE}.
  Sealing a different root key would leave this node unable to decrypt the
  cluster secrets it already holds. Nothing has been changed.
  Supply the cluster's actual key, or remove the stale key file deliberately
  if you know this node's data is being discarded."
        fi
        log "Existing cleartext root key matches CFGMS_SECRETS_KEY_B64 — migrating it to a sealed credential."
    fi

    decode_secrets_key | seal_credential "$SECRETS_KEY_CRED_ID" "$SECRETS_KEY_CRED"
    log "Sealed the shared root key to ${SECRETS_KEY_CRED} (key_mode=${KEY_MODE})."
}

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

    if ! tar -tzf "$TMPTAR" cfgms-controller >/dev/null 2>&1; then
        echo "Error: signed archive does not contain top-level cfgms-controller." >&2
        exit 1
    fi
    tar -xzf "$TMPTAR" -C "$CFGMS_BIN_DIR" cfgms-controller
    chmod 0755 "$CONTROLLER_BIN"

    rm -f "$TMPTAR" "$TMPBUNDLE"
    trap - EXIT INT TERM
    log "Binary installed to $CONTROLLER_BIN"
fi

# ── Step 4: Sealed credentials ────────────────────────────────────────────────

log "Step 4: Sealed credentials (key_mode=${KEY_MODE})"

seal_credential_if_absent "$DB_PASSWORD_CRED_ID"   "$DB_PASSWORD_CRED"   "$CFGMS_STORAGE_DB_PASSWORD"
seal_credential_if_absent "$SESSION_HMAC_CRED_ID"  "$SESSION_HMAC_CRED"  "$CFGMS_SESSION_HMAC_KEY"
seal_credential_if_absent "$OPENBAO_TOKEN_CRED_ID" "$OPENBAO_TOKEN_CRED" "${OPENBAO_TOKEN:-${BAO_TOKEN:-}}"

# Record which binding was actually used. The cluster's at-rest guarantee is its
# weakest node's, so this has to be readable per node rather than assumed.
{
    echo "# Written by ha-cluster-node-bootstrap.sh — do not edit."
    echo "node_id: ${NODE_ID}"
    echo "key_mode: ${KEY_MODE}"
    echo "sealed_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$BOOTSTRAP_RECORD"
chmod 0640 "$BOOTSTRAP_RECORD"
log "Recorded key_mode=${KEY_MODE} in ${BOOTSTRAP_RECORD}."

# Migration: the sealed credentials now hold everything the legacy cleartext
# files did, so remove them. Leaving them behind would keep the exact material
# on disk that this change exists to eliminate.
for legacy in "$LEGACY_SECRETS_ENV" "$LEGACY_SECRETS_KEY_FILE"; do
    if [[ -f "$legacy" ]]; then
        rm -f "$legacy"
        log "Removed legacy cleartext secret file ${legacy} (superseded by sealed credentials)."
    fi
done

# ── Step 5: Config ─────────────────────────────────────────────────────────────

log "Step 5: Config"

# Included in this node's own server-cert SAN below: clients that reach this
# node by IP (the reliable path in this lab — see --node-id's doc note above
# on FQDN resolution not being independently verified) still need the cert to
# validate. hostname -I lists all addresses; the first is this VM's primary
# LAN IP.
NODE_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" || NODE_IP=""
NODE_IP_SAN_LINE=""
[[ -n "$NODE_IP" ]] && NODE_IP_SAN_LINE="      - \"${NODE_IP}\""

# internal_listen_addr REQUIRES a fixed, explicit loopback or private IP —
# config.ValidatePrivateListenerAddress rejects both hostnames and the
# 0.0.0.0 wildcard (binding all interfaces would risk exposing Raft traffic
# on any public-facing NIC, which the internal listener must never do). This
# is therefore a hard requirement here, unlike the cert SAN use above.
if [[ -z "$NODE_IP" && -z "$INSTALL_PREFIX" ]]; then
    echo "Error: could not determine this node's private IP (hostname -I)." >&2
    echo "  internal_listen_addr requires a fixed private IP — see docs/operations/cluster-ca.md" >&2
    exit 1
fi
RAFT_LISTEN_HOST="${NODE_IP:-127.0.0.1}"

if [[ -f "$CONTROLLER_CFG" ]]; then
    log "Config already exists at $CONTROLLER_CFG — skipping generation."
else
    cat > "$CONTROLLER_CFG" <<EOF
# CFGMS HA Cluster Node Configuration
# Generated by ha-cluster-node-bootstrap.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Node: ${NODE_ID} (${HOSTNAME_FLAG})
# See docs/testing/controller-ha-real-cluster-runbook.md "Cluster Formation"

security_profile: "public-beta"
execution:
  require_signed_adhoc: true

listen_addr: "0.0.0.0:9080"
metrics_listen_addr: "127.0.0.1:9090"
external_url: "https://${HOSTNAME_FLAG}:9080"
data_dir: "/var/lib/cfgms"

# Private listener for controller-to-controller Raft traffic only — required,
# top-level (not under ha:), never Internet-published. Must be a fixed private
# IP, not 0.0.0.0 (config.ValidatePrivateListenerAddress rejects the wildcard
# — see the RAFT_LISTEN_HOST comment above). Peers dial this node at
# <this node's --node-id>:${RAFT_PORT}, matching the port here.
internal_listen_addr: "${RAFT_LISTEN_HOST}:${RAFT_PORT}"

ha:
  mode: cluster

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
${NODE_IP_SAN_LINE}
    organization: "CFGMS Tier 1"
  cluster_ca:
    vault_address: "${VAULT_ADDRESS}"
    vault_key_path: "${VAULT_KEY_PATH}"

storage:
  provider: database
  config:
    host: "${PG_HOST}"
    port: 5432
    database: "${PG_DB}"
    username: "${PG_USER}"
    password: "\${CFGMS_STORAGE_DB_PASSWORD}"
    sslmode: "disable"
  cluster:
    postgres_dsn: "host=${PG_HOST} port=5432 dbname=${PG_DB} user=${PG_USER} password=\${CFGMS_STORAGE_DB_PASSWORD} sslmode=disable"
    session_hmac_key: "\${CFGMS_SESSION_HMAC_KEY}"
    s3:
      bucket: "${S3_BUCKET}"
      endpoint_url: "${S3_ENDPOINT}"

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
    if [[ -z "$INSTALL_PREFIX" ]]; then
        chown cfgms:cfgms "$CONTROLLER_CFG"
        chmod 640 "$CONTROLLER_CFG"
    fi
    log "Config rendered to $CONTROLLER_CFG"
fi

# ── Step 6: Init ──────────────────────────────────────────────────────────────

log "Step 6: Controller init (loads the shared cluster CA from vault — see docs/operations/cluster-ca.md)"

if [[ -f "$INIT_MARKER" ]]; then
    log "Init marker found at $INIT_MARKER — controller already initialized, skipping."
else
    # OPENBAO_ADDR (not just certificate.cluster_ca.vault_address in the
    # rendered config) is required: pkg/secrets/providers/openbao's Available()
    # pre-check is a zero-arg method that only ever reads this env var, with no
    # visibility into the config map CreateSecretStore later receives — so a
    # correctly configured vault_address alone still fails the registry's
    # availability gate. Same root cause hit during the #3127/#3130 CA
    # migration into vault; tracked as a provider-level gap, not fixed here.
    # `--init` runs once, from this script, OUTSIDE systemd — so it has no
    # credentials directory to read from. The sealed blobs are unsealed into a
    # short-lived directory on tmpfs and the values are passed by PATH, never by
    # value: no secret enters this invocation's environment or argv.
    #
    # tmpfs is asserted, not assumed. /tmp is a directory on the root filesystem
    # on Debian and Ubuntu, and `shred` does not reliably destroy overwritten
    # data on ext4/XFS/btrfs or on thin-provisioned virtual disks — so "write it
    # to a temp file and shred it afterwards" would put the cluster's root key
    # on persistent storage with no dependable way to remove it (ADR-030).
    if [[ -z "$INSTALL_PREFIX" ]]; then
        RUNTIME_FSTYPE="$(findmnt -no FSTYPE --target /run 2>/dev/null || true)"
        if [[ "$RUNTIME_FSTYPE" != "tmpfs" ]]; then
            die "/run is ${RUNTIME_FSTYPE:-unknown}, not tmpfs — refusing to unseal secrets onto persistent storage."
        fi
        INIT_CRED_DIR="$(mktemp -d /run/cfgms-init-creds-XXXXXX)"
    else
        INIT_CRED_DIR="${INSTALL_PREFIX}/run/cfgms-init-creds"
        mkdir -p "$INIT_CRED_DIR"
    fi
    chmod 0700 "$INIT_CRED_DIR"
    cleanup_init_creds() { rm -rf "$INIT_CRED_DIR"; }
    trap cleanup_init_creds EXIT INT TERM

    unseal_credential "$SECRETS_KEY_CRED_ID"   "$SECRETS_KEY_CRED"   "${INIT_CRED_DIR}/${SECRETS_KEY_CRED_ID}"
    unseal_credential "$DB_PASSWORD_CRED_ID"   "$DB_PASSWORD_CRED"   "${INIT_CRED_DIR}/${DB_PASSWORD_CRED_ID}"
    unseal_credential "$SESSION_HMAC_CRED_ID"  "$SESSION_HMAC_CRED"  "${INIT_CRED_DIR}/${SESSION_HMAC_CRED_ID}"
    unseal_credential "$OPENBAO_TOKEN_CRED_ID" "$OPENBAO_TOKEN_CRED" "${INIT_CRED_DIR}/${OPENBAO_TOKEN_CRED_ID}"

    INIT_ENV=(
        "CFGMS_NODE_ID=${NODE_ID}"
        "CFGMS_HA_EXTERNAL_ADDRESS=${HOSTNAME_FLAG}"
        "CFGMS_HA_CLUSTER_NODES=${CLUSTER_NODES}"
        "CFGMS_HA_CA_CERT_PATH=${CFGMS_DATA_DIR}/certs/ca/ca.crt"
        "CFGMS_SECRETS_KEY_FILE=${INIT_CRED_DIR}/${SECRETS_KEY_CRED_ID}"
        "CFGMS_STORAGE_DB_PASSWORD_FILE=${INIT_CRED_DIR}/${DB_PASSWORD_CRED_ID}"
        "CFGMS_SESSION_HMAC_KEY_FILE=${INIT_CRED_DIR}/${SESSION_HMAC_CRED_ID}"
        "OPENBAO_TOKEN_FILE=${INIT_CRED_DIR}/${OPENBAO_TOKEN_CRED_ID}"
        "OPENBAO_ADDR=${VAULT_ADDRESS}"
    )
    # Drop the operator-supplied by-value copies before handing control to the
    # controller. They are this script's input, not the controller's: leaving
    # them in the child environment would reinstate exactly the exposure the
    # sealed credentials remove, and would let a by-path regression go unnoticed
    # because the by-value fallback would quietly keep working.
    INIT_ENV_UNSET=(
        -u CFGMS_STORAGE_DB_PASSWORD
        -u CFGMS_SESSION_HMAC_KEY
        -u CFGMS_SECRETS_KEY_B64
        -u OPENBAO_TOKEN
        -u BAO_TOKEN
    )
    if [[ -z "$INSTALL_PREFIX" ]]; then
        chown -R cfgms:cfgms "$INIT_CRED_DIR"
        runuser --user cfgms -- env "${INIT_ENV_UNSET[@]}" "${INIT_ENV[@]}" \
            "$CONTROLLER_BIN" --init --config "$CONTROLLER_CFG"
    else
        env "${INIT_ENV_UNSET[@]}" "${INIT_ENV[@]}" \
            "$CONTROLLER_BIN" --init --config "$CONTROLLER_CFG"
    fi

    cleanup_init_creds
    trap - EXIT INT TERM
fi

# ── Step 7: Systemd ───────────────────────────────────────────────────────────

log "Step 7: Systemd service"

cat > "$CONTROLLER_SERVICE" <<EOF
[Unit]
Description=CFGMS Controller (HA cluster node ${NODE_ID})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-controller --config /etc/cfgms/controller.cfg
LoadCredentialEncrypted=cfgms-secrets-key:/etc/cfgms/secrets.key.cred
LoadCredentialEncrypted=cfgms-db-password:/etc/cfgms/db-password.cred
LoadCredentialEncrypted=cfgms-session-hmac-key:/etc/cfgms/session-hmac-key.cred
LoadCredentialEncrypted=cfgms-openbao-token:/etc/cfgms/openbao-token.cred
Environment=CFGMS_SECRETS_KEY_FILE=%d/cfgms-secrets-key
Environment=CFGMS_STORAGE_DB_PASSWORD_FILE=%d/cfgms-db-password
Environment=CFGMS_SESSION_HMAC_KEY_FILE=%d/cfgms-session-hmac-key
Environment=OPENBAO_TOKEN_FILE=%d/cfgms-openbao-token
Environment=CFGMS_NODE_ID=${NODE_ID}
Environment=CFGMS_HA_EXTERNAL_ADDRESS=${HOSTNAME_FLAG}
Environment=CFGMS_HA_CLUSTER_NODES=${CLUSTER_NODES}
Environment=CFGMS_HA_CA_CERT_PATH=/var/lib/cfgms/certs/ca/ca.crt
Environment=OPENBAO_ADDR=${VAULT_ADDRESS}
Environment=CFGMS_SECURITY_PROFILE=public-beta
Environment=CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC=true
Environment=CFGMS_S3_INSTALLER_BUCKET=${S3_BUCKET}
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
InaccessiblePaths=/etc/cfgms/db-password.cred
InaccessiblePaths=/etc/cfgms/session-hmac-key.cred
InaccessiblePaths=/etc/cfgms/openbao-token.cred
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

# ── Step 8: Smoke test ────────────────────────────────────────────────────────

if [[ "$SKIP_SMOKE" == "true" ]]; then
    log "Step 8: Smoke test skipped (--skip-smoke)."
elif [[ -n "$INSTALL_PREFIX" ]]; then
    log "Step 8: Test isolation: smoke test skipped (no live controller in test mode)."
else
    log "Step 8: Smoke test"
    RETRIES=12
    for ((i = 1; i <= RETRIES; i++)); do
        if curl --fail --silent --show-error --insecure \
            "https://localhost:9080/api/v1/health" &>/dev/null; then
            log "Controller REST API is healthy."
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

# ── Step 9: Final output ──────────────────────────────────────────────────────

echo ""
echo "=========================================="
echo " HA Cluster Node Bootstrap Complete: ${NODE_ID}"
echo "=========================================="
echo ""
echo "Node: ${NODE_ID}  Hostname: ${HOSTNAME_FLAG}"
echo "Cluster peers: ${CLUSTER_NODES}"
echo ""
echo "Verify Raft status once all 3 nodes are up:"
echo "  curl --insecure https://${HOSTNAME_FLAG}:9080/api/v1/raft/status"
echo ""
echo "See docs/testing/controller-ha-real-cluster-runbook.md for cutover sequencing."
echo ""
