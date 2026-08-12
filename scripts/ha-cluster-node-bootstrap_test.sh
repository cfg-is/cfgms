#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# ha-cluster-node-bootstrap_test.sh — Tests for scripts/ha-cluster-node-bootstrap.sh.
#
# Uses CFGMS_INSTALL_PREFIX for isolation: all paths are prefixed and a mock
# controller binary is pre-populated, so tests run without root or network
# access. Mirrors the pattern from tier1-bootstrap_test.sh.
#
# Usage:
#   bash scripts/ha-cluster-node-bootstrap_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SH="${SCRIPT_DIR}/ha-cluster-node-bootstrap.sh"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; ((PASS++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL++)) || true; }

# ── Mock binary helper ────────────────────────────────────────────────────────

# make_mock_controller writes a mock cfgms-controller binary to the given
# prefix directory. The mock implements --init: records the CFGMS_NODE_ID,
# CFGMS_HA_CLUSTER_NODES, CFGMS_HA_CA_CERT_PATH and CFGMS_SECRETS_KEY_FILE it
# was invoked with (so tests can assert cluster-mode env wiring reached the
# binary) and creates the init marker + a stub admin bundle, mirroring
# tier1-bootstrap_test.sh's mock.
make_mock_controller() {
    local prefix="$1"
    local bin_dir="${prefix}/usr/local/bin"
    mkdir -p "$bin_dir"

    cat > "${bin_dir}/cfgms-controller" <<'MOCK'
#!/usr/bin/env bash
# Mock cfgms-controller for ha-cluster-node-bootstrap tests.
PREFIX="${CFGMS_INSTALL_PREFIX:-}"
ETC="${PREFIX}/etc/cfgms"
INIT_MARKER="${ETC}/.admin-bundle-issued"
ADMIN_BUNDLE="${ETC}/admin.bundle.yaml"
INIT_ENV_RECORD="${ETC}/.init-env-record"

DO_INIT=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --init) DO_INIT=true; shift ;;
        --config) shift 2 ;;
        *) shift ;;
    esac
done

if [[ "$DO_INIT" == "true" ]]; then
    if [[ -f "$INIT_MARKER" ]]; then
        echo "Controller already initialized (mock: idempotent skip)"
        exit 0
    fi
    mkdir -p "$ETC"
    touch "$INIT_MARKER"
    printf 'CFGMS_NODE_ID=%s\nCFGMS_HA_CLUSTER_NODES=%s\nCFGMS_HA_CA_CERT_PATH=%s\nCFGMS_SECRETS_KEY_FILE=%s\nOPENBAO_ADDR=%s\n' \
        "${CFGMS_NODE_ID:-}" "${CFGMS_HA_CLUSTER_NODES:-}" "${CFGMS_HA_CA_CERT_PATH:-}" "${CFGMS_SECRETS_KEY_FILE:-}" "${OPENBAO_ADDR:-}" > "$INIT_ENV_RECORD"
    cat > "$ADMIN_BUNDLE" <<'YAML'
controller_url: "https://test-host:9080"
cert_pem: |
  -----BEGIN CERTIFICATE-----
  TESTCERT
  -----END CERTIFICATE-----
key_pem: |
  -----BEGIN PRIVATE KEY-----
  TESTKEY
  -----END PRIVATE KEY-----
ca_pem: |
  -----BEGIN CERTIFICATE-----
  TESTCA
  -----END CERTIFICATE-----
YAML
    chmod 600 "$ADMIN_BUNDLE"
    echo "Controller initialization complete (mock)"
fi
exit 0
MOCK
    chmod +x "${bin_dir}/cfgms-controller"
}

# run_bootstrap executes ha-cluster-node-bootstrap.sh with CFGMS_INSTALL_PREFIX=PREFIX
# and the standard set of required secret env vars pre-populated with test values.
# Additional arguments are forwarded. Sets LAST_EXIT and LAST_OUTPUT.
LAST_EXIT=0
LAST_OUTPUT=""
run_bootstrap() {
    local prefix="$1"
    shift
    LAST_EXIT=0
    LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$prefix" \
        CFGMS_STORAGE_DB_PASSWORD="test-pg-password" \
        CFGMS_SESSION_HMAC_KEY="test-session-hmac-key" \
        CFGMS_SECRETS_KEY_B64="dGVzdC1zZWNyZXRzLWtleS0zMi1ieXRlcy1sb25nISE=" \
        OPENBAO_TOKEN="test-vault-token" \
        bash "$BOOTSTRAP_SH" "$@" 2>&1)" || LAST_EXIT=$?
}

# Standard flag set used by the happy-path tests.
STD_FLAGS=(
    --hostname=ha-node2.test.lab
    --node-id=cfgms-ha-node2
    --cluster-nodes="cfgms-ctrl-01:9443,cfgms-ha-node2:9443,cfgms-ha-node3:9443"
    --postgres-host=192.168.234.105
    --s3-endpoint=http://192.168.234.105:9000
    --vault-address=http://192.168.234.105:8200
    --vault-key-path=root/cluster-ca
)

# ── Test 1: Missing required flags exits 1 with usage ─────────────────────────

T1_PREFIX="$(mktemp -d)"
run_bootstrap "$T1_PREFIX"

if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -qi "usage"; then
    pass "test1: missing required flags exits 1 with usage message"
else
    fail "test1: expected exit 1 and 'usage' in output (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T1_PREFIX"

# ── Test 2: Missing required secret env vars exits 1 ──────────────────────────

T2_PREFIX="$(mktemp -d)"
make_mock_controller "$T2_PREFIX"

LAST_EXIT=0
LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$T2_PREFIX" bash "$BOOTSTRAP_SH" "${STD_FLAGS[@]}" 2>&1)" || LAST_EXIT=$?

if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -q "CFGMS_STORAGE_DB_PASSWORD"; then
    pass "test2: missing secret env vars exits 1 naming the missing variable"
else
    fail "test2: expected exit 1 naming CFGMS_STORAGE_DB_PASSWORD (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T2_PREFIX"

# CFGMS_SECRETS_KEY_B64 must be independently required (#3130 — it must be
# the SAME value on all 3 nodes, so it cannot fall back to self-generation).
T2B_PREFIX="$(mktemp -d)"
make_mock_controller "$T2B_PREFIX"
LAST_EXIT=0
LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$T2B_PREFIX" \
    CFGMS_STORAGE_DB_PASSWORD="test-pg-password" \
    CFGMS_SESSION_HMAC_KEY="test-session-hmac-key" \
    OPENBAO_TOKEN="test-vault-token" \
    bash "$BOOTSTRAP_SH" "${STD_FLAGS[@]}" 2>&1)" || LAST_EXIT=$?
if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -q "CFGMS_SECRETS_KEY_B64"; then
    pass "test2b: missing CFGMS_SECRETS_KEY_B64 exits 1 naming the variable"
else
    fail "test2b: expected exit 1 naming CFGMS_SECRETS_KEY_B64 (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T2B_PREFIX"

# ── Test 3: Happy path creates expected file structure and wires cluster env ──

T3_PREFIX="$(mktemp -d)"
make_mock_controller "$T3_PREFIX"

run_bootstrap "$T3_PREFIX" "${STD_FLAGS[@]}" --skip-smoke

if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test3: happy path exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
else
    PASS_THIS=true

    CFG_FILE="${T3_PREFIX}/etc/cfgms/controller.cfg"
    if [[ ! -f "$CFG_FILE" ]]; then
        fail "test3: controller.cfg not created"
        PASS_THIS=false
    elif ! grep -Fxq '  mode: cluster' "$CFG_FILE"; then
        fail "test3: controller.cfg does not set ha.mode: cluster"
        PASS_THIS=false
    elif ! grep -q 'vault_address: "http://192.168.234.105:8200"' "$CFG_FILE"; then
        fail "test3: controller.cfg missing cluster_ca.vault_address"
        PASS_THIS=false
    elif ! grep -q 'vault_key_path: "root/cluster-ca"' "$CFG_FILE"; then
        fail "test3: controller.cfg missing cluster_ca.vault_key_path"
        PASS_THIS=false
    elif ! grep -q 'bucket: "cfgms-installer-blobs"' "$CFG_FILE"; then
        fail "test3: controller.cfg missing storage.cluster.s3.bucket"
        PASS_THIS=false
    # internal_listen_addr must be a fixed private/loopback IP, never the
    # 0.0.0.0 wildcard — config.ValidatePrivateListenerAddress rejects it, and
    # binding all interfaces would risk exposing Raft traffic on a public NIC.
    elif grep -q 'internal_listen_addr: "0.0.0.0' "$CFG_FILE"; then
        fail "test3: controller.cfg binds internal_listen_addr to the 0.0.0.0 wildcard"
        PASS_THIS=false
    elif ! grep -Eq '^internal_listen_addr: "[0-9.]+:9443"$' "$CFG_FILE"; then
        fail "test3: controller.cfg internal_listen_addr is not a fixed IP:port"
        PASS_THIS=false
    fi

    # Secret placeholders, never literal secret values, in the committed-shape config
    if grep -q "test-pg-password" "$CFG_FILE" 2>/dev/null; then
        fail "test3: controller.cfg contains a literal secret value (must use \${VAR} expansion)"
        PASS_THIS=false
    fi

    SECRETS_ENV="${T3_PREFIX}/etc/cfgms/ha-secrets.env"
    if [[ ! -f "$SECRETS_ENV" ]]; then
        fail "test3: secrets env file not created"
        PASS_THIS=false
    elif ! grep -q "CFGMS_STORAGE_DB_PASSWORD=test-pg-password" "$SECRETS_ENV"; then
        fail "test3: secrets env file missing CFGMS_STORAGE_DB_PASSWORD"
        PASS_THIS=false
    fi

    # Cluster env vars reached the mock controller's --init invocation
    INIT_RECORD="${T3_PREFIX}/etc/cfgms/.init-env-record"
    if [[ ! -f "$INIT_RECORD" ]]; then
        fail "test3: init env record not created (controller --init was not invoked)"
        PASS_THIS=false
    else
        if ! grep -q "^CFGMS_NODE_ID=cfgms-ha-node2$" "$INIT_RECORD"; then
            fail "test3: CFGMS_NODE_ID not passed to --init"
            PASS_THIS=false
        fi
        if ! grep -q "^CFGMS_HA_CLUSTER_NODES=cfgms-ctrl-01:9443,cfgms-ha-node2:9443,cfgms-ha-node3:9443$" "$INIT_RECORD"; then
            fail "test3: CFGMS_HA_CLUSTER_NODES not passed to --init"
            PASS_THIS=false
        fi
        if ! grep -q "^CFGMS_SECRETS_KEY_FILE=${T3_PREFIX}/etc/cfgms/secrets.key$" "$INIT_RECORD"; then
            fail "test3: CFGMS_SECRETS_KEY_FILE not passed to --init"
            PASS_THIS=false
        fi
        if ! grep -q "^OPENBAO_ADDR=http://192.168.234.105:8200$" "$INIT_RECORD"; then
            fail "test3: OPENBAO_ADDR not passed to --init"
            PASS_THIS=false
        fi
    fi

    SECRETS_KEY_FILE="${T3_PREFIX}/etc/cfgms/secrets.key"
    if [[ ! -f "$SECRETS_KEY_FILE" ]]; then
        fail "test3: secrets.key not generated"
        PASS_THIS=false
    fi

    MARKER="${T3_PREFIX}/etc/cfgms/.admin-bundle-issued"
    if [[ ! -f "$MARKER" ]]; then
        fail "test3: init marker not created"
        PASS_THIS=false
    fi

    SERVICE="${T3_PREFIX}/etc/systemd/system/cfgms-controller.service"
    if [[ ! -f "$SERVICE" ]]; then
        fail "test3: systemd unit not written"
        PASS_THIS=false
    else
        for directive in \
            'User=cfgms' \
            'Group=cfgms' \
            'EnvironmentFile=/etc/cfgms/ha-secrets.env' \
            'Environment=CFGMS_NODE_ID=cfgms-ha-node2' \
            'NoNewPrivileges=true' \
            'ProtectSystem=strict' \
            'LoadCredential=cfgms-secrets-key:/etc/cfgms/secrets.key' \
            'Environment=CFGMS_SECRETS_KEY_FILE=%d/cfgms-secrets-key' \
            'Environment=OPENBAO_ADDR=http://192.168.234.105:8200' \
            'InaccessiblePaths=/etc/cfgms/ha-secrets.env' \
            'InaccessiblePaths=/etc/cfgms/secrets.key'; do
            if ! grep -Fxq "$directive" "$SERVICE"; then
                fail "test3: systemd unit missing directive: $directive"
                PASS_THIS=false
            fi
        done
    fi

    if [[ "$PASS_THIS" == "true" ]]; then
        pass "test3: happy path creates expected file structure and wires cluster-mode env"
    fi
fi
rm -rf "$T3_PREFIX"

# ── Test 4: Idempotent re-run exits 0 without overwriting state ───────────────

T4_PREFIX="$(mktemp -d)"
make_mock_controller "$T4_PREFIX"

run_bootstrap "$T4_PREFIX" "${STD_FLAGS[@]}" --skip-smoke
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test4: first run exited ${LAST_EXIT} (expected 0)"
    rm -rf "$T4_PREFIX"
else
    CFG_FILE="${T4_PREFIX}/etc/cfgms/controller.cfg"
    MARKER="${T4_PREFIX}/etc/cfgms/.admin-bundle-issued"
    MTIME_CFG="$(stat -c %Y "$CFG_FILE" 2>/dev/null || stat -f %m "$CFG_FILE" 2>/dev/null)"
    MTIME_MARKER="$(stat -c %Y "$MARKER" 2>/dev/null || stat -f %m "$MARKER" 2>/dev/null)"

    sleep 1

    run_bootstrap "$T4_PREFIX" "${STD_FLAGS[@]}" --skip-smoke

    if [[ $LAST_EXIT -ne 0 ]]; then
        fail "test4: idempotent re-run exited ${LAST_EXIT} (expected 0)"
    else
        MTIME_CFG2="$(stat -c %Y "$CFG_FILE" 2>/dev/null || stat -f %m "$CFG_FILE" 2>/dev/null)"
        MTIME_MARKER2="$(stat -c %Y "$MARKER" 2>/dev/null || stat -f %m "$MARKER" 2>/dev/null)"

        if [[ "$MTIME_CFG" == "$MTIME_CFG2" && "$MTIME_MARKER" == "$MTIME_MARKER2" ]]; then
            pass "test4: idempotent re-run exits 0 and does not modify existing state"
        else
            fail "test4: idempotent re-run modified existing files (cfg=${MTIME_CFG}=>${MTIME_CFG2} marker=${MTIME_MARKER}=>${MTIME_MARKER2})"
        fi
    fi
    rm -rf "$T4_PREFIX"
fi

# ── Test 5: --skip-smoke flag passes through without error ────────────────────

T5_PREFIX="$(mktemp -d)"
make_mock_controller "$T5_PREFIX"

run_bootstrap "$T5_PREFIX" "${STD_FLAGS[@]}" --skip-smoke

if [[ $LAST_EXIT -eq 0 ]] && echo "$LAST_OUTPUT" | grep -q "Smoke test skipped"; then
    pass "test5: --skip-smoke exits 0 and logs skip message"
else
    fail "test5: expected exit 0 and skip message (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T5_PREFIX"

# ── Test 6: --binary-path installs the provided binary ───────────────────────

T6_PREFIX="$(mktemp -d)"
# Do NOT pre-populate cfgms-controller: the --binary-path flag should install it.

T6_BIN="$(mktemp)"
cat > "$T6_BIN" <<'MOCK'
#!/usr/bin/env bash
PREFIX="${CFGMS_INSTALL_PREFIX:-}"
ETC="${PREFIX}/etc/cfgms"
INIT_MARKER="${ETC}/.admin-bundle-issued"
ADMIN_BUNDLE="${ETC}/admin.bundle.yaml"
DO_INIT=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --init) DO_INIT=true; shift ;;
        --config) shift 2 ;;
        *) shift ;;
    esac
done
if [[ "$DO_INIT" == "true" ]]; then
    if [[ ! -f "$INIT_MARKER" ]]; then
        mkdir -p "$ETC"
        touch "$INIT_MARKER"
        printf 'controller_url: "https://test-host:9080"\ncert_pem: |\n  TEST\nkey_pem: |\n  TEST\nca_pem: |\n  TEST\n' > "$ADMIN_BUNDLE"
    fi
fi
exit 0
MOCK
chmod +x "$T6_BIN"

mkdir -p "${T6_PREFIX}/usr/local/bin" "${T6_PREFIX}/etc/systemd/system"

run_bootstrap "$T6_PREFIX" "${STD_FLAGS[@]}" --binary-path="$T6_BIN" --skip-smoke

T6_INSTALLED="${T6_PREFIX}/usr/local/bin/cfgms-controller"
if [[ $LAST_EXIT -eq 0 ]] && [[ -x "$T6_INSTALLED" ]]; then
    pass "test6: --binary-path installs the provided binary"
else
    fail "test6: expected exit 0 and installed binary (exit=${LAST_EXIT} binary_exists=$([ -x "$T6_INSTALLED" ] && echo yes || echo no))"
fi
rm -rf "$T6_PREFIX"
rm -f "$T6_BIN"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
