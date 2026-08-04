#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# tier1-bootstrap_test.sh — Tests for scripts/tier1-bootstrap.sh.
#
# Uses CFGMS_INSTALL_PREFIX for isolation: all paths are prefixed and mock
# binaries are pre-populated, so tests run without root or network access.
# Mirrors the pattern from build/linux/install_test.sh.
#
# Usage:
#   bash scripts/tier1-bootstrap_test.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SH="${SCRIPT_DIR}/tier1-bootstrap.sh"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; ((PASS++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL++)) || true; }

# ── Mock binary helpers ───────────────────────────────────────────────────────

# make_mock_controller writes a mock cfgms-controller binary to the given
# prefix directory. The mock implements --init: creates the init marker and
# a stub admin bundle so bootstrap steps 5+ can verify their logic.
make_mock_controller() {
    local prefix="$1"
    local bin_dir="${prefix}/usr/local/bin"
    mkdir -p "$bin_dir"

    cat > "${bin_dir}/cfgms-controller" <<'MOCK'
#!/usr/bin/env bash
# Mock cfgms-controller for tier1-bootstrap tests.
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
    if [[ -f "$INIT_MARKER" ]]; then
        echo "Controller already initialized (mock: idempotent skip)"
        exit 0
    fi
    mkdir -p "$ETC"
    touch "$INIT_MARKER"
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

# make_mock_cfg writes a mock cfg binary that implements tenant create.
# The mock records created tenants in a marker file and is idempotent.
make_mock_cfg() {
    local prefix="$1"
    local bin_dir="${prefix}/usr/local/bin"
    mkdir -p "$bin_dir"

    cat > "${bin_dir}/cfg" <<'MOCK'
#!/usr/bin/env bash
# Mock cfg for tier1-bootstrap tests.
PREFIX="${CFGMS_INSTALL_PREFIX:-}"
TENANT_MARKER="${PREFIX}/etc/cfgms/.tenants-seeded"
mkdir -p "${PREFIX}/etc/cfgms"

CMD="${1:-}"
SUBCMD="${2:-}"
TENANT_ID=""
shift 2 2>/dev/null || true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tenant-id=*) TENANT_ID="${1#*=}"; shift ;;
        --tenant-id)   TENANT_ID="$2"; shift 2 ;;
        --parent=*)    shift ;;
        --parent)      shift 2 ;;
        *)             shift ;;
    esac
done

if [[ "$CMD" == "tenant" && "$SUBCMD" == "create" && -n "$TENANT_ID" ]]; then
    if grep -q "^${TENANT_ID}$" "$TENANT_MARKER" 2>/dev/null; then
        echo "tenant already exists: ${TENANT_ID}"
        exit 0
    fi
    echo "$TENANT_ID" >> "$TENANT_MARKER"
    echo "tenant created: ${TENANT_ID}"
fi
exit 0
MOCK
    chmod +x "${bin_dir}/cfg"
}

# run_bootstrap executes tier1-bootstrap.sh with CFGMS_INSTALL_PREFIX=PREFIX.
# Additional arguments are forwarded. Sets LAST_EXIT and LAST_OUTPUT.
LAST_EXIT=0
LAST_OUTPUT=""
run_bootstrap() {
    local prefix="$1"
    shift
    LAST_EXIT=0
    LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$prefix" bash "$BOOTSTRAP_SH" "$@" 2>&1)" \
        || LAST_EXIT=$?
}

# ── Test 1: Missing --hostname exits 1 with usage ─────────────────────────────

T1_PREFIX="$(mktemp -d)"
run_bootstrap "$T1_PREFIX"

if [[ $LAST_EXIT -eq 1 ]] && echo "$LAST_OUTPUT" | grep -qi "hostname"; then
    pass "test1: missing --hostname exits 1 with usage message"
else
    fail "test1: expected exit 1 and 'hostname' in output (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T1_PREFIX"

# ── Test 2: Happy path creates expected file structure ────────────────────────

T2_PREFIX="$(mktemp -d)"
make_mock_controller "$T2_PREFIX"
make_mock_cfg "$T2_PREFIX"

run_bootstrap "$T2_PREFIX" --hostname=ctrl.test.lab --skip-smoke

if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test2: happy path exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
else
    PASS_THIS=true

    # Controller config rendered with hostname
    CFG_FILE="${T2_PREFIX}/etc/cfgms/controller.cfg"
    if [[ ! -f "$CFG_FILE" ]]; then
        fail "test2: controller.cfg not created"
        PASS_THIS=false
    elif ! grep -q "ctrl.test.lab" "$CFG_FILE"; then
        fail "test2: controller.cfg does not contain hostname"
        PASS_THIS=false
    elif ! grep -Fxq 'security_profile: "public-beta"' "$CFG_FILE"; then
        fail "test2: controller.cfg does not select public-beta security"
        PASS_THIS=false
    elif ! grep -Fxq '  require_signed_adhoc: true' "$CFG_FILE"; then
        fail "test2: controller.cfg does not require signed ad-hoc execution"
        PASS_THIS=false
    elif ! grep -Fxq 'metrics_listen_addr: "127.0.0.1:9090"' "$CFG_FILE"; then
        fail "test2: controller.cfg does not bind metrics to the private loopback listener"
        PASS_THIS=false
    fi

    # Init marker created
    MARKER="${T2_PREFIX}/etc/cfgms/.admin-bundle-issued"
    if [[ ! -f "$MARKER" ]]; then
        fail "test2: init marker not created"
        PASS_THIS=false
    fi

    # Admin bundle created
    BUNDLE="${T2_PREFIX}/etc/cfgms/admin.bundle.yaml"
    if [[ ! -f "$BUNDLE" ]]; then
        fail "test2: admin bundle not created"
        PASS_THIS=false
    fi

    # External secret-encryption key created with no group/other access.
    SECRETS_KEY="${T2_PREFIX}/etc/cfgms/secrets.key"
    if [[ ! -f "$SECRETS_KEY" ]]; then
        fail "test2: external secret-encryption key not created"
        PASS_THIS=false
    elif [[ "$(stat -c '%a' "$SECRETS_KEY")" != "600" ]]; then
        fail "test2: external secret-encryption key mode is not 0600"
        PASS_THIS=false
    fi

    # Systemd unit written
    SERVICE="${T2_PREFIX}/etc/systemd/system/cfgms-controller.service"
    if [[ ! -f "$SERVICE" ]]; then
        fail "test2: systemd unit not written"
        PASS_THIS=false
    elif grep -q '^User=root$' "$SERVICE"; then
        fail "test2: systemd unit must not run the controller as root"
        PASS_THIS=false
    else
        for directive in \
            'User=cfgms' \
            'Group=cfgms' \
            'Environment=CFGMS_SECURITY_PROFILE=public-beta' \
            'Environment=CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC=true' \
            'NoNewPrivileges=true' \
            'ProtectSystem=strict' \
            'PrivateTmp=true' \
            'CapabilityBoundingSet=' \
            'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'; do
            if ! grep -Fxq "$directive" "$SERVICE"; then
                fail "test2: systemd unit missing hardening directive: $directive"
                PASS_THIS=false
            fi
        done
    fi

    # Required directories created
    for d in \
        "${T2_PREFIX}/etc/cfgms" \
        "${T2_PREFIX}/var/lib/cfgms/storage" \
        "${T2_PREFIX}/var/lib/cfgms/certs/ca" \
        "${T2_PREFIX}/var/log/cfgms"; do
        if [[ ! -d "$d" ]]; then
            fail "test2: directory not created: $d"
            PASS_THIS=false
        fi
    done

    # Three tenants seeded
    SEED_MARKER="${T2_PREFIX}/etc/cfgms/.tenants-seeded"
    for tenant in team-root agent-test infra-hyperv; do
        if ! grep -q "^${tenant}$" "$SEED_MARKER" 2>/dev/null; then
            fail "test2: tenant not seeded: $tenant"
            PASS_THIS=false
        fi
    done

    if [[ "$PASS_THIS" == "true" ]]; then
        pass "test2: happy path creates expected file structure and seeds tenants"
    fi
fi
rm -rf "$T2_PREFIX"

# ── Test 3: Idempotent re-run exits 0 without overwriting state ───────────────

T3_PREFIX="$(mktemp -d)"
make_mock_controller "$T3_PREFIX"
make_mock_cfg "$T3_PREFIX"

# First run
run_bootstrap "$T3_PREFIX" --hostname=ctrl.test.lab --skip-smoke
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test3: first run exited ${LAST_EXIT} (expected 0)"
    rm -rf "$T3_PREFIX"
else
    # Record mtime of key state files before the second run
    CFG_FILE="${T3_PREFIX}/etc/cfgms/controller.cfg"
    MARKER="${T3_PREFIX}/etc/cfgms/.admin-bundle-issued"
    BUNDLE="${T3_PREFIX}/etc/cfgms/admin.bundle.yaml"
    MTIME_CFG="$(stat -c %Y "$CFG_FILE" 2>/dev/null || stat -f %m "$CFG_FILE" 2>/dev/null)"
    MTIME_MARKER="$(stat -c %Y "$MARKER" 2>/dev/null || stat -f %m "$MARKER" 2>/dev/null)"
    MTIME_BUNDLE="$(stat -c %Y "$BUNDLE" 2>/dev/null || stat -f %m "$BUNDLE" 2>/dev/null)"

    # Wait a tick so any re-write would produce a different mtime
    sleep 1

    # Second run (idempotent re-run)
    run_bootstrap "$T3_PREFIX" --hostname=ctrl.test.lab --skip-smoke

    if [[ $LAST_EXIT -ne 0 ]]; then
        fail "test3: idempotent re-run exited ${LAST_EXIT} (expected 0)"
    else
        MTIME_CFG2="$(stat -c %Y "$CFG_FILE" 2>/dev/null || stat -f %m "$CFG_FILE" 2>/dev/null)"
        MTIME_MARKER2="$(stat -c %Y "$MARKER" 2>/dev/null || stat -f %m "$MARKER" 2>/dev/null)"
        MTIME_BUNDLE2="$(stat -c %Y "$BUNDLE" 2>/dev/null || stat -f %m "$BUNDLE" 2>/dev/null)"

        if [[ "$MTIME_CFG" == "$MTIME_CFG2" && "$MTIME_MARKER" == "$MTIME_MARKER2" && "$MTIME_BUNDLE" == "$MTIME_BUNDLE2" ]]; then
            pass "test3: idempotent re-run exits 0 and does not modify existing state"
        else
            fail "test3: idempotent re-run modified existing files (cfg=${MTIME_CFG}=>${MTIME_CFG2} marker=${MTIME_MARKER}=>${MTIME_MARKER2})"
        fi
    fi
    rm -rf "$T3_PREFIX"
fi

# ── Test 4: Partial-state recovery completes remaining steps ──────────────────

T4_PREFIX="$(mktemp -d)"
make_mock_controller "$T4_PREFIX"
make_mock_cfg "$T4_PREFIX"

# Simulate partial state: OS baseline done (dirs created), but config not yet written.
mkdir -p \
    "${T4_PREFIX}/etc/cfgms" \
    "${T4_PREFIX}/var/lib/cfgms/storage" \
    "${T4_PREFIX}/var/lib/cfgms/certs/ca" \
    "${T4_PREFIX}/var/log/cfgms" \
    "${T4_PREFIX}/usr/local/bin" \
    "${T4_PREFIX}/etc/systemd/system"

# Run bootstrap to complete the remaining steps
run_bootstrap "$T4_PREFIX" --hostname=ctrl.test.lab --skip-smoke

if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test4: partial-state recovery exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
else
    CFG_FILE="${T4_PREFIX}/etc/cfgms/controller.cfg"
    BUNDLE="${T4_PREFIX}/etc/cfgms/admin.bundle.yaml"
    if [[ -f "$CFG_FILE" && -f "$BUNDLE" ]]; then
        pass "test4: partial-state recovery completes remaining steps"
    else
        fail "test4: partial-state recovery did not create config (${CFG_FILE}: $([ -f "$CFG_FILE" ] && echo present || echo missing)) or bundle (${BUNDLE}: $([ -f "$BUNDLE" ] && echo present || echo missing))"
    fi
fi
rm -rf "$T4_PREFIX"

# ── Test 5: --skip-tenant-seed skips tenant seeding ──────────────────────────

T5_PREFIX="$(mktemp -d)"
make_mock_controller "$T5_PREFIX"
make_mock_cfg "$T5_PREFIX"

run_bootstrap "$T5_PREFIX" --hostname=ctrl.test.lab --skip-tenant-seed --skip-smoke

SEED_MARKER="${T5_PREFIX}/etc/cfgms/.tenants-seeded"
if [[ $LAST_EXIT -eq 0 ]] && [[ ! -f "$SEED_MARKER" ]]; then
    pass "test5: --skip-tenant-seed exits 0 and does not create tenant seed marker"
else
    fail "test5: expected exit 0 and no seed marker (exit=${LAST_EXIT} marker_exists=$([ -f "$SEED_MARKER" ] && echo yes || echo no))"
fi
rm -rf "$T5_PREFIX"

# ── Test 6: --skip-smoke flag passes through without error ────────────────────

T6_PREFIX="$(mktemp -d)"
make_mock_controller "$T6_PREFIX"
make_mock_cfg "$T6_PREFIX"

run_bootstrap "$T6_PREFIX" --hostname=ctrl.test.lab --skip-tenant-seed --skip-smoke

if [[ $LAST_EXIT -eq 0 ]] && echo "$LAST_OUTPUT" | grep -q "Smoke test skipped"; then
    pass "test6: --skip-smoke exits 0 and logs skip message"
else
    fail "test6: expected exit 0 and skip message (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T6_PREFIX"

# ── Test 7: --version flag accepted without error ────────────────────────────

T7_PREFIX="$(mktemp -d)"
make_mock_controller "$T7_PREFIX"
make_mock_cfg "$T7_PREFIX"

# Pre-populate binary so the download step is skipped; --version should still
# be accepted (it's recorded but the download is elided because binary exists).
run_bootstrap "$T7_PREFIX" --hostname=ctrl.test.lab --version=v1.2.3 --skip-tenant-seed --skip-smoke

if [[ $LAST_EXIT -eq 0 ]]; then
    pass "test7: --version flag accepted when binary already present"
else
    fail "test7: expected exit 0 with --version flag (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T7_PREFIX"

# ── Test 8: --binary-path installs the provided binary ───────────────────────

T8_PREFIX="$(mktemp -d)"
make_mock_cfg "$T8_PREFIX"
# Do NOT pre-populate cfgms-controller: the --binary-path flag should install it.

# Create a minimal stand-in binary to copy
T8_BIN="$(mktemp)"
cat > "$T8_BIN" <<'MOCK'
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
chmod +x "$T8_BIN"

mkdir -p "${T8_PREFIX}/usr/local/bin" \
         "${T8_PREFIX}/etc/systemd/system"

run_bootstrap "$T8_PREFIX" --hostname=ctrl.test.lab \
    --binary-path="$T8_BIN" --skip-tenant-seed --skip-smoke

T8_INSTALLED="${T8_PREFIX}/usr/local/bin/cfgms-controller"
if [[ $LAST_EXIT -eq 0 ]] && [[ -x "$T8_INSTALLED" ]]; then
    pass "test8: --binary-path installs the provided binary"
else
    fail "test8: expected exit 0 and installed binary (exit=${LAST_EXIT} binary_exists=$([ -x "$T8_INSTALLED" ] && echo yes || echo no))"
fi
rm -rf "$T8_PREFIX"
rm -f "$T8_BIN"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
