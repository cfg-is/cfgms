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

# ── systemd-creds stand-in ────────────────────────────────────────────────────

# The real `systemd-creds` needs systemd and a TPM2 or host key, none of which
# exists on a developer workstation or in a CI container, so the sealing path
# would otherwise be untestable. This stand-in models the two properties the
# bootstrap depends on: the plaintext is consumed from stdin (or a source file)
# and never appears in the blob, and the credential name embedded at encrypt
# time must match the name it is decrypted under.
FAKE_CREDS=""
make_fake_systemd_creds() {
    local dir="$1"
    mkdir -p "$dir"
    FAKE_CREDS="${dir}/systemd-creds"

    cat > "$FAKE_CREDS" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail

cmd="${1:-}"; shift || true
NAME=""; WITH_KEY=""
positional=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name=*)     NAME="${1#*=}"; shift ;;
        --with-key=*) WITH_KEY="${1#*=}"; shift ;;
        *)            positional+=("$1"); shift ;;
    esac
done

src="${positional[0]:-}"
dest="${positional[1]:-}"

case "$cmd" in
    encrypt)
        if [[ "$src" == "-" ]]; then payload="$(cat | base64 | tr -d '\n')"
        else payload="$(base64 < "$src" | tr -d '\n')"; fi
        {
            echo "FAKE-SEALED-CREDENTIAL"
            echo "name=${NAME}"
            echo "with-key=${WITH_KEY}"
            echo "payload-b64=${payload}"
        } > "$dest"
        ;;
    decrypt)
        embedded="$(sed -n 's/^name=//p' "$src")"
        if [[ -n "$NAME" && "$embedded" != "$NAME" ]]; then
            echo "fake systemd-creds: credential name mismatch (blob=${embedded} requested=${NAME})" >&2
            exit 1
        fi
        sed -n 's/^payload-b64=//p' "$src" | base64 -d > "$dest"
        ;;
    *)
        echo "fake systemd-creds: unsupported command '${cmd}'" >&2
        exit 64
        ;;
esac
FAKE
    chmod +x "$FAKE_CREDS"
}

sealed_payload() {
    sed -n 's/^payload-b64=//p' "$1" | base64 -d
}

FAKE_CREDS_DIR="$(mktemp -d)"
make_fake_systemd_creds "$FAKE_CREDS_DIR"
trap 'rm -rf "$FAKE_CREDS_DIR"' EXIT

# run_bootstrap executes tier1-bootstrap.sh with CFGMS_INSTALL_PREFIX=PREFIX.
# Additional arguments are forwarded. Sets LAST_EXIT and LAST_OUTPUT.
#
# TPM2 detection is pinned to "present" so the happy path exercises the default
# binding rather than depending on the test host's hardware; the tests that care
# about a missing TPM2 override it.
LAST_EXIT=0
LAST_OUTPUT=""
run_bootstrap() {
    local prefix="$1"
    shift
    LAST_EXIT=0
    LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$prefix" \
        CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
        CFGMS_BOOTSTRAP_TPM2_PROBE="true" \
        bash "$BOOTSTRAP_SH" "$@" 2>&1)" \
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
    elif ! grep -Fxq 'external_url: "https://ctrl.test.lab:9080"' "$CFG_FILE"; then
        fail "test2: controller.cfg missing top-level external_url with hostname and REST port (Issue #3170)"
        PASS_THIS=false
    elif ! grep -Fxq '  external_address: "ctrl.test.lab"' "$CFG_FILE"; then
        fail "test2: controller.cfg missing transport.external_address (Issue #3170)"
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

    # The external secret-encryption key exists ONLY as a sealed credential
    # (#3462): the plaintext is piped straight from `openssl rand` into
    # `systemd-creds encrypt` and is never written to a file.
    SECRETS_KEY="${T2_PREFIX}/etc/cfgms/secrets.key"
    SECRETS_KEY_CRED="${T2_PREFIX}/etc/cfgms/secrets.key.cred"
    if [[ -f "$SECRETS_KEY" ]]; then
        fail "test2: cleartext secrets.key written at $SECRETS_KEY"
        PASS_THIS=false
    fi
    if [[ ! -f "$SECRETS_KEY_CRED" ]]; then
        fail "test2: sealed secret-encryption key not created"
        PASS_THIS=false
    else
        if ! grep -Fxq 'with-key=tpm2' "$SECRETS_KEY_CRED"; then
            fail "test2: root key was not sealed with --with-key=tpm2 by default"
            PASS_THIS=false
        fi
        if [[ "$(sealed_payload "$SECRETS_KEY_CRED" | wc -c | tr -d '[:space:]')" != "32" ]]; then
            fail "test2: sealed root key is not 32 bytes"
            PASS_THIS=false
        fi
    fi

    BOOTSTRAP_RECORD="${T2_PREFIX}/etc/cfgms/.bootstrap-record"
    if [[ ! -f "$BOOTSTRAP_RECORD" ]] || ! grep -Fxq 'key_mode: tpm2' "$BOOTSTRAP_RECORD"; then
        fail "test2: bootstrap record does not record key_mode: tpm2"
        PASS_THIS=false
    fi

    # Nothing may be left on tmpfs after --init returns.
    if [[ -e "${T2_PREFIX}/run/cfgms-init-creds" ]]; then
        fail "test2: unsealed init credential directory was not removed"
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

# ── Test 9: TPM2 absent — refuse, unless the operator opts in explicitly ──────
#
# Sealing must not silently fall back to the disk-resident host key: that voids
# the "a stolen disk image yields nothing" property with no signal to the
# operator, and a host provisioned that way is indistinguishable afterwards from
# a TPM-bound one.

T9_PREFIX="$(mktemp -d)"
make_mock_controller "$T9_PREFIX"
make_mock_cfg "$T9_PREFIX"
LAST_EXIT=0
LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$T9_PREFIX" \
    CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
    CFGMS_BOOTSTRAP_TPM2_PROBE="false" \
    bash "$BOOTSTRAP_SH" --hostname=ctrl.test.lab --skip-smoke 2>&1)" || LAST_EXIT=$?

if [[ $LAST_EXIT -ne 0 ]] && echo "$LAST_OUTPUT" | grep -q "allow-host-key"; then
    if [[ -e "${T9_PREFIX}/etc/cfgms/secrets.key" || -e "${T9_PREFIX}/etc/cfgms/secrets.key.cred" ]]; then
        fail "test9: exited on the missing TPM2 but left key material behind"
    else
        pass "test9: a host with no usable TPM2 refuses to provision and names --allow-host-key"
    fi
else
    fail "test9: expected a non-zero exit naming --allow-host-key (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T9_PREFIX"

# ── Test 10: --allow-host-key provisions, warns, and records the binding ──────

T10_PREFIX="$(mktemp -d)"
make_mock_controller "$T10_PREFIX"
make_mock_cfg "$T10_PREFIX"
LAST_EXIT=0
LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$T10_PREFIX" \
    CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
    CFGMS_BOOTSTRAP_TPM2_PROBE="false" \
    bash "$BOOTSTRAP_SH" --hostname=ctrl.test.lab --allow-host-key --skip-smoke 2>&1)" || LAST_EXIT=$?

T10_PASS=true
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test10: --allow-host-key run exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
    T10_PASS=false
else
    if ! echo "$LAST_OUTPUT" | grep -q "stolen disk image"; then
        fail "test10: --allow-host-key did not warn about the consequence"
        T10_PASS=false
    fi
    if ! grep -Fxq 'key_mode: host' "${T10_PREFIX}/etc/cfgms/.bootstrap-record" 2>/dev/null; then
        fail "test10: bootstrap record does not record key_mode: host"
        T10_PASS=false
    fi
    if ! grep -Fxq 'with-key=host' "${T10_PREFIX}/etc/cfgms/secrets.key.cred" 2>/dev/null; then
        fail "test10: root key was not sealed with --with-key=host"
        T10_PASS=false
    fi
    if grep -q 'with-key=auto' "${T10_PREFIX}/etc/cfgms/secrets.key.cred" 2>/dev/null; then
        fail "test10: root key was sealed with --with-key=auto, which downgrades silently"
        T10_PASS=false
    fi
fi
[[ "$T10_PASS" == "true" ]] && pass "test10: --allow-host-key provisions with a loud warning and records key_mode: host"
rm -rf "$T10_PREFIX"

# ── Test 11: upgrade path — an existing cleartext key migrates in place ───────
#
# A controller provisioned before ADR-030 holds /etc/cfgms/secrets.key in
# cleartext. Re-running must seal THAT key — generating a new one would leave a
# controller that starts cleanly and cannot decrypt its own stored secrets.

T11_PREFIX="$(mktemp -d)"
make_mock_controller "$T11_PREFIX"
make_mock_cfg "$T11_PREFIX"
mkdir -p "${T11_PREFIX}/etc/cfgms"
printf 'pre-existing-root-key-32-bytes!!' > "${T11_PREFIX}/etc/cfgms/secrets.key"

run_bootstrap "$T11_PREFIX" --hostname=ctrl.test.lab --skip-smoke

T11_PASS=true
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test11: migration run exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
    T11_PASS=false
else
    if [[ -e "${T11_PREFIX}/etc/cfgms/secrets.key" ]]; then
        fail "test11: legacy cleartext secrets.key survived the migration"
        T11_PASS=false
    fi
    if [[ ! -f "${T11_PREFIX}/etc/cfgms/secrets.key.cred" ]]; then
        fail "test11: migration did not produce a sealed root key"
        T11_PASS=false
    elif [[ "$(sealed_payload "${T11_PREFIX}/etc/cfgms/secrets.key.cred")" != "pre-existing-root-key-32-bytes!!" ]]; then
        fail "test11: migration sealed a NEW root key instead of the host's existing one"
        T11_PASS=false
    fi
fi
[[ "$T11_PASS" == "true" ]] && pass "test11: an existing cleartext root key migrates into a sealed credential unchanged"
rm -rf "$T11_PREFIX"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
