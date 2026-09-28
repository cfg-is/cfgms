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
# a stub admin bundle so bootstrap steps 5+ can verify their logic. The bundle
# is written wherever --config's admin_bundle_path says, exactly like the real
# binary (features/controller/initialization) — never a path the mock invents
# on its own, so the mock stays faithful to the tmpfs-only behavior under test.
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

DO_INIT=false
CONFIG_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --init) DO_INIT=true; shift ;;
        --config) CONFIG_PATH="$2"; shift 2 ;;
        *) shift ;;
    esac
done

ADMIN_BUNDLE="${ETC}/admin.bundle.yaml"
if [[ -n "$CONFIG_PATH" ]] && grep -q '^admin_bundle_path:' "$CONFIG_PATH" 2>/dev/null; then
    ADMIN_BUNDLE="$(sed -n 's/^admin_bundle_path: *"\(.*\)"$/\1/p' "$CONFIG_PATH" | head -1)"
fi

if [[ "$DO_INIT" == "true" ]]; then
    # Real behavior: the CA/storage marker this checks is independent of the
    # script-owned issuance marker; the mock only needs to not re-issue when
    # the bundle directory is reused across a test's two invocations.
    mkdir -p "$(dirname "$ADMIN_BUNDLE")"
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

    # The admin bundle (Issue #4342) is never written to persistent storage,
    # transiently or otherwise: not at the old default path, and not at the
    # tmpfs path it was issued to — that copy must be gone by the time this
    # script exits, success or not.
    LEGACY_BUNDLE="${T2_PREFIX}/etc/cfgms/admin.bundle.yaml"
    if [[ -e "$LEGACY_BUNDLE" ]]; then
        fail "test2: cleartext admin bundle left at legacy path $LEGACY_BUNDLE"
        PASS_THIS=false
    fi
    if [[ -e "${T2_PREFIX}/run/cfgms-admin-bundle" ]]; then
        fail "test2: tmpfs admin bundle directory was not removed after a successful run"
        PASS_THIS=false
    fi

    # It must have been delivered somehow: printed to stdout during this run.
    if ! echo "$LAST_OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
        fail "test2: admin bundle was not printed to stdout"
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
#
# Also covers the re-issuance/re-exposure AC (Issue #4342): a second run must
# not re-print the admin bundle, since the operator already took delivery of
# it on the first run and the issuance marker records that.

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
    MTIME_CFG="$(stat -c %Y "$CFG_FILE" 2>/dev/null || stat -f %m "$CFG_FILE" 2>/dev/null)"
    MTIME_MARKER="$(stat -c %Y "$MARKER" 2>/dev/null || stat -f %m "$MARKER" 2>/dev/null)"

    # Wait a tick so any re-write would produce a different mtime
    sleep 1

    # Second run (idempotent re-run)
    run_bootstrap "$T3_PREFIX" --hostname=ctrl.test.lab --skip-smoke

    if [[ $LAST_EXIT -ne 0 ]]; then
        fail "test3: idempotent re-run exited ${LAST_EXIT} (expected 0)"
    else
        MTIME_CFG2="$(stat -c %Y "$CFG_FILE" 2>/dev/null || stat -f %m "$CFG_FILE" 2>/dev/null)"
        MTIME_MARKER2="$(stat -c %Y "$MARKER" 2>/dev/null || stat -f %m "$MARKER" 2>/dev/null)"

        T3_PASS=true
        if [[ "$MTIME_CFG" != "$MTIME_CFG2" || "$MTIME_MARKER" != "$MTIME_MARKER2" ]]; then
            fail "test3: idempotent re-run modified existing files (cfg=${MTIME_CFG}=>${MTIME_CFG2} marker=${MTIME_MARKER}=>${MTIME_MARKER2})"
            T3_PASS=false
        fi
        if echo "$LAST_OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
            fail "test3: idempotent re-run re-printed (re-exposed) the admin bundle"
            T3_PASS=false
        fi
        if [[ -e "${T3_PREFIX}/run/cfgms-admin-bundle" ]]; then
            fail "test3: idempotent re-run left a tmpfs admin bundle directory behind"
            T3_PASS=false
        fi
        [[ "$T3_PASS" == "true" ]] && pass "test3: idempotent re-run exits 0, changes nothing, and does not re-expose the bundle"
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
    MARKER="${T4_PREFIX}/etc/cfgms/.admin-bundle-issued"
    if [[ -f "$CFG_FILE" && -f "$MARKER" ]] && echo "$LAST_OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
        pass "test4: partial-state recovery completes remaining steps"
    else
        fail "test4: partial-state recovery did not create config (${CFG_FILE}: $([ -f "$CFG_FILE" ] && echo present || echo missing)) or issue the admin bundle"
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
DO_INIT=false
CONFIG_PATH=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --init) DO_INIT=true; shift ;;
        --config) CONFIG_PATH="$2"; shift 2 ;;
        *) shift ;;
    esac
done
ADMIN_BUNDLE="${ETC}/admin.bundle.yaml"
if [[ -n "$CONFIG_PATH" ]] && grep -q '^admin_bundle_path:' "$CONFIG_PATH" 2>/dev/null; then
    ADMIN_BUNDLE="$(sed -n 's/^admin_bundle_path: *"\(.*\)"$/\1/p' "$CONFIG_PATH" | head -1)"
fi
if [[ "$DO_INIT" == "true" ]]; then
    mkdir -p "$(dirname "$ADMIN_BUNDLE")"
    printf 'controller_url: "https://test-host:9080"\ncert_pem: |\n  TEST\nkey_pem: |\n  TEST\nca_pem: |\n  TEST\n' > "$ADMIN_BUNDLE"
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

# ── Test 12: no cleartext admin bundle remains after a successful run ─────────
#
# [REQUIRED TEST, Issue #4342] Restated as a dedicated, narrowly-scoped test —
# test2 already covers this as part of its broader happy-path assertions.

T12_PREFIX="$(mktemp -d)"
make_mock_controller "$T12_PREFIX"
make_mock_cfg "$T12_PREFIX"

run_bootstrap "$T12_PREFIX" --hostname=ctrl.test.lab --skip-smoke

T12_PASS=true
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test12: successful run exited ${LAST_EXIT} (expected 0)"
    T12_PASS=false
fi
if [[ -e "${T12_PREFIX}/etc/cfgms/admin.bundle.yaml" ]]; then
    fail "test12: cleartext admin bundle left at the legacy issuance path after a successful run"
    T12_PASS=false
fi
if [[ -e "${T12_PREFIX}/run/cfgms-admin-bundle" ]]; then
    fail "test12: cleartext admin bundle left on tmpfs after a successful run"
    T12_PASS=false
fi
[[ "$T12_PASS" == "true" ]] && pass "test12: no cleartext admin bundle remains anywhere after a successful run"
rm -rf "$T12_PREFIX"

# ── Test 13: no cleartext admin bundle remains after a run that fails AFTER
#             issuance ────────────────────────────────────────────────────────
#
# [REQUIRED TEST, Issue #4342] Delivers SIGTERM to the bootstrap process once
# issuance (step 5) has completed but before the script would otherwise exit —
# the EXIT/INT/TERM trap installed in step 5 must still remove the tmpfs
# bundle. make_mock_cfg_slow pads each tenant-create call so there is a
# reliable window, after the issuance marker appears, in which to deliver the
# signal while the bootstrap process is blocked on a foreground child (bash
# defers a TERM trap until the current foreground command returns, so the
# padding matters — without it the signal could arrive between steps with
# nothing to catch it against).

make_mock_cfg_slow() {
    local prefix="$1"
    local bin_dir="${prefix}/usr/local/bin"
    mkdir -p "$bin_dir"
    cat > "${bin_dir}/cfg" <<'MOCK'
#!/usr/bin/env bash
sleep 1
exit 0
MOCK
    chmod +x "${bin_dir}/cfg"
}

T13_PREFIX="$(mktemp -d)"
make_mock_controller "$T13_PREFIX"
make_mock_cfg_slow "$T13_PREFIX"

CFGMS_INSTALL_PREFIX="$T13_PREFIX" \
    CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
    CFGMS_BOOTSTRAP_TPM2_PROBE="true" \
    bash "$BOOTSTRAP_SH" --hostname=ctrl.test.lab --skip-smoke >/dev/null 2>&1 &
T13_PID=$!

T13_MARKER="${T13_PREFIX}/etc/cfgms/.admin-bundle-issued"
T13_WAITED=0
while [[ ! -f "$T13_MARKER" && $T13_WAITED -lt 100 ]]; do
    sleep 0.1
    T13_WAITED=$((T13_WAITED + 1))
done

if [[ ! -f "$T13_MARKER" ]]; then
    fail "test13: issuance marker never appeared — cannot exercise the failure-after-issuance path"
    kill -TERM "$T13_PID" 2>/dev/null || true
    wait "$T13_PID" 2>/dev/null || true
else
    kill -TERM "$T13_PID" 2>/dev/null || true
    T13_EXIT=0
    wait "$T13_PID" 2>/dev/null || T13_EXIT=$?

    T13_PASS=true
    if [[ $T13_EXIT -eq 0 ]]; then
        fail "test13: expected the terminated run to exit non-zero (got 0)"
        T13_PASS=false
    fi
    if [[ -e "${T13_PREFIX}/run/cfgms-admin-bundle" ]]; then
        fail "test13: cleartext admin bundle left on tmpfs after a run that failed after issuance"
        T13_PASS=false
    fi
    [[ "$T13_PASS" == "true" ]] && pass "test13: no cleartext admin bundle remains after a run that fails after issuance"
fi
rm -rf "$T13_PREFIX"

# ── Test 14: a config pointing admin_bundle_path outside the script's own
#             tmpfs directory fails the run and destroys nothing ──────────────
#
# [REGRESSION] An earlier revision re-derived the bundle directory from
# admin_bundle_path and ran `rm -rf` on it. A --config override naming
# /etc/cfgms/admin.bundle.yaml — a documented, reachable configuration —
# therefore deleted the whole /etc/cfgms tree, taking the sealed root key
# (the only copy, ADR-030), controller.cfg and the bootstrap record with it.

T14_PREFIX="$(mktemp -d)"
make_mock_controller "$T14_PREFIX"
make_mock_cfg "$T14_PREFIX"
mkdir -p "${T14_PREFIX}/etc/cfgms"
echo "operator data that predates this run" > "${T14_PREFIX}/etc/cfgms/sentinel"

T14_CONFIG="$(mktemp)"
cat > "$T14_CONFIG" <<EOF
listen_addr: "0.0.0.0:9080"
data_dir: "/var/lib/cfgms"
admin_bundle_path: "${T14_PREFIX}/etc/cfgms/admin.bundle.yaml"
EOF

run_bootstrap "$T14_PREFIX" --hostname=ctrl.test.lab --config="$T14_CONFIG" --skip-smoke

T14_PASS=true
if [[ $LAST_EXIT -eq 0 ]]; then
    fail "test14: expected a non-zero exit for an admin_bundle_path outside the script's tmpfs directory"
    T14_PASS=false
fi
if ! echo "$LAST_OUTPUT" | grep -q "admin_bundle_path"; then
    fail "test14: refusal did not name admin_bundle_path (output='${LAST_OUTPUT}')"
    T14_PASS=false
fi
for survivor in \
    "${T14_PREFIX}/etc/cfgms/sentinel" \
    "${T14_PREFIX}/etc/cfgms/secrets.key.cred" \
    "${T14_PREFIX}/etc/cfgms/.bootstrap-record" \
    "${T14_PREFIX}/etc/cfgms/controller.cfg"; do
    if [[ ! -e "$survivor" ]]; then
        fail "test14: refusing the run destroyed $survivor"
        T14_PASS=false
    fi
done
if [[ ! -d "${T14_PREFIX}/var/lib/cfgms/certs/ca" ]]; then
    fail "test14: refusing the run destroyed the CA directory"
    T14_PASS=false
fi
[[ "$T14_PASS" == "true" ]] && pass "test14: an admin_bundle_path outside the script's tmpfs directory fails the run and deletes nothing"
rm -rf "$T14_PREFIX"
rm -f "$T14_CONFIG"

# ── Test 15: a config predating admin_bundle_path gets the key appended ───────
#
# [REGRESSION] Step 4 skips generation for an existing controller.cfg, so a host
# provisioned by an earlier version of this script had no admin_bundle_path at
# all and the controller fell back to its own default,
# /etc/cfgms/admin.bundle.yaml (features/controller/initialization/bundle_marker.go).
# --init then wrote the full admin cert and key to persistent storage and the run
# aborted with that file left behind indefinitely.

T15_PREFIX="$(mktemp -d)"
make_mock_controller "$T15_PREFIX"
make_mock_cfg "$T15_PREFIX"
mkdir -p "${T15_PREFIX}/etc/cfgms"
cat > "${T15_PREFIX}/etc/cfgms/controller.cfg" <<'LEGACYCFG'
listen_addr: "0.0.0.0:9080"
data_dir: "/var/lib/cfgms"
storage:
  flatfile_root: "/var/lib/cfgms/storage"
LEGACYCFG
# ...and the cleartext bundle that earlier version left behind.
printf 'cert_pem: |\n  LEGACY\n' > "${T15_PREFIX}/etc/cfgms/admin.bundle.yaml"

run_bootstrap "$T15_PREFIX" --hostname=ctrl.test.lab --skip-smoke

T15_PASS=true
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test15: run against a config predating admin_bundle_path exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
    T15_PASS=false
fi
if ! grep -Fxq "admin_bundle_path: \"${T15_PREFIX}/run/cfgms-admin-bundle/admin.bundle.yaml\"" \
        "${T15_PREFIX}/etc/cfgms/controller.cfg"; then
    fail "test15: admin_bundle_path was not appended to the pre-existing config"
    T15_PASS=false
fi
if [[ -e "${T15_PREFIX}/etc/cfgms/admin.bundle.yaml" ]]; then
    fail "test15: cleartext admin bundle remains on persistent storage"
    T15_PASS=false
fi
if [[ -e "${T15_PREFIX}/run/cfgms-admin-bundle" ]]; then
    fail "test15: tmpfs admin bundle directory was not removed"
    T15_PASS=false
fi
if ! echo "$LAST_OUTPUT" | grep -q "BEGIN CERTIFICATE"; then
    fail "test15: admin bundle was not printed to stdout"
    T15_PASS=false
fi
[[ "$T15_PASS" == "true" ]] && pass "test15: a config predating admin_bundle_path gets the tmpfs path appended and leaves no cleartext bundle"
rm -rf "$T15_PREFIX"

# ── Test 16: the legacy cleartext bundle is removed even when the run fails
#             before the step that used to remove it ────────────────────────────
#
# [REGRESSION] The legacy-bundle removal used to run inline between steps 5 and
# 6, so any failure before that line left the cleartext credential on disk
# indefinitely — the exposure Issue #4342 exists to remove, on precisely the
# path an operator is least likely to inspect. Removal now lives in the cleanup
# trap armed in step 4. The failure is injected inside step 5: the mock's --init
# writes the bundle and then exits non-zero, modelling an init that fails after
# the credential has already been issued.

make_mock_controller_init_fails() {
    local prefix="$1"
    make_mock_controller "$prefix"
    # Same mock, but its final exit status is failure: the bundle is written to
    # the configured path first, exactly as the real binary does before a later
    # stage of init can fail.
    local bin="${prefix}/usr/local/bin/cfgms-controller"
    sed -i '$ s/^exit 0$/exit 1/' "$bin"
    grep -qx 'exit 1' "$bin" || { echo "test16: failed to build a failing --init mock" >&2; exit 1; }
}

T16_PREFIX="$(mktemp -d)"
make_mock_controller_init_fails "$T16_PREFIX"
make_mock_cfg "$T16_PREFIX"
mkdir -p "${T16_PREFIX}/etc/cfgms"
printf 'cert_pem: |\n  LEGACY\n' > "${T16_PREFIX}/etc/cfgms/admin.bundle.yaml"

run_bootstrap "$T16_PREFIX" --hostname=ctrl.test.lab --skip-smoke

T16_PASS=true
if [[ $LAST_EXIT -eq 0 ]]; then
    fail "test16: expected a non-zero exit when controller --init fails"
    T16_PASS=false
fi
if [[ -e "${T16_PREFIX}/etc/cfgms/admin.bundle.yaml" ]]; then
    fail "test16: legacy cleartext admin bundle survived a run that failed after issuance"
    T16_PASS=false
fi
if [[ -e "${T16_PREFIX}/run/cfgms-admin-bundle" ]]; then
    fail "test16: tmpfs admin bundle survived a run whose --init failed after issuing it"
    T16_PASS=false
fi
if [[ -e "${T16_PREFIX}/run/cfgms-init-creds" ]]; then
    fail "test16: unsealed root key survived a run whose --init failed"
    T16_PASS=false
fi
if [[ ! -f "${T16_PREFIX}/etc/cfgms/secrets.key.cred" ]]; then
    fail "test16: the failed run removed the sealed root key"
    T16_PASS=false
fi
[[ "$T16_PASS" == "true" ]] && pass "test16: the legacy cleartext bundle is removed even when the run fails inside step 5"
rm -rf "$T16_PREFIX"

# ── Test 17: stdout carries the admin bundle and NOTHING else ─────────────────
#
# [REGRESSION] The documented capture idiom is
# `ssh host 'sudo bash tier1-bootstrap.sh ...' > admin.bundle.yaml`, so anything
# on stdout ahead of the bundle corrupts the operator's only copy of a live
# admin credential — one the script deliberately will not re-issue. The script's
# own messages always went to stderr, but its CHILDREN did not: `--init` printed
# a completion banner, `cfg tenant create` printed "tenant created: <id>" per
# tenant, and the smoke test printed "[PASS] ..." lines, all on stdout. Every
# other test in this file captures 2>&1 into one string and so could not see it.
#
# This test keeps the streams apart and asserts stdout is byte-identical to the
# bundle. It also asserts the child output is still present ON STDERR, so
# discarding it (>/dev/null) does not pass.

T17_PREFIX="$(mktemp -d)"
make_mock_controller "$T17_PREFIX"
make_mock_cfg "$T17_PREFIX"

# Reference copy of the bundle bytes, produced by the same mock --init the
# bootstrap will run, so the comparison never drifts from the mock's content.
T17_REF_DIR="$(mktemp -d)"
printf 'admin_bundle_path: "%s"\n' "${T17_REF_DIR}/bundle.yaml" > "${T17_REF_DIR}/ref.cfg"
CFGMS_INSTALL_PREFIX="$T17_REF_DIR" "${T17_PREFIX}/usr/local/bin/cfgms-controller" \
    --init --config "${T17_REF_DIR}/ref.cfg" > /dev/null

T17_OUT="${T17_REF_DIR}/stdout.txt"
T17_ERR="${T17_REF_DIR}/stderr.txt"
T17_EXIT=0
CFGMS_INSTALL_PREFIX="$T17_PREFIX" \
    CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
    CFGMS_BOOTSTRAP_TPM2_PROBE="true" \
    bash "$BOOTSTRAP_SH" --hostname=ctrl.test.lab \
    > "$T17_OUT" 2> "$T17_ERR" || T17_EXIT=$?

T17_PASS=true
if [[ $T17_EXIT -ne 0 ]]; then
    fail "test17: bootstrap exited ${T17_EXIT} (expected 0); stderr='$(cat "$T17_ERR")'"
    T17_PASS=false
fi

if ! diff -u "${T17_REF_DIR}/bundle.yaml" "$T17_OUT" > "${T17_REF_DIR}/stdout.diff" 2>&1; then
    fail "test17: stdout is not exactly the admin bundle; diff: $(cat "${T17_REF_DIR}/stdout.diff")"
    T17_PASS=false
fi

# Named offenders, called out individually so a regression says which child leaked.
if grep -q 'Controller initialization complete' "$T17_OUT"; then
    fail "test17: controller --init output leaked onto stdout ahead of the bundle"
    T17_PASS=false
fi
if grep -q 'tenant created:' "$T17_OUT"; then
    fail "test17: cfg tenant create output leaked onto stdout ahead of the bundle"
    T17_PASS=false
fi
if grep -q '\[bootstrap\]' "$T17_OUT"; then
    fail "test17: bootstrap status messages leaked onto stdout"
    T17_PASS=false
fi

# Redirected, not discarded: the operator still sees the child output.
if ! grep -q 'Controller initialization complete' "$T17_ERR"; then
    fail "test17: controller --init output was discarded instead of redirected to stderr"
    T17_PASS=false
fi
if ! grep -q 'tenant created: agent-test' "$T17_ERR"; then
    fail "test17: cfg tenant create output was discarded instead of redirected to stderr"
    T17_PASS=false
fi

[[ "$T17_PASS" == "true" ]] && pass "test17: stdout carries the admin bundle and nothing else; child output goes to stderr"
rm -rf "$T17_PREFIX" "$T17_REF_DIR"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
