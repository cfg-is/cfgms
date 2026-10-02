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
skip() { echo "SKIP: $1"; }

# POSIX_MODES reports whether this filesystem can actually represent the
# permission bits chmod is given. It cannot under Git Bash on Windows, where a
# chmod 0400 file still stats as 0444 — so a literal mode assertion there would
# fail on a correct script. The permission checks below are gated on this rather
# than weakened, so they keep their full strength on the Linux hosts these
# bootstrap scripts actually run on.
POSIX_MODES=false
_mode_probe_dir="$(mktemp -d)"
: > "${_mode_probe_dir}/probe"
chmod 0400 "${_mode_probe_dir}/probe"
if [[ "$(stat -c '%a' "${_mode_probe_dir}/probe" 2>/dev/null || stat -f '%Lp' "${_mode_probe_dir}/probe" 2>/dev/null)" == "400" ]]; then
    POSIX_MODES=true
fi
rm -rf "$_mode_probe_dir"

file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }

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
    {
        printf 'CFGMS_NODE_ID=%s\n' "${CFGMS_NODE_ID:-}"
        printf 'CFGMS_HA_CLUSTER_NODES=%s\n' "${CFGMS_HA_CLUSTER_NODES:-}"
        printf 'CFGMS_HA_CA_CERT_PATH=%s\n' "${CFGMS_HA_CA_CERT_PATH:-}"
        printf 'CFGMS_SECRETS_KEY_FILE=%s\n' "${CFGMS_SECRETS_KEY_FILE:-}"
        printf 'OPENBAO_ADDR=%s\n' "${OPENBAO_ADDR:-}"
        # Recorded so tests can prove secrets arrive by PATH and never by value.
        printf 'CFGMS_STORAGE_DB_PASSWORD_FILE=%s\n' "${CFGMS_STORAGE_DB_PASSWORD_FILE:-}"
        printf 'CFGMS_SESSION_HMAC_KEY_FILE=%s\n' "${CFGMS_SESSION_HMAC_KEY_FILE:-}"
        printf 'OPENBAO_TOKEN_FILE=%s\n' "${OPENBAO_TOKEN_FILE:-}"
        printf 'CFGMS_STORAGE_DB_PASSWORD=%s\n' "${CFGMS_STORAGE_DB_PASSWORD:-}"
        printf 'CFGMS_SESSION_HMAC_KEY=%s\n' "${CFGMS_SESSION_HMAC_KEY:-}"
        printf 'OPENBAO_TOKEN=%s\n' "${OPENBAO_TOKEN:-}"
        # The unseal directory is removed as soon as --init returns; record
        # whether the credentials were actually readable while it ran.
        printf 'SECRETS_KEY_READABLE=%s\n' "$([[ -r "${CFGMS_SECRETS_KEY_FILE:-/nonexistent}" ]] && echo yes || echo no)"
    } > "$INIT_ENV_RECORD"
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

# ── systemd-creds stand-in ────────────────────────────────────────────────────

# FAKE_CREDS is a stand-in for `systemd-creds`, injected via
# CFGMS_SYSTEMD_CREDS_BIN. The real binary needs systemd and a TPM2 or host key,
# neither of which exists on a developer workstation or in a CI container, so
# these tests would otherwise be unable to reach the sealing path at all.
#
# It models the two properties the bootstrap actually depends on: the plaintext
# is consumed from stdin and never appears in the blob, and the credential name
# embedded at encrypt time must match the name it is later decrypted under
# (systemd rejects a mismatch, which is why the unit's LoadCredentialEncrypted=
# IDs and the --name= arguments have to agree).
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
        # Base64 the plaintext straight out of the stream. Holding it in a shell
        # variable first would drop NUL bytes, so a binary key would be silently
        # truncated by the stand-in rather than by the code under test.
        if [[ "$src" == "-" ]]; then payload="$(base64 | tr -d '\n')"
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

# sealed_payload prints the plaintext a fake-sealed blob carries, so tests can
# assert the right value reached the right credential.
sealed_payload() {
    sed -n 's/^payload-b64=//p' "$1" | base64 -d
}

FAKE_CREDS_DIR="$(mktemp -d)"
make_fake_systemd_creds "$FAKE_CREDS_DIR"
trap 'rm -rf "$FAKE_CREDS_DIR"' EXIT

# run_bootstrap executes ha-cluster-node-bootstrap.sh with CFGMS_INSTALL_PREFIX=PREFIX
# and the standard set of required secret env vars pre-populated with test values.
# Additional arguments are forwarded. Sets LAST_EXIT and LAST_OUTPUT.
#
# TPM2 detection is pinned to "present" and sealing is pointed at the stand-in,
# so the happy path exercises the default (tpm2) binding rather than depending on
# whatever the test host happens to have. The tests that care about a missing
# TPM2 or the host-key opt-in override these deliberately.
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
        CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
        CFGMS_BOOTSTRAP_TPM2_PROBE="true" \
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
    if [[ -e "${T2B_PREFIX}/etc/cfgms/secrets.key" || -e "${T2B_PREFIX}/etc/cfgms/secrets.key.cred" ]]; then
        fail "test2b: exited on the missing key but left key material behind"
    else
        pass "test2b: missing CFGMS_SECRETS_KEY_B64 exits 1 naming the variable, writing no key file"
    fi
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

    # The cleartext secrets env file must be GONE, and each value it used to
    # carry must now exist as a sealed credential instead. This assertion was
    # inverted rather than deleted (#3462): it is the evidence that the
    # EnvironmentFile= delivery path is actually absent, not merely unused.
    SECRETS_ENV="${T3_PREFIX}/etc/cfgms/ha-secrets.env"
    if [[ -f "$SECRETS_ENV" ]]; then
        fail "test3: cleartext secrets env file still written at $SECRETS_ENV"
        PASS_THIS=false
    fi

    DB_PASSWORD_CRED="${T3_PREFIX}/etc/cfgms/db-password.cred"
    SESSION_HMAC_CRED="${T3_PREFIX}/etc/cfgms/session-hmac-key.cred"
    OPENBAO_TOKEN_CRED="${T3_PREFIX}/etc/cfgms/openbao-token.cred"
    SECRETS_KEY_CRED="${T3_PREFIX}/etc/cfgms/secrets.key.cred"

    for cred in "$DB_PASSWORD_CRED" "$SESSION_HMAC_CRED" "$OPENBAO_TOKEN_CRED" "$SECRETS_KEY_CRED"; do
        if [[ ! -f "$cred" ]]; then
            fail "test3: sealed credential not created: $cred"
            PASS_THIS=false
        elif [[ "$POSIX_MODES" == "true" ]] && [[ "$(file_mode "$cred")" != "400" ]]; then
            fail "test3: sealed credential $cred is mode $(file_mode "$cred"), expected 0400"
            PASS_THIS=false
        fi
    done
    if [[ "$POSIX_MODES" != "true" ]]; then
        skip "test3: sealed-credential mode assertions (this filesystem does not represent POSIX permission bits)"
    fi

    # Each secret reached its OWN credential — a swapped pair would still
    # produce four files and a unit that starts, then fail at runtime.
    if [[ -f "$DB_PASSWORD_CRED" ]] && [[ "$(sealed_payload "$DB_PASSWORD_CRED")" != "test-pg-password" ]]; then
        fail "test3: db-password credential does not carry CFGMS_STORAGE_DB_PASSWORD"
        PASS_THIS=false
    fi
    if [[ -f "$SESSION_HMAC_CRED" ]] && [[ "$(sealed_payload "$SESSION_HMAC_CRED")" != "test-session-hmac-key" ]]; then
        fail "test3: session-hmac-key credential does not carry CFGMS_SESSION_HMAC_KEY"
        PASS_THIS=false
    fi
    if [[ -f "$OPENBAO_TOKEN_CRED" ]] && [[ "$(sealed_payload "$OPENBAO_TOKEN_CRED")" != "test-vault-token" ]]; then
        fail "test3: openbao-token credential does not carry the vault token"
        PASS_THIS=false
    fi

    # No sealed blob may contain its plaintext. A "sealing" step that left the
    # value readable would pass every existence check above.
    for cred in "$DB_PASSWORD_CRED" "$SESSION_HMAC_CRED" "$OPENBAO_TOKEN_CRED"; do
        if [[ -f "$cred" ]] && grep -qF -e "test-pg-password" -e "test-session-hmac-key" -e "test-vault-token" "$cred"; then
            fail "test3: sealed credential $cred contains a cleartext secret value"
            PASS_THIS=false
        fi
    done

    # Default binding is the TPM2, not the disk-resident host key.
    if [[ -f "$SECRETS_KEY_CRED" ]] && ! grep -Fxq 'with-key=tpm2' "$SECRETS_KEY_CRED"; then
        fail "test3: root key was not sealed with --with-key=tpm2 by default"
        PASS_THIS=false
    fi

    BOOTSTRAP_RECORD="${T3_PREFIX}/etc/cfgms/.bootstrap-record"
    if [[ ! -f "$BOOTSTRAP_RECORD" ]]; then
        fail "test3: bootstrap record not written"
        PASS_THIS=false
    elif ! grep -Fxq 'key_mode: tpm2' "$BOOTSTRAP_RECORD"; then
        fail "test3: bootstrap record does not record key_mode: tpm2"
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
        # --init runs outside systemd, so it gets the values from a short-lived
        # unseal directory on tmpfs — never from the old cleartext
        # /etc/cfgms/secrets.key, and never by value.
        if ! grep -q "^CFGMS_SECRETS_KEY_FILE=${T3_PREFIX}/run/cfgms-init-creds/cfgms-secrets-key$" "$INIT_RECORD"; then
            fail "test3: CFGMS_SECRETS_KEY_FILE not pointed at the unsealed init credential"
            PASS_THIS=false
        fi
        if grep -q "^CFGMS_SECRETS_KEY_FILE=${T3_PREFIX}/etc/cfgms/secrets.key$" "$INIT_RECORD"; then
            fail "test3: --init still reads the cleartext /etc/cfgms/secrets.key"
            PASS_THIS=false
        fi
        for var in CFGMS_STORAGE_DB_PASSWORD_FILE CFGMS_SESSION_HMAC_KEY_FILE OPENBAO_TOKEN_FILE; do
            if ! grep -q "^${var}=${T3_PREFIX}/run/cfgms-init-creds/" "$INIT_RECORD"; then
                fail "test3: ${var} not passed to --init"
                PASS_THIS=false
            fi
        done
        for var in CFGMS_STORAGE_DB_PASSWORD CFGMS_SESSION_HMAC_KEY OPENBAO_TOKEN; do
            if grep -q "^${var}=." "$INIT_RECORD"; then
                fail "test3: secret ${var} passed to --init by value instead of by path"
                PASS_THIS=false
            fi
        done
        if ! grep -q "^OPENBAO_ADDR=http://192.168.234.105:8200$" "$INIT_RECORD"; then
            fail "test3: OPENBAO_ADDR not passed to --init"
            PASS_THIS=false
        fi
    fi

    # Inverted (#3462): the cluster root key must exist ONLY as a sealed
    # credential. A cleartext /etc/cfgms/secrets.key is the condition this story
    # removes, so its continued absence is the assertion worth keeping.
    SECRETS_KEY_FILE="${T3_PREFIX}/etc/cfgms/secrets.key"
    if [[ -f "$SECRETS_KEY_FILE" ]]; then
        fail "test3: cleartext secrets.key still written at $SECRETS_KEY_FILE"
        PASS_THIS=false
    fi
    if [[ -f "$SECRETS_KEY_CRED" ]] && [[ "$(sealed_payload "$SECRETS_KEY_CRED")" != "test-secrets-key-32-bytes-long!!" ]]; then
        fail "test3: sealed root key does not carry the value from CFGMS_SECRETS_KEY_B64"
        PASS_THIS=false
    fi

    # Nothing may be left on tmpfs after --init returns.
    if [[ -e "${T3_PREFIX}/run/cfgms-init-creds" ]]; then
        fail "test3: unsealed init credential directory was not removed"
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
            'Environment=CFGMS_NODE_ID=cfgms-ha-node2' \
            'NoNewPrivileges=true' \
            'ProtectSystem=strict' \
            'LoadCredentialEncrypted=cfgms-secrets-key:/etc/cfgms/secrets.key.cred' \
            'LoadCredentialEncrypted=cfgms-db-password:/etc/cfgms/db-password.cred' \
            'LoadCredentialEncrypted=cfgms-session-hmac-key:/etc/cfgms/session-hmac-key.cred' \
            'LoadCredentialEncrypted=cfgms-openbao-token:/etc/cfgms/openbao-token.cred' \
            'Environment=CFGMS_SECRETS_KEY_FILE=%d/cfgms-secrets-key' \
            'Environment=CFGMS_STORAGE_DB_PASSWORD_FILE=%d/cfgms-db-password' \
            'Environment=CFGMS_SESSION_HMAC_KEY_FILE=%d/cfgms-session-hmac-key' \
            'Environment=OPENBAO_TOKEN_FILE=%d/cfgms-openbao-token' \
            'Environment=OPENBAO_ADDR=http://192.168.234.105:8200' \
            'InaccessiblePaths=/etc/cfgms/secrets.key.cred' \
            'InaccessiblePaths=/etc/cfgms/db-password.cred' \
            'InaccessiblePaths=/etc/cfgms/session-hmac-key.cred' \
            'InaccessiblePaths=/etc/cfgms/openbao-token.cred'; do
            if ! grep -Fxq "$directive" "$SERVICE"; then
                fail "test3: systemd unit missing directive: $directive"
                PASS_THIS=false
            fi
        done

        # The two directives below were assertions that the env-file pattern was
        # PRESENT. Inverted rather than removed (#3462): they are the standing
        # evidence that EnvironmentFile= secret delivery is gone, and that no
        # plaintext LoadCredential= replaced it.
        if grep -q '^EnvironmentFile=' "$SERVICE"; then
            fail "test3: systemd unit still uses EnvironmentFile= (secrets must arrive via LoadCredentialEncrypted=)"
            PASS_THIS=false
        fi
        if grep -q '^InaccessiblePaths=/etc/cfgms/ha-secrets.env$' "$SERVICE"; then
            fail "test3: systemd unit still references the removed /etc/cfgms/ha-secrets.env"
            PASS_THIS=false
        fi
        if grep -qE '^LoadCredential=' "$SERVICE"; then
            fail "test3: systemd unit loads a plaintext credential; every secret must be LoadCredentialEncrypted="
            PASS_THIS=false
        fi

        # No secret value may appear anywhere in the unit — it is world-readable.
        if grep -qF -e 'test-pg-password' -e 'test-session-hmac-key' -e 'test-vault-token' "$SERVICE"; then
            fail "test3: systemd unit contains a literal secret value"
            PASS_THIS=false
        fi
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

# ── Test 7: provision_secrets_key fails loudly and writes no key ──────────────
#
# The function under test is provision_secrets_key() in
# scripts/ha-cluster-node-bootstrap.sh. Its contract is not merely "exit
# non-zero": an implementation that failed *after* writing key material would
# pass an exit-code-only check while leaving a fresh, wrong root of trust on
# disk for a later run to adopt. Every case below asserts the exit code AND the
# absence of both key artifacts.

run_bootstrap_with_key() {
    local prefix="$1" key_b64="$2"
    shift 2
    LAST_EXIT=0
    LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$prefix" \
        CFGMS_STORAGE_DB_PASSWORD="test-pg-password" \
        CFGMS_SESSION_HMAC_KEY="test-session-hmac-key" \
        CFGMS_SECRETS_KEY_B64="$key_b64" \
        OPENBAO_TOKEN="test-vault-token" \
        CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
        CFGMS_BOOTSTRAP_TPM2_PROBE="true" \
        bash "$BOOTSTRAP_SH" "$@" 2>&1)" || LAST_EXIT=$?
}

assert_no_key_material() {
    local prefix="$1" label="$2"
    if [[ -e "${prefix}/etc/cfgms/secrets.key" ]]; then
        fail "${label}: a cleartext secrets.key was written despite the failure"
        return 1
    fi
    if [[ -e "${prefix}/etc/cfgms/secrets.key.cred" ]]; then
        fail "${label}: a sealed secrets.key.cred was written despite the failure"
        return 1
    fi
    return 0
}

# 7a: the supplied key is not valid base64.
T7A_PREFIX="$(mktemp -d)"
make_mock_controller "$T7A_PREFIX"
run_bootstrap_with_key "$T7A_PREFIX" "!!!not-base64!!!" "${STD_FLAGS[@]}" --skip-smoke
if [[ $LAST_EXIT -ne 0 ]] && echo "$LAST_OUTPUT" | grep -qi "not valid base64"; then
    if assert_no_key_material "$T7A_PREFIX" "test7a"; then
        pass "test7a: provision_secrets_key rejects a non-base64 root key without writing one"
    fi
else
    fail "test7a: expected a non-zero exit naming invalid base64 (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T7A_PREFIX"

# 7b: the supplied key decodes to the wrong length. SOPS needs exactly 32 bytes;
# a short key would be accepted here and rejected far away at controller start.
T7B_PREFIX="$(mktemp -d)"
make_mock_controller "$T7B_PREFIX"
run_bootstrap_with_key "$T7B_PREFIX" "$(printf 'too-short' | base64 | tr -d '\n')" "${STD_FLAGS[@]}" --skip-smoke
if [[ $LAST_EXIT -ne 0 ]] && echo "$LAST_OUTPUT" | grep -q "expected 32"; then
    if assert_no_key_material "$T7B_PREFIX" "test7b"; then
        pass "test7b: provision_secrets_key rejects a wrong-length root key without writing one"
    fi
else
    fail "test7b: expected a non-zero exit naming the 32-byte requirement (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T7B_PREFIX"

# 7c: the node already holds a different root key. Sealing the supplied one
# would leave this node unable to decrypt the cluster secrets it already has —
# the "looks healthy, wrong root of trust" failure this story exists to prevent.
T7C_PREFIX="$(mktemp -d)"
make_mock_controller "$T7C_PREFIX"
mkdir -p "${T7C_PREFIX}/etc/cfgms"
printf 'a-completely-different-32-byte!!' > "${T7C_PREFIX}/etc/cfgms/secrets.key"
run_bootstrap_with_key "$T7C_PREFIX" "dGVzdC1zZWNyZXRzLWtleS0zMi1ieXRlcy1sb25nISE=" "${STD_FLAGS[@]}" --skip-smoke
if [[ $LAST_EXIT -ne 0 ]] && echo "$LAST_OUTPUT" | grep -q "does not match"; then
    if [[ -e "${T7C_PREFIX}/etc/cfgms/secrets.key.cred" ]]; then
        fail "test7c: sealed a mismatched root key instead of refusing"
    elif [[ "$(cat "${T7C_PREFIX}/etc/cfgms/secrets.key")" != "a-completely-different-32-byte!!" ]]; then
        fail "test7c: the node's existing root key was modified"
    else
        pass "test7c: a root key that disagrees with the node's existing key is refused, changing nothing"
    fi
else
    fail "test7c: expected a non-zero exit naming the mismatch (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T7C_PREFIX"

# 7d: a real 32-byte random key contains NUL bytes. Routing it through a shell
# variable silently truncates it at the first NUL — the key then measures short,
# compares unequal against the node's existing key, and seals wrong. Observed
# live on cfg-lab, where an actual cluster key measured 31 bytes. This asserts
# the key survives byte-for-byte.
T7D_PREFIX="$(mktemp -d)"
make_mock_controller "$T7D_PREFIX"
T7D_KEY_FILE="$(mktemp)"
printf 'AAAA\x00BBBB\x00CCCCCCCCCCCCCCCCCCCCCC' > "$T7D_KEY_FILE"
if [[ "$(wc -c < "$T7D_KEY_FILE" | tr -d '[:space:]')" != "32" ]]; then
    fail "test7d: fixture key is not 32 bytes — test is invalid"
else
    run_bootstrap_with_key "$T7D_PREFIX" "$(base64 -w0 < "$T7D_KEY_FILE" 2>/dev/null || base64 < "$T7D_KEY_FILE" | tr -d '\n')" \
        "${STD_FLAGS[@]}" --skip-smoke
    if [[ $LAST_EXIT -ne 0 ]]; then
        fail "test7d: a valid 32-byte key containing NUL bytes was rejected (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
    elif ! sealed_payload "${T7D_PREFIX}/etc/cfgms/secrets.key.cred" | cmp -s - "$T7D_KEY_FILE"; then
        fail "test7d: the sealed root key does not match the supplied key byte-for-byte"
    else
        pass "test7d: a 32-byte root key containing NUL bytes is sealed byte-for-byte"
    fi
fi
rm -rf "$T7D_PREFIX"
rm -f "$T7D_KEY_FILE"

# ── Test 8: TPM2 absent — refuse, unless the operator opts in explicitly ──────

# 8a: no usable TPM2 and no opt-in. Sealing must NOT silently fall back to the
# disk-resident host key: that voids the "a stolen disk image yields nothing"
# property with no signal to the operator.
T8A_PREFIX="$(mktemp -d)"
make_mock_controller "$T8A_PREFIX"
LAST_EXIT=0
LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$T8A_PREFIX" \
    CFGMS_STORAGE_DB_PASSWORD="test-pg-password" \
    CFGMS_SESSION_HMAC_KEY="test-session-hmac-key" \
    CFGMS_SECRETS_KEY_B64="dGVzdC1zZWNyZXRzLWtleS0zMi1ieXRlcy1sb25nISE=" \
    OPENBAO_TOKEN="test-vault-token" \
    CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
    CFGMS_BOOTSTRAP_TPM2_PROBE="false" \
    bash "$BOOTSTRAP_SH" "${STD_FLAGS[@]}" --skip-smoke 2>&1)" || LAST_EXIT=$?

if [[ $LAST_EXIT -ne 0 ]] && echo "$LAST_OUTPUT" | grep -q "allow-host-key"; then
    if assert_no_key_material "$T8A_PREFIX" "test8a"; then
        pass "test8a: a node with no usable TPM2 refuses to provision and names --allow-host-key"
    fi
else
    fail "test8a: expected a non-zero exit naming --allow-host-key (exit=${LAST_EXIT} output='${LAST_OUTPUT}')"
fi
rm -rf "$T8A_PREFIX"

# 8b: the same node with the explicit opt-in provisions, warns, and records the
# weaker binding so the cluster's at-rest guarantee stays auditable per node.
T8B_PREFIX="$(mktemp -d)"
make_mock_controller "$T8B_PREFIX"
LAST_EXIT=0
LAST_OUTPUT="$(CFGMS_INSTALL_PREFIX="$T8B_PREFIX" \
    CFGMS_STORAGE_DB_PASSWORD="test-pg-password" \
    CFGMS_SESSION_HMAC_KEY="test-session-hmac-key" \
    CFGMS_SECRETS_KEY_B64="dGVzdC1zZWNyZXRzLWtleS0zMi1ieXRlcy1sb25nISE=" \
    OPENBAO_TOKEN="test-vault-token" \
    CFGMS_SYSTEMD_CREDS_BIN="$FAKE_CREDS" \
    CFGMS_BOOTSTRAP_TPM2_PROBE="false" \
    bash "$BOOTSTRAP_SH" "${STD_FLAGS[@]}" --allow-host-key --skip-smoke 2>&1)" || LAST_EXIT=$?

T8B_PASS=true
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test8b: --allow-host-key run exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
    T8B_PASS=false
else
    if ! echo "$LAST_OUTPUT" | grep -q "stolen disk image"; then
        fail "test8b: --allow-host-key did not warn about the consequence"
        T8B_PASS=false
    fi
    if ! grep -Fxq 'key_mode: host' "${T8B_PREFIX}/etc/cfgms/.bootstrap-record" 2>/dev/null; then
        fail "test8b: bootstrap record does not record key_mode: host"
        T8B_PASS=false
    fi
    if ! grep -Fxq 'with-key=host' "${T8B_PREFIX}/etc/cfgms/secrets.key.cred" 2>/dev/null; then
        fail "test8b: root key was not sealed with --with-key=host"
        T8B_PASS=false
    fi
    if grep -q 'with-key=auto' "${T8B_PREFIX}/etc/cfgms/"*.cred 2>/dev/null; then
        fail "test8b: a credential was sealed with --with-key=auto, which downgrades silently"
        T8B_PASS=false
    fi
fi
[[ "$T8B_PASS" == "true" ]] && pass "test8b: --allow-host-key provisions with a loud warning and records key_mode: host"
rm -rf "$T8B_PREFIX"

# ── Test 9: upgrade path — an existing env-file node migrates in place ────────
#
# This is the shape of the live 3-node cluster before this change: a cleartext
# ha-secrets.env plus a cleartext secrets.key. Re-running the bootstrap has to
# convert that node rather than only serving fresh installs.

T9_PREFIX="$(mktemp -d)"
make_mock_controller "$T9_PREFIX"
mkdir -p "${T9_PREFIX}/etc/cfgms" "${T9_PREFIX}/etc/systemd/system"

# Pre-existing node state, exactly as the previous script left it.
printf 'test-secrets-key-32-bytes-long!!' > "${T9_PREFIX}/etc/cfgms/secrets.key"
cat > "${T9_PREFIX}/etc/cfgms/ha-secrets.env" <<'LEGACY'
CFGMS_STORAGE_DB_PASSWORD=test-pg-password
CFGMS_SESSION_HMAC_KEY=test-session-hmac-key
OPENBAO_TOKEN=test-vault-token
LEGACY
cat > "${T9_PREFIX}/etc/systemd/system/cfgms-controller.service" <<'LEGACY'
[Service]
EnvironmentFile=/etc/cfgms/ha-secrets.env
LoadCredential=cfgms-secrets-key:/etc/cfgms/secrets.key
LEGACY

run_bootstrap "$T9_PREFIX" "${STD_FLAGS[@]}" --skip-smoke

T9_PASS=true
if [[ $LAST_EXIT -ne 0 ]]; then
    fail "test9: migration run exited ${LAST_EXIT} (expected 0); output='${LAST_OUTPUT}'"
    T9_PASS=false
else
    if [[ -e "${T9_PREFIX}/etc/cfgms/ha-secrets.env" ]]; then
        fail "test9: legacy ha-secrets.env survived the migration"
        T9_PASS=false
    fi
    if [[ -e "${T9_PREFIX}/etc/cfgms/secrets.key" ]]; then
        fail "test9: legacy cleartext secrets.key survived the migration"
        T9_PASS=false
    fi
    for cred in secrets.key.cred db-password.cred session-hmac-key.cred openbao-token.cred; do
        if [[ ! -f "${T9_PREFIX}/etc/cfgms/${cred}" ]]; then
            fail "test9: migration did not produce ${cred}"
            T9_PASS=false
        fi
    done
    # The migrated root key must be the node's OWN existing key, not a new one.
    if [[ -f "${T9_PREFIX}/etc/cfgms/secrets.key.cred" ]] && \
       [[ "$(sealed_payload "${T9_PREFIX}/etc/cfgms/secrets.key.cred")" != "test-secrets-key-32-bytes-long!!" ]]; then
        fail "test9: migration sealed a different root key than the node already held"
        T9_PASS=false
    fi
    if grep -q '^EnvironmentFile=' "${T9_PREFIX}/etc/systemd/system/cfgms-controller.service"; then
        fail "test9: migrated unit still carries EnvironmentFile="
        T9_PASS=false
    fi
fi
[[ "$T9_PASS" == "true" ]] && pass "test9: an existing env-file node migrates to sealed credentials in place"
rm -rf "$T9_PREFIX"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
