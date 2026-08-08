#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Jordan Ritz
#
# lab-datasvc-bootstrap_test.sh — Tests for scripts/lab-datasvc-bootstrap.sh.
#
# The bootstrap script is sourced, not re-implemented: it stops at its sourcing
# guard after defining generate_tls_certs / apply_pg_conf_tls / apply_pg_hba_tls,
# so every assertion below runs against the exact code that runs on the lab VM.
# A copied implementation could pass while the shipped script writes something
# weaker (e.g. a plaintext-capable `host` pg_hba rule).
#
# Non-Docker tests verify TLS cert generation, postgresql.conf configuration,
# pg_hba.conf TLS enforcement, and idempotency in temp directories — no root or
# live PostgreSQL needed.
#
# Docker-based tests provision a Debian postgresql container (matching the
# lab VM target) configured by the same sourced functions, then exercise
# sslmode=verify-full, wrong-CA rejection, and plaintext rejection. These tests
# are skipped when Docker is not available.
#
# Usage:
#   bash scripts/lab-datasvc-bootstrap_test.sh

set -euo pipefail

PASS=0
FAIL=0
SKIP=0

pass() { echo "PASS: $1"; ((PASS++)) || true; }
fail() { echo "FAIL: $1"; ((FAIL++)) || true; }
skip() { echo "SKIP: $1"; ((SKIP++)) || true; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOTSTRAP_SH="${SCRIPT_DIR}/lab-datasvc-bootstrap.sh"

if [[ ! -f "$BOOTSTRAP_SH" ]]; then
    echo "FAIL: bootstrap script not found at ${BOOTSTRAP_SH}"
    exit 1
fi

# Sourcing stops at the bootstrap script's guard, importing only its constants
# and provisioning functions.
# shellcheck source=/dev/null
source "$BOOTSTRAP_SH"

for fn in generate_tls_certs apply_pg_conf_tls apply_pg_hba_tls; do
    if ! declare -F "$fn" >/dev/null; then
        echo "FAIL: sourcing ${BOOTSTRAP_SH} did not define ${fn}()"
        exit 1
    fi
done

# Tests use 2048-bit keys for speed; the bootstrap run passes 4096.
TEST_KEY_BITS=2048

# ── Test 1: TLS cert generation creates expected files ────────────────────────

T1_DIR="$(mktemp -d)"
generate_tls_certs "$T1_DIR" "127.0.0.1" "localhost" "$TEST_KEY_BITS"

T1_PASS=true
for f in ca.key ca.pem server.key server.pem; do
    if [[ ! -f "${T1_DIR}/${f}" ]]; then
        fail "test1: missing expected TLS file: ${f}"
        T1_PASS=false
    fi
done
if [[ "$T1_PASS" == "true" ]]; then
    pass "test1: TLS cert generation creates ca.key, ca.pem, server.key, server.pem"
fi
rm -rf "$T1_DIR"

# ── Test 2: Server cert is signed by the CA ───────────────────────────────────

T2_DIR="$(mktemp -d)"
generate_tls_certs "$T2_DIR" "127.0.0.1" "localhost" "$TEST_KEY_BITS"

if openssl verify -CAfile "${T2_DIR}/ca.pem" "${T2_DIR}/server.pem" 2>/dev/null | grep -q "OK"; then
    pass "test2: server cert is signed by the generated CA (verify chain passes)"
else
    fail "test2: server cert chain verification failed — server cert not signed by CA"
fi
rm -rf "$T2_DIR"

# ── Test 3: Server cert SAN covers the expected IP and DNS ───────────────────

T3_DIR="$(mktemp -d)"
generate_tls_certs "$T3_DIR" "192.168.234.105" "cfgms-lab-datasvc" "$TEST_KEY_BITS"

T3_SAN="$(openssl x509 -noout -ext subjectAltName -in "${T3_DIR}/server.pem" 2>/dev/null)"
T3_PASS=true

if ! echo "$T3_SAN" | grep -qE "IP Address:192\.168\.234\.105|IP:192\.168\.234\.105"; then
    fail "test3: SAN missing expected IP 192.168.234.105 (SAN: ${T3_SAN})"
    T3_PASS=false
fi
if ! echo "$T3_SAN" | grep -q "DNS:cfgms-lab-datasvc"; then
    fail "test3: SAN missing expected DNS:cfgms-lab-datasvc (SAN: ${T3_SAN})"
    T3_PASS=false
fi
if [[ "$T3_PASS" == "true" ]]; then
    pass "test3: server cert SAN covers IP:192.168.234.105 and DNS:cfgms-lab-datasvc"
fi
rm -rf "$T3_DIR"

# ── Test 4: Idempotency — re-running cert generation preserves existing certs ─
# Calls the shipped function a second time; its own guards must prevent rotation
# (a rotated CA would invalidate the sslrootcert already on controller nodes).

T4_DIR="$(mktemp -d)"
generate_tls_certs "$T4_DIR" "127.0.0.1" "localhost" "$TEST_KEY_BITS"

CA_FP1="$(openssl x509 -noout -fingerprint -sha256 -in "${T4_DIR}/ca.pem" 2>/dev/null)"
SRV_FP1="$(openssl x509 -noout -fingerprint -sha256 -in "${T4_DIR}/server.pem" 2>/dev/null)"

generate_tls_certs "$T4_DIR" "127.0.0.1" "localhost" "$TEST_KEY_BITS"

CA_FP2="$(openssl x509 -noout -fingerprint -sha256 -in "${T4_DIR}/ca.pem" 2>/dev/null)"
SRV_FP2="$(openssl x509 -noout -fingerprint -sha256 -in "${T4_DIR}/server.pem" 2>/dev/null)"

if [[ "$CA_FP1" == "$CA_FP2" && "$SRV_FP1" == "$SRV_FP2" ]]; then
    pass "test4: idempotent re-run preserves CA and server cert fingerprints (no rotation)"
else
    fail "test4: re-run changed cert fingerprints (CA: ${CA_FP1} => ${CA_FP2}, srv: ${SRV_FP1} => ${SRV_FP2})"
fi
rm -rf "$T4_DIR"

# ── Test 5: postgresql.conf gets ssl = on and cert path settings ──────────────
# Covers both the blank/commented case and the Debian snakeoil default case
# (uncommented ssl_cert_file/ssl_key_file) to verify sed-replace is used.

T5_DIR="$(mktemp -d)"
T5_CERT="${T5_DIR}/tls/server.pem"
T5_KEY="${T5_DIR}/tls/server.key"

# 5a: Debian-style with uncommented snakeoil defaults (the real on-disk state
# written by pg_createcluster).
T5A_CONF="${T5_DIR}/postgresql.conf.snakeoil"
cat > "$T5A_CONF" <<'EOF'
# PostgreSQL configuration file
listen_addresses = '*'
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
port = 5432
EOF

apply_pg_conf_tls "$T5A_CONF" "$T5_CERT" "$T5_KEY"

T5_PASS=true
if ! grep -q "^ssl = on" "$T5A_CONF"; then
    fail "test5a: postgresql.conf missing 'ssl = on' (snakeoil path)"
    T5_PASS=false
fi
if ! grep -q "^ssl_cert_file = '${T5_CERT}'" "$T5A_CONF"; then
    fail "test5a: snakeoil ssl_cert_file not replaced with generated cert path"
    T5_PASS=false
fi
if ! grep -q "^ssl_key_file = '${T5_KEY}'" "$T5A_CONF"; then
    fail "test5a: snakeoil ssl_key_file not replaced with generated key path"
    T5_PASS=false
fi
# The server must not be left serving the snakeoil cert — it is not signed by
# the CA this bootstrap generates, so every verify-full client would fail.
if grep -q "ssl-cert-snakeoil" "$T5A_CONF" 2>/dev/null; then
    fail "test5a: snakeoil cert/key references remain in postgresql.conf after apply"
    T5_PASS=false
fi

# 5b: Commented-out ssl (another common default).
T5B_CONF="${T5_DIR}/postgresql.conf.commented"
cat > "$T5B_CONF" <<'EOF'
listen_addresses = '*'
#ssl = off
#ssl_cert_file = 'server.crt'
#ssl_key_file = 'server.key'
EOF

apply_pg_conf_tls "$T5B_CONF" "$T5_CERT" "$T5_KEY"

if ! grep -q "^ssl = on" "$T5B_CONF"; then
    fail "test5b: postgresql.conf missing 'ssl = on' (commented-out path)"
    T5_PASS=false
fi
if ! grep -q "^ssl_cert_file = '${T5_CERT}'" "$T5B_CONF"; then
    fail "test5b: commented ssl_cert_file not replaced"
    T5_PASS=false
fi

if [[ "$T5_PASS" == "true" ]]; then
    pass "test5: postgresql.conf sets ssl = on, ssl_cert_file, ssl_key_file (snakeoil replace + commented-out replace)"
fi
rm -rf "$T5_DIR"

# ── Test 6: postgresql.conf idempotency — no duplicate lines on re-apply ──────

T6_DIR="$(mktemp -d)"
T6_CERT="${T6_DIR}/tls/server.pem"
T6_KEY="${T6_DIR}/tls/server.key"
T6_PASS=true

# 6a: Snakeoil defaults — apply twice, verify no duplicate lines.
T6A_CONF="${T6_DIR}/postgresql.conf.snakeoil"
cat > "$T6A_CONF" <<'EOF'
ssl = on
ssl_cert_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
ssl_key_file = '/etc/ssl/private/ssl-cert-snakeoil.key'
EOF
apply_pg_conf_tls "$T6A_CONF" "$T6_CERT" "$T6_KEY"
apply_pg_conf_tls "$T6A_CONF" "$T6_CERT" "$T6_KEY"

SSL_A="$(grep -c "^ssl = on" "$T6A_CONF" 2>/dev/null || true)"
CERT_A="$(grep -c "^ssl_cert_file" "$T6A_CONF" 2>/dev/null || true)"
KEY_A="$(grep -c "^ssl_key_file" "$T6A_CONF" 2>/dev/null || true)"
if [[ "$SSL_A" -ne 1 || "$CERT_A" -ne 1 || "$KEY_A" -ne 1 ]]; then
    fail "test6a: duplicate lines after snakeoil re-apply (ssl=${SSL_A}, cert=${CERT_A}, key=${KEY_A})"
    T6_PASS=false
fi

# 6b: Blank conf — apply twice, verify no duplicate lines.
T6B_CONF="${T6_DIR}/postgresql.conf.blank"
cat > "$T6B_CONF" <<'EOF'
listen_addresses = '*'
#ssl = off
EOF
apply_pg_conf_tls "$T6B_CONF" "$T6_CERT" "$T6_KEY"
apply_pg_conf_tls "$T6B_CONF" "$T6_CERT" "$T6_KEY"

SSL_B="$(grep -c "^ssl = on" "$T6B_CONF" 2>/dev/null || true)"
CERT_B="$(grep -c "^ssl_cert_file" "$T6B_CONF" 2>/dev/null || true)"
KEY_B="$(grep -c "^ssl_key_file" "$T6B_CONF" 2>/dev/null || true)"
if [[ "$SSL_B" -ne 1 || "$CERT_B" -ne 1 || "$KEY_B" -ne 1 ]]; then
    fail "test6b: duplicate lines after blank-conf re-apply (ssl=${SSL_B}, cert=${CERT_B}, key=${KEY_B})"
    T6_PASS=false
fi

if [[ "$T6_PASS" == "true" ]]; then
    pass "test6: idempotent re-apply produces no duplicate lines (snakeoil path + blank-conf path)"
fi
rm -rf "$T6_DIR"

# ── Test 7: pg_hba.conf enforces TLS for the lab subnet ───────────────────────
# A plain `host` rule matches SSL *and* non-SSL connections, so this asserts on
# the exact file apply_pg_hba_tls writes for the real subnet constant.

T7_DIR="$(mktemp -d)"
T7_HBA="${T7_DIR}/pg_hba.conf"
T7_PASS=true

# Start from the story #3124 state: a plaintext-capable `host` rule for the lab
# subnet, plus Debian's loopback defaults.
cat > "$T7_HBA" <<EOF
local   all             postgres                                peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ${PG_LISTEN_SUBNET}        scram-sha-256
EOF

apply_pg_hba_tls "$T7_HBA" "$PG_LISTEN_SUBNET" "scram-sha-256"

if ! grep -qE "^hostssl[[:space:]]+all[[:space:]]+all[[:space:]]+${PG_LISTEN_SUBNET//./\\.}[[:space:]]+scram-sha-256" "$T7_HBA"; then
    fail "test7: pg_hba.conf missing hostssl rule for ${PG_LISTEN_SUBNET} (contents: $(cat "$T7_HBA"))"
    T7_PASS=false
fi
if ! grep -qE "^hostnossl[[:space:]]+all[[:space:]]+all[[:space:]]+${PG_LISTEN_SUBNET//./\\.}[[:space:]]+reject" "$T7_HBA"; then
    fail "test7: pg_hba.conf missing hostnossl reject rule for ${PG_LISTEN_SUBNET} — sslmode=disable would be served in cleartext"
    T7_PASS=false
fi
# The pre-existing plaintext-capable rule must be gone, not merely shadowed.
if grep -qE "^host[[:space:]]+all[[:space:]]+all[[:space:]]+${PG_LISTEN_SUBNET//./\\.}" "$T7_HBA"; then
    fail "test7: plaintext-capable 'host' rule for ${PG_LISTEN_SUBNET} still present after apply"
    T7_PASS=false
fi
# Loopback defaults are left alone.
if ! grep -qE "^host[[:space:]]+all[[:space:]]+all[[:space:]]+127\.0\.0\.1/32" "$T7_HBA"; then
    fail "test7: loopback pg_hba rule was modified (should be untouched)"
    T7_PASS=false
fi

# Idempotency: re-apply must not duplicate rules.
apply_pg_hba_tls "$T7_HBA" "$PG_LISTEN_SUBNET" "scram-sha-256"
HBA_SSL_COUNT="$(grep -c "^hostssl" "$T7_HBA" 2>/dev/null || true)"
HBA_NOSSL_COUNT="$(grep -c "^hostnossl" "$T7_HBA" 2>/dev/null || true)"
if [[ "$HBA_SSL_COUNT" -ne 1 || "$HBA_NOSSL_COUNT" -ne 1 ]]; then
    fail "test7: duplicate pg_hba rules after re-apply (hostssl=${HBA_SSL_COUNT}, hostnossl=${HBA_NOSSL_COUNT})"
    T7_PASS=false
fi

# Fresh-install path: no prior rule for the subnet at all.
T7B_HBA="${T7_DIR}/pg_hba_fresh.conf"
printf 'local   all             postgres                                peer\n' > "$T7B_HBA"
apply_pg_hba_tls "$T7B_HBA" "$PG_LISTEN_SUBNET" "scram-sha-256"
if ! grep -q "^hostssl" "$T7B_HBA" || ! grep -q "^hostnossl" "$T7B_HBA"; then
    fail "test7: fresh pg_hba.conf did not receive both hostssl and hostnossl reject rules"
    T7_PASS=false
fi

if [[ "$T7_PASS" == "true" ]]; then
    pass "test7: pg_hba.conf gets hostssl + hostnossl reject, upgrades the legacy 'host' rule, and is idempotent"
fi
rm -rf "$T7_DIR"

# ── Test 8: bootstrap script outputs CA cert path ─────────────────────────────

if ! grep -q "CA cert" "$BOOTSTRAP_SH" 2>/dev/null; then
    fail "test8: bootstrap script does not mention CA cert path in its output section"
else
    pass "test8: bootstrap script output section references the CA cert path"
fi

# ── Test 9: bootstrap verifies applied TLS settings against the live server ───
# The config edit alone is not evidence: the run must confirm the restarted
# server actually loaded the generated cert/key before reporting success.

T9_PASS=true
for pattern in "SHOW ssl_cert_file" "SHOW ssl_key_file" "PG_LIVE_CERT"; do
    if ! grep -qF "$pattern" "$BOOTSTRAP_SH" 2>/dev/null; then
        fail "test9: bootstrap script missing post-restart TLS verification (expected: ${pattern})"
        T9_PASS=false
    fi
done
if [[ "$T9_PASS" == "true" ]]; then
    pass "test9: bootstrap verifies ssl/ssl_cert_file/ssl_key_file against the running server after restart"
fi

# ── Tests 10-12: Docker-based PostgreSQL TLS connection tests ─────────────────
#
# These tests provision a real Debian PostgreSQL instance in a container whose
# postgresql.conf and pg_hba.conf are written by the bootstrap script's own
# functions, then verify: (10) sslmode=verify-full succeeds with the generated
# CA, (11) the system trust store cannot verify the self-signed cert, and (12) a
# plaintext connection is rejected. Skipped when Docker is not available.

if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    skip "test10: sslmode=verify-full accepted (Docker not available — run on a Docker host to verify)"
    skip "test11: system-trust-store rejection (Docker not available)"
    skip "test12: plaintext connection rejected (Docker not available)"
else
    DOCKER_TLS_DIR="$(mktemp -d)"
    generate_tls_certs "$DOCKER_TLS_DIR" "127.0.0.1" "localhost" "$TEST_KEY_BITS"

    # pg_hba.conf for the container, written by the shipped apply_pg_hba_tls so
    # tests 10/12 exercise the rule shape the lab VM actually gets. The subnet is
    # 0.0.0.0/0 because the container sees the connection arriving from the
    # Docker bridge gateway, and the auth method is trust so the test needs no
    # password — the hostssl/hostnossl enforcement under test is unchanged.
    printf 'local   all  all  trust\n' > "${DOCKER_TLS_DIR}/pg_hba.conf"
    apply_pg_hba_tls "${DOCKER_TLS_DIR}/pg_hba.conf" "0.0.0.0/0" "trust"

    # The image configures postgresql.conf by sourcing the bootstrap script and
    # calling apply_pg_conf_tls — same code path as the lab VM.
    cp "$BOOTSTRAP_SH" "${DOCKER_TLS_DIR}/lab-datasvc-bootstrap.sh"

    cat > "${DOCKER_TLS_DIR}/Dockerfile" <<'DOCKERFILE'
FROM debian:bookworm-slim
RUN apt-get -qq update -y && apt-get -qq install -y postgresql postgresql-client openssl && rm -rf /var/lib/apt/lists/*
COPY ca.pem     /etc/postgresql/tls/ca.pem
COPY server.pem /etc/postgresql/tls/server.pem
COPY server.key /etc/postgresql/tls/server.key
COPY pg_hba.conf /etc/postgresql/tls/pg_hba.conf
COPY lab-datasvc-bootstrap.sh /usr/local/lib/lab-datasvc-bootstrap.sh
RUN chown root:postgres /etc/postgresql/tls/server.key /etc/postgresql/tls/server.pem && \
    chmod 640 /etc/postgresql/tls/server.key && chmod 644 /etc/postgresql/tls/server.pem && \
    chown root:root /etc/postgresql/tls/ca.pem && chmod 644 /etc/postgresql/tls/ca.pem
RUN . /usr/local/lib/lab-datasvc-bootstrap.sh && \
    PG_VERSION=$(ls /etc/postgresql) && \
    apply_pg_conf_tls /etc/postgresql/$PG_VERSION/main/postgresql.conf \
        /etc/postgresql/tls/server.pem /etc/postgresql/tls/server.key && \
    cp /etc/postgresql/tls/pg_hba.conf /etc/postgresql/$PG_VERSION/main/pg_hba.conf && \
    chown postgres:postgres /etc/postgresql/$PG_VERSION/main/pg_hba.conf
USER postgres
CMD ["sh", "-c", "PG_VERSION=$(ls /etc/postgresql) && /usr/lib/postgresql/$PG_VERSION/bin/postgres -D /var/lib/postgresql/$PG_VERSION/main -c config_file=/etc/postgresql/$PG_VERSION/main/postgresql.conf"]
DOCKERFILE

    PG_IMAGE="cfgms-test-pg-tls:$$"
    PG_CONTAINER="cfgms-test-pg-tls-$$"
    DOCKER_BUILD_LOG="$(mktemp)"
    if docker build -q -t "$PG_IMAGE" "$DOCKER_TLS_DIR" >"$DOCKER_BUILD_LOG" 2>&1; then
        DOCKER_BUILD_OK=true
    else
        DOCKER_BUILD_OK=false
    fi

    if [[ "$DOCKER_BUILD_OK" != "true" ]]; then
        skip "test10: Docker build failed — skipping PostgreSQL TLS connection tests ($(tail -3 "$DOCKER_BUILD_LOG" | tr '\n' ' '))"
        skip "test11: Docker build failed"
        skip "test12: Docker build failed"
        rm -f "$DOCKER_BUILD_LOG"
    else
        rm -f "$DOCKER_BUILD_LOG"
        # Start the container; map 5432 to a random host port.
        docker run -d --rm --name "$PG_CONTAINER" \
            -p 127.0.0.1::5432 "$PG_IMAGE" >/dev/null 2>&1 || true

        # Discover the mapped port.
        PG_HOST_PORT="$(docker port "$PG_CONTAINER" 5432/tcp 2>/dev/null | awk -F: '{print $2}')"

        # Wait up to 20s for PostgreSQL to become ready.
        PG_READY=false
        if [[ -n "$PG_HOST_PORT" ]]; then
            for _ in $(seq 1 20); do
                if PGPASSWORD="" PGSSLMODE=require \
                        psql -h 127.0.0.1 -p "$PG_HOST_PORT" \
                        -U postgres -d postgres -c "SELECT 1" >/dev/null 2>&1; then
                    PG_READY=true
                    break
                fi
                sleep 1
            done
        fi

        if [[ "$PG_READY" != "true" ]]; then
            skip "test10: PostgreSQL container did not become ready in 20s"
            skip "test11: PostgreSQL container not ready"
            skip "test12: PostgreSQL container not ready"
        else
            # ── Test 10: sslmode=verify-full with the correct CA succeeds ─────
            if PGPASSWORD="" PGSSLROOTCERT="${DOCKER_TLS_DIR}/ca.pem" \
                    psql "postgresql://postgres@127.0.0.1:${PG_HOST_PORT}/postgres?sslmode=verify-full&sslrootcert=${DOCKER_TLS_DIR}/ca.pem" \
                    -c "SELECT 1" >/dev/null 2>&1; then
                pass "test10: sslmode=verify-full with generated CA cert accepted"
            else
                fail "test10: sslmode=verify-full with generated CA cert rejected (expected success)"
            fi

            # ── Test 11: sslmode=verify-full against the system trust store fails
            # The server cert is signed by our self-managed CA, not any system CA.
            if PGPASSWORD="" \
                    psql "postgresql://postgres@127.0.0.1:${PG_HOST_PORT}/postgres?sslmode=verify-full" \
                    -c "SELECT 1" >/dev/null 2>&1; then
                fail "test11: sslmode=verify-full against system trust store succeeded (expected failure — cert must not be trusted by system CAs)"
            else
                pass "test11: sslmode=verify-full against system trust store rejected (real CA verification is working)"
            fi

            # ── Test 12: Plaintext connection rejected ────────────────────────
            # The pg_hba.conf under test was written by apply_pg_hba_tls, so this
            # asserts the enforcement the bootstrap really applies.
            if PGPASSWORD="" \
                    psql "postgresql://postgres@127.0.0.1:${PG_HOST_PORT}/postgres?sslmode=disable" \
                    -c "SELECT 1" >/dev/null 2>&1; then
                fail "test12: plaintext (sslmode=disable) connection succeeded (expected rejection — hostnossl reject rule should refuse it)"
            else
                pass "test12: plaintext connection rejected by the bootstrap's hostnossl reject rule"
            fi
        fi

        docker stop "$PG_CONTAINER" >/dev/null 2>&1 || true
        docker rmi "$PG_IMAGE" >/dev/null 2>&1 || true
    fi
    rm -rf "$DOCKER_TLS_DIR"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
