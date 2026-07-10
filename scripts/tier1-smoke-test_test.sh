#!/bin/bash
# Fixture-based tests for tier1-smoke-test.sh.
#
# Starts a stub HTTPS server (Python ssl) with generated test certs to cover
# both the all-pass path and several failure modes without a real controller.
#
# Dependencies: bash >=4, openssl, python3, go (to build cfg for the health check)
#
# Exit codes: 0 = all tests passed, 1 = any test failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SMOKE="$SCRIPT_DIR/tier1-smoke-test.sh"

# Build the cfg client the smoke test uses for its health check (#2458 RC2).
# cfg does mTLS via crypto/tls (PEM, cross-platform) — the whole point is to
# avoid curl+Schannel on Windows. `go build -o <dir>/` names the binary per-OS
# (cfg / cfg.exe). The smoke test picks it up via CFGMS_CFG_BIN.
CFG_BUILD_DIR="$(mktemp -d)"
CFG_BUILD_ERR=""
if command -v go >/dev/null 2>&1; then
  # Capture the build error rather than discarding it, so a real compile failure
  # (go present but build broken) is surfaced below instead of the misleading
  # "no go/cfg on PATH" message.
  CFG_BUILD_ERR=$( cd "$SCRIPT_DIR/.." && go build -o "$CFG_BUILD_DIR/" ./cmd/cfg 2>&1 ) || true
fi
if [[ -x "$CFG_BUILD_DIR/cfg" ]]; then
  export CFGMS_CFG_BIN="$CFG_BUILD_DIR/cfg"
elif [[ -x "$CFG_BUILD_DIR/cfg.exe" ]]; then
  export CFGMS_CFG_BIN="$CFG_BUILD_DIR/cfg.exe"
elif command -v cfg >/dev/null 2>&1; then
  export CFGMS_CFG_BIN="cfg"
else
  echo "ERROR: could not build or find the cfg client (need 'go' or 'cfg' on PATH)" >&2
  [[ -n "$CFG_BUILD_ERR" ]] && echo "go build error was:" >&2 && echo "$CFG_BUILD_ERR" >&2
  exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

_pass() {
  echo -e "${GREEN}[PASS]${NC} $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

_fail() {
  echo -e "${RED}[FAIL]${NC} $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

# ---------------------------------------------------------------------------
# Cert generation
# ---------------------------------------------------------------------------
_setup_certs() {
  local d="$1"

  # On Git-Bash/MSYS the runtime auto-converts POSIX-looking arguments to Windows
  # paths before handing them to the native openssl.exe. That corrupts the leading
  # '/' of openssl's -subj value ("/CN=Test CA" becomes
  # "C:/Program Files/Git/CN=Test CA" -> "subject name is expected to be in the
  # format /type0=value0/..."). Excluding only /CN= arguments keeps the -subj DN
  # intact while still letting real path arguments (keys, certs, extfiles) convert
  # normally. The variable is ignored on Linux/macOS, so setting it here is safe on
  # every host.
  local MSYS2_ARG_CONV_EXCL="/CN="
  export MSYS2_ARG_CONV_EXCL

  # Extension files are written to the scratch dir instead of process substitution
  # (-extfile <(printf ...)), which resolves to /proc/<pid>/fd/NN — unavailable in
  # the MSYS shell ("Can't open /proc/<pid>/fd/63 for reading").
  printf "subjectAltName=IP:127.0.0.1,DNS:localhost\n" > "$d/server.ext"
  printf "extendedKeyUsage=clientAuth\n" > "$d/client.ext"

  # CA
  # The CA cert MUST carry basicConstraints CA:TRUE + keyUsage keyCertSign, or a
  # strict verifier (Python's ssl on OpenSSL 3.x, used by the tenant check) rejects
  # the chain with "CA cert does not include key usage extension". Go's crypto/tls
  # (the cfg health check) and old curl accept a plain self-signed cert leniently,
  # but the test CA must be a real CA for every client. (#2458)
  openssl req -x509 -newkey rsa:2048 -keyout "$d/ca.key" -out "$d/ca.crt" \
    -days 1 -nodes -subj "/CN=Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

  # Server cert with Subject Alternative Name so curl trusts 127.0.0.1
  openssl req -newkey rsa:2048 -keyout "$d/server.key" -out "$d/server.csr" \
    -nodes -subj "/CN=127.0.0.1" 2>/dev/null
  openssl x509 -req -in "$d/server.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" \
    -CAcreateserial -out "$d/server.crt" -days 1 \
    -extfile "$d/server.ext" 2>/dev/null

  # Client cert (mTLS)
  openssl req -newkey rsa:2048 -keyout "$d/client.key" -out "$d/client.csr" \
    -nodes -subj "/CN=admin" 2>/dev/null
  openssl x509 -req -in "$d/client.csr" -CA "$d/ca.crt" -CAkey "$d/ca.key" \
    -CAcreateserial -out "$d/client.crt" -days 1 \
    -extfile "$d/client.ext" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Bundle YAML generation (no pyyaml needed: produces Go yaml.v3 block-literal format)
# ---------------------------------------------------------------------------
_make_bundle() {
  local d="$1"
  local port="$2"
  D="$d" PORT="$port" python3 - <<'PYEOF'
import os

def block(s):
    """Format a string as a YAML block literal (|) with 4-space indent."""
    lines = s.rstrip('\n').split('\n')
    return '|\n' + ''.join('    ' + l + '\n' for l in lines)

d    = os.environ['D']
port = os.environ['PORT']

cert = open(d + '/client.crt').read()
key  = open(d + '/client.key').read()
ca   = open(d + '/ca.crt').read()

yaml_text = (
    'cert_pem: '      + block(cert) +
    'key_pem: '       + block(key) +
    'ca_pem: '        + block(ca) +
    'controller_url: https://127.0.0.1:' + port + '\n' +
    'audit_subject: ""\n' +
    'cert_serial: "01"\n' +
    'cert_fingerprint: test\n'
)
with open(d + '/bundle.yaml', 'w') as f:
    f.write(yaml_text)
PYEOF
}

# Same as _make_bundle but uses a deliberately wrong controller_url.
_make_bundle_bad_url() {
  local d="$1"
  D="$d" python3 - <<'PYEOF'
import os

def block(s):
    lines = s.rstrip('\n').split('\n')
    return '|\n' + ''.join('    ' + l + '\n' for l in lines)

d = os.environ['D']

cert = open(d + '/client.crt').read()
key  = open(d + '/client.key').read()
ca   = open(d + '/ca.crt').read()

yaml_text = (
    'cert_pem: '      + block(cert) +
    'key_pem: '       + block(key) +
    'ca_pem: '        + block(ca) +
    'controller_url: https://127.0.0.1:9\n' +
    'audit_subject: ""\n' +
    'cert_serial: "01"\n' +
    'cert_fingerprint: test\n'
)
with open(d + '/bundle_bad_url.yaml', 'w') as f:
    f.write(yaml_text)
PYEOF
}

# ---------------------------------------------------------------------------
# Stub HTTPS server (Python ssl + http.server, no pyyaml dependency)
# ---------------------------------------------------------------------------
_write_stub_server() {
  local path="$1"
  cat > "$path" << 'PYEOF'
import ssl, http.server, json, os

MODE    = os.environ.get('STUB_MODE', 'all-pass')
READY_F = os.environ['STUB_READY_FILE']
PORT_F  = os.environ['STUB_PORT_FILE']

TENANTS = {
    'all-pass':           ['team-root', 'agent-test', 'infra-hyperv'],
    'health-fail':        ['team-root', 'agent-test', 'infra-hyperv'],
    'missing-team-root':  ['agent-test', 'infra-hyperv'],
}
present = TENANTS.get(MODE, TENANTS['all-pass'])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if self.path in ('/api/v1/health', '/api/v1/health/detailed'):
                # /health/detailed is what `cfg controller status` requests; both
                # paths mirror the same healthy/unhealthy behavior.
                if MODE == 'health-fail':
                    self.send_response(503)
                    self.end_headers()
                    self.wfile.write(b'{"status":"unhealthy"}')
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"status":"healthy"}')
            elif self.path.startswith('/api/v1/tenants/'):
                tid = self.path.rsplit('/', 1)[-1]
                if tid in present:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'id': tid}).encode())
                else:
                    self.send_response(404)
                    self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()
        except Exception:
            pass

    def log_message(self, *args):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ['STUB_CRT'], os.environ['STUB_KEY'])
ctx.verify_mode = ssl.CERT_REQUIRED
ctx.load_verify_locations(os.environ['STUB_CA'])

httpd = http.server.HTTPServer(('127.0.0.1', 0), Handler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

port = httpd.server_address[1]
with open(PORT_F, 'w') as f:
    f.write(str(port))
with open(READY_F, 'w') as f:
    f.write('ready')

httpd.serve_forever()
PYEOF
}

# ---------------------------------------------------------------------------
# Server lifecycle helpers
# ---------------------------------------------------------------------------
SERVER_PID=""
SERVER_PORT=""

_start_server() {
  local mode="$1"
  local d="$2"

  rm -f "$d/ready" "$d/port"

  STUB_MODE="$mode" \
  STUB_CRT="$d/server.crt" \
  STUB_KEY="$d/server.key" \
  STUB_CA="$d/ca.crt" \
  STUB_READY_FILE="$d/ready" \
  STUB_PORT_FILE="$d/port" \
    python3 "$d/stub_server.py" &
  SERVER_PID=$!

  # Wait up to 5 s for ready signal
  local waited=0
  while [[ ! -f "$d/ready" && $waited -lt 50 ]]; do
    sleep 0.1
    waited=$((waited + 1))
  done

  if [[ ! -f "$d/ready" ]]; then
    _fail "stub server ($mode): did not become ready within 5 s"
    kill "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    SERVER_PORT=""
    return 1
  fi

  SERVER_PORT=$(cat "$d/port")
}

_stop_server() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
  fi
  SERVER_PORT=""
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

test_syntax() {
  if bash -n "$SMOKE" 2>/dev/null; then
    _pass "syntax: tier1-smoke-test.sh has valid bash syntax"
  else
    _fail "syntax: tier1-smoke-test.sh has a syntax error"
  fi
}

test_bundle_missing() {
  local out="" rc=0
  out=$(bash "$SMOKE" --bundle "/nonexistent/path/bundle.yaml" 2>&1) || rc=$?

  if [[ $rc -eq 1 ]]; then
    _pass "bundle-missing: exits 1 when bundle file does not exist"
  else
    _fail "bundle-missing: expected exit 1, got $rc"
  fi

  if grep -q '\[FAIL\].*bundle' <<< "$out"; then
    _pass "bundle-missing: output contains [FAIL] bundle line"
  else
    _fail "bundle-missing: expected [FAIL] bundle line — output: $out"
  fi
}

test_bundle_malformed() {
  local d="$TMPDIR_ROOT/malformed"
  mkdir -p "$d"

  # A file that exists but has cert field pointing to obviously invalid PEM
  printf 'cert_pem: "not-a-cert"\nkey_pem: ""\nca_pem: ""\ncontroller_url: https://127.0.0.1:9\n' \
    > "$d/malformed.yaml"

  local out="" rc=0
  out=$(bash "$SMOKE" --bundle "$d/malformed.yaml" 2>&1) || rc=$?

  if [[ $rc -eq 1 ]]; then
    _pass "bundle-malformed: exits 1 when required cert fields are empty"
  else
    _fail "bundle-malformed: expected exit 1, got $rc — output: $out"
  fi

  if grep -q '\[FAIL\].*bundle' <<< "$out"; then
    _pass "bundle-malformed: output contains [FAIL] bundle-load line"
  else
    _fail "bundle-malformed: expected [FAIL] bundle-load line — output: $out"
  fi
}

test_bundle_missing_controller_url() {
  local d="$TMPDIR_ROOT/no-controller-url"
  mkdir -p "$d"
  _setup_certs "$d"

  # Bundle with valid certs but no controller_url field
  D="$d" python3 - <<'PYEOF'
import os

def block(s):
    lines = s.rstrip('\n').split('\n')
    return '|\n' + ''.join('    ' + l + '\n' for l in lines)

d = os.environ['D']
cert = open(d + '/client.crt').read()
key  = open(d + '/client.key').read()
ca   = open(d + '/ca.crt').read()

# Intentionally omit controller_url
yaml_text = (
    'cert_pem: '  + block(cert) +
    'key_pem: '   + block(key) +
    'ca_pem: '    + block(ca) +
    'cert_serial: "01"\n' +
    'cert_fingerprint: test\n'
)
with open(d + '/bundle_no_url.yaml', 'w') as f:
    f.write(yaml_text)
PYEOF

  local out="" rc=0
  out=$(bash "$SMOKE" --bundle "$d/bundle_no_url.yaml" 2>&1) || rc=$?

  if [[ $rc -eq 1 ]]; then
    _pass "bundle-no-url: exits 1 when controller_url absent and --controller-url not passed"
  else
    _fail "bundle-no-url: expected exit 1, got $rc — output: $out"
  fi

  if grep -q '\[FAIL\].*bundle-load.*controller_url' <<< "$out"; then
    _pass "bundle-no-url: output contains [FAIL] bundle-load controller_url line"
  else
    _fail "bundle-no-url: expected [FAIL] bundle-load controller_url line — output: $out"
  fi
}

test_all_pass() {
  local d="$TMPDIR_ROOT/all-pass"
  mkdir -p "$d"
  _setup_certs "$d"
  _write_stub_server "$d/stub_server.py"
  _start_server "all-pass" "$d" || return

  _make_bundle "$d" "$SERVER_PORT"

  local out="" rc=0
  out=$(bash "$SMOKE" --bundle "$d/bundle.yaml" 2>&1) || rc=$?
  _stop_server

  if [[ $rc -eq 0 ]]; then
    _pass "all-pass: exits 0 when all checks succeed"
  else
    _fail "all-pass: expected exit 0, got $rc — output: $out"
    return
  fi

  local pass_lines
  pass_lines=$(grep -c '^\[PASS\]' <<< "$out" 2>/dev/null) || pass_lines=0
  if [[ "$pass_lines" -eq 4 ]]; then
    _pass "all-pass: output contains 4 [PASS] lines"
  else
    _fail "all-pass: expected 4 [PASS] lines, got $pass_lines — output: $out"
  fi

  local fail_lines
  fail_lines=$(grep -c '^\[FAIL\]' <<< "$out" 2>/dev/null) || fail_lines=0
  if [[ "$fail_lines" -eq 0 ]]; then
    _pass "all-pass: output contains 0 [FAIL] lines"
  else
    _fail "all-pass: expected 0 [FAIL] lines, got $fail_lines — output: $out"
  fi

  if grep -q '^Result: 4 passed, 0 failed' <<< "$out"; then
    _pass "all-pass: summary line correct"
  else
    _fail "all-pass: missing or wrong summary line — output: $out"
  fi
}

test_health_fail() {
  local d="$TMPDIR_ROOT/health-fail"
  mkdir -p "$d"
  _setup_certs "$d"
  _write_stub_server "$d/stub_server.py"
  _start_server "health-fail" "$d" || return

  _make_bundle "$d" "$SERVER_PORT"

  local out="" rc=0
  out=$(bash "$SMOKE" --bundle "$d/bundle.yaml" 2>&1) || rc=$?
  _stop_server

  if [[ $rc -eq 1 ]]; then
    _pass "health-fail: exits 1 when health check fails"
  else
    _fail "health-fail: expected exit 1, got $rc — output: $out"
  fi

  if grep -q '^\[FAIL\] health:' <<< "$out"; then
    _pass "health-fail: [FAIL] line present for health check"
  else
    _fail "health-fail: missing [FAIL] health line — output: $out"
  fi

  # Tenant checks must still run even after health failure (3 [PASS] lines expected)
  local pass_lines
  pass_lines=$(grep -c '^\[PASS\]' <<< "$out" 2>/dev/null) || pass_lines=0
  if [[ "$pass_lines" -eq 3 ]]; then
    _pass "health-fail: tenant checks still run (3 [PASS] tenant lines)"
  else
    _fail "health-fail: expected 3 [PASS] tenant lines, got $pass_lines — output: $out"
  fi
}

test_missing_tenant() {
  local d="$TMPDIR_ROOT/missing-tenant"
  mkdir -p "$d"
  _setup_certs "$d"
  _write_stub_server "$d/stub_server.py"
  _start_server "missing-team-root" "$d" || return

  _make_bundle "$d" "$SERVER_PORT"

  local out="" rc=0
  out=$(bash "$SMOKE" --bundle "$d/bundle.yaml" 2>&1) || rc=$?
  _stop_server

  if [[ $rc -eq 1 ]]; then
    _pass "missing-tenant: exits 1 when a tenant is absent"
  else
    _fail "missing-tenant: expected exit 1, got $rc — output: $out"
  fi

  if grep -q '^\[FAIL\] tenant-exists: team-root' <<< "$out"; then
    _pass "missing-tenant: [FAIL] line present for team-root"
  else
    _fail "missing-tenant: missing [FAIL] tenant-exists: team-root line — output: $out"
  fi

  if grep -q '^\[PASS\] tenant-exists: agent-test' <<< "$out" &&
     grep -q '^\[PASS\] tenant-exists: infra-hyperv' <<< "$out"; then
    _pass "missing-tenant: remaining tenants still pass"
  else
    _fail "missing-tenant: expected [PASS] for agent-test and infra-hyperv — output: $out"
  fi
}

test_controller_url_override() {
  local d="$TMPDIR_ROOT/url-override"
  mkdir -p "$d"
  _setup_certs "$d"
  _write_stub_server "$d/stub_server.py"
  _start_server "all-pass" "$d" || return

  # Bundle has a wrong URL; --controller-url flag must override it
  _make_bundle_bad_url "$d"

  local out="" rc=0
  out=$(bash "$SMOKE" \
    --bundle "$d/bundle_bad_url.yaml" \
    --controller-url "https://127.0.0.1:${SERVER_PORT}" \
    2>&1) || rc=$?
  _stop_server

  if [[ $rc -eq 0 ]]; then
    _pass "url-override: --controller-url flag overrides bundle controller_url"
  else
    _fail "url-override: expected exit 0, got $rc — output: $out"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if [[ ! -f "$SMOKE" ]]; then
  _fail "tier1-smoke-test.sh not found at $SMOKE"
  echo ""
  echo "Result: 0 passed, 1 failed"
  exit 1
fi

TMPDIR_ROOT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_ROOT" "$CFG_BUILD_DIR"; _stop_server' EXIT

echo "tier1-smoke-test fixture tests"
echo "=============================="
echo ""

test_syntax
echo ""
test_bundle_missing
echo ""
test_bundle_malformed
echo ""
test_bundle_missing_controller_url
echo ""
test_all_pass
echo ""
test_health_fail
echo ""
test_missing_tenant
echo ""
test_controller_url_override
echo ""

echo "Result: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
exit 0
