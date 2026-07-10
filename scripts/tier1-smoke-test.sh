#!/bin/bash
# Tier 1 controller smoke test.
#
# Verifies REST API reachability, mTLS authentication from the admin bundle,
# expected health response, and presence of three required tenants on a live
# Tier 1 controller after a bootstrap run.
#
# Dependencies (runtime): bash >=4, curl, python3 (standard on Debian/Ubuntu)
#
# NOTE: Story #1848 (cfg tenant create + GET /api/v1/tenants/{id}) must be
#       merged and run before the tenant-existence checks here can pass on a
#       freshly bootstrapped controller.
#
# Usage:
#   ./tier1-smoke-test.sh [--bundle <path>] [--controller-url <url>]
#
# Flags:
#   --bundle <path>        Path to the CFGMS admin bundle YAML.
#                          Default: $CFGMS_ADMIN_BUNDLE or /etc/cfgms/admin.bundle.yaml
#   --controller-url <url> Controller base URL (overrides bundle controller_url field).
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed, or fatal setup error

set -uo pipefail

BUNDLE_PATH="${CFGMS_ADMIN_BUNDLE:-/etc/cfgms/admin.bundle.yaml}"
CONTROLLER_URL=""
# CFG_BIN is the cfg client used for the health check (mTLS via crypto/tls/PEM,
# never curl+Schannel — see #2458). Override with CFGMS_CFG_BIN when the binary is
# not on PATH (e.g. the test harness points at a freshly-built ./bin/cfg).
CFG_BIN="${CFGMS_CFG_BIN:-cfg}"
PASS_COUNT=0
FAIL_COUNT=0

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "ERROR: --bundle requires a path argument" >&2
        exit 1
      fi
      BUNDLE_PATH="$2"
      shift 2
      ;;
    --controller-url)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "ERROR: --controller-url requires a URL argument" >&2
        exit 1
      fi
      CONTROLLER_URL="$2"
      shift 2
      ;;
    -h|--help)
      sed -n 's/^# //p; s/^#$//p' "$0" | head -40
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      echo "Usage: $0 [--bundle <path>] [--controller-url <url>]" >&2
      exit 1
      ;;
  esac
done

# --- Validate bundle file exists ---
if [[ ! -f "$BUNDLE_PATH" ]]; then
  echo "[FAIL] bundle-load: bundle file not found: $BUNDLE_PATH"
  echo ""
  echo "Result: 0 passed, 1 failed"
  exit 1
fi

# --- Temp files for cert material ---
CERT_FILE=$(mktemp /tmp/cfgms-smoke-cert-XXXXXX.pem)
KEY_FILE=$(mktemp /tmp/cfgms-smoke-key-XXXXXX.pem)
CA_FILE=$(mktemp /tmp/cfgms-smoke-ca-XXXXXX.pem)

# Never leave private key material on disk after exit (success, failure, or Ctrl+C).
trap 'rm -f "$CERT_FILE" "$KEY_FILE" "$CA_FILE"' EXIT INT TERM

# --- Extract certs from bundle ---
# Uses yaml if available, falls back to a minimal inline parser for the
# block-literal format produced by Go's gopkg.in/yaml.v3 marshal.
_extract_rc=0
BUNDLE_PATH="$BUNDLE_PATH" CERT_FILE="$CERT_FILE" KEY_FILE="$KEY_FILE" CA_FILE="$CA_FILE" \
  python3 - <<'PYTHON' 2>&1 || _extract_rc=$?

import os, sys

def parse_bundle(path):
    """Parse the bundle YAML file. Tries pyyaml first; falls back to inline parser."""
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh)
    except ImportError:
        pass
    # Inline parser for Go yaml.v3 block-literal format (no external deps needed).
    result = {}
    with open(path) as fh:
        lines = fh.read().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith('#'):
            i += 1
            continue
        if ': |' in stripped or stripped.endswith(': |'):
            key = stripped[:stripped.index(':')].strip()
            i += 1
            content, indent = [], None
            while i < len(lines):
                cl = lines[i]
                if not cl.strip():
                    content.append('')
                    i += 1
                    continue
                sp = len(cl) - len(cl.lstrip())
                if indent is None:
                    indent = sp
                if sp < indent:
                    break
                content.append(cl[indent:])
                i += 1
            result[key] = '\n'.join(content) + '\n'
        elif ': ' in stripped:
            colon = stripped.index(': ')
            key = stripped[:colon].strip()
            val = stripped[colon + 2:].strip()
            if (val.startswith('"') and val.endswith('"')) or \
               (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            result[key] = val
            i += 1
        else:
            i += 1
    return result

bundle_path = os.environ['BUNDLE_PATH']
try:
    b = parse_bundle(bundle_path)
except Exception as exc:
    print(f"failed to parse bundle: {exc}", file=sys.stderr)
    sys.exit(1)

for field, path in [('cert_pem', os.environ['CERT_FILE']),
                    ('key_pem',  os.environ['KEY_FILE']),
                    ('ca_pem',   os.environ['CA_FILE'])]:
    val = b.get(field, '')
    if not val:
        print(f"bundle missing required field: {field}", file=sys.stderr)
        sys.exit(1)
    with open(path, 'w') as fh:
        fh.write(val)
PYTHON

if [[ $_extract_rc -ne 0 ]]; then
  echo "[FAIL] bundle-load: failed to extract certs from $BUNDLE_PATH (see above)"
  echo ""
  echo "Result: 0 passed, 1 failed"
  exit 1
fi

# --- Resolve controller URL from bundle if not provided via flag ---
if [[ -z "$CONTROLLER_URL" ]]; then
  _url_rc=0
  CONTROLLER_URL=$(BUNDLE_PATH="$BUNDLE_PATH" python3 - 2>/dev/null <<'PYTHON'
import os, sys

def parse_bundle(path):
    try:
        import yaml
        with open(path) as fh:
            return yaml.safe_load(fh)
    except ImportError:
        pass
    result = {}
    with open(path) as fh:
        lines = fh.read().splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith('#'):
            i += 1
            continue
        if ': |' in stripped or stripped.endswith(': |'):
            key = stripped[:stripped.index(':')].strip()
            i += 1
            content, indent = [], None
            while i < len(lines):
                cl = lines[i]
                if not cl.strip():
                    content.append('')
                    i += 1
                    continue
                sp = len(cl) - len(cl.lstrip())
                if indent is None:
                    indent = sp
                if sp < indent:
                    break
                content.append(cl[indent:])
                i += 1
            result[key] = '\n'.join(content) + '\n'
        elif ': ' in stripped:
            colon = stripped.index(': ')
            key = stripped[:colon].strip()
            val = stripped[colon + 2:].strip()
            if (val.startswith('"') and val.endswith('"')) or \
               (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            result[key] = val
            i += 1
        else:
            i += 1
    return result

bundle_path = os.environ['BUNDLE_PATH']
try:
    b = parse_bundle(bundle_path)
    url = b.get('controller_url', '').rstrip('/')
    if not url:
        print("bundle missing controller_url field", file=sys.stderr)
        sys.exit(1)
    print(url)
except Exception as exc:
    print(f"failed to read controller_url: {exc}", file=sys.stderr)
    sys.exit(1)
PYTHON
) || _url_rc=$?

  if [[ $_url_rc -ne 0 || -z "$CONTROLLER_URL" ]]; then
    echo "[FAIL] bundle-load: controller_url not found in bundle; pass --controller-url"
    echo ""
    echo "Result: 0 passed, 1 failed"
    exit 1
  fi
fi

CONTROLLER_URL="${CONTROLLER_URL%/}"

# --- Per-check record helpers ---
_record_pass() {
  echo "[PASS] $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

_record_fail() {
  echo "[FAIL] $1: $2"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

# --- Check 1: controller health via the cfg client ---
# cfg builds mTLS from the admin bundle through pkg/cert / crypto/tls (PEM,
# cross-platform) and hits GET /api/v1/health/detailed, returning non-zero when
# the controller is unreachable or not healthy. This dogfoods the exact client
# operators use and never touches curl/Schannel (#2458 RC2).
if _health_out=$("$CFG_BIN" controller status --bundle "$BUNDLE_PATH" --url "$CONTROLLER_URL" 2>&1); then
  _record_pass "health: cfg controller status"
else
  _record_fail "health: cfg controller status" \
    "controller unhealthy/unreachable: $(printf '%s' "$_health_out" | tr '\n' ' ' | cut -c1-200)"
fi

# --- Checks 2-4: required tenant existence ---
_check_tenant() {
  local tenant_id="$1"
  local code
  # mTLS GET via python3's ssl module (OpenSSL-backed PEM on every OS — no
  # curl/Schannel). cfg has no `tenant get` subcommand today (only the
  # GetTenantViaAPI client method is wired), so per #2458's AC this check uses the
  # permitted python3 stdlib fallback "where cfg can't express the check".
  # Pass the PEM material as CONTENT (not file paths): a native (non-MSYS) python3
  # on Windows cannot open an MSYS-style /tmp/... path passed via env var, so
  # python writes the certs to its own temp files (native paths) and loads those.
  # This keeps the check cross-platform without any MSYS path conversion.
  code=$(CT_URL="${CONTROLLER_URL}/api/v1/tenants/${tenant_id}" \
    CT_CERT_PEM="$(cat "$CERT_FILE")" CT_KEY_PEM="$(cat "$KEY_FILE")" CT_CA_PEM="$(cat "$CA_FILE")" \
    python3 - <<'PYTHON' 2>/dev/null
import os, ssl, tempfile, urllib.request, urllib.error
d = tempfile.mkdtemp()
paths = {}
for name, env in (('cert', 'CT_CERT_PEM'), ('key', 'CT_KEY_PEM'), ('ca', 'CT_CA_PEM')):
    p = os.path.join(d, name + '.pem')
    with open(p, 'w') as fh:
        fh.write(os.environ[env])
    paths[name] = p
ctx = ssl.create_default_context(cafile=paths['ca'])
ctx.load_cert_chain(certfile=paths['cert'], keyfile=paths['key'])
req = urllib.request.Request(os.environ['CT_URL'], method='GET')
try:
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
        print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception:
    print('000')
PYTHON
)
  [[ -z "$code" ]] && code="000"

  if [[ "$code" == "200" ]]; then
    _record_pass "tenant-exists: ${tenant_id}"
  elif [[ "$code" == "404" ]]; then
    _record_fail "tenant-exists: ${tenant_id}" \
      "tenant not found (404) — run 'cfg tenant create' first (story #1848)"
  else
    _record_fail "tenant-exists: ${tenant_id}" "unexpected HTTP ${code}"
  fi
}

_check_tenant "team-root"
_check_tenant "agent-test"
_check_tenant "infra-hyperv"

# --- Summary ---
echo ""
echo "Result: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"

if [[ $FAIL_COUNT -gt 0 ]]; then
  exit 1
fi
exit 0
