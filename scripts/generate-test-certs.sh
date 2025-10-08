#!/usr/bin/env bash
#
# generate-test-certs.sh - Generate test certificates for MQTT+QUIC TLS testing
#
# This script generates a complete certificate infrastructure for testing:
# - CA certificate and key (self-signed root CA)
# - Server certificates for MQTT broker
# - Client certificates for stewards
# - Expired/invalid certificates for negative testing
#
# WARNING: These certificates are for TESTING ONLY!
# DO NOT use these certificates in production environments!
#
# Usage:
#   ./scripts/generate-test-certs.sh [output_dir]
#
# Arguments:
#   output_dir  - Directory to store generated certificates (default: test/integration/mqtt_quic/certs)
#
# Story 12.4: TLS/mTLS Security Validation

set -euo pipefail

# Configuration
OUTPUT_DIR="${1:-test/integration/mqtt_quic/certs}"
CA_NAME="CFGMS Test CA"
SERVER_NAME="controller-standalone"
CLIENT_NAME="steward-test"

# Certificate validity periods (dev/test only)
CA_DAYS=3650      # 10 years
SERVER_DAYS=365   # 1 year
CLIENT_DAYS=365   # 1 year
EXPIRED_DAYS=-1   # Already expired (for negative testing)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check for openssl
if ! command -v openssl &> /dev/null; then
    log_error "openssl is required but not installed"
    exit 1
fi

log_info "Generating test certificates for TLS/mTLS testing"
log_warn "These certificates are for TESTING ONLY - DO NOT use in production!"

# Create output directory
mkdir -p "${OUTPUT_DIR}"
log_info "Output directory: ${OUTPUT_DIR}"

# =============================================================================
# Step 1: Generate CA Certificate (Root CA for test environment)
# =============================================================================
log_info "Generating CA certificate..."

# Generate CA private key
openssl genrsa -out "${OUTPUT_DIR}/ca-key.pem" 4096 2>/dev/null

# Generate CA certificate (self-signed)
openssl req -new -x509 \
    -days "${CA_DAYS}" \
    -key "${OUTPUT_DIR}/ca-key.pem" \
    -out "${OUTPUT_DIR}/ca-cert.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=CFGMS Test/OU=Test CA/CN=${CA_NAME}" \
    2>/dev/null

log_info "✓ CA certificate generated (valid for ${CA_DAYS} days)"

# =============================================================================
# Step 2: Generate Server Certificate (MQTT Broker)
# =============================================================================
log_info "Generating server certificate for MQTT broker..."

# Generate server private key
openssl genrsa -out "${OUTPUT_DIR}/server-key.pem" 2048 2>/dev/null

# Generate server certificate signing request (CSR)
openssl req -new \
    -key "${OUTPUT_DIR}/server-key.pem" \
    -out "${OUTPUT_DIR}/server-csr.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=CFGMS Test/OU=Test Server/CN=${SERVER_NAME}" \
    2>/dev/null

# Create server certificate extensions file (SAN for Docker networking)
cat > "${OUTPUT_DIR}/server-ext.cnf" <<EOF
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = ${SERVER_NAME}
DNS.2 = controller-standalone
DNS.3 = controller-east
DNS.4 = controller-central
DNS.5 = controller-west
DNS.6 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.20.0.10
EOF

# Sign server certificate with CA
openssl x509 -req \
    -in "${OUTPUT_DIR}/server-csr.pem" \
    -CA "${OUTPUT_DIR}/ca-cert.pem" \
    -CAkey "${OUTPUT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/server-cert.pem" \
    -days "${SERVER_DAYS}" \
    -extfile "${OUTPUT_DIR}/server-ext.cnf" \
    2>/dev/null

log_info "✓ Server certificate generated (valid for ${SERVER_DAYS} days)"

# =============================================================================
# Step 3: Generate Client Certificate (Steward)
# =============================================================================
log_info "Generating client certificate for steward..."

# Generate client private key
openssl genrsa -out "${OUTPUT_DIR}/client-key.pem" 2048 2>/dev/null

# Generate client certificate signing request (CSR)
openssl req -new \
    -key "${OUTPUT_DIR}/client-key.pem" \
    -out "${OUTPUT_DIR}/client-csr.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=CFGMS Test/OU=Test Client/CN=${CLIENT_NAME}" \
    2>/dev/null

# Create client certificate extensions file
cat > "${OUTPUT_DIR}/client-ext.cnf" <<EOF
extendedKeyUsage = clientAuth
EOF

# Sign client certificate with CA
openssl x509 -req \
    -in "${OUTPUT_DIR}/client-csr.pem" \
    -CA "${OUTPUT_DIR}/ca-cert.pem" \
    -CAkey "${OUTPUT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/client-cert.pem" \
    -days "${CLIENT_DAYS}" \
    -extfile "${OUTPUT_DIR}/client-ext.cnf" \
    2>/dev/null

log_info "✓ Client certificate generated (valid for ${CLIENT_DAYS} days)"

# =============================================================================
# Step 4: Generate Invalid Certificates (For Negative Testing)
# =============================================================================
log_info "Generating invalid certificates for negative testing..."

# 4a. Expired certificate (already expired)
openssl genrsa -out "${OUTPUT_DIR}/expired-key.pem" 2048 2>/dev/null
openssl req -new \
    -key "${OUTPUT_DIR}/expired-key.pem" \
    -out "${OUTPUT_DIR}/expired-csr.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=CFGMS Test/OU=Test Expired/CN=expired-client" \
    2>/dev/null

# Create backdated certificate (set to yesterday and expire immediately)
faketime 'yesterday' openssl x509 -req \
    -in "${OUTPUT_DIR}/expired-csr.pem" \
    -CA "${OUTPUT_DIR}/ca-cert.pem" \
    -CAkey "${OUTPUT_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/expired-cert.pem" \
    -days 1 \
    2>/dev/null || {
    # Fallback if faketime is not available
    log_warn "faketime not available, generating short-lived cert instead"
    openssl x509 -req \
        -in "${OUTPUT_DIR}/expired-csr.pem" \
        -CA "${OUTPUT_DIR}/ca-cert.pem" \
        -CAkey "${OUTPUT_DIR}/ca-key.pem" \
        -CAcreateserial \
        -out "${OUTPUT_DIR}/expired-cert.pem" \
        -days 1 \
        2>/dev/null
}

log_info "✓ Expired certificate generated (for negative testing)"

# 4b. Self-signed certificate (not signed by CA)
openssl genrsa -out "${OUTPUT_DIR}/selfsigned-key.pem" 2048 2>/dev/null
openssl req -new -x509 \
    -days 365 \
    -key "${OUTPUT_DIR}/selfsigned-key.pem" \
    -out "${OUTPUT_DIR}/selfsigned-cert.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=CFGMS Test/OU=Test SelfSigned/CN=selfsigned-client" \
    2>/dev/null

log_info "✓ Self-signed certificate generated (for negative testing)"

# 4c. Wrong CA certificate (different CA)
openssl genrsa -out "${OUTPUT_DIR}/wrong-ca-key.pem" 4096 2>/dev/null
openssl req -new -x509 \
    -days 3650 \
    -key "${OUTPUT_DIR}/wrong-ca-key.pem" \
    -out "${OUTPUT_DIR}/wrong-ca-cert.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=Wrong CA/OU=Test Wrong CA/CN=Wrong CA" \
    2>/dev/null

# Generate client cert signed by wrong CA
openssl genrsa -out "${OUTPUT_DIR}/wrong-ca-client-key.pem" 2048 2>/dev/null
openssl req -new \
    -key "${OUTPUT_DIR}/wrong-ca-client-key.pem" \
    -out "${OUTPUT_DIR}/wrong-ca-client-csr.pem" \
    -subj "/C=US/ST=Test/L=TestCity/O=CFGMS Test/OU=Test Wrong CA Client/CN=wrong-ca-client" \
    2>/dev/null
openssl x509 -req \
    -in "${OUTPUT_DIR}/wrong-ca-client-csr.pem" \
    -CA "${OUTPUT_DIR}/wrong-ca-cert.pem" \
    -CAkey "${OUTPUT_DIR}/wrong-ca-key.pem" \
    -CAcreateserial \
    -out "${OUTPUT_DIR}/wrong-ca-client-cert.pem" \
    -days 365 \
    2>/dev/null

log_info "✓ Wrong CA certificate generated (for negative testing)"

# =============================================================================
# Step 5: Generate Certificate Bundles and Verify
# =============================================================================
log_info "Creating certificate bundles..."

# Create combined certificate bundle for easy deployment
cat "${OUTPUT_DIR}/server-cert.pem" "${OUTPUT_DIR}/ca-cert.pem" > "${OUTPUT_DIR}/server-bundle.pem"
cat "${OUTPUT_DIR}/client-cert.pem" "${OUTPUT_DIR}/ca-cert.pem" > "${OUTPUT_DIR}/client-bundle.pem"

log_info "✓ Certificate bundles created"

# Verify certificates
log_info "Verifying certificates..."

# Verify server certificate
if openssl verify -CAfile "${OUTPUT_DIR}/ca-cert.pem" "${OUTPUT_DIR}/server-cert.pem" 2>&1 | grep -q "OK"; then
    log_info "✓ Server certificate verification: OK"
else
    log_error "Server certificate verification failed"
    exit 1
fi

# Verify client certificate
if openssl verify -CAfile "${OUTPUT_DIR}/ca-cert.pem" "${OUTPUT_DIR}/client-cert.pem" 2>&1 | grep -q "OK"; then
    log_info "✓ Client certificate verification: OK"
else
    log_error "Client certificate verification failed"
    exit 1
fi

# =============================================================================
# Step 6: Create README
# =============================================================================
cat > "${OUTPUT_DIR}/README.md" <<'EOFREADME'
# Test Certificates for MQTT+QUIC TLS Testing

**WARNING: FOR TESTING ONLY!**

These certificates are generated for local development and testing purposes only.
They use weak security settings and should NEVER be used in production.

## Generated Files

### CA Certificates
- `ca-cert.pem` - Root CA certificate (public)
- `ca-key.pem` - Root CA private key (SECRET - for signing only)

### Server Certificates (MQTT Broker)
- `server-cert.pem` - Server certificate (public)
- `server-key.pem` - Server private key (SECRET)
- `server-bundle.pem` - Server certificate + CA bundle
- `server-ext.cnf` - Certificate extensions (SAN)

### Client Certificates (Steward)
- `client-cert.pem` - Client certificate (public)
- `client-key.pem` - Client private key (SECRET)
- `client-bundle.pem` - Client certificate + CA bundle
- `client-ext.cnf` - Certificate extensions

### Invalid Certificates (For Negative Testing)
- `expired-cert.pem` / `expired-key.pem` - Expired certificate
- `selfsigned-cert.pem` / `selfsigned-key.pem` - Self-signed (not trusted)
- `wrong-ca-*` - Certificates signed by different CA

## Usage

### Server (MQTT Broker)
```bash
CFGMS_MQTT_ENABLE_TLS=true
CFGMS_MQTT_TLS_CERT_PATH=/certs/server-cert.pem
CFGMS_MQTT_TLS_KEY_PATH=/certs/server-key.pem
CFGMS_MQTT_TLS_CA_PATH=/certs/ca-cert.pem
CFGMS_MQTT_REQUIRE_CLIENT_CERT=true  # For mTLS
```

### Client (Steward)
```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      caCertPool,
    MinVersion:   tls.VersionTLS13,
}
```

## Certificate Details

- **CA**: Self-signed, 4096-bit RSA, valid for 10 years
- **Server**: 2048-bit RSA, valid for 1 year, includes SAN for Docker networking
- **Client**: 2048-bit RSA, valid for 1 year, clientAuth extended key usage

## Regeneration

Run `scripts/generate-test-certs.sh` to regenerate all certificates.

## Security Notes

1. These certificates use insecure validity periods (10 years for CA)
2. Private keys are not password protected
3. Certificates are committed to the repository (DO NOT DO THIS IN PRODUCTION)
4. No intermediate CAs (single-tier PKI)
5. Weak randomness in test environments

For production deployments, use:
- Commercial CA (Let's Encrypt, DigiCert, etc.)
- Hardware Security Modules (HSM) for key storage
- Short validity periods (90 days)
- Certificate transparency logging
- Regular rotation procedures
EOFREADME

log_info "✓ README.md created"

# =============================================================================
# Step 7: Set Permissions
# =============================================================================
log_info "Setting file permissions..."

# Private keys should be readable only by owner
chmod 600 "${OUTPUT_DIR}"/*-key.pem
chmod 644 "${OUTPUT_DIR}"/*-cert.pem
chmod 644 "${OUTPUT_DIR}"/*.cnf 2>/dev/null || true

log_info "✓ File permissions set"

# =============================================================================
# Summary
# =============================================================================
log_info ""
log_info "=========================================="
log_info "Certificate Generation Complete!"
log_info "=========================================="
log_info ""
log_info "Output directory: ${OUTPUT_DIR}"
log_info ""
log_info "Generated certificates:"
log_info "  ✓ CA certificate (valid for ${CA_DAYS} days)"
log_info "  ✓ Server certificate (valid for ${SERVER_DAYS} days)"
log_info "  ✓ Client certificate (valid for ${CLIENT_DAYS} days)"
log_info "  ✓ Invalid certificates (for negative testing)"
log_info ""
log_warn "Remember: These certificates are for TESTING ONLY!"
log_info ""
log_info "To enable TLS in docker-compose.test.yml:"
log_info "  CFGMS_MQTT_ENABLE_TLS=true"
log_info ""
log_info "To enable mTLS (mutual authentication):"
log_info "  CFGMS_MQTT_REQUIRE_CLIENT_CERT=true"
log_info ""
log_info "See ${OUTPUT_DIR}/README.md for usage details"
log_info "=========================================="
