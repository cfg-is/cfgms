# CFGMS Home Lab Deployment Guide

**Story #378**: Comprehensive guide for deploying CFGMS to a home lab environment with full MQTT+QUIC integration validated.

**Last Updated**: 2026-02-12
**CFGMS Version**: v0.9.x
**Deployment Time**: ~30-45 minutes (first-time setup)

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [Detailed Setup](#detailed-setup)
6. [Validation](#validation)
7. [Troubleshooting](#troubleshooting)
8. [Advanced Configuration](#advanced-configuration)

## Overview

This guide walks you through deploying a complete CFGMS environment in your home lab, including:

- **Controller**: Central management server (REST API, gRPC, QUIC)
- **Steward(s)**: Endpoint agents for configuration management
- **MQTT Broker**: Message broker for real-time communication
- **Storage Backend**: Git with SOPS encryption (default)

**What You'll Achieve**:
- Fully functional CFGMS deployment
- Validated MQTT+QUIC communication paths
- E2E config distribution flow working end-to-end
- Secure certificate-based authentication
- Production-ready infrastructure

## Architecture

### Component Communication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Home Lab Network                        │
│                                                              │
│  ┌──────────────┐                  ┌──────────────┐         │
│  │              │  MQTT (TLS)      │              │         │
│  │  Controller  │◄────────────────►│ MQTT Broker  │         │
│  │              │  1886            │              │         │
│  │  - REST API  │                  │ - mochi-mqtt │         │
│  │  - gRPC      │                  │ - TLS auth   │         │
│  │  - QUIC      │                  └──────────────┘         │
│  │              │                         ▲                  │
│  └──────────────┘                         │ MQTT (TLS)      │
│         ▲                                 │ 1886            │
│         │                                 │                  │
│         │ QUIC (mTLS)                     │                  │
│         │ 4433                            │                  │
│         │                                 │                  │
│  ┌──────┴─────────────────────────────────┴──────┐          │
│  │                                                │          │
│  │              Steward(s)                        │          │
│  │                                                │          │
│  │  - Config executor                            │          │
│  │  - Module engine (file, directory, script)    │          │
│  │  - Status reporter                            │          │
│  └───────────────────────────────────────────────┘          │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Control Plane: MQTT (commands, heartbeats, status reports)
Data Plane: QUIC (configuration sync, high-throughput data)
Management Plane: REST API (config uploads, admin operations)
```

### Communication Protocols

1. **MQTT** (Control Plane - Port 1886 with TLS):
   - Command delivery (`connect_quic`, `sync_config`, `heartbeat`)
   - Status reporting (`config-status`, `health-status`)
   - Real-time notifications

2. **QUIC** (Data Plane - Port 4433 with mTLS):
   - Configuration synchronization (signed configs)
   - High-performance data transfer
   - DNA (Desired Next Action) delivery

3. **REST API** (Management Plane - Port 8080 with HTTPS):
   - Configuration uploads
   - Steward registration
   - Administrative operations
   - Health checks

4. **gRPC** (Optional - Port 9090):
   - Legacy support
   - Inter-controller communication (future)

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB free | 50 GB free |
| OS | Linux, macOS, Windows | Linux (Ubuntu 22.04+) |
| Docker | 20.10+ | 24.0+ |
| Docker Compose | 2.0+ | 2.20+ |
| Go (for building) | 1.23+ | 1.23+ |

### Software Prerequisites

```bash
# Verify Docker
docker --version
# Expected: Docker version 24.0.0 or later

# Verify Docker Compose
docker compose version
# Expected: Docker Compose version v2.20.0 or later

# Verify Go (if building from source)
go version
# Expected: go version go1.23.0 or later

# Optional: MQTT client tools for testing
mosquitto_pub --help  # mosquitto-clients package
```

### Network Requirements

**Ports** (ensure these are available):
- `8080`: Controller REST API (HTTPS)
- `9090`: Controller gRPC (optional)
- `4433`: Controller QUIC server
- `1883`: MQTT broker (non-TLS, optional)
- `1886`: MQTT broker (TLS)

**Firewall Rules** (if applicable):
- Allow inbound on ports above from your home network
- Allow outbound HTTPS (443) for external integrations (M365, etc.)

## Quick Start

**For experienced users** - get CFGMS running in 5 minutes:

```bash
# 1. Clone and build
git clone https://github.com/cfg-is/cfgms.git
cd cfgms
make build

# 2. Start infrastructure
docker compose up -d controller mqtt-broker

# 3. Start a test steward
docker compose up -d steward-standalone

# 4. Verify deployment
docker logs controller | grep "Controller started"
docker logs steward-standalone | grep "Registration successful"

# 5. Run E2E validation
cd test/integration/mqtt_quic
go test -v -run TestE2EFlowDiagnostic
```

**Success**: If diagnostic test passes, your deployment is functional! Continue to [Validation](#validation) section.

## Detailed Setup

### Step 1: Repository Setup

```bash
# Clone the repository
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Checkout the latest stable release
git checkout main

# Verify repository structure
ls -la
# You should see: cmd/, features/, pkg/, test/, docker-compose.yml, Makefile
```

### Step 2: Build CFGMS Binaries

```bash
# Run complete validation (tests + security + lint)
make test-complete
# This MUST pass 100% before deploying

# Build binaries for your platform
make build
# Creates: bin/controller, bin/steward, bin/cfg

# Verify binaries
./bin/controller --version
./bin/steward --version
```

**Troubleshooting Build Issues**:
- If tests fail: Fix the failing tests before proceeding (zero tolerance policy)
- If build fails: Check Go version is 1.23+, run `go mod tidy`
- If security scan fails: Review and remediate security findings

### Step 3: Configure Storage Backend

**Option A: Git with SOPS** (Recommended for Home Lab)

```bash
# SOPS is used for encryption - install if not present
# On macOS: brew install sops
# On Linux: Download from https://github.com/mozilla/sops/releases

# Generate age encryption key for SOPS
age-keygen -o ~/.config/sops/age/keys.txt

# Extract public key
grep "public key:" ~/.config/sops/age/keys.txt

# Configure controller to use git storage
# Edit docker-compose.yml or set environment variables:
export CFGMS_STORAGE_PROVIDER=git
export CFGMS_STORAGE_GIT_URL=/data/git-storage
export CFGMS_SOPS_AGE_KEY=$(cat ~/.config/sops/age/keys.txt)
```

**Option B: Database** (Advanced - for larger deployments)

```bash
# Start PostgreSQL or TimescaleDB
docker compose up -d timescale

# Configure controller for database storage
export CFGMS_STORAGE_PROVIDER=database
export CFGMS_DB_HOST=localhost
export CFGMS_DB_PORT=5432
export CFGMS_DB_USER=cfgms
export CFGMS_DB_PASSWORD=$(openssl rand -base64 32)  # Generate secure password
export CFGMS_DB_NAME=cfgms
```

### Step 4: Start Controller

```bash
# Start controller and MQTT broker
docker compose up -d controller mqtt-broker

# Watch logs for initialization
docker logs -f controller

# Look for these log messages (wait 10-15 seconds):
# ✓ "Certificate manager initialized"
# ✓ "Generated server certificate" (if auto-generating)
# ✓ "MQTT client connected"
# ✓ "QUIC server listening on :4433"
# ✓ "REST API server listening on :8080"
# ✓ "Controller started successfully"

# Ctrl+C to stop watching logs
```

**Verify Controller Health**:

```bash
# Check REST API
curl -k https://localhost:8080/health
# Expected: {"status":"healthy"} or similar

# Check container status
docker ps | grep controller
# Expected: STATUS shows "Up X seconds/minutes"

# Check logs for errors
docker logs controller | grep -i error
# Expected: No critical errors (warnings are okay)
```

### Step 5: Start MQTT Broker

**Note**: If using `docker compose`, MQTT broker starts automatically with controller.

```bash
# Verify MQTT broker is running
docker logs mqtt-broker

# Look for:
# ✓ "mochi mqtt server started"
# ✓ "listening on :1886" (TLS)

# Test MQTT connectivity (requires mosquitto-clients)
mosquitto_pub -h localhost -p 1883 -t "test/topic" -m "hello" -d
# Expected: No errors, message published successfully
```

### Step 6: Deploy First Steward

```bash
# Option A: Docker Compose (easiest for testing)
docker compose up -d steward-standalone

# Option B: Native binary (for production stewards)
./bin/steward --config steward-config.yaml

# Watch steward logs
docker logs -f steward-standalone

# Look for these log messages:
# ✓ "Starting steward registration"
# ✓ "Registration successful"
# ✓ "Steward ID: steward-XXXXX"
# ✓ "MQTT client connected"
# ✓ "Ready to receive commands"
```

**Verify Steward Registration**:

```bash
# Extract steward ID from logs
STEWARD_ID=$(docker logs steward-standalone 2>&1 | grep "Steward ID:" | tail -1 | awk '{print $NF}')
echo "Steward ID: $STEWARD_ID"

# Verify controller sees the steward
docker logs controller | grep "$STEWARD_ID"
# Expected: Registration confirmation message
```

### Step 7: Test Configuration Sync

```bash
# Create a simple test configuration
cat > /tmp/test-config.yaml <<EOF
steward:
  id: $STEWARD_ID
  mode: controller

resources:
  - name: test-file
    module: file
    config:
      path: /test-workspace/hello.txt
      content: |
        Hello from CFGMS!
        Deployed successfully to home lab.
      permissions: "0644"
      ensure: present
EOF

# Upload configuration to controller
curl -k -X POST https://localhost:8080/api/v1/configurations \
  -H "Content-Type: application/yaml" \
  --data-binary @/tmp/test-config.yaml

# Trigger config sync via MQTT (or use controller API)
# The steward should automatically sync within 60 seconds
# OR manually trigger via commands (see advanced section)
```

**Verify Config Execution**:

```bash
# Check steward logs for config sync
docker logs steward-standalone | tail -30
# Look for:
# ✓ "QUIC connection established"
# ✓ "Configuration fetched"
# ✓ "Signature verified"
# ✓ "Module executed: file"
# ✓ "Status report published"

# Verify file was created
docker exec steward-standalone cat /test-workspace/hello.txt
# Expected: File content matches config
```

## Validation

### Automated E2E Tests

**Run the comprehensive E2E test suite**:

```bash
cd test/integration/mqtt_quic

# Network validation (pre-flight checks)
go test -v -run TestE2ENetworkValidation
# Expected: All phases pass, no connectivity issues

# Flow diagnostic (validates each E2E phase)
go test -v -run TestE2EFlowDiagnostic
# Expected: All 8 phases pass in < 30 seconds

# Config status reporting (full E2E flow)
go test -v -run TestConfigStatusReporting
# Expected: Status report received within 10 seconds

# Module failure reporting
go test -v -run TestModuleFailureReporting
# Expected: Error status report received correctly
```

**Success Criteria**:
- ✅ All E2E tests pass
- ✅ Tests complete in < 30 seconds (not timeout)
- ✅ No errors in test output
- ✅ Status reports received correctly

### Manual Validation Steps

**1. MQTT Connectivity**:
```bash
# Subscribe to all steward topics
mosquitto_sub -h localhost -p 1883 -t "cfgms/steward/#" -v

# In another terminal, check if you see:
# - Heartbeat messages
# - Status reports
# - Command acknowledgments
```

**2. QUIC Connectivity**:
```bash
# Check controller QUIC server is listening
docker logs controller | grep "QUIC server listening"

# Check steward can connect
docker logs steward-standalone | grep "QUIC.*established"
```

**3. Config Distribution**:
```bash
# Upload config (as shown in Step 7)
# Verify config appears in storage backend

# For git storage:
docker exec controller ls -la /data/git-storage/

# For database storage:
docker exec timescale psql -U cfgms -c "SELECT * FROM configurations;"
```

**4. Module Execution**:
```bash
# Create test file via config (shown above)
# Verify file exists
docker exec steward-standalone ls -la /test-workspace/

# Create test directory
# Verify directory exists
# Verify permissions are correct
```

**5. Status Reporting**:
```bash
# Check controller logs for status reports
docker logs controller | grep "config.*status"

# Verify status matches actual execution
# (file created → status should be "OK")
```

## Troubleshooting

See [home-lab-checklist.md](home-lab-checklist.md) for detailed troubleshooting steps.

### Quick Debug Commands

```bash
# View all container logs
docker compose logs -f

# Check controller health
curl -k https://localhost:8080/health

# Restart a component
docker restart controller
docker restart steward-standalone
docker restart mqtt-broker

# Clean restart (removes all data!)
docker compose down -v
docker compose up -d
```

### Common Issues

**Issue**: "Error: signature verification failed"
- **Root Cause**: Controller using mismatched certificates (Story #378)
- **Fix**: Ensure you're running v0.9.x with Story #378 fix applied
- **Verify**: Check controller logs show same certificate serial for signer and registration

**Issue**: "Timeout waiting for config status"
- **Debug**: Check QUIC connection established
- **Debug**: Check module executor initialized
- **Debug**: Check MQTT publish succeeds
- **Fix**: See diagnostic test output for exact failure point

**Issue**: "Cannot connect to MQTT broker"
- **Debug**: Check MQTT broker is running: `docker ps | grep mqtt`
- **Debug**: Check port 1886 is accessible
- **Fix**: Verify firewall rules, restart mqtt-broker

**Issue**: "QUIC connection failed"
- **Debug**: Check port 4433 is accessible from steward
- **Debug**: Check certificates are valid
- **Fix**: Test connectivity: `nc -zv controller-standalone 4433`

## Advanced Configuration

### Multi-Steward Deployment

```bash
# Deploy multiple stewards
for i in {1..3}; do
  docker compose up -d steward-$i
done

# Each steward gets unique ID automatically
# All connect to same controller via MQTT+QUIC
```

### Custom Certificate Authority

```bash
# Generate your own CA (instead of auto-generated)
./scripts/generate-ca.sh

# Configure controller to use custom CA
export CFGMS_CERT_CA_PATH=/path/to/ca.pem
export CFGMS_CERT_CERT_PATH=/path/to/server.pem
export CFGMS_CERT_KEY_PATH=/path/to/server-key.pem
```

### High Availability Setup

```bash
# Start multiple controllers (requires shared storage backend)
docker compose --profile ha up -d

# Use load balancer for REST API
# Controllers coordinate via shared database
```

### M365 Integration

```bash
# Configure Microsoft 365 directory provider
export CFGMS_DIRECTORY_PROVIDER=m365
export CFGMS_M365_TENANT_ID=your-tenant-id
export CFGMS_M365_CLIENT_ID=your-client-id
export CFGMS_M365_CLIENT_SECRET=your-client-secret

# Restart controller
docker restart controller
```

## Next Steps

After successful deployment:

1. **Read the User Guide**: Understand module configuration and resource management
2. **Explore Modules**: Try file, directory, and script modules
3. **Set Up Monitoring**: Configure logging provider (TimescaleDB recommended)
4. **Plan Scaling**: Add more stewards to manage more endpoints
5. **Enable Advanced Features**: RBAC, multi-tenancy, conditional access

## References

- **Roadmap**: [docs/product/roadmap.md](../product/roadmap.md)
- **Architecture**: [docs/architecture/](../architecture/)
- **E2E Testing**: [docs/testing/e2e-testing-guide.md](../testing/e2e-testing-guide.md)
- **MQTT+QUIC Details**: [docs/testing/mqtt-quic-testing-strategy.md](../testing/mqtt-quic-testing-strategy.md)
- **Troubleshooting**: [docs/troubleshooting/connectivity.md](../troubleshooting/connectivity.md)

---

**Deployment Support**: If you encounter issues, check GitHub issues or create a new issue with:
- Output of `docker compose logs`
- Output of E2E test runs
- Description of unexpected behavior
