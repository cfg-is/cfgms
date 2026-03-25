# CFGMS Home Lab Deployment Guide

**Story #391**: Comprehensive guide for deploying CFGMS to a home lab environment with native binaries and full gRPC-over-QUIC transport.

**Last Updated**: 2026-02-28
**CFGMS Version**: v0.9.x
**Deployment Time**: ~30-45 minutes (first-time setup)

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Detailed Setup](#detailed-setup)
5. [Validation](#validation)
6. [Troubleshooting](#troubleshooting)
7. [Advanced Configuration](#advanced-configuration)

## Overview

This guide walks you through deploying a complete CFGMS environment in your home lab using native binaries, including:

- **Controller**: Central management server (REST API + gRPC-over-QUIC transport)
- **Steward(s)**: Endpoint agents for configuration management
- **Storage Backend**: Git with SOPS encryption (default)

> **Quick Start?** See [QUICK_START.md](../../QUICK_START.md) for a 5-15 minute getting-started guide.
> This document covers production-style native deployment with systemd.

**What You'll Achieve**:
- Fully functional CFGMS deployment on native VMs
- Validated gRPC-over-QUIC communication paths
- E2E config distribution flow working end-to-end
- Secure certificate-based authentication (auto-generated)
- systemd-managed services for production reliability

## Architecture

### Component Communication Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Home Lab Network                        │
│                                                              │
│  ┌──────────────────────────────┐                           │
│  │         Controller           │                           │
│  │                              │                           │
│  │  - REST API       :9080      │                           │
│  │  - Transport      :4433      │  (gRPC-over-QUIC, mTLS)  │
│  │  - Certificate CA            │                           │
│  └──────────────────────────────┘                           │
│                    ▲                                         │
│                    │                                         │
│          gRPC-over-QUIC (mTLS)                              │
│          :4433 (control + data plane)                        │
│                    │                                         │
│  ┌─────────────────┴────────────────────────────┐          │
│  │                                                │          │
│  │              Steward(s)                        │          │
│  │                                                │          │
│  │  - Config executor                            │          │
│  │  - Module engine (file, directory, script)    │          │
│  │  - Status reporter                            │          │
│  └───────────────────────────────────────────────┘          │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Transport: gRPC-over-QUIC (commands, heartbeats, status, config sync) - port 4433 (UDP)
Management Plane: REST API (config uploads, admin operations) - port 9080
```

**Note**: A single port (4433/UDP) handles all controller-steward communication via gRPC-over-QUIC. There is no separate MQTT broker.

### Communication Protocols

1. **gRPC-over-QUIC** (Transport - Port 4433 with mTLS):
   - **Control plane**: Commands, heartbeats, status events, DNA deltas
   - **Data plane**: Configuration synchronization (signed configs), full DNA snapshots, bulk data transfer
   - Single multiplexed QUIC connection per steward with distinct gRPC service methods for each operation

2. **REST API** (Management Plane - Port 9080):
   - Configuration uploads
   - Steward registration token management
   - Administrative operations
   - Health checks

## Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 20 GB free | 50 GB free |
| Controller OS | Debian 12+, Ubuntu 22.04+ | Debian 12 |
| Steward OS | Linux, macOS, Windows | See [platform-support.md](platform-support.md) |
| Go (for building) | 1.25+ | 1.25+ |

### Software Prerequisites

```bash
# Verify Go (required for building from source)
go version
# Expected: go version go1.25.0 or later

# Optional: grpcurl for testing gRPC endpoints
grpcurl --version  # grpcurl is a command-line tool for gRPC
```

### Network Requirements

**Ports** (ensure these are available on the controller):
- `9080`: Controller REST API (HTTP/HTTPS)
- `4433`: gRPC-over-QUIC transport — all controller-steward communication (UDP)

**Firewall Rules** (if applicable):
```bash
# Controller firewall (e.g., ufw on Debian)
sudo ufw allow 9080/tcp   # REST API
sudo ufw allow 4433/udp   # gRPC-over-QUIC transport (UDP protocol)
sudo ufw allow 22/tcp     # SSH management
```

## Detailed Setup

### Step 1: Build CFGMS Binaries

```bash
# Clone the repository
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Build all binaries
make build
# Creates: bin/controller, bin/cfgms-steward, bin/cfg

# Verify binaries
./bin/controller --version
./bin/cfgms-steward --version
./bin/cfg --version
```

**Troubleshooting Build Issues**:
- If build fails: Check Go version is 1.25+, run `go mod tidy`
- If tests fail: Fix the failing tests before deploying (zero tolerance policy)

### Step 2: Configure Storage Backend

**Git with SOPS** (Recommended for Home Lab)

```bash
# SOPS is used for encryption - install if not present
# On Debian/Ubuntu: apt install sops
# On macOS: brew install sops
# Or download from https://github.com/mozilla/sops/releases

# Generate age encryption key for SOPS
age-keygen -o ~/.config/sops/age/keys.txt

# Extract public key (you'll need this for .sops.yaml)
grep "public key:" ~/.config/sops/age/keys.txt
```

### Step 3: Deploy Controller

#### 3a: Copy Binary to Controller VM

```bash
# From build machine to controller VM
scp bin/controller user@controller-vm:/usr/local/bin/cfgms-controller
ssh user@controller-vm "chmod +x /usr/local/bin/cfgms-controller"
```

#### 3b: Create Controller Configuration

```bash
# On the controller VM
sudo mkdir -p /etc/cfgms /var/lib/cfgms/storage /var/lib/cfgms/certs /var/log/cfgms

sudo tee /etc/cfgms/controller.cfg > /dev/null <<EOF
storage:
  provider: git
  config:
    repository_path: /var/lib/cfgms/storage
    branch: main
    auto_init: true

certificate:
  enable_cert_management: true
  auto_generate: true
  ca_path: /var/lib/cfgms/certs

logging:
  provider: file
  level: INFO
  file:
    directory: /var/log/cfgms

transport:
  listen_addr: "0.0.0.0:4433"
  use_cert_manager: true
  max_connections: 10000
  keepalive_period: 30s
  idle_timeout: 5m
EOF
```

#### 3c: Create systemd Service

```bash
sudo tee /etc/systemd/system/cfgms-controller.service > /dev/null <<EOF
[Unit]
Description=CFGMS Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-controller
Restart=always
RestartSec=10
User=root
WorkingDirectory=/var/lib/cfgms

# Environment (adjust SOPS key path as needed)
Environment=SOPS_AGE_KEY_FILE=/root/.config/sops/age/keys.txt

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cfgms-controller
sudo systemctl start cfgms-controller
```

#### 3d: Verify Controller Health

```bash
# Check service status
sudo systemctl status cfgms-controller

# Check logs for successful startup
sudo journalctl -u cfgms-controller --no-pager -n 30

# Look for these log messages:
# ✓ "Certificate manager initialized"
# ✓ "Generated server certificate" (first boot only)
# ✓ "Transport server listening on :4433"
# ✓ "REST API server listening on :9080"

# Check REST API
curl http://localhost:9080/api/v1/health
```

### Step 4: Create Registration Token

```bash
# Create a registration token for stewards
curl -X POST http://localhost:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "default",
    "group": "production",
    "validity_days": 7,
    "single_use": false
  }'

# Save the token from the response for steward deployment
```

### Step 5: Deploy First Steward

#### 5a: Copy Binary to Steward VM

```bash
# From build machine to steward VM
scp bin/cfgms-steward user@steward-vm:/usr/local/bin/cfgms-steward
ssh user@steward-vm "chmod +x /usr/local/bin/cfgms-steward"
```

#### 5b: Create systemd Service

```bash
# On the steward VM
# Replace CONTROLLER_IP and TOKEN with actual values

sudo tee /etc/systemd/system/cfgms-steward.service > /dev/null <<EOF
[Unit]
Description=CFGMS Steward Configuration Management Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-steward --regtoken REPLACE_WITH_TOKEN
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cfgms-steward
sudo systemctl start cfgms-steward
```

#### 5c: Verify Steward Registration

```bash
# Check steward logs
sudo journalctl -u cfgms-steward --no-pager -n 30

# Look for:
# ✓ "Registering with controller"
# ✓ "Certificate obtained"
# ✓ "Transport connection established"
# ✓ "Connected to controller"
# ✓ "Steward ready"

# Verify controller sees the steward
sudo journalctl -u cfgms-controller --no-pager | grep -i "registration"
```

### Step 6: Test Configuration Sync

```bash
# On the controller VM, upload a test configuration
cat > /tmp/test-config.yaml <<EOF
resources:
  - name: test-file
    module: file
    config:
      path: /tmp/hello-cfgms.txt
      content: |
        Hello from CFGMS!
        Deployed successfully to home lab.
      permissions: "0644"
      ensure: present
EOF

curl -X POST http://localhost:9080/api/v1/configurations \
  -H "Content-Type: application/yaml" \
  --data-binary @/tmp/test-config.yaml

# The steward should sync within 60 seconds
# Check steward logs for config application:
ssh user@steward-vm "sudo journalctl -u cfgms-steward --no-pager -n 20"
```

## Validation

### Automated E2E Tests

The E2E test suite validates the complete gRPC-over-QUIC transport flow:

```bash
cd test/integration/transport

# Registration flow
go test -v -run TestRegistration -timeout 60s

# Configuration sync via gRPC data plane
go test -v -run TestConfigSync -timeout 60s

# Module execution (file, directory, script)
go test -v -run TestModuleExecution -timeout 60s

# Heartbeat and failover detection
go test -v -run TestHeartbeatFailover -timeout 60s

# Multi-tenant isolation
go test -v -run TestMultiTenant -timeout 60s

# TLS/mTLS security validation
go test -v -run TestTLSSecurity -timeout 60s
```

**Success Criteria**:
- All 6 E2E tests pass
- Tests complete without timeout
- No errors in test output

### Manual Validation Steps

**1. Transport Connectivity**:
```bash
# Check controller logs for transport server
sudo journalctl -u cfgms-controller | grep "Transport server listening"

# Check steward logs for transport connection
sudo journalctl -u cfgms-steward | grep -i "transport.*established\|connected to controller"

# Verify port 4433 (UDP) is listening
sudo ss -ulnp | grep 4433
```

**2. REST API Health**:
```bash
# From any machine that can reach the controller
curl http://controller-vm:9080/api/v1/health
```

## Troubleshooting

See [home-lab-checklist.md](home-lab-checklist.md) for a detailed pre-deployment checklist.

### Quick Debug Commands

```bash
# View controller logs
sudo journalctl -u cfgms-controller -f

# View steward logs
sudo journalctl -u cfgms-steward -f

# Restart a component
sudo systemctl restart cfgms-controller
sudo systemctl restart cfgms-steward

# Check listening ports on controller (TCP for REST API, UDP for transport)
sudo ss -tlnp | grep 9080
sudo ss -ulnp | grep 4433
```

### Common Issues

**Issue**: "Error: signature verification failed"
- **Root Cause**: Controller using mismatched certificates
- **Fix**: Ensure controller generated certs on first boot; check `/var/lib/cfgms/certs/`
- **Verify**: Check controller logs show same certificate serial for signer and registration

**Issue**: "Timeout waiting for config status"
- **Debug**: Check transport connection established in steward logs
- **Debug**: Check module executor initialized
- **Debug**: Check gRPC SyncConfig call visible in steward logs
- **Fix**: See diagnostic test output for exact failure point

**Issue**: "Cannot connect to transport / connection refused on :4433"
- **Debug**: Check controller is running: `sudo systemctl status cfgms-controller`
- **Debug**: Check port 4433 is accessible from steward: `nc -zuv controller-vm 4433`
- **Debug**: Check certificates are valid in controller logs
- **Fix**: Verify firewall allows UDP port 4433; confirm transport config `listen_addr` is correct

**Issue**: "gRPC stream broken / TLS handshake error"
- **Debug**: Check steward and controller certificate fingerprints match
- **Debug**: Look for "certificate signed by unknown authority" in steward logs
- **Fix**: Steward may need to re-register to obtain a fresh certificate from the current CA

## Advanced Configuration

### Multi-Steward Deployment

```bash
# Use the same registration token (if single_use was false)
# Deploy cfgms-steward binary to each VM with its own systemd unit
# Each steward gets a unique ID automatically
# All connect to the same controller via gRPC-over-QUIC (port 4433)
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
# Controllers coordinate via Raft consensus
```

**HA Environment Variables:**

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CFGMS_HA_MODE` | Yes | `single` | Deployment mode: `single`, `blue-green`, or `cluster` |
| `CFGMS_HA_CA_CERT_PATH` | Recommended | (none) | Path to CA certificate PEM file for TLS validation between cluster nodes |
| `CFGMS_HA_EXTERNAL_ADDRESS` | Yes (cluster) | (none) | This node's address visible to other cluster nodes |
| `CFGMS_HA_CLUSTER_NODES` | Yes (cluster) | (none) | Comma-separated list of all cluster node addresses |
| `CFGMS_HA_DISCOVERY_METHOD` | No | `static` | Node discovery method |
| `CFGMS_HA_ELECTION_TIMEOUT` | No | `5s` | Raft leader election timeout |
| `CFGMS_HA_HEARTBEAT_INTERVAL` | No | `2s` | Heartbeat interval between nodes |

### M365 Integration

```bash
# Configure Microsoft 365 directory provider
export CFGMS_DIRECTORY_PROVIDER=m365
export CFGMS_M365_TENANT_ID=your-tenant-id
export CFGMS_M365_CLIENT_ID=your-client-id
export CFGMS_M365_CLIENT_SECRET=your-client-secret

# Restart controller
sudo systemctl restart cfgms-controller
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
- **Transport Architecture**: [docs/architecture/communication-layer-migration.md](../architecture/communication-layer-migration.md)
- **Quick Start**: [QUICK_START.md](../../QUICK_START.md)

---

**Deployment Support**: If you encounter issues, check GitHub issues or create a new issue with:
- Output of `sudo journalctl -u cfgms-controller --no-pager -n 50`
- Output of `sudo journalctl -u cfgms-steward --no-pager -n 50`
- Output of E2E test runs
- Description of unexpected behavior
