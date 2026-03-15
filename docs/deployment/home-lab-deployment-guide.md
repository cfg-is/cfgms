# CFGMS Home Lab Deployment Guide

**Story #391**: Comprehensive guide for deploying CFGMS to a home lab environment with native binaries and full MQTT+QUIC integration.

**Last Updated**: 2026-03-15
**CFGMS Version**: v0.9.x
**Deployment Time**: ~30-45 minutes (first-time setup)

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Detailed Setup](#detailed-setup)
   - [Step 1: Build Binaries](#step-1-build-cfgms-binaries)
   - [Step 2: Configure Storage](#step-2-configure-storage-backend)
   - [Step 3: Deploy Controller](#step-3-deploy-controller)
   - [Step 4: Create Registration Token](#step-4-create-registration-token)
   - [Step 5: Deploy Linux Steward](#step-5-deploy-linux-steward)
   - [Step 6: Deploy Windows Steward](#step-6-deploy-windows-steward)
   - [Step 7: Module Configuration Examples](#step-7-module-configuration-examples)
5. [Validation](#validation)
6. [Troubleshooting](#troubleshooting)
7. [Advanced Configuration](#advanced-configuration)

## Overview

This guide walks you through deploying a complete CFGMS environment in your home lab using native binaries, including:

- **Controller**: Central management server (REST API + embedded MQTT broker + QUIC data plane)
- **Steward(s)**: Endpoint agents for configuration management
- **Storage Backend**: Git with SOPS encryption (default)

> **Quick Start?** See [QUICK_START.md](../../QUICK_START.md) for a 5-15 minute getting-started guide.
> This document covers production-style native deployment with systemd.

**What You'll Achieve**:
- Fully functional CFGMS deployment on native VMs
- Validated MQTT+QUIC communication paths
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
│  │  - MQTT broker    :1883      │  (embedded, not separate) │
│  │  - QUIC server    :4433      │                           │
│  │  - Certificate CA            │                           │
│  └──────────────────────────────┘                           │
│         ▲              ▲                                     │
│         │              │                                     │
│    MQTT (mTLS)    QUIC (mTLS)                               │
│    :1883          :4433                                      │
│         │              │                                     │
│  ┌──────┴──────────────┴────────────────────────┐          │
│  │                                                │          │
│  │              Steward(s)                        │          │
│  │                                                │          │
│  │  - Config executor                            │          │
│  │  - Module engine (file, directory, script)    │          │
│  │  - Status reporter                            │          │
│  └───────────────────────────────────────────────┘          │
│                                                              │
└─────────────────────────────────────────────────────────────┘

Control Plane: MQTT (commands, heartbeats, status reports) - port 1883
Data Plane: QUIC (configuration sync, high-throughput data) - port 4433
Management Plane: REST API (config uploads, admin operations) - port 9080
```

**Note**: The MQTT broker is embedded in the controller binary. There is no separate MQTT broker service to deploy.

### Communication Protocols

1. **MQTT** (Control Plane - Port 1883 with mTLS):
   - Command delivery (`connect_quic`, `sync_config`, `heartbeat`)
   - Status reporting (`config-status`, `health-status`)
   - Real-time notifications

2. **QUIC** (Data Plane - Port 4433 with mTLS):
   - Configuration synchronization (signed configs)
   - High-performance data transfer
   - DNA (Desired Next Action) delivery

3. **REST API** (Management Plane - Port 9080):
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

# Optional: MQTT client tools for testing
mosquitto_pub --help  # mosquitto-clients package
```

### Network Requirements

**Ports** (ensure these are available on the controller):
- `9080`: Controller REST API (HTTP/HTTPS)
- `1883`: MQTT broker (mTLS, embedded in controller)
- `4433`: QUIC data plane (mTLS)

**Firewall Rules** (controller host):

All three ports must be reachable by stewards. Note that QUIC uses **UDP**, not TCP.

```bash
# Linux (ufw)
sudo ufw allow 9080/tcp   # REST API (registration + admin)
sudo ufw allow 1883/tcp   # MQTT control plane (heartbeats, commands)
sudo ufw allow 4433/udp   # QUIC data plane (config sync) — UDP, not TCP
sudo ufw allow 22/tcp     # SSH management

# Linux (firewalld)
sudo firewall-cmd --permanent --add-port=9080/tcp
sudo firewall-cmd --permanent --add-port=1883/tcp
sudo firewall-cmd --permanent --add-port=4433/udp
sudo firewall-cmd --reload

# Windows (PowerShell, if controller runs on Windows)
New-NetFirewallRule -DisplayName "CFGMS REST API" -Direction Inbound -Port 9080 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "CFGMS MQTT" -Direction Inbound -Port 1883 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "CFGMS QUIC" -Direction Inbound -Port 4433 -Protocol UDP -Action Allow
```

**Steward outbound requirements** (steward hosts only need outbound access):

| Destination | Port | Protocol | Purpose |
|-------------|------|----------|---------|
| Controller | 9080 | TCP | Initial registration (one-time) |
| Controller | 1883 | TCP | MQTT control plane (persistent) |
| Controller | 4433 | UDP | QUIC data plane (on-demand) |

Stewards do **not** need any inbound ports opened. All connections are initiated outbound
from the steward to the controller.

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
# CFGMS Controller Configuration
# See docs/examples/ for additional configuration options.

# --- Networking ---
# listen_addr: REST API bind address. Use 0.0.0.0 to accept connections
# from stewards on other machines.
listen_addr: "0.0.0.0:9080"

# external_url: The address stewards use to reach this controller.
# Set this to the controller's hostname or IP as seen from the network.
# Stewards receive MQTT/QUIC addresses derived from this URL during registration.
external_url: "https://CONTROLLER_IP_OR_HOSTNAME:9080"

# --- Storage ---
storage:
  provider: git
  config:
    repository_path: /var/lib/cfgms/storage
    branch: main
    auto_init: true
    # Optional: push to a remote for backup
    # remote_url: "git@github.com:yourorg/cfgms-config.git"
    # ssh_key_path: "/etc/cfgms/deploy-key"

# --- Certificates ---
# On first boot (--init), the controller generates a CA and server certificates.
# All MQTT and QUIC connections use mTLS from these certificates.
# Stewards receive their client certificates automatically during registration.
certificate:
  enable_cert_management: true
  ca_path: /var/lib/cfgms/certs
  server:
    common_name: cfgms-controller
    # Add your controller's hostname and IP so stewards can verify TLS.
    dns_names:
      - localhost
      - cfgms-controller
      - CONTROLLER_HOSTNAME
    ip_addresses:
      - "127.0.0.1"
      - "CONTROLLER_IP"

# --- Logging ---
logging:
  provider: file
  level: INFO
  config:
    directory: /var/log/cfgms

# --- MQTT (Control Plane) ---
mqtt:
  enabled: true
  listen_addr: "0.0.0.0:1883"
  enable_tls: true
  use_cert_manager: true
  require_client_cert: true

# --- QUIC (Data Plane) ---
quic:
  enabled: true
  listen_addr: "0.0.0.0:4433"
  use_cert_manager: true
EOF

echo ""
echo "IMPORTANT: Edit /etc/cfgms/controller.cfg and replace:"
echo "  - CONTROLLER_IP_OR_HOSTNAME with your controller's IP or hostname"
echo "  - CONTROLLER_HOSTNAME with the DNS name (if any)"
echo "  - CONTROLLER_IP with the IP address"
```

#### 3c: Initialize Controller (First Boot Only)

```bash
# Run initialization to generate CA, certificates, and storage.
# This only needs to happen once. Subsequent starts skip initialization.
sudo /usr/local/bin/cfgms-controller --init --config /etc/cfgms/controller.cfg

# Verify certificates were generated
ls /var/lib/cfgms/certs/
# Expected: ca/ directory with CA cert and key, plus server certificates
```

#### 3d: Create systemd Service

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

#### 3e: Verify Controller Health

```bash
# Check service status
sudo systemctl status cfgms-controller

# Check logs for successful startup
sudo journalctl -u cfgms-controller --no-pager -n 30

# Look for these log messages:
# ✓ "Certificate manager initialized"
# ✓ "Generated server certificate" (first boot only)
# ✓ "MQTT broker started"
# ✓ "QUIC server listening on :4433"
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

### Step 5: Deploy Linux Steward

The steward binary must be built with the controller URL baked in at compile time.
This is a security feature — the signed binary is a trust assertion about which controller it connects to.

#### 5a: Build Steward with Controller URL

```bash
# On the build machine, build with the controller URL embedded.
# Replace CONTROLLER_IP_OR_HOSTNAME with the same value from controller.cfg.
make build-steward STEWARD_CONTROLLER_URL=https://CONTROLLER_IP_OR_HOSTNAME:9080

# Or build directly with ldflags:
go build -ldflags "-X main.ControllerURL=https://CONTROLLER_IP_OR_HOSTNAME:9080" \
  -o bin/cfgms-steward ./cmd/steward
```

#### 5b: Copy Binary to Steward VM

```bash
scp bin/cfgms-steward user@steward-vm:/tmp/cfgms-steward
ssh user@steward-vm "chmod +x /tmp/cfgms-steward"
```

#### 5c: Install as Service

The steward has a built-in `install` subcommand that copies the binary to `/usr/local/bin/`,
creates a systemd unit with `Restart=always` and `RestartSec=10`, and starts the service.

```bash
# On the steward VM (requires root)
# Replace TOKEN with the registration token from Step 4.
sudo /tmp/cfgms-steward install --regtoken TOKEN
```

Expected output:
```
Installing to /usr/local/bin/cfgms-steward...
Registering systemd service...
Starting service...

Done. CFGMS Steward installed and running.
  Service name: cfgms-steward
  Status:  cfgms-steward status
  Remove:  cfgms-steward uninstall
```

**Alternative: Manual systemd setup** (if you prefer to control the unit file):

```bash
sudo cp /tmp/cfgms-steward /usr/local/bin/cfgms-steward

sudo tee /etc/systemd/system/cfgms-steward.service > /dev/null <<EOF
[Unit]
Description=CFGMS Steward Configuration Management Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-steward --regtoken TOKEN
Restart=always
RestartSec=10
User=root
Environment=CFGMS_LOG_DIR=/var/log/cfgms

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cfgms-steward
```

#### 5d: Verify Registration

```bash
# Check steward service status
sudo systemctl status cfgms-steward

# Check logs for successful registration
sudo journalctl -u cfgms-steward --no-pager -n 30

# Look for these messages (in order):
# ✓ "Using registration token for auto-registration (MQTT+QUIC mode)"
# ✓ "Registration successful via HTTP"
# ✓ "Connected to controller via MQTT+QUIC"
# ✓ "Configuration executor initialized"

# Or use the built-in status command:
cfgms-steward status
```

#### 5e: Managing the Service

```bash
# Check status
cfgms-steward status

# View live logs
sudo journalctl -u cfgms-steward -f

# Restart
sudo systemctl restart cfgms-steward

# Uninstall (stops service, removes unit file)
sudo cfgms-steward uninstall

# Uninstall and remove the binary
sudo cfgms-steward uninstall --purge
```

### Step 6: Deploy Windows Steward

#### 6a: Build for Windows

```bash
# Cross-compile from Linux/macOS build machine:
make build-steward-cross GOOS=windows GOARCH=amd64 \
  STEWARD_CONTROLLER_URL=https://CONTROLLER_IP_OR_HOSTNAME:9080

# Or build directly:
GOOS=windows GOARCH=amd64 go build \
  -ldflags "-X main.ControllerURL=https://CONTROLLER_IP_OR_HOSTNAME:9080" \
  -o bin/cfgms-steward.exe ./cmd/steward

# If building on Windows directly:
go build -ldflags "-X main.ControllerURL=https://CONTROLLER_IP_OR_HOSTNAME:9080" ^
  -o bin\cfgms-steward.exe .\cmd\steward
```

#### 6b: Copy Binary to Windows Machine

Copy `bin/cfgms-steward.exe` to the Windows machine. Any of these work:
- SCP/SFTP to a temporary location
- Network share
- USB drive
- RMM tool deployment

#### 6c: Install as Windows Service

**Option A: Interactive mode (double-click)**

Double-click `cfgms-steward.exe`. The interactive UI prompts for the registration token
and offers to install as a service:

```
CFGMS Steward v0.9.2

Controller: https://controller.example.com:9080

Registration token: ████████████████████████████

  [1] Install as service (recommended)
  [2] Run once (foreground)
  [3] Exit

Choice: 1

Installing to C:\Program Files\CFGMS\cfgms-steward.exe...
Registering Windows service...
Starting service...

Done. CFGMS Steward installed and running.
  Service name: CFGMSSteward
  Status:  cfgms-steward status
  Remove:  cfgms-steward uninstall
```

**Option B: Command-line install (Administrator)**

Open an Administrator Command Prompt or PowerShell:

```powershell
# Install as Windows Service (copies binary to C:\Program Files\CFGMS\)
.\cfgms-steward.exe install --regtoken TOKEN
```

The steward uses the native Windows Service API (`golang.org/x/sys/windows/svc`) — not
`sc.exe`. The service is registered as `CFGMSSteward` with automatic start and failure
recovery (restart after 10s, 30s, 60s escalating delays).

#### 6d: Verify on Windows

```powershell
# Built-in status command (works without Administrator)
cfgms-steward.exe status

# Or check Windows Services (services.msc)
# Look for "CFGMSSteward" — should show Status: Running, Startup Type: Automatic

# View logs in Event Viewer or log directory
# Default log location: C:\ProgramData\CFGMS\logs\ (when CFGMS_LOG_DIR is not set)
```

#### 6e: Managing the Windows Service

```powershell
# Check status
cfgms-steward.exe status

# Uninstall (stops service, removes registration)
cfgms-steward.exe uninstall

# Uninstall and remove binary from Program Files
cfgms-steward.exe uninstall --purge
```

**Re-installing (idempotent)**: Running `install` again stops the existing service,
replaces the binary, and restarts — no need to uninstall first.

### Step 7: Module Configuration Examples

After stewards are registered and connected, push configurations from the controller.
Below are practical examples for common modules.

#### Test Connectivity First

```bash
# On the controller, push a simple test file to verify the pipeline works.
curl -X POST http://localhost:9080/api/v1/configurations \
  -H "Content-Type: application/yaml" \
  --data-binary @- <<EOF
resources:
  - name: smoke-test
    module: file
    config:
      path: /tmp/cfgms-test.txt
      content: "CFGMS is working."
      permissions: "0644"
      ensure: present
EOF

# Check steward logs — should see config applied within 60 seconds.
```

#### File Module

Manages file content, ownership, and permissions. The steward creates the file if
it does not exist and corrects drift if the content or metadata changes.

```yaml
resources:
  - name: ntp-config
    module: file
    config:
      path: /etc/ntp.conf
      content: |
        # Managed by CFGMS — do not edit manually
        driftfile /var/lib/ntp/drift
        server 0.pool.ntp.org iburst
        server 1.pool.ntp.org iburst
        restrict default kod nomodify notrap nopeer noquery
        restrict 127.0.0.1
      owner: root
      group: root
      permissions: "0644"

  - name: motd
    module: file
    config:
      path: /etc/motd
      content: |
        ========================================
        This server is managed by CFGMS.
        Unauthorized changes will be reverted.
        ========================================
      permissions: "0644"
```

#### Directory Module

Creates directories and enforces ownership and permissions recursively.

```yaml
resources:
  - name: app-directories
    module: directory
    config:
      path: /opt/myapp
      owner: appuser
      permissions: 755
      recursive: true

  - name: log-directory
    module: directory
    config:
      path: /var/log/myapp
      owner: appuser
      group: appuser
      permissions: 750
```

#### Script Module

Executes scripts on the steward. Use for tasks that don't fit neatly into
declarative modules (bootstrapping, one-time setup, health checks).

```yaml
resources:
  - name: ensure-swap
    module: script
    config:
      interpreter: /bin/bash
      content: |
        #!/bin/bash
        # Ensure 2GB swap file exists
        if [ ! -f /swapfile ]; then
          fallocate -l 2G /swapfile
          chmod 600 /swapfile
          mkswap /swapfile
          swapon /swapfile
          echo '/swapfile none swap sw 0 0' >> /etc/fstab
          echo "Swap created"
        else
          echo "Swap already exists"
        fi
```

#### Package Module

Installs, removes, or updates packages. The steward detects the platform package
manager automatically (apt, yum/dnf, brew, choco).

```yaml
resources:
  - name: baseline-packages
    module: package
    config:
      packages:
        - name: curl
          state: installed
        - name: htop
          state: installed
        - name: unattended-upgrades
          state: installed
          version: latest
        - name: telnet
          state: absent
```

#### Firewall Module

Manages firewall rules. Uses iptables on Linux, Windows Firewall on Windows.

```yaml
resources:
  - name: web-server-rules
    module: firewall
    config:
      rules:
        - name: allow-ssh
          port: 22
          protocol: tcp
          action: allow
          source: "10.0.0.0/8"
        - name: allow-http
          port: 80
          protocol: tcp
          action: allow
          source: "0.0.0.0/0"
        - name: allow-https
          port: 443
          protocol: tcp
          action: allow
          source: "0.0.0.0/0"
        - name: block-telnet
          port: 23
          protocol: tcp
          action: deny
          source: "0.0.0.0/0"
```

#### Combining Modules (Real-World Example)

A complete configuration for a web server steward:

```yaml
resources:
  # 1. Ensure directory structure exists
  - name: web-directories
    module: directory
    config:
      path: /var/www/html
      owner: www-data
      group: www-data
      permissions: 755
      recursive: true

  # 2. Install required packages
  - name: web-packages
    module: package
    config:
      packages:
        - name: nginx
          state: installed
        - name: certbot
          state: installed

  # 3. Deploy nginx configuration
  - name: nginx-config
    module: file
    config:
      path: /etc/nginx/sites-available/default
      content: |
        server {
            listen 80 default_server;
            root /var/www/html;
            index index.html;
            server_name _;

            location / {
                try_files $uri $uri/ =404;
            }
        }
      owner: root
      group: root
      permissions: "0644"

  # 4. Open firewall ports
  - name: web-firewall
    module: firewall
    config:
      rules:
        - name: allow-http
          port: 80
          protocol: tcp
          action: allow
        - name: allow-https
          port: 443
          protocol: tcp
          action: allow

  # 5. Restart nginx after config changes
  - name: restart-nginx
    module: script
    config:
      interpreter: /bin/bash
      content: |
        nginx -t && systemctl reload nginx
```

## Validation

### Automated E2E Tests

The E2E test suite validates the complete MQTT+QUIC flow:

```bash
cd test/integration/mqtt_quic

# Registration flow
go test -v -run TestRegistration -timeout 60s

# Configuration sync via QUIC
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

**1. MQTT Connectivity**:
```bash
# Subscribe to steward topics (requires mosquitto-clients)
mosquitto_sub -h controller-vm -p 1883 -t "cfgms/steward/#" -v

# You should see heartbeat and status messages
```

**2. QUIC Connectivity**:
```bash
# Check controller logs for QUIC server
sudo journalctl -u cfgms-controller | grep "QUIC server listening"

# Check steward logs for QUIC connection
sudo journalctl -u cfgms-steward | grep "QUIC.*established"
```

**3. REST API Health**:
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

# Check listening ports on controller
sudo ss -tlnp | grep -E '9080|1883|4433'
```

### Common Issues

**Issue**: Steward fails with "controller URL not set"
- **Cause**: Binary was built without `-ldflags "-X main.ControllerURL=..."`.
- **Fix**: Rebuild the steward with the controller URL. See [Step 5a](#5a-build-steward-with-controller-url).

**Issue**: "HTTP registration failed" or "connection refused"
- **Cause**: Steward cannot reach the controller REST API on port 9080.
- **Debug**: From the steward machine, test connectivity:
  ```bash
  # Linux
  curl -k https://CONTROLLER_IP:9080/api/v1/health

  # Windows (PowerShell)
  Invoke-WebRequest -Uri https://CONTROLLER_IP:9080/api/v1/health -SkipCertificateCheck
  ```
- **Fix**: Check controller is running, firewall allows 9080/tcp, and `external_url` in
  controller.cfg matches the address stewards use.

**Issue**: "Error: signature verification failed"
- **Cause**: Controller using mismatched certificates (e.g., certs regenerated after stewards registered).
- **Fix**: Ensure controller generated certs on first boot with `--init`; check `/var/lib/cfgms/certs/`.
- **Verify**: Check controller logs show same certificate serial for signer and registration.

**Issue**: "Cannot connect to MQTT broker"
- **Cause**: Steward registered but cannot establish MQTT control plane connection.
- **Debug**:
  ```bash
  # Check controller is running
  sudo systemctl status cfgms-controller

  # Check port 1883 is reachable from steward machine
  nc -zv CONTROLLER_IP 1883
  ```
- **Fix**: Verify firewall allows port 1883/tcp. Check controller logs for MQTT broker startup.

**Issue**: "QUIC connection failed"
- **Cause**: Data plane cannot be established (config sync will fail).
- **Debug**:
  ```bash
  # QUIC uses UDP — test differently than TCP
  nc -zuv CONTROLLER_IP 4433
  ```
- **Fix**: Verify firewall allows **UDP** port 4433 (not TCP). This is the most commonly
  missed rule since QUIC runs over UDP.

**Issue**: "Timeout waiting for config status"
- **Cause**: MQTT connected but config sync over QUIC did not complete.
- **Debug**: Check steward logs for QUIC connection, module executor initialization, and
  MQTT publish success. The failure point narrows the root cause.

**Issue (Windows)**: "install requires Administrator privileges"
- **Cause**: The `install` and `uninstall` subcommands need elevated access to register a
  Windows Service.
- **Fix**: Right-click `cfgms-steward.exe` and select "Run as administrator", or open an
  Administrator Command Prompt/PowerShell first.

**Issue (Windows)**: Service shows "Stopped" in services.msc immediately after install
- **Debug**: Check Windows Event Viewer > Application log for the `CFGMSSteward` source.
- **Common cause**: Controller URL not baked in at build time, or controller unreachable
  from the Windows machine. The service starts, fails registration, and exits. The recovery
  policy will retry after 10 seconds.

**Issue (Linux)**: Steward logs show "WARNING: Using /tmp/cfgms for logs"
- **Cause**: `CFGMS_LOG_DIR` environment variable not set.
- **Fix**: Either set `Environment=CFGMS_LOG_DIR=/var/log/cfgms` in the systemd unit or
  create the directory: `sudo mkdir -p /var/log/cfgms`

## Advanced Configuration

### Multi-Steward Deployment

```bash
# Use the same registration token (if single_use was false)
# Deploy cfgms-steward binary to each VM with its own systemd unit
# Each steward gets a unique ID automatically
# All connect to the same controller via MQTT+QUIC
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
- **MQTT+QUIC Details**: [docs/testing/mqtt-quic-testing-strategy.md](../testing/mqtt-quic-testing-strategy.md)
- **Quick Start**: [QUICK_START.md](../../QUICK_START.md)

---

**Deployment Support**: If you encounter issues, check GitHub issues or create a new issue with:
- Output of `sudo journalctl -u cfgms-controller --no-pager -n 50`
- Output of `sudo journalctl -u cfgms-steward --no-pager -n 50`
- Output of E2E test runs
- Description of unexpected behavior
