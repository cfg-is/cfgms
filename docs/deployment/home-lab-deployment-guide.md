# CFGMS Deployment Guide

A modular guide to deploying CFGMS with a controller and stewards. Follow the sections relevant to your environment.

**Time**: ~30 minutes (first-time setup)

## Architecture

```text
┌─────────────────────────────────────────┐
│            Controller (Linux)           │
│                                         │
│  REST API (HTTPS)        :8080          │
│  gRPC-over-QUIC (mTLS)  :4433/UDP      │
│  Auto-generated CA + certificates       │
│  Git+SOPS config storage                │
└────────────┬───────────────┬────────────┘
             │               │
     outbound connections only
             │               │
┌────────────┴──┐  ┌────────┴────────────┐
│ Linux Steward │  │  Windows Steward    │
│               │  │                     │
│ systemd svc   │  │  Windows Service    │
│ file, dir,    │  │  file, dir, script, │
│ script, pkg,  │  │  pkg, firewall,     │
│ firewall      │  │  patch              │
└───────────────┘  └─────────────────────┘
```

**Ports**: Controller listens on 8080/TCP (REST) and 4433/UDP (transport). Stewards make outbound connections only — no ports to open.

## Production: Steward-Managed Controller

For production fleets and multi-node deployments, controller nodes should be managed by a steward — the same way every other endpoint is managed. The steward handles directories, packages, firewall rules, and systemd services via its convergence loop, while the controller focuses on fleet orchestration.

See [Controller Bootstrap with Steward](controller-bootstrap-with-steward.md) for the production deployment guide and [ADR-002](../architecture/decisions/002-steward-bootstrap-for-controllers.md) for the architectural rationale.

The steps below are the manual deployment path — suitable for home labs, development, and single-server setups where a steward isn't needed.

## Prerequisites

- **Controller**: Debian/Ubuntu Linux VM with `git` and `sops` installed
- **Linux steward**: Any Linux VM with systemd
- **Windows steward**: Windows 10/11 or Server 2019+
- **Network**: Stewards must reach the controller on ports 8080 and 4433
- **Go toolchain**: v1.25+ on the build machine (can be the controller VM)

## Step 1: Build Binaries

On your build machine (can be the controller VM):

```bash
# Clone the repository
git clone https://github.com/cfg-is/cfgms.git
cd cfgms

# Build controller (Linux AMD64)
GOOS=linux GOARCH=amd64 go build -o bin/controller ./cmd/controller

# Build steward for Linux
GOOS=linux GOARCH=amd64 go build \
  -ldflags "-X main.ControllerURL=https://controller.example.com:8080" \
  -o bin/cfgms-steward-linux ./cmd/steward

# Build steward for Windows
GOOS=windows GOARCH=amd64 go build \
  -ldflags "-X main.ControllerURL=https://controller.example.com:8080" \
  -o bin/cfgms-steward-windows.exe ./cmd/steward
```

> **Replace `controller.example.com`** with your controller's hostname or IP address. This URL is compiled into the steward binary and cannot be changed after build.

## Step 2: Deploy Controller

Copy `bin/controller` to the controller VM.

### Create configuration

```bash
sudo mkdir -p /etc/cfgms
```

Create `/etc/cfgms/controller.cfg`:

```yaml
# Controller configuration
# Adjust listen_addr to your controller's IP or 0.0.0.0 for all interfaces
listen_addr: "0.0.0.0:8080"

# Certificate management (auto-generates CA and certs on first boot)
certificate:
  enable_cert_management: true
  ca_path: "/var/lib/cfgms/certs/ca"
  cert_path: "/var/lib/cfgms/certs"
  renewal_threshold_days: 30
  server_cert_validity_days: 365
  client_cert_validity_days: 365
  server:
    common_name: "controller.example.com"
    dns_names:
      - "controller.example.com"
      - "localhost"
    ip_addresses:
      - "127.0.0.1"
    organization: "My Organization"

# Storage backend (Git with SOPS encryption)
storage:
  provider: "git"
  config:
    repository_path: "/var/lib/cfgms/storage"
    branch: "main"
    auto_init: true

# Logging
logging:
  level: "info"
  provider: "file"
  config:
    directory: "/var/log/cfgms"
    max_file_size: 10485760
    max_files: 5

# gRPC-over-QUIC transport (steward connections)
transport:
  listen_addr: "0.0.0.0:4433"
  use_cert_manager: true
  max_connections: 50000
  keepalive_period: "30s"
  idle_timeout: "5m"
```

> **Replace `controller.example.com`** with your controller's actual hostname or IP in `common_name`, `dns_names`, and wherever it appears.

### Initialize and start

```bash
# Create data directories
sudo mkdir -p /var/lib/cfgms /var/log/cfgms

# Copy binary to standard location
sudo cp bin/controller /usr/local/bin/cfgms-controller
sudo chmod +x /usr/local/bin/cfgms-controller

# Initialize (generates CA and certificates)
sudo cfgms-controller --init --config /etc/cfgms/controller.cfg

# Start the controller
sudo cfgms-controller --config /etc/cfgms/controller.cfg
```

### Verify

```bash
# Health check
curl -k https://localhost:8080/health

# Or use the cfg CLI
cfg controller status --url https://localhost:8080 --insecure
```

You should see a healthy response with certificate info and transport status.

### Install as systemd service (recommended)

Create `/etc/systemd/system/cfgms-controller.service`:

```ini
[Unit]
Description=CFGMS Controller
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-controller --config /etc/cfgms/controller.cfg
Restart=on-failure
RestartSec=5
User=root
WorkingDirectory=/var/lib/cfgms

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable cfgms-controller
sudo systemctl start cfgms-controller
sudo systemctl status cfgms-controller
```

## Step 3: Create Registration Token

```bash
cfg token create \
  --tenant-id=my-lab \
  --controller-url=controller.example.com:4433 \
  --expires=30d
```

Save the token output — stewards need it to register.

## Step 4: Deploy Linux Steward

Copy `bin/cfgms-steward-linux` to the target Linux VM.

```bash
# Install as systemd service (requires root)
sudo ./cfgms-steward-linux install --regtoken <TOKEN>
```

This copies the binary to `/usr/local/bin/cfgms-steward`, creates a systemd service, registers with the controller, and starts automatically.

### Verify

```bash
sudo systemctl status cfgms-steward
sudo journalctl -u cfgms-steward -f
```

Look for: `Registration successful`, `Connected to controller successfully`, `Heartbeat sent`.

## Step 5: Deploy Windows Steward

Copy `bin/cfgms-steward-windows.exe` to the target Windows VM.

Open an **Administrator PowerShell**:

```powershell
.\cfgms-steward-windows.exe install --regtoken <TOKEN>
```

This copies to `C:\Program Files\CFGMS\cfgms-steward.exe`, registers as a Windows Service, and starts automatically.

### Verify

```powershell
Get-Service cfgms-steward
Get-EventLog -LogName Application -Source cfgms-steward -Newest 20
```

## Step 6: Push Configuration

Find your steward IDs:

```bash
curl -k https://controller.example.com:8080/api/v1/stewards | jq '.[] | {id, hostname}'
```

Replace `<STEWARD_ID>` in the examples below with a real steward ID.

### File module

Create a managed config file on the target.

**Linux** (`/etc/cfgms/example.conf`):

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "example-config",
      "module": "file",
      "config": {
        "path": "/etc/cfgms/example.conf",
        "content": "# Managed by CFGMS\nserver_name=my-server\nlog_level=info\n",
        "mode": "0644"
      }
    }]
  }'
```

**Windows** (`C:\cfgms\example.conf`):

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "example-config-win",
      "module": "file",
      "config": {
        "path": "C:\\cfgms\\example.conf",
        "content": "# Managed by CFGMS\r\nserver_name=my-server\r\nlog_level=info\r\n",
        "mode": "0644"
      }
    }]
  }'
```

### Directory module

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "app-directories",
      "module": "directory",
      "config": {
        "path": "/opt/myapp",
        "mode": "0755"
      }
    }]
  }'
```

### Script module

**Linux** (bash):

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "setup-script",
      "module": "script",
      "config": {
        "interpreter": "/bin/bash",
        "content": "#!/bin/bash\necho \"CFGMS setup complete\" > /tmp/cfgms-setup.log\ndate >> /tmp/cfgms-setup.log",
        "timeout": "30s"
      }
    }]
  }'
```

**Windows** (PowerShell):

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "setup-script-win",
      "module": "script",
      "config": {
        "interpreter": "powershell",
        "content": "Write-Output \"CFGMS setup complete\" | Out-File C:\\cfgms\\setup.log\nGet-Date | Out-File C:\\cfgms\\setup.log -Append",
        "timeout": "30s"
      }
    }]
  }'
```

### Package module

**Linux** (apt):

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "install-htop",
      "module": "package",
      "config": {
        "name": "htop",
        "state": "present",
        "provider": "apt"
      }
    }]
  }'
```

**Windows** (winget):

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "install-notepadpp",
      "module": "package",
      "config": {
        "name": "Notepad++.Notepad++",
        "state": "present",
        "provider": "winget"
      }
    }]
  }'
```

### Firewall module

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "allow-http",
      "module": "firewall",
      "config": {
        "rule": "allow",
        "protocol": "tcp",
        "port": 80,
        "direction": "inbound",
        "description": "Allow HTTP traffic"
      }
    }]
  }'
```

### Patch module (Windows only)

```bash
curl -k -X PUT https://controller.example.com:8080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d '{
    "steward": {"id": "<STEWARD_ID>", "mode": "controller"},
    "resources": [{
      "name": "patch-compliance",
      "module": "patch",
      "config": {
        "action": "check",
        "maintenance_window": {
          "start": "02:00",
          "end": "06:00",
          "days": ["Saturday", "Sunday"]
        }
      }
    }]
  }'
```

## Step 7: Validation Checklist

- [ ] **File**: Config files created with correct content and permissions
- [ ] **Directory**: Directories created with correct ownership
- [ ] **Script**: Scripts executed, output files created
- [ ] **Package**: Packages installed (`which htop`, `winget list`)
- [ ] **Firewall**: Rules active (`iptables -L` / `Get-NetFirewallRule`)
- [ ] **Patch**: Compliance check completed (Windows)
- [ ] **Status**: `curl -k https://controller.example.com:8080/api/v1/stewards/<ID>/config/status`
- [ ] **Controller restart**: `sudo systemctl restart cfgms-controller` — stewards reconnect
- [ ] **Steward restart**: Restart steward service — re-registers and reconnects

## Troubleshooting

### Controller won't start

```bash
sudo journalctl -u cfgms-controller -n 50

# Port in use:
ss -tlnp | grep 8080

# Permission denied:
ls -la /var/lib/cfgms /var/log/cfgms

# Certificate error — re-initialize:
sudo rm -rf /var/lib/cfgms/certs
sudo cfgms-controller --init --config /etc/cfgms/controller.cfg
```

### Steward won't register

```bash
# Linux logs
sudo journalctl -u cfgms-steward -n 50

# Windows logs
Get-EventLog -LogName Application -Source cfgms-steward -Newest 20

# "connection refused" → controller not running or firewall blocking 8080/4433
# "invalid token" → token expired or single-use already consumed
# "certificate error" → controller hostname doesn't match cert DNS names
```

### Config not applying

```bash
# Check config status on controller
curl -k https://controller.example.com:8080/api/v1/stewards/<ID>/config/status

# Check steward logs for module errors
sudo journalctl -u cfgms-steward --since "5 minutes ago"
```

### Connection drops

Stewards reconnect automatically with exponential backoff. Check:

- Network connectivity to controller ports 8080 and 4433
- Controller logs: `sudo journalctl -u cfgms-controller | grep -i error`
- Transport metrics: `cfg controller metrics --url https://controller.example.com:8080 --insecure`

## Next Steps

- Push configs with multiple resources in a single request
- Create sub-tenants for organizing stewards by role or location
- Monitor fleet health with `cfg controller metrics`
- Scale to 50,000+ concurrent steward connections
