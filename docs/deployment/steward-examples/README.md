# Steward Examples

Example steward configurations for common server roles. Use these as a starting point and customize for your environment.

Each example includes a `.cfg` file that can be used in two ways:

## Standalone Mode

A standalone steward runs from a local config file with no controller. It applies the desired state and exits.

### Building a standalone steward

Build the steward without a controller URL compiled in. Use `go build` directly — `make build-steward` always bakes in a default controller URL via ldflags, which you don't want for standalone use:

```bash
# Build a standalone steward (no controller URL baked in)
GOOS=linux GOARCH=amd64 go build -o bin/cfgms-steward ./cmd/steward
GOOS=windows GOARCH=amd64 go build -o bin/cfgms-steward.exe ./cmd/steward
```

Compare this to a controller-connected build, which bakes the controller URL into the binary so the steward knows where to register:

```bash
# Build a controller-connected steward (URL compiled in)
make build-steward STEWARD_CONTROLLER_URL=https://controller.example.com:9080
```

### Running

```bash
sudo cfgms-steward --config /etc/cfgms/steward.cfg
```

The steward reads the config, applies the desired state, and exits. Run it on a schedule (systemd timer, cron, Task Scheduler) to converge drift automatically.

## Controller-Managed Mode

Push the same resource definitions to a steward through the controller REST API. The steward receives its configuration over the network and applies it via its convergence loop.

```bash
curl -k -X PUT https://controller.example.com:9080/api/v1/stewards/<STEWARD_ID>/config \
  -H "Content-Type: application/json" \
  -d @steward-config.json
```

The `.cfg` files below define the same resources you'd include in the JSON payload's `resources` array. The structure is identical — the only difference is delivery method.

## Examples

### Windows

| Role | Config | What it manages |
|------|--------|----------------|
| Domain Controller | [domain-controller.cfg](domain-controller.cfg) | AD tools, DNS/DHCP services, event log auditing, firewall rules |
| File Server | [file-server.cfg](file-server.cfg) | Share directories, DFS, shadow copies, SMB firewall rules |
| SQL Server | [sql-server.cfg](sql-server.cfg) | SQL service, backup directories, TempDB config, firewall rules |
| Hyper-V Host | [hyperv-host.cfg](hyperv-host.cfg) | Hyper-V role, VM storage paths, virtual switch, live migration firewall |

### Linux

| Role | Config | What it manages |
|------|--------|----------------|
| Web Server | [web-server.cfg](web-server.cfg) | nginx, site config, TLS certificates directory, firewall rules |
| Database Server | [database-server.cfg](database-server.cfg) | PostgreSQL, data directories, pg_hba.conf, backup schedule, firewall rules |
| Docker Host | [docker-host.cfg](docker-host.cfg) | Docker engine, daemon.json, log rotation, storage directories |

## Customizing

Every example has `# CHANGE:` comments on the lines you need to modify for your environment. At minimum you'll need to update:

- Paths and directory names for your naming conventions
- IP addresses and subnets in firewall rules
- Service-specific settings (database names, site names, share paths, etc.)

## Running on a Schedule

For standalone mode, set up a timer to run the steward periodically:

### Linux (systemd timer)

```ini
# /etc/systemd/system/cfgms-steward.service
[Unit]
Description=CFGMS Steward convergence run

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cfgms-steward --config /etc/cfgms/steward.cfg
```

```ini
# /etc/systemd/system/cfgms-steward.timer
[Unit]
Description=Run CFGMS Steward every 30 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cfgms-steward.timer
```

### Windows (Scheduled Task)

```powershell
schtasks /create /tn "CFGMS Steward" /sc minute /mo 30 /ru SYSTEM `
  /tr "\"C:\Program Files\CFGMS\cfgms-steward.exe\" --config C:\ProgramData\CFGMS\steward.cfg"
```
