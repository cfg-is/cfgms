# Role Config Recipes

Fleet config recipes for common server roles. Push these to stewards from a controller
once your environment is set up.

**These are NOT steward boot configs.** A boot config identifies the steward and sets
basic runtime options — see [`docs/deployment/steward.cfg`](../../deployment/steward.cfg)
for the canonical steward boot config.

A role config recipe defines the *desired state* for a server role: packages, files,
firewall rules, scheduled tasks, etc. You push it to a steward from the controller:

```bash
cfg config upload --steward <STEWARD_ID> --config role-config.cfg
```

The steward then converges the endpoint to that desired state on its next run.

## Recipes

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

Every recipe has `# CHANGE:` comments on the lines you need to modify for your
environment. At minimum you'll need to update:

- Paths and directory names for your naming conventions
- IP addresses and subnets in firewall rules
- Service-specific settings (database names, site names, share paths, etc.)

## Using recipes standalone (no controller)

Each recipe also works as a standalone steward config if you don't have a controller
yet. Build the steward without a controller URL compiled in:

```bash
# Build a standalone steward (no controller URL baked in)
GOOS=linux GOARCH=amd64 go build -o bin/cfgms-steward ./cmd/steward
GOOS=windows GOARCH=amd64 go build -o bin/cfgms-steward.exe ./cmd/steward
```

Then run it directly:

```bash
sudo cfgms-steward --config /etc/cfgms/steward.cfg
```

The steward reads the config, applies the desired state, and exits. Run it on a
schedule to converge drift automatically.

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
