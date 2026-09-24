# CFGMS Production Operations Runbook

**Version**: 2.0  
**Last Updated**: 2026-09-21  
**Applies To**: CFGMS single-controller (Tier 1) production deployments

## Overview

This runbook provides step-by-step procedures for common operational scenarios
in CFGMS production environments. It covers monitoring, troubleshooting,
incident response, and disaster recovery procedures.

Every command in this runbook exists in the shipped binaries. Where CFGMS has
no command for a task, the runbook says so rather than inventing one.

## Table of Contents

1. [System Architecture Overview](#system-architecture-overview)
2. [Monitoring and Alerting](#monitoring-and-alerting)
3. [Common Operational Procedures](#common-operational-procedures)
4. [Incident Response Procedures](#incident-response-procedures)
5. [Disaster Recovery Procedures](#disaster-recovery-procedures)
6. [Performance Troubleshooting](#performance-troubleshooting)
7. [Maintenance Procedures](#maintenance-procedures)

## System Architecture Overview

### Core Components

- **Controller**: Central management system (`cfgms-controller`)
- **Stewards**: Endpoint agents (`cfgms-steward`, outbound connections only)
- **Certificate Manager**: mTLS certificate lifecycle management (`pkg/cert`)
- **Terminal Manager**: Secure terminal session management
- **RBAC Manager**: Role-based access control
- **Workflow Engine**: Automation and orchestration
- **Admin CLI**: `cfg`, a stateless invoke-and-exit client of the REST API

### Key Directories

- `/var/lib/cfgms/` - Controller data storage (SQLite database and flat-file state)
- `/var/log/cfgms/` - Controller and steward log files
- `/etc/cfgms/controller.cfg` - Controller configuration (YAML)
- `/etc/cfgms/certs/` - Certificate storage
- `/etc/cfgms/secrets.key.cred` - `systemd-creds`-sealed secret-encryption key (ADR-030)

### Network Architecture

- All steward connections are outbound (no open ports on endpoints)
- The controller has three listeners, each set in `controller.cfg`:
  - `listen_addr` - REST API (HTTPS). Default `127.0.0.1:8080`.
  - `transport.listen_addr` - gRPC-over-QUIC steward transport (mTLS)
  - `metrics_listen_addr` - private HTTPS metrics listener (required; the
    controller refuses to start without it)
- mTLS is required for all internal communication

## Monitoring and Alerting

### Critical Metrics to Monitor

#### System Health

- **Controller Availability**: Must be >99.9%
- **Certificate Expiration**: Alert 7 days before expiry
- **Memory Usage**: Alert if >80% of allocated memory
- **CPU Usage**: Alert if >70% sustained for >5 minutes
- **Disk Space**: Alert if >85% full

#### Performance Metrics

- **Transport Connection Count**: Alert if approaching `transport.max_connections`
- **gRPC Request Latency**: Alert if P95 >500ms
- **Error Rate**: Alert if >5% of requests fail

#### Security Metrics

- **Denied or Failed Requests**: Alert if >10/minute in the audit log
- **Certificate Validation Failures**: Alert immediately
- **Unusual Terminal Activity**: Alert for suspicious commands

### Monitoring Tools Integration

#### Health Check Endpoints

Both endpoints are unauthenticated and served on the REST API listener.

```bash
# Liveness: object presence. Returns "degraded" while a cluster drain is active.
curl https://<controller>:8080/api/v1/health

# Readiness: round-trips durable storage.
curl https://<controller>:8080/api/v1/ready

# Authenticated component health (requires monitoring:read-health)
curl -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
  https://<controller>:8080/api/v1/monitoring/health
```

#### Detailed Health, Metrics and Request Tracing

`GET /api/v1/health/detailed`, `GET /api/v1/health/metrics` and
`GET /api/v1/health/trace/{request_id}` are authenticated (mTLS admin bundle
or session), served on the REST API listener, and gated by the same
permission pattern as `/api/v1/monitoring/*`
(`monitoring:read-detailed-health`, `monitoring:read-metrics`,
`monitoring:read-trace` respectively). They back the `cfg` CLI's operational
commands:

```bash
# Component-by-component health status, active alerts, and uptime
cfg controller status --url https://<controller>:8080

# Transport, storage, application and system metrics
cfg controller metrics --url https://<controller>:8080

# A specific request's trace (spans, timing, status) by request ID
cfg trace <request-id> --url https://<controller>:8080
```

Traces are retained for 24 hours. `GET /api/v1/health/metrics/history`,
`GET /api/v1/health/alerts`, `GET /api/v1/health/alerts/history` and
`GET /api/v1/health/traces` are registered on the same listener under the
matching `monitoring:read-*` permissions but have no dedicated `cfg`
subcommand yet.

#### Metrics

CFGMS does not expose a Prometheus scrape endpoint. Metrics are JSON, served
only on the private metrics listener (`metrics_listen_addr`) and gated by the
`monitoring:read-metrics` permission:

```bash
curl -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
  https://<metrics-listen-addr>/api/v1/monitoring/metrics
```

The response carries CPU, memory, disk and network figures plus active and
total steward counts.

#### Log Monitoring

The file logging provider writes `cfgms-<timestamp>.log` files under
`/var/log/cfgms/` on both controller and steward hosts and rotates them itself
(`max_file_size`, `max_files`, `compress_rotated` under `logging.config`).

```bash
# Follow the newest controller log file
tail -f "$(ls -t /var/log/cfgms/cfgms-*.log | head -1)"

# Service logs
journalctl -u cfgms-controller -f
journalctl -u cfgms-steward -f
```

## Common Operational Procedures

### 1. Controller Restart

**When to use**: Controller service issues, configuration changes, memory leaks

```bash
# Check current status
systemctl status cfgms-controller

# Graceful restart
systemctl restart cfgms-controller

# Verify restart
systemctl status cfgms-controller
curl https://<controller>:8080/api/v1/ready

# Check logs for errors
journalctl -u cfgms-controller --since "5 minutes ago"
```

**Expected restart time**: < 30 seconds  
**Steward reconnection time**: < 60 seconds

### 2. Certificate Renewal

**When to use**: Certificate expiration alerts, manual renewal

The controller generates its CA and server certificates on first boot and
manages them through `pkg/cert`. Three credential types have their own
renewal path:

```bash
# Inspect the certificate store (default --storage /etc/cfgms/certs)
cert-manager list
cert-manager stats
cert-manager validate --serial <serial>

# Renew one stored certificate by serial
cert-manager renew --serial <serial>

# Renew this host's admin mTLS credential before it expires
cfg credential renew

# Rotate the controller's payload-signing certificate
cfg controller signing-cert rotate --url https://<controller>:8080

# Steward certificate refresh: stewards raise refresh requests; approve them
cfg steward refresh list
cfg steward refresh approve <pending_id>

# Verify a certificate on disk
openssl x509 -in /etc/cfgms/certs/<file>.crt -text -noout | grep "Not After"
```

Restart `cfgms-controller` after replacing a certificate the running process
loaded at startup.

### 3. Terminal Session Management

**When to use**: Terminal sessions stuck, resource exhaustion

Terminal sessions end when the WebSocket closes or when the terminal
manager's session timeout elapses; restarting `cfgms-controller` ends all of them.

Login sessions (cfg CLI and web) are a separate object and can be managed:

```bash
# List active login sessions (requires session:list)
curl -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
  https://<controller>:8080/api/v1/sessions

# Revoke one login session (requires session:revoke)
curl -X DELETE -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
  https://<controller>:8080/api/v1/sessions/<session_id>
```

### 4. Steward Connection Issues

**When to use**: Stewards not connecting, authentication failures

```bash
# Fleet view; the STATUS column shows each steward's connection state
cfg steward list
cfg steward status <hostname-or-selector>

# Check steward logs on the endpoint
journalctl -u cfgms-steward --since "10 minutes ago"

# Re-register a steward: mint a token on the controller ...
cfg token create --tenant-id <tenant> --controller-url https://<controller>:4433

# ... then re-run install on the endpoint (idempotent; restarts the service)
cfgms-steward install --regtoken <token> \
  --controller-url https://<controller> \
  --controller-ca /etc/cfgms/controller-ca.crt \
  --fingerprint <ca-sha256-hex>

# Pending registrations awaiting approval
cfg registration pending
cfg registration approve <pending_id>
```

The steward requests its own certificate refresh; approve it with
`cfg steward refresh approve`.

### 5. Database Maintenance

**When to use**: Scheduled maintenance, performance issues

Before maintenance, take the complete cold controller-state backup documented in
[`tier1-controller-bringup.md`](tier1-controller-bringup.md#cold-backup).
Backing up only SQLite is not sufficient: flat-file data, certificates, the
configuration, and the external secrets key are also required for recovery.

```bash
# Check database size
du -sh /var/lib/cfgms/cfgms.db /var/lib/cfgms

# With the controller service stopped, optimize SQLite
sqlite3 /var/lib/cfgms/cfgms.db "VACUUM; ANALYZE;"

# Check for corruption
sqlite3 /var/lib/cfgms/cfgms.db "PRAGMA integrity_check;"
```

## Incident Response Procedures

### High Availability Incident Response

#### Severity 1: Complete System Outage

**Response Time**: 15 minutes

1. **Immediate Actions** (0-5 minutes)

   ```bash
   # Check controller status
   systemctl status cfgms-controller

   # Check system resources
   free -h
   df -h
   top

   # Check the REST listener is bound (port from listen_addr)
   ss -tuln | grep 8080
   ```

2. **Diagnosis** (5-10 minutes)

   ```bash
   # Check recent logs
   journalctl -u cfgms-controller --since "30 minutes ago" --priority=err

   # Check certificate validity
   cert-manager list

   # Check database connectivity
   sqlite3 /var/lib/cfgms/cfgms.db ".tables"
   ```

3. **Recovery Actions** (10-15 minutes)

   ```bash
   # Restart controller service
   systemctl restart cfgms-controller

   # If state is corrupt, keep the controller stopped and follow the
   # complete cold-restore procedure in tier1-controller-bringup.md.

   # Verify recovery
   curl https://<controller>:8080/api/v1/ready
   ```

#### Severity 2: Performance Degradation

**Response Time**: 30 minutes

1. **Check Performance Metrics**

   ```bash
   # Check CPU and memory usage
   htop

   # Check transport connection count (port from transport.listen_addr)
   ss -an | grep :4433 | wc -l

   # Authenticated metrics snapshot
   curl -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
     https://<metrics-listen-addr>/api/v1/monitoring/metrics
   ```

2. **Mitigation Actions**

   Connection limits are keys in `/etc/cfgms/controller.cfg` and take effect
   on restart:

   ```yaml
   transport:
     max_connections: 100   # concurrent steward transport connections
     keepalive_period: 30s  # minimum 1s
     idle_timeout: 5m
   ```

   ```bash
   # Apply the change
   systemctl restart cfgms-controller
   ```

#### Severity 3: Individual Component Issues

**Response Time**: 60 minutes

1. **Isolate Affected Component**
2. **Check Component-Specific Logs**
3. **Apply Targeted Fix**
4. **Monitor for Resolution**

### Security Incident Response

#### Unauthorized Access Attempt

1. **Immediate Response**

   ```bash
   # Denied and failed requests in the last hour
   cfg controller audit list --url https://<controller>:8080 \
     --result denied --since "$(date -u -d '1 hour ago' +%FT%TZ)" --limit 500
   cfg controller audit list --url https://<controller>:8080 \
     --result failure --since "$(date -u -d '1 hour ago' +%FT%TZ)" --limit 500

   # Block suspicious IPs at the host firewall (if applicable)
   iptables -A INPUT -s <suspicious_ip> -j DROP
   ```

2. **Investigation**

   ```bash
   # All audit activity for one account
   cfg controller audit list --url https://<controller>:8080 \
     --user-id <username> --since <RFC3339> --format json

   # Certificates bound to the account
   cfg account certs <username>

   # Enrolment-flow certificates with no account binding
   cfg credential list-orphaned
   ```

3. **Containment**

   ```bash
   # Disable the account
   cfg account update <username> --disabled true

   # Revoke the account's certificates (serials from `cfg account certs`)
   cfg account revoke-cert <username> <serial>

   # Revoke passkeys registered to the account
   cfg webauthn list
   cfg webauthn revoke <credential_id>

   # Revoke a leaked steward registration token
   cfg token revoke <token>

   # Revoke every admin credential issued from one enrolment token
   cfg credential revoke-by-token <token-id>

   # Revoke active login sessions one at a time
   curl -X DELETE -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
     https://<controller>:8080/api/v1/sessions/<session_id>
   ```

   CFGMS accounts authenticate with mTLS certificates and passkeys; disabling
   the account and revoking its certificates and passkeys is the full
   containment step.

## Disaster Recovery Procedures

### Data Backup Procedures

CFGMS does not currently expose online `cfg backup` or `cfg restore` commands.
Use the supported systemd cold-backup and cold-restore procedures in
[`tier1-controller-bringup.md`](tier1-controller-bringup.md#8-recovery).
They capture `/var/lib/cfgms`, `/etc/cfgms/controller.cfg`, and the external
secret-encryption key at one stopped-service consistency point. The key is a
`systemd-creds`-sealed blob at `/etc/cfgms/secrets.key.cred` (ADR-030), so the
procedure unseals it for escrow and re-seals it on the target host — copying the
blob alone survives losing the file, not losing the machine.

Backups must be encrypted and access-controlled off-host. Restore-test them on
an isolated host at the same release, including audit-chain verification,
certificate validation, steward reconnection, and a signed configuration
operation. A checksum proves transfer integrity; it does not make an untrusted
archive safe to extract.

### Network Partition Recovery

**Scenario**: Network connectivity lost between controller and stewards

1. **Detection**

   ```bash
   # Fleet view; read the STATUS and LAST SEEN columns
   cfg steward list

   # Network connectivity to the transport listener
   ping <controller>
   nc -vz <controller> 4433
   ```

2. **Recovery**

   ```bash
   # On stewards: check network configuration
   ip route show

   # Restart steward service to trigger reconnection
   systemctl restart cfgms-steward

   # On controller: confirm stewards return
   cfg steward list
   ```

## Performance Troubleshooting

### High Memory Usage

1. **Diagnosis**

   ```bash
   # Check memory usage by component
   ps aux | grep cfgms | sort -k4 -nr

   # Authenticated metrics snapshot (heap and RSS bytes)
   curl -H "Authorization: Bearer $CFGMS_SESSION_TOKEN" \
     https://<metrics-listen-addr>/api/v1/monitoring/metrics
   ```

2. **Resolution**

   ```bash
   # Lower transport.max_connections in /etc/cfgms/controller.cfg, then
   systemctl restart cfgms-controller
   ```

### High CPU Usage

1. **Diagnosis**

   ```bash
   # Check CPU usage by component
   top -p $(pgrep -d, cfgms)

   # Check active transport connections
   ss -an | grep :4433 | wc -l

   # Check for runaway processes
   ps aux | grep cfgms | grep -v grep
   ```

2. **Resolution**

   ```bash
   # Lower transport.max_connections in /etc/cfgms/controller.cfg, then
   systemctl restart cfgms-controller
   ```

   To add capacity, deploy a controller cluster (see the `ha` section of
   `controller.cfg`).

### Slow Terminal Response

1. **Diagnosis**

   ```bash
   # Network latency from the steward host to the controller
   ping -c 10 <controller>
   mtr <controller>

   # Steward-side log while a session is open
   journalctl -u cfgms-steward -f
   ```

2. **Resolution**

   There are no terminal buffer-size or update-interval settings. Resolve the
   network path first; then restart `cfgms-steward` on the endpoint.

## Maintenance Procedures

### Regular Maintenance Tasks

#### Weekly Maintenance

```bash
#!/bin/bash
# /opt/cfgms/scripts/weekly-maintenance.sh

# Certificate inventory and expiry check
cert-manager stats
cert-manager list

# Database integrity (read-only check; safe while the controller runs)
sqlite3 /var/lib/cfgms/cfgms.db "PRAGMA integrity_check;"

# Clean up old backups (keep 30 days)
find /backup/cfgms -name "*.tar.gz" -mtime +30 -delete
```

Log rotation is done by the file logging provider itself; no external
`logrotate` job is needed.

#### Monthly Maintenance

```bash
#!/bin/bash
# /opt/cfgms/scripts/monthly-maintenance.sh

# Full system backup
# Follow the stopped-service cold-backup procedure linked above.

# Audit review: denied and failed requests for the month
cfg controller audit list --url https://<controller>:8080 \
  --result denied --since "$(date -u -d '30 days ago' +%FT%TZ)" --limit 500 --format json

# Orphaned enrolment-flow certificates
cfg credential list-orphaned

# Certificate inventory
cert-manager list
```

### Upgrade Procedures

#### Minor Version Upgrade

The generic `cfg migrate` command migrates storage, secrets and blob providers;
it does not migrate a database between release versions. Use the staged
systemd upgrade and explicit rollback procedure in
[`tier1-controller-bringup.md`](tier1-controller-bringup.md#6-manual-upgrade).
Take and restore-test a cold backup first, preserve the previous binary, and
confirm state-format compatibility in the exact release notes.

Steward upgrades are driven from the controller with `cfg steward upgrade run`,
tracked with `cfg steward upgrade status`, and reversed with
`cfg steward upgrade rollback`.

#### Major Version Upgrade

Do not infer a major-version migration procedure. Use only the signed release's
version-specific migration and rollback instructions after validating them in
an isolated copy of production state.

## Emergency Contacts

### Escalation Matrix

- **Level 1**: Operations Team (24/7)
- **Level 2**: Engineering Team (business hours)
- **Level 3**: Architecture Team (on-call)

### Communication Channels

- **Chat**: #cfgms-ops
- **Email**: <cfgms-ops@example.com>
- **Phone**: +1-555-CFGMS-OPS

## Appendix

### Log File Locations

```
/var/log/cfgms/cfgms-<timestamp>.log  - Controller log files (file logging provider)
/var/log/cfgms/cfgms-<timestamp>.log  - Steward log files (same provider, on each endpoint)
journalctl -u cfgms-controller        - Controller service output
journalctl -u cfgms-steward           - Steward service output
```

Audit entries live in the controller's database, not in a log file. Read them
with `cfg controller audit list`.

### Configuration Files

```
/etc/cfgms/controller.cfg           - Controller configuration (YAML)
```

Stewards installed with `cfgms-steward install` have no local configuration
file: the controller supplies their configuration through config sync. A
steward started with `cfgms-steward --config <file>` runs in standalone mode
from that file instead.

### Service Files

```
/etc/systemd/system/cfgms-controller.service
/etc/systemd/system/cfgms-steward.service
```

---

**Document Control**

- **Owner**: CFGMS Operations Team
- **Review Cycle**: Quarterly
- **Next Review**: 2026-12-21
- **Approval**: DevOps Manager, Security Team Lead
