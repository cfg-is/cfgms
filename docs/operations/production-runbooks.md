# CFGMS v0.3.0 Production Operations Runbook

**Version**: 1.0  
**Last Updated**: 2025-08-01  
**Applies To**: CFGMS v0.3.0 Production Deployment

## Overview

This runbook provides step-by-step procedures for common operational scenarios in CFGMS v0.3.0 production environments. It covers monitoring, troubleshooting, incident response, and disaster recovery procedures.

## Table of Contents

1. [System Architecture Overview](#system-architecture-overview)
2. [Monitoring and Alerting](#monitoring-and-alerting)
3. [Common Operational Procedures](#common-operational-procedures)
4. [Incident Response Procedures](#incident-response-procedures)
5. [Disaster Recovery Procedures](#disaster-recovery-procedures)
6. [Performance Troubleshooting](#performance-troubleshooting)
7. [Security Incident Response](#security-incident-response)
8. [Maintenance Procedures](#maintenance-procedures)

## System Architecture Overview

### Core Components
- **Controller**: Central management system (port 8080)
- **Stewards**: Endpoint agents (outbound connections only)
- **Certificate Manager**: mTLS certificate lifecycle management
- **Terminal Manager**: Secure terminal session management
- **RBAC Manager**: Role-based access control
- **Workflow Engine**: Automation and orchestration

### Key Directories
- `/opt/cfgms/` - Application binaries and configs
- `/var/log/cfgms/` - Application logs
- `/var/lib/cfgms/` - Data storage
- `/etc/cfgms/certs/` - TLS certificates

### Network Architecture
- All steward connections are outbound (no open ports on endpoints)
- Controller listens on port 8080 (HTTPS/gRPC)
- mTLS required for all internal communication

## Monitoring and Alerting

### Critical Metrics to Monitor

#### System Health
- **Controller Availability**: Must be >99.9%
- **Certificate Expiration**: Alert 7 days before expiry
- **Memory Usage**: Alert if >80% of allocated memory
- **CPU Usage**: Alert if >70% sustained for >5 minutes
- **Disk Space**: Alert if >85% full

#### Performance Metrics
- **Session Creation Latency**: Alert if >2 seconds average
- **Terminal Session Count**: Alert if approaching MaxSessions limit
- **gRPC Request Latency**: Alert if P95 >500ms
- **Error Rate**: Alert if >5% of requests fail

#### Security Metrics
- **Failed Authentication Attempts**: Alert if >10/minute
- **Privilege Escalation Attempts**: Alert immediately
- **Certificate Validation Failures**: Alert immediately
- **Unusual Terminal Activity**: Alert for suspicious commands

### Monitoring Tools Integration

#### Prometheus Metrics
```bash
# Check system metrics
curl http://localhost:8080/metrics

# Key metrics to monitor:
# - cfgms_controller_uptime_seconds
# - cfgms_terminal_active_sessions
# - cfgms_certificate_days_until_expiry
# - cfgms_grpc_request_duration_seconds
# - cfgms_error_rate_percent
```

#### Health Check Endpoints
```bash
# Controller health
curl https://localhost:8080/health

# Expected response: {"status": "healthy", "timestamp": "..."}
```

#### Log Monitoring
```bash
# Monitor application logs
tail -f /var/log/cfgms/controller.log
tail -f /var/log/cfgms/terminal-manager.log

# Monitor system logs
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
curl https://localhost:8080/health

# Check logs for errors
journalctl -u cfgms-controller --since "5 minutes ago"
```

**Expected restart time**: < 30 seconds  
**Steward reconnection time**: < 60 seconds

### 2. Certificate Renewal

**When to use**: Certificate expiration alerts, manual renewal

```bash
# Check certificate status
/opt/cfgms/bin/cert-manager status

# Renew certificates
/opt/cfgms/bin/cert-manager renew --all

# Restart services to pick up new certificates
systemctl restart cfgms-controller
systemctl restart cfgms-steward

# Verify certificate validity
openssl x509 -in /etc/cfgms/certs/server.crt -text -noout | grep "Not After"
```

### 3. Terminal Session Management

**When to use**: Terminal sessions stuck, resource exhaustion

```bash
# List active sessions
curl -H "Authorization: Bearer $API_TOKEN" \
  https://localhost:8080/api/v1/terminal/sessions

# Terminate specific session
curl -X DELETE -H "Authorization: Bearer $API_TOKEN" \
  https://localhost:8080/api/v1/terminal/sessions/{session_id}

# Emergency: Terminate all sessions
systemctl restart cfgms-terminal-manager
```

### 4. Steward Connection Issues

**When to use**: Stewards not connecting, authentication failures

```bash
# Check steward status
curl -H "Authorization: Bearer $API_TOKEN" \
  https://localhost:8080/api/v1/stewards

# Check steward logs on endpoint
journalctl -u cfgms-steward --since "10 minutes ago"

# Re-register steward (on endpoint)
/opt/cfgms/bin/cfgms-steward --register --controller-url https://controller.example.com:8080

# Regenerate steward certificate
/opt/cfgms/bin/cert-manager generate-client --steward-id {steward_id}
```

### 5. Database Maintenance

**When to use**: Scheduled maintenance, performance issues

```bash
# Backup database
/opt/cfgms/bin/cfgcli backup --output /backup/cfgms-$(date +%Y%m%d).sql

# Check database size
du -sh /var/lib/cfgms/database/

# Optimize database (if using SQLite)
sqlite3 /var/lib/cfgms/database/cfgms.db "VACUUM; ANALYZE;"

# Check for corruption
sqlite3 /var/lib/cfgms/database/cfgms.db "PRAGMA integrity_check;"
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
   
   # Check network connectivity
   netstat -tuln | grep 8080
   ```

2. **Diagnosis** (5-10 minutes)
   ```bash
   # Check recent logs
   journalctl -u cfgms-controller --since "30 minutes ago" --priority=err
   
   # Check certificate validity
   openssl x509 -in /etc/cfgms/certs/server.crt -checkend 86400
   
   # Check database connectivity
   sqlite3 /var/lib/cfgms/database/cfgms.db ".tables"
   ```

3. **Recovery Actions** (10-15 minutes)
   ```bash
   # Restart controller service
   systemctl restart cfgms-controller
   
   # If database issues, restore from backup
   /opt/cfgms/bin/cfgcli restore --input /backup/cfgms-latest.sql
   
   # Verify recovery
   curl https://localhost:8080/health
   ```

#### Severity 2: Performance Degradation
**Response Time**: 30 minutes

1. **Check Performance Metrics**
   ```bash
   # Check CPU and memory usage
   htop
   
   # Check active terminal sessions
   curl -H "Authorization: Bearer $API_TOKEN" \
     https://localhost:8080/api/v1/terminal/sessions | jq length
   
   # Check gRPC connection count
   netstat -an | grep :8080 | wc -l
   ```

2. **Mitigation Actions**
   ```bash
   # If high session count, implement session limits
   /opt/cfgms/bin/cfgcli config set terminal.max_sessions 50
   
   # If memory issues, restart controller
   systemctl restart cfgms-controller
   
   # If certificate issues, renew certificates
   /opt/cfgms/bin/cert-manager renew --all
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
   # Check failed authentication logs
   grep "authentication failed" /var/log/cfgms/controller.log
   
   # Check source IP addresses
   grep "authentication failed" /var/log/cfgms/controller.log | awk '{print $5}' | sort | uniq -c
   
   # Block suspicious IPs (if applicable)
   iptables -A INPUT -s {suspicious_ip} -j DROP
   ```

2. **Investigation**
   ```bash
   # Check all recent authentication events
   grep -E "(login|authentication|certificate)" /var/log/cfgms/*.log
   
   # Check certificate usage
   /opt/cfgms/bin/cert-manager audit --since "24 hours ago"
   
   # Check terminal session activity
   grep "session created\|command executed" /var/log/cfgms/terminal-manager.log
   ```

3. **Containment**
   ```bash
   # Revoke compromised certificates
   /opt/cfgms/bin/cert-manager revoke --serial {certificate_serial}
   
   # Force password reset for affected users
   /opt/cfgms/bin/cfgcli user reset-password --user {username}
   
   # Terminate all active sessions
   curl -X DELETE -H "Authorization: Bearer $API_TOKEN" \
     https://localhost:8080/api/v1/terminal/sessions/all
   ```

## Disaster Recovery Procedures

### Data Backup Procedures

#### Daily Backup
```bash
#!/bin/bash
# /opt/cfgms/scripts/daily-backup.sh

BACKUP_DIR="/backup/cfgms/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup database
/opt/cfgms/bin/cfgcli backup --output $BACKUP_DIR/database.sql

# Backup certificates
cp -r /etc/cfgms/certs $BACKUP_DIR/

# Backup configuration
cp -r /etc/cfgms/config $BACKUP_DIR/

# Backup logs (last 7 days)
find /var/log/cfgms -name "*.log" -mtime -7 -exec cp {} $BACKUP_DIR/ \;

# Compress backup
tar -czf $BACKUP_DIR.tar.gz -C /backup/cfgms $(basename $BACKUP_DIR)
rm -rf $BACKUP_DIR

# Upload to remote storage (implement according to your setup)
# aws s3 cp $BACKUP_DIR.tar.gz s3://cfgms-backups/
```

#### Disaster Recovery Restore
```bash
#!/bin/bash
# /opt/cfgms/scripts/disaster-restore.sh

RESTORE_DATE=$1
if [ -z "$RESTORE_DATE" ]; then
    echo "Usage: $0 YYYYMMDD"
    exit 1
fi

BACKUP_FILE="/backup/cfgms/$RESTORE_DATE.tar.gz"

# Stop services
systemctl stop cfgms-controller
systemctl stop cfgms-steward

# Extract backup
tar -xzf $BACKUP_FILE -C /tmp/

# Restore database
/opt/cfgms/bin/cfgcli restore --input /tmp/$RESTORE_DATE/database.sql

# Restore certificates
cp -r /tmp/$RESTORE_DATE/certs/* /etc/cfgms/certs/

# Restore configuration
cp -r /tmp/$RESTORE_DATE/config/* /etc/cfgms/config/

# Start services
systemctl start cfgms-controller
systemctl start cfgms-steward

# Verify recovery
sleep 30
curl https://localhost:8080/health

echo "Disaster recovery completed for backup date: $RESTORE_DATE"
```

### Network Partition Recovery

**Scenario**: Network connectivity lost between controller and stewards

1. **Detection**
   ```bash
   # Check steward connectivity
   /opt/cfgms/bin/cfgcli steward list --status offline
   
   # Check network connectivity
   ping controller.example.com
   telnet controller.example.com 8080
   ```

2. **Recovery**
   ```bash
   # On stewards: Check network configuration
   systemctl status network
   ip route show
   
   # Restart steward service to trigger reconnection
   systemctl restart cfgms-steward
   
   # On controller: Monitor steward reconnections
   tail -f /var/log/cfgms/controller.log | grep "steward connected"
   ```

## Performance Troubleshooting

### High Memory Usage

1. **Diagnosis**
   ```bash
   # Check memory usage by component
   ps aux | grep cfgms | sort -k4 -nr
   
   # Check for memory leaks
   valgrind --tool=memcheck --leak-check=full /opt/cfgms/bin/controller
   
   # Check terminal session count
   curl -H "Authorization: Bearer $API_TOKEN" \
     https://localhost:8080/api/v1/terminal/sessions | jq length
   ```

2. **Resolution**
   ```bash
   # Reduce terminal session limit
   /opt/cfgms/bin/cfgcli config set terminal.max_sessions 50
   
   # Reduce session timeout
   /opt/cfgms/bin/cfgcli config set terminal.session_timeout 300
   
   # Restart controller to free memory
   systemctl restart cfgms-controller
   ```

### High CPU Usage

1. **Diagnosis**
   ```bash
   # Check CPU usage by component
   top -p $(pgrep -d, cfgms)
   
   # Check active connections
   netstat -an | grep :8080 | wc -l
   
   # Check for runaway processes
   ps aux | grep cfgms | grep -v grep
   ```

2. **Resolution**
   ```bash
   # Limit concurrent connections
   /opt/cfgms/bin/cfgcli config set server.max_connections 100
   
   # Implement rate limiting
   /opt/cfgms/bin/cfgcli config set server.rate_limit 1000
   
   # Scale horizontally if needed
   # Deploy additional controller instances with load balancer
   ```

### Slow Terminal Response

1. **Diagnosis**
   ```bash
   # Check terminal session latency
   curl -H "Authorization: Bearer $API_TOKEN" \
     https://localhost:8080/api/v1/metrics | grep terminal_latency
   
   # Check shell executor performance
   strace -p $(pgrep cfgms-steward) -e trace=read,write
   
   # Check network latency
   ping -c 10 controller.example.com
   ```

2. **Resolution**
   ```bash
   # Optimize terminal buffer size
   /opt/cfgms/bin/cfgcli config set terminal.buffer_size 8192
   
   # Reduce terminal update frequency
   /opt/cfgms/bin/cfgcli config set terminal.update_interval 50ms
   
   # Check for network issues
   mtr controller.example.com
   ```

## Maintenance Procedures

### Regular Maintenance Tasks

#### Weekly Maintenance
```bash
#!/bin/bash
# /opt/cfgms/scripts/weekly-maintenance.sh

# Rotate logs
logrotate -f /etc/logrotate.d/cfgms

# Clean up old terminal recordings
find /var/lib/cfgms/recordings -name "*.rec" -mtime +30 -delete

# Update certificate if needed
/opt/cfgms/bin/cert-manager check --auto-renew

# Check database integrity
sqlite3 /var/lib/cfgms/database/cfgms.db "PRAGMA integrity_check;"

# Clean up old backups (keep 30 days)
find /backup/cfgms -name "*.tar.gz" -mtime +30 -delete
```

#### Monthly Maintenance
```bash
#!/bin/bash
# /opt/cfgms/scripts/monthly-maintenance.sh

# Full system backup
/opt/cfgms/scripts/daily-backup.sh

# Security audit
/opt/cfgms/bin/cfgcli security audit --full

# Performance baseline check
/opt/cfgms/bin/cfgcli performance baseline --update

# Certificate inventory
/opt/cfgms/bin/cert-manager inventory --export-csv /var/log/cfgms/cert-inventory.csv

# System health report
/opt/cfgms/bin/cfgcli health report --email admin@example.com
```

### Upgrade Procedures

#### Minor Version Upgrade (e.g., v0.3.0 to v0.3.1)
```bash
# 1. Backup current system
/opt/cfgms/scripts/daily-backup.sh

# 2. Download new version
wget https://releases.example.com/cfgms/v0.3.1/cfgms-v0.3.1-linux-amd64.tar.gz

# 3. Stop services
systemctl stop cfgms-controller
systemctl stop cfgms-steward

# 4. Install new binaries
tar -xzf cfgms-v0.3.1-linux-amd64.tar.gz -C /opt/cfgms/

# 5. Run database migrations
/opt/cfgms/bin/cfgcli migrate --from v0.3.0 --to v0.3.1

# 6. Start services
systemctl start cfgms-controller
systemctl start cfgms-steward

# 7. Verify upgrade
/opt/cfgms/bin/cfgcli version
curl https://localhost:8080/health
```

#### Major Version Upgrade (e.g., v0.3.x to v0.4.0)
```bash
# Follow detailed upgrade guide for breaking changes
# See: docs/upgrade/v0.3-to-v0.4.md
```

## Emergency Contacts

### Escalation Matrix
- **Level 1**: Operations Team (24/7)
- **Level 2**: Engineering Team (business hours)
- **Level 3**: Architecture Team (on-call)

### Communication Channels
- **Slack**: #cfgms-ops
- **Email**: cfgms-ops@example.com
- **Phone**: +1-555-CFGMS-OPS

## Appendix

### Log File Locations
```
/var/log/cfgms/controller.log       - Controller application logs
/var/log/cfgms/steward.log          - Steward application logs
/var/log/cfgms/terminal-manager.log - Terminal session logs
/var/log/cfgms/cert-manager.log     - Certificate management logs
/var/log/cfgms/audit.log            - Security audit logs
```

### Configuration Files
```
/etc/cfgms/controller.yaml          - Controller configuration
/etc/cfgms/steward.yaml             - Steward configuration
/etc/cfgms/terminal.yaml            - Terminal configuration
/etc/cfgms/rbac.yaml                - RBAC policies
```

### Service Files
```
/etc/systemd/system/cfgms-controller.service
/etc/systemd/system/cfgms-steward.service
/etc/systemd/system/cfgms-cert-manager.service
```

---

**Document Control**
- **Owner**: CFGMS Operations Team
- **Review Cycle**: Quarterly
- **Next Review**: 2025-11-01
- **Approval**: DevOps Manager, Security Team Lead