# Backup Configuration Template

Comprehensive backup configuration template that sets up automated file and directory backups with retention policies, encryption, remote sync, and monitoring. Uses directory and script modules to create enterprise-grade backup infrastructure.

## Features

- **Automated Scheduling**: Daily, weekly, and monthly backups via cron
- **Retention Policies**: Configurable retention for different backup types
- **Compression**: Configurable tar.gz compression (levels 1-9)
- **Encryption**: Optional AES-256-CBC encryption for backup archives
- **Remote Backup**: Optional rsync to remote backup location
- **Monitoring**: Email notifications for backup success/failure
- **Storage Management**: Automatic cleanup of old backups and logs
- **Easy Restore**: Simple restore script for recovery operations
- **Verification**: Built-in backup configuration validation

## Backup Strategy

### Three-Tier Retention
- **Daily**: 7 days retention (runs at 2 AM)
- **Weekly**: 4 weeks retention (runs Sunday 3 AM)
- **Monthly**: 12 months retention (runs 1st of month 4 AM)

### What Gets Backed Up
Default backup paths (configurable):
- `/etc` - System configuration
- `/home` - User home directories
- `/var/www` - Web content
- `/opt` - Optional application data

### Exclusions
Default exclusions (configurable):
- Temporary files (`*.tmp`)
- Cache files (`*.cache`, `/var/cache`)
- User cache directories (`/home/*/.cache`)

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `backup_enabled` | true | Enable automated backups |
| `backup_schedule` | "0 2 * * *" | Daily backup cron schedule |
| `backup_base_dir` | "/var/backups/cfgms" | Base backup directory |
| `backup_paths` | [/etc, /home, /var/www, /opt] | Paths to backup |
| `backup_exclusions` | [*.tmp, *.cache, ...] | Patterns to exclude |
| `daily_retention` | 7 | Days to keep daily backups |
| `weekly_retention` | 4 | Weeks to keep weekly backups |
| `monthly_retention` | 12 | Months to keep monthly backups |
| `compression_enabled` | true | Enable tar.gz compression |
| `compression_level` | 6 | Compression level (1-9) |
| `encryption_enabled` | false | Enable AES-256 encryption |
| `encryption_key_path` | "/etc/cfgms/backup/backup.key" | Encryption key file |
| `remote_backup_enabled` | false | Enable remote rsync |
| `remote_backup_host` | "" | Remote backup hostname |
| `remote_backup_path` | "" | Remote backup path |
| `remote_backup_user` | "backup" | Remote backup user |
| `backup_notifications_enabled` | true | Enable email notifications |
| `backup_notification_email` | "admin@example.com" | Notification email |
| `max_backup_size_gb` | 100 | Maximum backup storage size |

## Usage

### Basic Usage (Local Backups)

```yaml
extends: backup-config

variables:
  # Customize backup paths
  backup_paths:
    - /etc
    - /home
    - /var/www
    - /opt/important-app

  # Set notification email
  backup_notification_email: "ops@example.com"
```

### With Encryption

```yaml
extends: backup-config

variables:
  # Enable encryption
  encryption_enabled: true
  encryption_key_path: "/etc/cfgms/backup/backup.key"

  # Must create encryption key first:
  # openssl rand -base64 32 > /etc/cfgms/backup/backup.key
  # chmod 400 /etc/cfgms/backup/backup.key
```

### With Remote Backup

```yaml
extends: backup-config

variables:
  # Enable remote sync
  remote_backup_enabled: true
  remote_backup_host: "backup.example.com"
  remote_backup_path: "/backups/production"
  remote_backup_user: "backup"

  # Setup SSH key authentication first:
  # ssh-keygen -t ed25519 -f /root/.ssh/backup_key
  # ssh-copy-id -i /root/.ssh/backup_key.pub backup@backup.example.com
```

### High-Retention Configuration

```yaml
extends: backup-config

variables:
  # Longer retention for compliance
  daily_retention: 30    # 30 days
  weekly_retention: 12   # 12 weeks
  monthly_retention: 24  # 24 months

  # Higher compression for storage efficiency
  compression_level: 9
```

### Custom Schedule

```yaml
extends: backup-config

variables:
  # Run backups at 11 PM
  backup_schedule: "0 23 * * *"

  # Exclude more paths
  backup_exclusions:
    - "*.tmp"
    - "*.cache"
    - "*.log"
    - "/home/*/Downloads"
    - "/var/tmp"
```

## Platform Support

- Ubuntu 20.04, 22.04
- Debian 11, 12
- RHEL 8, 9
- CentOS 8

## Compliance

Supports data protection requirements for:
- **SOC2**: CC5.1 (logical and physical access controls)
- **GDPR**: Article 32 (security of processing)
- **HIPAA**: 164.308(a)(7)(ii)(A) (data backup plan)

## Scripts Provided

### perform-backup.sh
Main backup execution script:
```bash
# Manual backup execution
/usr/local/bin/cfgms-backup/perform-backup.sh daily
/usr/local/bin/cfgms-backup/perform-backup.sh weekly
/usr/local/bin/cfgms-backup/perform-backup.sh monthly
```

### restore-backup.sh
Restore from backup:
```bash
# List available backups
/usr/local/bin/cfgms-backup/restore-backup.sh

# Restore specific backup
/usr/local/bin/cfgms-backup/restore-backup.sh /var/backups/cfgms/daily/hostname_daily_20251013-020000.tar.gz /restore/path
```

### setup-backup-schedule.sh
Configure cron jobs (runs automatically on apply):
```bash
# View configured schedule
cat /etc/cron.d/cfgms-backup
```

### verify-backup-config.sh
Verify backup configuration:
```bash
# Run verification
/usr/local/bin/cfgms-backup/verify-backup-config.sh
```

## Verification

After applying template:

```bash
# Verify configuration
cfg exec --device server-01 -- /usr/local/bin/cfgms-backup/verify-backup-config.sh

# Test backup (dry run)
cfg exec --device server-01 -- /usr/local/bin/cfgms-backup/perform-backup.sh daily

# Check backup logs
cfg exec --device server-01 -- tail -50 /var/log/cfgms-backup/backup-*.log

# List backups
cfg exec --device server-01 -- ls -lh /var/backups/cfgms/daily/
```

## Monitoring

### Backup Status
```bash
# Check last backup status
cfg exec --device server-01 -- tail /var/log/cfgms-backup/backup-*.log | grep "Backup Summary"

# Check backup sizes
cfg exec --device server-01 -- du -sh /var/backups/cfgms/*/

# Check disk space
cfg exec --device server-01 -- df -h /var/backups/cfgms
```

### Alerts
Configure email alerts for backup failures:
- Success notifications (optional)
- Failure notifications (enabled by default)
- Low disk space warnings

## Disaster Recovery

### Full System Restore
```bash
# Boot from rescue media
# Mount partitions
mount /dev/sda1 /mnt

# List available backups
ls -lh /mnt/var/backups/cfgms/daily/

# Restore latest backup
cd /mnt
tar xzf /mnt/var/backups/cfgms/daily/latest.tar.gz

# Reinstall bootloader and reboot
```

### Selective Restore
```bash
# Restore specific files
tar xzf backup.tar.gz etc/nginx/nginx.conf

# Restore entire directory
tar xzf backup.tar.gz home/user/documents/
```

## Storage Planning

### Disk Space Calculation
Estimate backup storage needs:
```
Daily:   (backup_size * daily_retention)     = size * 7
Weekly:  (backup_size * weekly_retention)    = size * 4
Monthly: (backup_size * monthly_retention)   = size * 12

Total: ~23x backup size
```

### Example
If single backup = 10GB:
- Daily: 70GB
- Weekly: 40GB
- Monthly: 120GB
- **Total: ~230GB storage needed**

### Optimization Tips
1. Increase compression level (up to 9)
2. Enable encryption (adds ~1% size overhead)
3. Exclude unnecessary files (cache, logs, temp)
4. Use remote backup to offload storage
5. Adjust retention policies as needed

## Security Notes

⚠️ **Important**:
- Encryption keys must be stored securely and backed up separately
- Remote backup requires SSH key authentication (no passwords)
- Backup directories have 0700 permissions (root only)
- Email notifications may contain sensitive system information
- Test restores regularly to ensure backup integrity

## Troubleshooting

### Backup Fails with "No space left on device"
```bash
# Check disk space
df -h /var/backups/cfgms

# Manually clean old backups
find /var/backups/cfgms -name "*.tar.gz" -mtime +30 -delete

# Reduce retention or add more storage
```

### Remote Sync Fails
```bash
# Test SSH connection
ssh backup@backup.example.com

# Check rsync
rsync -avz --dry-run /var/backups/cfgms/daily/ backup@backup.example.com:/backups/
```

### Encryption Key Lost
⚠️ **Backups cannot be recovered without encryption key**
- Always back up encryption key to secure location
- Consider using key management system (KMS)
- Store key backup offsite

## License

MIT License - See LICENSE file for details

## Support

- Documentation: https://cfgms.io/docs/templates/backup-config
- Issues: https://github.com/cfg-is/cfgms-templates/issues
- Community: https://discord.gg/cfgms
