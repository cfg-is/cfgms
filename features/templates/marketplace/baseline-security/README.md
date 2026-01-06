# Baseline Security Template

Comprehensive baseline security template that implements fundamental security controls for Linux endpoints using file, directory, and script modules. Provides defense-in-depth security posture with firewall, audit logging, automatic security updates, and system hardening.

## Features

- **Multi-Module Architecture**: Uses file, directory, and script modules
- **Firewall Configuration**: Automated UFW/firewalld setup with secure defaults
- **Audit Logging**: Complete auditd configuration with security event monitoring
- **Automatic Updates**: Security patches applied automatically
- **Password Policy**: Strong password requirements enforced
- **Kernel Hardening**: Secure sysctl parameters for network stack protection
- **Login Security**: Failed login lockout and account protection
- **Verification Script**: Automated validation of security posture

## Security Controls

### System Hardening
- Kernel security parameters (IP forwarding disabled, SYN cookies enabled)
- Source route validation and martian packet logging
- TCP SYN flood protection
- Address space layout randomization (ASLR)
- Kernel pointer and dmesg access restrictions

### Password Security
- Minimum password length: 14 characters (configurable)
- Password complexity requirements enforced
- Maximum password age: 90 days (configurable)
- Failed login lockout after 5 attempts (configurable)
- Password history and dictionary checking

### Firewall Protection
- Default deny incoming, allow outgoing
- SSH access on configurable port
- HTTP/HTTPS services as needed
- Stateful firewall with connection tracking

### Audit Logging
- Comprehensive authentication event logging
- System call auditing for security events
- Configuration file change monitoring
- 90-day log retention (configurable)
- Immutable audit rules

### Automatic Security Updates
- Daily security patch checks
- Automatic installation of critical updates
- Unused kernel and dependency cleanup
- Configurable reboot scheduling

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `firewall_enabled` | true | Enable host-based firewall |
| `allowed_ssh_port` | 22 | SSH port for firewall rules |
| `auto_security_updates` | true | Enable automatic security updates |
| `audit_enabled` | true | Enable audit logging |
| `audit_retention_days` | 90 | Days to retain audit logs |
| `password_max_age` | 90 | Maximum password age (days) |
| `password_min_length` | 14 | Minimum password length |
| `failed_login_lockout` | 5 | Failed attempts before lockout |

## Usage

### Basic Usage (Maximum Security)

```yaml
extends: baseline-security

# Accept all defaults for maximum security posture
```

### Custom Configuration

```yaml
extends: baseline-security

variables:
  # Custom SSH port
  allowed_ssh_port: 2222

  # Stricter password policy
  password_min_length: 16
  password_max_age: 60

  # More sensitive lockout
  failed_login_lockout: 3

  # Longer audit retention
  audit_retention_days: 365
```

### Development Environment (Less Restrictive)

```yaml
extends: baseline-security

variables:
  # More lenient for development
  password_min_length: 12
  failed_login_lockout: 10

  # Keep firewall but allow more services
  firewall_enabled: true
```

### Compliance-Driven Configuration

```yaml
extends: baseline-security

variables:
  # PCI-DSS compliant settings
  password_max_age: 90
  password_min_length: 12
  failed_login_lockout: 6
  audit_retention_days: 365
  auto_security_updates: true
```

## Platform Support

- Ubuntu 20.04, 22.04
- Debian 11, 12
- RHEL 8, 9
- CentOS 8

## Compliance

This template implements controls from:
- **CIS**: CIS Distribution Independent Linux Benchmark (Level 1 & 2)
- **NIST**: NIST SP 800-53 (AC, AU, CM, IA, SC controls)
- **PCI-DSS**: Requirement 2 (secure configuration)
- **SOC2**: CC6.1, CC6.6 (logical and physical access controls)

## Module Usage

### File Module
- Security configuration files
- Password policy configuration (pwquality.conf)
- Login security (faillock.conf, login.defs)
- Kernel parameters (sysctl.conf)

### Directory Module
- Security configuration directory structure
- Audit log directories with proper permissions

### Script Module
- Firewall configuration automation
- Automatic update setup
- Audit logging configuration
- Security verification testing

## Verification

After applying, verify security posture:

```bash
# Run built-in verification script
cfg exec --device server-01 -- /usr/local/bin/verify-baseline-security.sh

# Manual checks
cfg exec --device server-01 -- sysctl net.ipv4.tcp_syncookies
cfg exec --device server-01 -- systemctl status auditd
cfg exec --device server-01 -- ufw status verbose
```

## Dependencies

Optional dependency on `ssh-hardening` template for complete SSH security.

## Testing

Test in safe environment before production:

```bash
# Apply to test server
cfg config apply --template baseline-security --device test-server

# Verify security controls
cfg exec --device test-server -- /usr/local/bin/verify-baseline-security.sh

# Check firewall rules
cfg exec --device test-server -- ufw status numbered

# Review audit rules
cfg exec --device test-server -- auditctl -l
```

## Rollback

If issues occur:

```bash
# Rollback configuration
cfg config rollback --device affected-server --version previous

# Disable firewall temporarily (emergency access)
cfg exec --device affected-server -- ufw disable
```

## Security Notes

⚠️ **Important**:
- Firewall rules may block legitimate traffic - review before applying
- Automatic updates may cause service disruptions - plan maintenance windows
- Password policy changes affect all users immediately
- Audit logging increases disk usage - monitor space

## Maintenance

Regular maintenance tasks:

```bash
# Review audit logs
cfg exec --device server-01 -- aureport -au

# Check for security updates
cfg exec --device server-01 -- apt-get update && apt-get -s upgrade | grep -i security

# Verify firewall rules
cfg exec --device server-01 -- ufw status numbered
```

## License

MIT License - See LICENSE file for details

## Support

- Documentation: https://cfgms.io/docs/templates/baseline-security
- Issues: https://github.com/cfg-is/cfgms-templates/issues
- Community: https://discord.gg/cfgms
