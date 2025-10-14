# SSH Hardening Template

Comprehensive SSH hardening template that implements industry best practices for secure SSH configuration based on CIS benchmarks and NIST guidelines.

## Features

- **Strong Cryptography**: Modern ciphers, MACs, and key exchange algorithms
- **Authentication Hardening**: Forced key-based authentication, disabled root login
- **Connection Security**: Dead connection detection, grace time limits
- **Attack Surface Reduction**: Disabled forwarding, tunneling, and X11
- **Comprehensive Logging**: Verbose logging for audit trails
- **Customizable**: All settings configurable via template variables

## Security Controls

### Cryptographic Settings
- **Ciphers**: ChaCha20-Poly1305, AES-256-GCM, AES-128-GCM, AES-256-CTR
- **MACs**: HMAC-SHA2-512-ETM, HMAC-SHA2-256-ETM
- **Key Exchange**: Curve25519, ECDH-SHA2 (NIST P-curves), DH-Group-Exchange-SHA256

### Authentication Controls
- Public key authentication enforced
- Password authentication disabled by default
- Root login disabled by default
- Maximum 3 authentication attempts
- Empty passwords prohibited

### Connection Controls
- Client alive interval: 300 seconds
- Login grace time: 60 seconds
- Dead connection detection enabled

### Attack Surface Reduction
- TCP forwarding disabled
- Agent forwarding disabled
- X11 forwarding disabled
- Tunneling disabled
- User environment variables disabled

## Configuration Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ssh_port` | 22 | SSH listen port |
| `permit_root_login` | "no" | Allow root login |
| `password_authentication` | "no" | Enable password auth |
| `max_auth_tries` | 3 | Max authentication attempts |
| `client_alive_interval` | 300 | Seconds between alive checks |
| `login_grace_time` | 60 | Time allowed for authentication |
| `allow_tcp_forwarding` | "no" | Enable TCP forwarding |
| `x11_forwarding` | "no" | Enable X11 forwarding |
| `banner_enabled` | true | Show warning banner |

## Usage

### Basic Usage

```yaml
# Inherit the SSH hardening template
extends: ssh-hardening

# Accept all defaults for maximum security
```

### Custom SSH Port

```yaml
extends: ssh-hardening

variables:
  ssh_port: 2222
```

### Allow Root Login (Not Recommended)

```yaml
extends: ssh-hardening

variables:
  permit_root_login: "yes"
  # Still requires key-based authentication
```

### Development Environment (Less Restrictive)

```yaml
extends: ssh-hardening

variables:
  password_authentication: "yes"
  allow_tcp_forwarding: "yes"
  allow_agent_forwarding: "yes"
```

## Platform Support

- Ubuntu 20.04, 22.04
- Debian 11, 12
- RHEL 8, 9
- CentOS 8

## Compliance

This template implements controls from:
- **CIS**: CIS Distribution Independent Linux Benchmark
- **NIST**: NIST SP 800-53 (AC-17, IA-2, IA-5, SC-13)
- **SOC2**: Security configuration requirements

## Testing

Before deploying to production, test in a safe environment:

```bash
# Apply template
cfgctl config apply --template ssh-hardening --device test-server

# Verify SSH configuration
cfgctl exec --device test-server -- sshd -t

# Test SSH connection
ssh -p 2222 user@test-server
```

## Rollback

If SSH connectivity is lost:

1. Access via console or other means
2. Rollback configuration:
   ```bash
   cfgctl config rollback --device affected-server --version previous
   ```

## Security Notes

⚠️ **Important**: Always keep a backup access method (console, IPMI, etc.) before applying SSH hardening templates to prevent lockouts.

## License

MIT License - See LICENSE file for details

## Support

- Documentation: https://cfgms.io/docs/templates/ssh-hardening
- Issues: https://github.com/cfg-is/cfgms-templates/issues
- Community: https://discord.gg/cfgms
