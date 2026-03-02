# Steward Registration

This document describes how stewards register with the controller using registration tokens.

## Overview

Registration tokens enable steward deployment where a single binary can be deployed across multiple tenants and devices. The registration token is passed as a `--regtoken` command-line parameter and authenticates the steward with the controller via MQTT+QUIC.

## Registration Tokens (Current - Story #198)

### How It Works

1. Admin creates a registration token via the controller REST API
2. Token is passed to steward via `--regtoken` command-line flag
3. Steward connects to controller's embedded MQTT broker (port 1883)
4. Controller validates the token and provisions the steward
5. Steward receives certificates and begins MQTT+QUIC communication

### Creating Registration Tokens

```bash
# Create a registration token via the REST API
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "group": "production",
    "validity_days": 7,
    "single_use": false
  }'

# Response includes the token and connection details
# Save the token for steward deployment
```

### Deploying Stewards with Registration Tokens

#### Linux (Direct)

```bash
# Register and start the steward
./bin/cfgms-steward --regtoken cfgms_reg_abc123xyz...
```

#### Linux (systemd)

```bash
# Create systemd service
sudo tee /etc/systemd/system/cfgms-steward.service > /dev/null <<EOF
[Unit]
Description=CFGMS Steward Configuration Management Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-steward --regtoken cfgms_reg_abc123xyz...
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

#### Windows

```powershell
# Direct execution
.\cfgms-steward.exe --regtoken cfgms_reg_abc123xyz...

# Windows Service
sc create CFGMSSteward binPath="C:\Program Files\CFGMS\cfgms-steward.exe --regtoken cfgms_reg_abc123xyz..."
sc start CFGMSSteward
```

#### macOS

```bash
# Direct execution
./cfgms-steward --regtoken cfgms_reg_abc123xyz...
```

### Token Features

- **Expiration**: Tokens can have a validity period (e.g., 7 days)
- **Single-use**: Tokens can be restricted to one registration
- **Tenant scoping**: Each token is bound to a specific tenant
- **Group assignment**: Tokens can assign stewards to groups

### Steward Auto-Registration Flow

When a steward starts with `--regtoken`:

1. **Connect to controller** MQTT broker on port 1883 (mTLS)
2. **Submit registration token** for validation
3. **Controller validates** tenant_id and token credentials
4. **Steward receives** certificates for ongoing mTLS communication
5. **Generate steward_id** with tenant prefix: `{tenant_id}-{uuid}`
6. **Begin operations**: heartbeats, config sync via QUIC (port 4433), status reporting

## MSP Workflow

### 1. Generate Registration Tokens

MSP admin generates tokens for each tenant:

```bash
# Tenant A - Production
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-a", "group": "production", "validity_days": 30}'

# Tenant B - Production
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-b", "group": "production", "validity_days": 30}'
```

### 2. Deploy Same Binary with Different Tokens

```bash
# Same binary for all tenants - only the token changes
# Tenant A
./cfgms-steward --regtoken cfgms_reg_tenantA_token...

# Tenant B
./cfgms-steward --regtoken cfgms_reg_tenantB_token...
```

### 3. Application Allowlisting

One binary hash per platform for allowlisting:

**Windows AppLocker:**

```xml
<FilePathRule Id="..." Name="CFGMS Steward" Description="Allow CFGMS Steward" UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions>
    <FileHashCondition>
      <FileHash Type="SHA256" Data="abc123..." SourceFileName="cfgms-steward.exe" />
    </FileHashCondition>
  </Conditions>
</FilePathRule>
```

## Security Considerations

### Token Security

- **Transport security**: MQTT connections use mTLS (port 1883)
- **Controller validation**: Controller validates tenant credentials from token
- **Tenant isolation**: Each tenant has unique credentials
- **Token expiry**: Tokens should have appropriate validity periods

### Secure Distribution

**Recommended:**

- Store registration tokens in secure credential management (Vault, Key Manager)
- Inject tokens at deployment time from secure storage
- Use short validity periods for tokens
- Monitor unauthorized registration attempts

**Avoid:**

- Hardcoding tokens in scripts committed to version control
- Sharing tokens via email or chat
- Storing tokens in plaintext configuration management systems

## Troubleshooting

### Connection Failed

**Error**: `Failed to connect to MQTT broker: connection refused`

**Solution**:
- Verify controller is running and MQTT broker is listening on port 1883
- Check network connectivity: `nc -zv controller-host 1883`
- Verify firewall allows TCP port 1883

### Registration Rejected

**Error**: `Registration rejected: invalid tenant credentials`

**Solution**:
- Verify the registration token is valid and not expired
- Check tenant_id exists on controller
- Review controller logs for rejection reason

### Duplicate Steward ID

**Error**: `Registration rejected: steward_id already exists`

**Solution**:
- Check for duplicate steward installations
- Verify steward generates unique UUID for steward_id
- Review tenant prefix collision

## Implementation Status

### Completed (Story #198)

- MQTT-based registration with API key-style tokens (`--regtoken`)
- Controller tenant validation for registration tokens
- Steward_id generation with tenant prefix (`{tenant_id}-{uuid}`)
- Token expiration and single-use support
- Session-based QUIC authentication
- mTLS certificate provisioning during registration

### Future Enhancements

- Credential rotation mechanism
- Token revocation API
- Multi-region token distribution
- CLI tool for token management (`cfg token create/list/revoke`)

---

## Deprecated: Registration Codes (`--regcode`)

> **Note**: The `--regcode` system described below has been deprecated since Story #198.
> Use `--regtoken` with the MQTT+QUIC architecture instead. The `--regcode` flag is still
> accepted for backward compatibility but will print a deprecation warning.

### Legacy Registration Code Format

Registration codes were base64-encoded JSON:

```json
{
  "tenant_id": "acme-corp",
  "controller_url": "mqtt://controller.example.com:8883",
  "group": "production",
  "version": 1
}
```

### Legacy Generation

```bash
# Deprecated - use REST API token creation instead
cfg regcode \
  --tenant-id=acme-corp \
  --controller-url=mqtt://controller.acme.com:8883 \
  --group=production
```

### Legacy Deployment

```bash
# Deprecated
./cfgms-steward --regcode "eyJ0ZW5hbnRfaWQi..."
# Steward will warn: "Use --regtoken with MQTT+QUIC registration tokens"
```

## References

- [Home Lab Deployment Guide](./home-lab-deployment-guide.md)
- [Quick Start Guide](../../QUICK_START.md)
- [Platform Support](./platform-support.md)
