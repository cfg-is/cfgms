# Registration Code Deployment

This document describes the registration code system for simplified steward deployment.

## Overview

Registration codes enable MSP-style deployments where a single code-signed installer can be deployed across multiple tenants and devices. The registration code is passed as a command-line parameter and contains tenant credentials and controller information.

## Benefits

- **Single Signed Installer**: One binary hash for application allowlisting
- **No Config Files**: Registration code is command-line parameter only
- **Tenant Isolation**: Each deployment gets unique tenant credentials
- **Simple MSP Deployment**: Just change REGCODE parameter per tenant
- **Secure**: Controller validates tenant credentials

## Registration Code Format

### Structure

Registration codes are base64-encoded JSON with the following structure:

```json
{
  "tenant_id": "acme-corp",
  "controller_url": "mqtt://controller.example.com:8883",
  "group": "production",
  "version": 1
}
```

**Fields:**
- `tenant_id` (required): Unique identifier for the tenant
- `controller_url` (required): MQTT broker URL (mqtt:// or mqtts://)
- `group` (optional): Group identifier for organization
- `version` (required): Registration code format version (currently 1)

### Example

**Decoded JSON:**
```json
{
  "tenant_id": "acme-corp",
  "controller_url": "mqtt://controller.acme.com:8883",
  "group": "production",
  "version": 1
}
```

**Encoded Registration Code:**
```
eyJ0ZW5hbnRfaWQiOiJhY21lLWNvcnAiLCJjb250cm9sbGVyX3VybCI6Im1xdHQ6Ly9jb250cm9sbGVyLmFjbWUuY29tOjg4ODMiLCJncm91cCI6InByb2R1Y3Rpb24iLCJ2ZXJzaW9uIjoxfQ==
```

## Generating Registration Codes

### Using cfg

```bash
# Generate registration code
cfg regcode \
  --tenant-id=acme-corp \
  --controller-url=mqtt://controller.acme.com:8883 \
  --group=production

# Output:
# Registration Code: eyJ0ZW5hbnRfaWQi...
#
# Deployment Examples:
#
# Windows MSI:
#   msiexec /i cfgms-steward.msi /quiet REGCODE="eyJ0ZW5hbnRfaWQi..."
#
# Linux/macOS:
#   ./cfgms-steward-install --regcode="eyJ0ZW5hbnRfaWQi..."
```

### Decoding Registration Codes

```bash
# Decode to verify contents
cfg regcode --decode eyJ0ZW5hbnRfaWQi...

# Output:
# Decoded Registration Code:
#
#   Tenant ID:      acme-corp
#   Controller URL: mqtt://controller.acme.com:8883
#   Group:          production
#   Version:        1
```

## Deployment Methods

### Windows MSI Deployment

#### Group Policy (GPO)

```powershell
# Create MSI deployment package
$RegCode = "eyJ0ZW5hbnRfaWQi..."
msiexec /i \\domain\netlogon\cfgms-steward.msi /quiet REGCODE="$RegCode"
```

**GPO Configuration:**
1. Computer Configuration → Policies → Software Settings → Software Installation
2. New Package → Select cfgms-steward.msi
3. Deployment Method: Assigned
4. Modifications → Transforms → Add REGCODE property

#### Microsoft Intune (MDM)

```powershell
# Create Win32 app package
# Install command:
msiexec /i cfgms-steward.msi /quiet REGCODE="eyJ0ZW5hbnRfaWQi..."

# Uninstall command:
msiexec /x {ProductCode} /quiet
```

**Intune Configuration:**
1. Apps → Windows → Add → Windows app (Win32)
2. Upload .intunewin package
3. Install command: `msiexec /i cfgms-steward.msi /quiet REGCODE="<REGCODE>"`
4. Detection: File exists at `C:\Program Files\CFGMS\steward.exe`

#### PowerShell Direct

```powershell
# Silent install with registration code
$RegCode = "eyJ0ZW5hbnRfaWQiOiJhY21lLWNvcnAiLCJjb250cm9sbGVyX3VybCI6Im1xdHQ6Ly9jb250cm9sbGVyLmFjbWUuY29tOjg4ODMiLCJncm91cCI6InByb2R1Y3Rpb24iLCJ2ZXJzaW9uIjoxfQ=="

Start-Process msiexec.exe -ArgumentList "/i","cfgms-steward.msi","/quiet","REGCODE=$RegCode" -Wait
```

### Linux Deployment

#### Ansible

```yaml
# playbook.yml
- name: Deploy CFGMS Steward
  hosts: all
  vars:
    regcode: "eyJ0ZW5hbnRfaWQi..."
  tasks:
    - name: Download steward installer
      get_url:
        url: https://releases.cfgms.io/steward/latest/cfgms-steward-linux-amd64
        dest: /tmp/cfgms-steward-install
        mode: '0755'

    - name: Install steward with registration code
      command: /tmp/cfgms-steward-install --regcode="{{ regcode }}"
      args:
        creates: /usr/local/bin/cfgms-steward
```

#### Shell Script

```bash
#!/bin/bash
# deploy-steward.sh

REGCODE="eyJ0ZW5hbnRfaWQi..."

# Download installer
curl -o /tmp/cfgms-steward-install \
  https://releases.cfgms.io/steward/latest/cfgms-steward-linux-amd64

# Make executable
chmod +x /tmp/cfgms-steward-install

# Install with registration code
/tmp/cfgms-steward-install --regcode="$REGCODE"
```

#### systemd Service

```bash
# Install steward
./cfgms-steward-install --regcode="eyJ0ZW5hbnRfaWQi..."

# Create systemd service
cat > /etc/systemd/system/cfgms-steward.service <<EOF
[Unit]
Description=CFGMS Steward Configuration Management Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-steward -regcode=eyJ0ZW5hbnRfaWQi...
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable cfgms-steward
systemctl start cfgms-steward
```

### macOS Deployment

#### Jamf Pro

```bash
# Jamf policy script
#!/bin/bash

REGCODE="eyJ0ZW5hbnRfaWQi..."

# Download installer
curl -o /tmp/cfgms-steward-install \
  https://releases.cfgms.io/steward/latest/cfgms-steward-darwin-arm64

# Install
chmod +x /tmp/cfgms-steward-install
/tmp/cfgms-steward-install --regcode="$REGCODE"

# Create LaunchDaemon
cat > /Library/LaunchDaemons/com.cfgms.steward.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cfgms.steward</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/cfgms-steward</string>
        <string>-regcode</string>
        <string>$REGCODE</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

launchctl load /Library/LaunchDaemons/com.cfgms.steward.plist
```

## MSP Workflow

### 1. Generate Registration Codes

MSP admin generates unique registration codes for each tenant:

```bash
# Tenant A - Production
cfg regcode \
  --tenant-id=tenant-a \
  --controller-url=mqtt://controller.msp.com:8883 \
  --group=production \
  > tenant-a-prod-regcode.txt

# Tenant A - Development
cfg regcode \
  --tenant-id=tenant-a \
  --controller-url=mqtt://controller.msp.com:8883 \
  --group=development \
  > tenant-a-dev-regcode.txt

# Tenant B - Production
cfg regcode \
  --tenant-id=tenant-b \
  --controller-url=mqtt://controller.msp.com:8883 \
  --group=production \
  > tenant-b-prod-regcode.txt
```

### 2. Distribute Same Signed Installer

MSP uses the same code-signed installer for all tenants:

- **Windows**: `cfgms-steward-v1.0.0-signed.msi` (SHA256: abc123...)
- **Linux**: `cfgms-steward-v1.0.0-linux-amd64` (SHA256: def456...)
- **macOS**: `cfgms-steward-v1.0.0-darwin-arm64` (SHA256: ghi789...)

### 3. Application Allowlisting

Configure allowlisting policies with single hash per platform:

**Windows AppLocker:**
```xml
<FilePathRule Id="..." Name="CFGMS Steward" Description="Allow CFGMS Steward" UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions>
    <FileHashCondition>
      <FileHash Type="SHA256" Data="abc123..." SourceFileName="cfgms-steward.msi" />
    </FileHashCondition>
  </Conditions>
</FilePathRule>
```

**macOS Gatekeeper:**
```bash
# Code signing verification
codesign -v /usr/local/bin/cfgms-steward
# Signature verified for: CFGMS Steward (Developer ID: CFGMS Inc)

# Allowlist by developer certificate
spctl --add --label "CFGMS Steward" /usr/local/bin/cfgms-steward
```

### 4. Deploy with Tenant-Specific Codes

Deploy same installer with different REGCODE per tenant:

```powershell
# Tenant A deployment
msiexec /i cfgms-steward.msi /quiet REGCODE="<Tenant-A-Code>"

# Tenant B deployment
msiexec /i cfgms-steward.msi /quiet REGCODE="<Tenant-B-Code>"
```

### 5. Steward Auto-Registration

When steward starts:

1. **Decode registration code** from command-line parameter
2. **Generate steward_id** with tenant prefix: `{tenant_id}-{uuid}`
3. **Connect to MQTT broker** using tenant credentials from registration
4. **Publish registration message** to `cfgms/steward/{steward_id}/register`
5. **Controller validates** tenant_id and provisions steward
6. **Steward receives** configuration and begins operations

## Security Considerations

### Registration Code Security

- **Not Encryption**: Registration codes are base64-encoded, not encrypted
- **Controller Validation**: Controller must validate tenant credentials
- **Tenant Isolation**: Each tenant has unique credentials
- **TLS/mTLS**: MQTT connections use TLS for transport security

### Secure Distribution

**Recommended:**
- Store registration codes in secure credential management (Vault, Key Manager)
- Inject codes at deployment time from secure storage
- Rotate tenant credentials periodically
- Monitor unauthorized registration attempts

**Avoid:**
- Hardcoding registration codes in scripts committed to version control
- Sharing registration codes via email or chat
- Storing codes in plaintext configuration management systems

### Credential Rotation

When rotating tenant credentials:

1. Generate new registration code with updated credentials
2. Update deployment tools with new code
3. Redeploy stewards with new code (or update via MQTT command)
4. Invalidate old credentials on controller

## Troubleshooting

### Invalid Registration Code

**Error**: `Failed to decode registration code: illegal base64 data at input byte X`

**Solution**: Verify registration code is correctly copied (base64 strings are case-sensitive)

### Connection Failed

**Error**: `Failed to connect to MQTT broker: connection refused`

**Solution**:
- Verify controller URL in registration code is correct
- Check network connectivity to controller
- Verify firewall allows egress to MQTT port (8883)

### Registration Rejected

**Error**: `Registration rejected: invalid tenant credentials`

**Solution**:
- Verify tenant_id exists on controller
- Check tenant credentials are valid
- Review controller logs for rejection reason

### Duplicate Steward ID

**Error**: `Registration rejected: steward_id already exists`

**Solution**:
- Check for duplicate steward installations
- Verify steward generates unique UUID for steward_id
- Review tenant prefix collision

## Implementation Status

### Completed ✅

- Registration code format design
- `cfg regcode` command for generation/decoding
- Steward `--regcode` parameter for deployment
- Registration code decoder in steward startup

**Note**: Base64-encoded registration codes (`--regcode`) have been deprecated in Story #198.
Use registration tokens (`--regtoken`) with MQTT+QUIC architecture instead.

## Implementation Status (Story #198 Complete)

✅ **Completed Features**:
- MQTT-based registration with API key-style tokens
- Controller tenant validation for registration tokens
- Steward_id generation with tenant prefix (`{tenant_id}-{uuid}`)
- Token expiration and single-use support
- Session-based QUIC authentication

🔜 **Future Enhancements**:
- Credential rotation mechanism
- Token revocation API
- Multi-region token distribution

## References

- [Story #198: Communication Protocol Migration](../../docs/product/roadmap.md)
- [MQTT Communication](./mqtt-protocol.md)
- [Deployment Guide](./deployment-guide.md)
- [Security Model](../architecture/security-model.md)
