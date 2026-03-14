# Steward Registration & Deployment

How stewards are built, deployed, and registered with a controller. Designed for MSP mass deployment via MDM tools (Intune, GPO, SCCM, RMM).

## Deployment Model

The steward is a single binary with the controller URL compiled in at build time. Deployment requires only one runtime argument: the registration token.

```
┌─────────────────────────────────────────────────┐
│                  Build Time                      │
│                                                  │
│  go build -ldflags                               │
│    "-X main.ControllerURL=https://ctrl.msp.com"  │
│  → cfgms-steward (controller URL baked in)       │
│  → codesign / signtool (trusted binary)          │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│                 Deploy Time                      │
│                                                  │
│  Intune / GPO / RMM / SCCM pushes:             │
│    cfgms-steward --regtoken <token>              │
│                                                  │
│  Token determines: tenant + group                │
│  Binary determines: which controller             │
└─────────────────────────────────────────────────┘
```

### Why Compile-Time Controller URL

The controller URL has **no runtime override** — no `--url` flag, no environment variable. This is a deliberate security decision:

- The signed binary is a **trust assertion** about which controller it connects to
- An attacker who obtains the binary cannot redirect it to a malicious controller
- Changing the controller requires building and signing a new binary
- For development, compile with the dev controller URL

### Token Format

Registration tokens are 26-character opaque strings (128 bits of entropy, base32 encoded):

```
abcdefghijklmnopqrstuvwxyz
```

No prefix — the `--regtoken` flag identifies the token type. Short enough for MDM policy fields.

## Building the Steward

### Production Build (SaaS / MSP)

```bash
# Build with controller URL baked in
make build-steward STEWARD_CONTROLLER_URL=https://controller.yourmsp.com

# Or directly with go build
go build -ldflags "-X main.ControllerURL=https://controller.yourmsp.com" \
  -o cfgms-steward ./cmd/steward

# Sign the binary
# Linux:
gpg --detach-sign cfgms-steward

# Windows:
signtool sign /sha1 <thumbprint> /t http://timestamp.digicert.com cfgms-steward.exe

# macOS:
codesign -s "Developer ID Application: Your Company" cfgms-steward
```

### Development Build

```bash
# Build pointing at local controller
make build-steward STEWARD_CONTROLLER_URL=https://localhost:9080
```

## Creating Registration Tokens

Admin creates tokens via the controller REST API. Tokens are tenant-scoped and optionally group-scoped.

```bash
# Long-lived, reusable token for mass deployment
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "group": "production"
  }'

# Short-lived, single-use token for one-off registration
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "acme-corp",
    "group": "staging",
    "expires_in": "24h",
    "single_use": true
  }'
```

### Token Properties

| Property | Description | Default |
|----------|-------------|---------|
| `tenant_id` | Tenant this token registers stewards into (required) | — |
| `group` | Group within tenant (optional) | none |
| `expires_in` | Token lifetime: `"24h"`, `"7d"`, `"365d"`, or omit for no expiry | no expiry |
| `single_use` | If true, token can only be used once | false |

**For mass deployment**, create tokens with no expiry and `single_use: false`. This allows the same token to be embedded in MDM policies that persist across new device enrollments.

### Token Management

```bash
# List tokens for a tenant
curl http://controller:9080/api/v1/registration/tokens?tenant_id=acme-corp

# Revoke a compromised token
curl -X POST http://controller:9080/api/v1/registration/tokens/<token>/revoke

# Delete a token
curl -X DELETE http://controller:9080/api/v1/registration/tokens/<token>
```

## Deploying Stewards

### Linux (systemd)

```bash
sudo tee /etc/systemd/system/cfgms-steward.service > /dev/null <<EOF
[Unit]
Description=CFGMS Steward Configuration Management Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cfgms-steward --regtoken abcdefghijklmnopqrstuvwxyz
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cfgms-steward
```

### Windows (Service)

```powershell
# Install as Windows service
sc.exe create CFGMSSteward binPath="C:\Program Files\CFGMS\cfgms-steward.exe --regtoken abcdefghijklmnopqrstuvwxyz"
sc.exe config CFGMSSteward start=auto
sc.exe start CFGMSSteward
```

### macOS (launchd)

```bash
sudo tee /Library/LaunchDaemons/com.cfgms.steward.plist > /dev/null <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cfgms.steward</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/cfgms-steward</string>
        <string>--regtoken</string>
        <string>abcdefghijklmnopqrstuvwxyz</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.cfgms.steward.plist
```

## Registration Flow

When a steward starts with `--regtoken`:

1. **Connect to controller** — uses the compiled-in controller URL to reach the REST API (port 9080)
2. **Submit token** — controller validates: token exists, not revoked, not expired, not already used (if single-use)
3. **Receive certificates** — controller provisions mTLS certificates for ongoing communication
4. **Generate steward_id** — controller creates a unique ID with tenant prefix: `{tenant_id}-{uuid}`
5. **Switch to MQTT+QUIC** — steward establishes control plane (MQTT, port 1883) and data plane (QUIC, port 4433)
6. **Begin operations** — heartbeats, config sync, status reporting

After initial registration, the steward reconnects automatically on restart using its stored certificates. The registration token is only used once per steward.

## MSP Workflow

### 1. Build Signed Binary

One build per MSP deployment. The controller URL is the only compile-time setting.

```bash
make build-steward STEWARD_CONTROLLER_URL=https://controller.yourmsp.com
# Sign for each target platform
```

### 2. Create Tokens per Tenant

```bash
# Token for Tenant A — all production devices
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-a", "group": "production"}'

# Token for Tenant B — all production devices
curl -X POST http://controller:9080/api/v1/admin/registration-tokens \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "tenant-b", "group": "production"}'
```

### 3. Deploy via MDM

Same signed binary for all tenants. The token differentiates tenant placement.

**Intune (Windows):**
- Push `cfgms-steward.exe` as a Win32 app
- Install command: `cfgms-steward.exe --regtoken <tenant-token>`
- Detection rule: service `CFGMSSteward` exists

**GPO (Windows):**
- Deploy binary via software distribution
- Startup script installs service with `--regtoken <tenant-token>`

**RMM (Any platform):**
- Push binary + run install script with tenant-specific token

### 4. Application Allowlisting

One binary hash per platform — all tenants use the same signed binary.

**Windows AppLocker:**

```xml
<FilePathRule Id="..." Name="CFGMS Steward" Description="Allow CFGMS Steward"
              UserOrGroupSid="S-1-1-0" Action="Allow">
  <Conditions>
    <FileHashCondition>
      <FileHash Type="SHA256" Data="abc123..." SourceFileName="cfgms-steward.exe" />
    </FileHashCondition>
  </Conditions>
</FilePathRule>
```

## Security

### Binary Trust Model

- **Controller URL is immutable** — compiled in, not configurable at runtime
- **Code signing** — binary is signed by the MSP, verifiable by endpoint security
- **One hash per platform** — simplifies allowlisting across the fleet
- **Attacker cannot redirect** — obtaining the binary does not help an attacker; it will only talk to the legitimate controller

### Token Security

- **Transport security**: initial registration over HTTPS (port 9080), ongoing communication over mTLS
- **Tenant isolation**: each token bound to exactly one tenant
- **Revocation**: compromised tokens can be revoked immediately via API
- **Audit**: controller logs all registration attempts (successful and failed)

### Token Distribution

**Recommended:**

- Store tokens in MDM/RMM credential fields (not in scripts)
- Use separate tokens per tenant (never share tokens across tenants)
- Revoke tokens when decommissioning a tenant
- Monitor registration events for unauthorized attempts

**Avoid:**

- Committing tokens to version control
- Sharing tokens via email or chat
- Using the same token for all tenants (defeats tenant isolation)

## Troubleshooting

### Connection Failed

**Error**: `Failed to connect to controller: connection refused`

**Solution**:
- Verify controller is running and listening on port 9080
- Check network connectivity: `curl -k https://controller-host:9080/api/v1/health`
- Verify firewall allows TCP ports 9080 (REST), 1883 (MQTT), 4433 (QUIC/UDP)
- Confirm the binary was built with the correct controller URL

### Registration Rejected

**Error**: `Registration rejected: invalid token`

**Solution**:
- Verify the token has not been revoked
- Check token has not expired
- If single-use, check if it was already consumed
- Review controller logs for rejection details

### Certificate Error After Registration

**Error**: `TLS handshake failed` on reconnect

**Solution**:
- Check stored certificates have not expired
- Verify controller CA has not been rotated without re-provisioning stewards
- Re-register the steward if certificates are corrupted

## Implementation Status

### Completed (Story #198)

- MQTT-based registration with `--regtoken`
- Controller tenant validation
- Steward_id generation with tenant prefix
- Token expiration and single-use support
- mTLS certificate provisioning during registration
- Session-based QUIC authentication

### Completed (Story #421)

- Compile-time controller URL via ldflags (no runtime override)
- Removed `cfgms_reg_` token prefix (26-char base32 tokens)
- `STEWARD_CONTROLLER_URL` Makefile variable for build targets

### Future Enhancements

- Credential rotation mechanism
- Multi-region token distribution
- CLI tool for token management (`cfg token create/list/revoke`)
- MSI/DEB/RPM packaging with token injection

## References

- [Home Lab Deployment Guide](./home-lab-deployment-guide.md)
- [Quick Start Guide](../../QUICK_START.md)
- [Platform Support](./platform-support.md)
- [Steward Operating Model](../architecture/steward-operating-model.md)
