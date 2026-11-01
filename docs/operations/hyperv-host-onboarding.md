# Hyper-V Host Onboarding

This runbook documents how to register a Windows Server Hyper-V host with CFGMS
using the generic steward install. Hyper-V role management (convergence, VM
lifecycle) is delivered via cfg pushed by the controller after registration —
no role-specific flags are required at install time.

---

## 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Windows Server with Hyper-V role** | Hyper-V role installed and enabled. Server 2019 or 2022 recommended. |
| **Administrator shell** | Install must run in an elevated Administrator PowerShell session. |
| **Registration token** | From `cfg token create --tenant-id <tenant> --controller-url <host:port>`. Tokens expire after 1 hour; generate one just before installing. |
| **CA cert + fingerprint** *(private-CA only)* | From the installer download bundle's `installer/ca.crt` and `installer/ca.fingerprint` (see §2). Required only when the controller certificate is not issued by a public CA (Tier 1, internal CA, lab). |

---

## 2. Install

Run in an **elevated Administrator** shell on the Hyper-V host.

### Standard (public CA controller)

Write the token to a file only SYSTEM and Administrators can read, then install
from it (the steward rejects a token file that is readable by other users):

```powershell
$tokenFile = Join-Path $env:SystemRoot 'Temp\cfgms-regtoken'
Set-Content -LiteralPath $tokenFile -Value '<token>' -NoNewline
icacls $tokenFile /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)'
cfgms-steward.exe install --regtoken-file $tokenFile
Remove-Item -LiteralPath $tokenFile -Force
```

(Omitting `--controller-url` uses the binary's compile-time-baked controller
URL. Pass it explicitly if this binary wasn't built for this controller.)

### Private-CA deployment (Tier 1 / internal CA / lab)

Fetch the CA cert and fingerprint from the controller's installer download
endpoint first — no authentication required, this is the distribution
mechanism (Issue #1704):

```powershell
Invoke-WebRequest -Uri "https://<controller-host>:9080/api/v1/installer/download/windows/amd64" -OutFile installer.tar.gz
tar -xzf installer.tar.gz
# extracts to installer\ca.crt, installer\ca.fingerprint, installer\windows-amd64\cfgms-steward.exe
```

(Create `$tokenFile` as in the standard example above.)

```powershell
cfgms-steward.exe install `
    --regtoken-file $tokenFile `
    --controller-url <host:port> `
    --controller-ca .\installer\ca.crt `
    --fingerprint (Get-Content .\installer\ca.fingerprint)
```

The `--fingerprint` value is the SHA-256 fingerprint of the controller CA
certificate (lowercase hex, no colons) — the exact contents of
`installer/ca.fingerprint` in the bundle above.

---

## 3. Verify

```powershell
cfgms-steward status
```

Expected output shows `Status: running` and the controller URL. The controller
dashboard (`cfg steward list`) will show the new host within seconds.

---

## 4. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `registration pending operator approval` | Quarantine policy active | Run `cfg registration approve <pending_id>` on the controller |
| `fingerprint mismatch` | Wrong `--fingerprint` value | Re-download the installer bundle (§2) and use the exact contents of `installer/ca.fingerprint` — the CA may have been rotated since the value you have was captured |
| `install requires elevated privileges` | Not running as Administrator | Right-click PowerShell → Run as administrator |
| Service shows `stopped` after install | Startup failure (bad token, network) | Check `cfgms-steward status` and controller logs |
