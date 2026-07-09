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
| **Registration token** | From `cfg token create --tenant <tenant>`. Tokens expire after 1 hour; generate one just before installing. |
| **CA cert + fingerprint** *(private-CA only)* | From `cfg admin ca export` and `cfg admin ca fingerprint`. Required only when the controller certificate is not issued by a public CA (Tier 1, internal CA, lab). |

---

## 2. Install

Run in an **elevated Administrator** shell on the Hyper-V host.

### Standard (public CA controller)

```powershell
cfgms-steward.exe install --regtoken <token>
```

### Private-CA deployment (Tier 1 / internal CA / lab)

```powershell
cfgms-steward.exe install `
    --regtoken <token> `
    --ca-cert .\ca.crt `
    --fingerprint <lowercase-hex-no-colons>
```

The `--fingerprint` value is the SHA-256 fingerprint of the controller CA
certificate, printed by `cfg admin init` and retrievable at any time with:

```powershell
cfg admin ca fingerprint
```

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
| `fingerprint mismatch` | Wrong `--fingerprint` value | Re-run `cfg admin ca fingerprint` and copy the exact output |
| `install requires elevated privileges` | Not running as Administrator | Right-click PowerShell → Run as administrator |
| Service shows `stopped` after install | Startup failure (bad token, network) | Check `cfgms-steward status` and controller logs |
