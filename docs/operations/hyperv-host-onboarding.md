# Hyper-V Host Onboarding

**M1 deliverable.** This runbook documents how to register a Windows Server Hyper-V host
with CFGMS. A second operator following it cold can stand up a new host from scratch.

Scope: workgroup (non-domain) Windows Server hosts running the Hyper-V role.
Domain-joined hosts are out of scope for M1 — see §8.

---

## 1. Prerequisites

The following must be in place before running the install script. These are
operator-owned: the script does not configure them.

| Requirement | Notes |
|-------------|-------|
| **Windows Server with Hyper-V role** | Hyper-V role installed and enabled. Server 2019 or 2022 recommended. |
| **PowerShell 7+ (pwsh)** | Required to run `install-hyperv-host.ps1`. Install from the [GitHub releases page](https://github.com/PowerShell/PowerShell/releases). |
| **Administrator shell** | The install script must run in an elevated (Administrator) PowerShell session. |
| **WinRM enabled** | Run `Enable-PSRemoting -Force` once before the script. The script's WinRM hardening replaces the default cert; the base service must be enabled first. |
| **Controller URL** | From the Tier 1 bootstrap output, e.g. `https://ctrl.cfgms.lab:9080`. |
| **Registration token** | From `cfg token create --tenant infra-hyperv`. Tokens expire after 1 hour by default; generate one just before running the script. |
| **CA cert file** | `ca.crt` from the Tier 1 admin bundle, or exported from the controller with `cfg admin ca export`. |
| **CA fingerprint** | SHA-256 fingerprint printed by `cfg admin init` output, e.g. `a1b2c3...` (lowercase hex, no colons). |

To obtain the CA cert and fingerprint from a running controller:

```powershell
# On the operator workstation (Linux/macOS) or in WSL:
cfg admin ca export --out ca.crt
cfg admin ca fingerprint
```

Copy `ca.crt` to the Hyper-V host before running the install script.

---

## 2. One-Command Install

Run in an **elevated Administrator PowerShell session** on the Hyper-V host:

```powershell
.\scripts\install-hyperv-host.ps1 `
    -ControllerURL https://ctrl.cfgms.lab:9080 `
    -RegToken <token> `
    -CAFingerprint <lowercase-hex-no-colons> `
    -CACertPath .\ca.crt
```

**Omit `-WinRMPass`** to auto-generate a unique 32-byte random password for this host.
Never reuse the same WinRM password across hosts — a unique credential per host limits
blast radius if one host is compromised.

With a pre-downloaded binary (air-gapped environments):

```powershell
.\scripts\install-hyperv-host.ps1 `
    -ControllerURL https://ctrl.cfgms.lab:9080 `
    -RegToken <token> `
    -CAFingerprint <fingerprint> `
    -CACertPath .\ca.crt `
    -BinaryPath .\artifacts\cfgms-steward.exe
```

Expected output on success:

```
CA fingerprint verified.
WinRM password auto-generated (unique per host).

Installing CFGMS Steward (Hyper-V host)...
Step 1/8: Running base steward install...
Step 2/8: Generating WinRM TLS certificate (5yr) for hv01.cfgms.lab...
         Certificate thumbprint: ABCDEF1234567890...
Step 3/8: Configuring WinRM HTTPS listener on 127.0.0.1:5986...
Step 4/8: Configuring firewall rules (loopback-only for port 5986)...
Step 5/8: Creating local service account cfgms-hyperv...
Step 6/8: Adding cfgms-hyperv to Hyper-V Administrators and Remote Management Users...
Step 7/8: Storing WinRM credentials in secret store...
Step 8/8: Done.

Hyper-V host install complete.
Add the following to your steward config:

  winrm_host: localhost
  winrm_user_secret: hyperv/winrm_user
  winrm_pass_secret: hyperv/winrm_pass
Install command succeeded.

Waiting for steward to report healthy (up to 60 s)...

CFGMS Steward is registered and healthy.
```

If the script exits non-zero, see §7 (Troubleshooting).

---

## 3. What the Script Does

The orchestrator (`install-hyperv-host.ps1`) performs these steps in order.

### 3a. Resolve binary

If `-BinaryPath` is not supplied, the script resolves the latest GitHub release tag
via the GitHub API and downloads `cfgms-steward-windows-amd64.exe` to `$env:TEMP`.
A cached copy is reused across runs.

**Manual equivalent:**
```powershell
$ver = (Invoke-RestMethod https://api.github.com/repos/cfg-is/cfgms/releases/latest).tag_name
Invoke-WebRequest "https://github.com/cfg-is/cfgms/releases/download/$ver/cfgms-steward-windows-amd64.exe" `
    -OutFile "$env:TEMP\cfgms-steward.exe" -UseBasicParsing
```

### 3b. Verify CA fingerprint

The script computes the SHA-256 fingerprint of the PEM-encoded CA cert and compares it
to `-CAFingerprint`. If there is a mismatch, the script exits immediately before
touching the host.

**Manual equivalent:**
```powershell
$certBytes = [IO.File]::ReadAllBytes('ca.crt')
$cert      = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
$sha256    = [Security.Cryptography.SHA256]::Create()
$hash      = $sha256.ComputeHash($cert.RawData)
($hash | ForEach-Object { $_.ToString('x2') }) -join ''
# Compare the printed value to -CAFingerprint before proceeding.
```

### 3c. Generate WinRM password

If `-WinRMPass` is omitted, the script generates a 32-byte CSPRNG password encoded
as Base64. The plaintext is held only in memory for the duration of the stdin pipe
write, then immediately cleared.

**Manual equivalent:** generate any 32-byte random Base64 string; store it securely.

### 3d. Base steward install (Step 1/8)

Runs `cfgms-steward install --regtoken <token> --hyperv --winrm-user cfgms-hyperv --winrm-pass-stdin`.
This registers the steward binary as a Windows SCM service, writes the CA cert to the
steward credential store, and verifies the controller fingerprint.

**Why `--winrm-pass-stdin`?** Passing credentials via `$args` would expose the plaintext
in the Windows process list (visible to any local Administrator via Task Manager or
`Get-WmiObject Win32_Process`). Piping via stdin keeps it out of all observable surfaces
(stdout, stderr, Windows event log, PowerShell transcripts, and the process argument list).

**Manual equivalent:**
```powershell
$pass | & .\cfgms-steward.exe install `
    --regtoken <token> `
    --hyperv `
    --winrm-user cfgms-hyperv `
    --winrm-pass-stdin `
    --ca-cert .\ca.crt `
    --fingerprint <fingerprint> `
    --controller-url https://ctrl.cfgms.lab:9080
```

### 3e. Generate WinRM TLS certificate (Step 2/8)

Runs `New-SelfSignedCertificate` in `cert:\LocalMachine\My` with SAN set to
`{localhost, 127.0.0.1, <FQDN>}` and `-NotAfter` set to 5 years from now.

**Why replace the default WinRM cert?** `Enable-PSRemoting` installs a self-signed
cert whose SAN is just the machine name — it lacks `127.0.0.1` and `localhost`. The
CFGMS Hyper-V module connects to `localhost:5986`; if `localhost` or `127.0.0.1` is
absent from the SAN, TLS verification fails and WinRM connections are rejected. The
5-year lifetime avoids the ~1-year default expiry, which causes silent breakage (F10).

**Manual equivalent:**
```powershell
$fqdn = [System.Net.Dns]::GetHostEntry('').HostName
$cert = New-SelfSignedCertificate `
    -DnsName @('localhost', '127.0.0.1', $fqdn) `
    -CertStoreLocation cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(5)
$thumbprint = $cert.Thumbprint
```

### 3f. Bind WinRM listener to loopback (Step 3/8)

Deletes any existing WinRM HTTPS listener and creates a new one bound to
`127.0.0.1:5986` using the thumbprint from Step 2/8.

**Why `127.0.0.1` not `0.0.0.0`?** The CFGMS steward runs on the same host as the
Hyper-V module and connects to WinRM over loopback only. Binding to `0.0.0.0` would
expose the WinRM HTTPS port on all network interfaces, increasing the attack surface
for credential theft. Loopback-only binding ensures no remote host can initiate a
WinRM connection.

**Manual equivalent:**
```powershell
& winrm delete 'winrm/config/Listener?Address=*+Transport=HTTPS' 2>$null
& winrm set 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' `
    "@{CertificateThumbprint='$thumbprint'}"
```

### 3g. Configure firewall rules (Step 4/8)

Removes the broad WinRM allow rules created by `Enable-PSRemoting` (which allow port
5986 from any address) and replaces them with:

1. Allow inbound TCP 5986 when `LocalAddress=127.0.0.1` **and** `RemoteAddress=127.0.0.1`
2. Block all other inbound TCP traffic on port 5986

**Why restrict to loopback?** The loopback listener (Step 3f) prevents remote
connections at the socket level, but Windows Firewall rules provide defence-in-depth.
The explicit deny rule ensures that even if the listener binding is accidentally
changed to `0.0.0.0`, non-loopback traffic is still dropped at the firewall.

**Manual equivalent:**
```powershell
Get-NetFirewallRule -DisplayName 'Windows Remote Management*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'CFGMS WinRM HTTPS (loopback only)' `
    -Direction Inbound -Protocol TCP -LocalPort 5986 `
    -LocalAddress 127.0.0.1 -RemoteAddress 127.0.0.1 -Action Allow | Out-Null
New-NetFirewallRule -DisplayName 'CFGMS WinRM HTTPS (deny non-loopback)' `
    -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Block | Out-Null
```

### 3h. Create local service account (Step 5/8)

Creates (or updates) the local user `cfgms-hyperv` with the auto-generated password
and sets `PasswordNeverExpires`. The password is passed via stdin to the PowerShell
script — it never appears in `$args`.

**Manual equivalent:**
```powershell
$secPass = ConvertTo-SecureString -String '<password>' -AsPlainText -Force
try {
    New-LocalUser -Name cfgms-hyperv -Password $secPass -PasswordNeverExpires
} catch {
    Set-LocalUser -Name cfgms-hyperv -Password $secPass -PasswordNeverExpires
}
```

### 3i. Add to required groups (Step 6/8)

Adds `cfgms-hyperv` to the following local groups:

| Group | Reason |
|-------|--------|
| **Users** | Default group for all local users; already assigned by `New-LocalUser`. |
| **Hyper-V Administrators** | Required to enumerate and manage VMs, switches, and checkpoints. |
| **Remote Management Users** | Required to accept inbound WinRM connections. |

**Manual equivalent:**
```powershell
Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member cfgms-hyperv -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group 'Remote Management Users' -Member cfgms-hyperv -ErrorAction SilentlyContinue
```

Verify membership:
```powershell
Get-LocalGroupMember 'Hyper-V Administrators'
Get-LocalGroupMember 'Remote Management Users'
Get-LocalGroupMember 'Users'
```

### 3j. Store WinRM credentials (Step 7/8)

Pre-populates the OS-native steward secret store with two keys:

| Key | Value |
|-----|-------|
| `hyperv/winrm_user` | `cfgms-hyperv` (username) |
| `hyperv/winrm_pass` | Auto-generated password |

The Hyper-V module reads these keys on every WinRM call — credentials are never cached
between calls.

**Manual equivalent (if using a pre-set password):**
```powershell
# Register the steward, then store credentials in its secret store:
.\cfgms-steward.exe secret set --key hyperv/winrm_user --value cfgms-hyperv
.\cfgms-steward.exe secret set --key hyperv/winrm_pass --value '<password>'
```

### 3k. Poll until healthy (orchestrator step)

After the `cfgms-steward install` command returns, the orchestrator calls
`cfgms-steward status` every 5 seconds for up to 60 seconds. When `status` exits 0
the host is registered and healthy.

**Manual equivalent:**
```powershell
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
    if (& .\cfgms-steward.exe status; $LASTEXITCODE -eq 0) { break }
    Start-Sleep 5
}
```

---

## 4. Manual Equivalent (Restricted Environments)

If the orchestrator script cannot run (no PowerShell 7, restricted execution policy,
no outbound internet), perform each step manually in the order listed in §3.

Summary checklist for manual installs:

1. Download `cfgms-steward-windows-amd64.exe` (§3a)
2. Verify CA fingerprint (§3b)
3. Generate a unique WinRM password (§3c); store it in your password manager
4. Run `cfgms-steward install --hyperv --winrm-pass-stdin` with password piped via
   stdin (§3d)
5. Generate TLS cert with SAN `{localhost, 127.0.0.1, <FQDN>}`, 5-year lifetime (§3e)
6. Delete the default WinRM HTTPS listener; create loopback-bound listener at
   `127.0.0.1:5986` with the new thumbprint (§3f)
7. Remove the broad `Enable-PSRemoting` WinRM firewall rules; add loopback-only allow
   and block-all-other rules for port 5986 (§3g)
8. Create local user `cfgms-hyperv` with the password, `PasswordNeverExpires` (§3h)
9. Add `cfgms-hyperv` to `Hyper-V Administrators` and `Remote Management Users` (§3i)
10. Store credentials in the steward secret store (§3j)
11. Start the `cfgms-steward` Windows service and wait for `cfgms-steward status` to
    exit 0 (§3k)

---

## 5. Verification

### On the Hyper-V host

Verify the steward service is running:

```powershell
# Check Windows service status
Get-Service cfgms-steward

# Check steward health
.\cfgms-steward.exe status
```

Expected output from `cfgms-steward status`:

```
✓ Transport (healthy)
✓ Storage (healthy)
✓ Application (healthy)
```

Check the steward logs (Windows event log):

```powershell
Get-EventLog -LogName Application -Source cfgms-steward -Newest 20
```

### From the operator workstation

List all registered stewards. A healthy Hyper-V host entry looks like this:

```
ID              STATUS     VERSION  LAST SEEN             HOSTNAME
--              ------     -------  ---------             --------
steward-a1b2c3  connected  1.2.0    2026-06-02 14:00:18   hv01
```

`STATUS` must be `connected`. `LAST SEEN` must be within the last 30 seconds — the
steward heartbeats every 20 seconds (base interval per epic #1664, ±up to 10 s jitter;
effective interval always in [20 s, 30 s)). If `LAST SEEN` is older than 60 seconds,
the controller has marked the steward offline (3 missed heartbeats).

Inspect the specific steward for full details:

```
$ cfg steward status steward-a1b2c3

ID:               steward-a1b2c3
Status:           connected
Connection:       connected
Last Seen:        2026-06-02 14:00:18
Version:          1.2.0
Hostname:         hv01
OS:               windows
Architecture:     amd64
```

To confirm live heartbeats, poll `cfg steward status` twice 30 seconds apart and
confirm `Last Seen` advances:

```powershell
cfg steward status steward-a1b2c3
Start-Sleep 30
cfg steward status steward-a1b2c3
# Last Seen must have advanced.
```

---

## 6. Adding a Second Host

Run the same script invocation on the new host. **Omit `-WinRMPass`** for each host
so that each host receives a unique auto-generated credential:

```powershell
# On hv02 — note: no -WinRMPass flag
.\scripts\install-hyperv-host.ps1 `
    -ControllerURL https://ctrl.cfgms.lab:9080 `
    -RegToken <new-token-for-hv02> `
    -CAFingerprint <fingerprint> `
    -CACertPath .\ca.crt
```

After the script completes, verify from the operator workstation:

```
$ cfg steward list

ID              STATUS     VERSION  LAST SEEN             HOSTNAME
--              ------     -------  ---------             --------
steward-a1b2c3  connected  1.2.0    2026-06-02 14:00:18   hv01
steward-d4e5f6  connected  1.2.0    2026-06-02 14:00:20   hv02
```

Each host has its own steward ID and its own `cfgms-hyperv` local account with a
distinct password. Reusing a password across hosts means a compromised credential on
one host grants WinRM access to all hosts sharing that password.

---

## 7. Troubleshooting

### WinRM TLS cert SAN mismatch

**Symptom:** WinRM connections from the steward fail with a TLS error:
```
WinRM: TLS certificate verification failed — the server certificate does not contain
the required Subject Alternative Names
```
or the Hyper-V module logs:
```
winrm: x509: certificate is valid for SERVERNAME, not 127.0.0.1
```

**Cause:** The WinRM cert was not replaced during install, or a subsequent
`Enable-PSRemoting` call overwrote it with a cert that lacks `localhost` or
`127.0.0.1` in the SAN.

**Resolution:** Confirm the current WinRM cert SANs:
```powershell
$thumb = (Get-WSManInstance winrm/config/Listener -Selector @{Address='IP:127.0.0.1';Transport='HTTPS'}).CertificateThumbprint
(Get-ChildItem cert:\LocalMachine\My\$thumb).DnsNameList
# Must include: localhost, 127.0.0.1, and the machine FQDN
```

If `localhost` or `127.0.0.1` is missing, regenerate the cert and rebind the listener:
```powershell
$fqdn = [System.Net.Dns]::GetHostEntry('').HostName
$cert = New-SelfSignedCertificate `
    -DnsName @('localhost', '127.0.0.1', $fqdn) `
    -CertStoreLocation cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(5)
& winrm delete 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' 2>$null
& winrm set 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' `
    "@{CertificateThumbprint='$($cert.Thumbprint)'}"
```

The install script (§3e–3f) installs both the correct cert and the loopback-bound
listener in a single run.

### WinRM listener bound to wrong address

**Symptom:** WinRM connections fail with `connection refused` or the listener is
reachable on non-loopback interfaces.

**Check:** Confirm the listener is bound to `127.0.0.1`:
```powershell
Get-WSManInstance winrm/config/Listener -Enumerate |
    Select-Object Address, Transport, Port, CertificateThumbprint
# Address must be 'IP:127.0.0.1', not '*' (0.0.0.0)
```

**Resolution:** Delete the broad listener and create a loopback-bound one (§3f manual
equivalent). Re-running the install script is idempotent and will correct this.

### Firewall rule verification

**Check:** Confirm that port 5986 is only reachable from loopback:
```powershell
Get-NetFirewallRule -DisplayName 'CFGMS WinRM*' | Select-Object DisplayName, Action |
    Format-Table -AutoSize

# Expected:
# DisplayName                           Action
# -----------                           ------
# CFGMS WinRM HTTPS (loopback only)     Allow
# CFGMS WinRM HTTPS (deny non-loopback) Block
```

If the `Windows Remote Management*` rules are present (created by `Enable-PSRemoting`),
they allow traffic from any address and must be removed:
```powershell
Get-NetFirewallRule -DisplayName 'Windows Remote Management*' |
    Remove-NetFirewallRule
```

### Service account group membership

**Check:** Verify `cfgms-hyperv` belongs to exactly these local groups:

```powershell
Get-LocalGroupMember 'Users' | Where-Object Name -like '*cfgms-hyperv*'
Get-LocalGroupMember 'Hyper-V Administrators' | Where-Object Name -like '*cfgms-hyperv*'
Get-LocalGroupMember 'Remote Management Users' | Where-Object Name -like '*cfgms-hyperv*'
```

All three commands must return a result. If `Hyper-V Administrators` or
`Remote Management Users` is missing, add the account:
```powershell
Add-LocalGroupMember -Group 'Hyper-V Administrators' -Member cfgms-hyperv
Add-LocalGroupMember -Group 'Remote Management Users' -Member cfgms-hyperv
```

### Registration failures

**Symptom:** `cfgms-steward status` exits non-zero or shows `not installed`.

**Check:**
```powershell
Get-EventLog -LogName Application -Source cfgms-steward -Newest 50 |
    Where-Object EntryType -ne 'Information'
```

Common causes:

| Log message | Cause | Fix |
|-------------|-------|-----|
| `registration token expired` | Token created more than 1 hour before install | Generate a new token: `cfg token create --tenant infra-hyperv` |
| `fingerprint mismatch` | `-CAFingerprint` does not match the CA cert file | Obtain the correct fingerprint: `cfg admin ca fingerprint` |
| `controller unreachable` | Network or firewall issue on port 9080 (REST) or 4433/UDP (gRPC) | Verify connectivity from the host to the controller |
| `requires Administrator privileges` | Script not run as Administrator | Right-click PowerShell → Run as administrator |

### WinRM certificate expiry

**Symptom:** WinRM connections that previously worked begin failing with a TLS
handshake error. The steward logs show:

```
winrm: x509: certificate has expired or is not yet valid
```

Check the expiry of the current WinRM cert:

```powershell
$thumb = (Get-WSManInstance winrm/config/Listener `
    -Selector @{Address='IP:127.0.0.1';Transport='HTTPS'}).CertificateThumbprint
$expiry = (Get-ChildItem cert:\LocalMachine\My\$thumb).NotAfter
Write-Host "WinRM cert expires: $expiry"
```

If the cert is expired (or near expiry), rotate it manually:

```powershell
# 1. Generate a new 5-year cert with the required SAN
$fqdn = [System.Net.Dns]::GetHostEntry('').HostName
$newCert = New-SelfSignedCertificate `
    -DnsName @('localhost', '127.0.0.1', $fqdn) `
    -CertStoreLocation cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(5)

# 2. Update the WinRM listener to use the new thumbprint
& winrm delete 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' 2>$null
& winrm set 'winrm/config/Listener?Address=IP:127.0.0.1+Transport=HTTPS' `
    "@{CertificateThumbprint='$($newCert.Thumbprint)'}"

# 3. Verify
Write-Host "New thumbprint: $($newCert.Thumbprint)"
Write-Host "New expiry: $($newCert.NotAfter)"
```

The install script sets `-NotAfter (Get-Date).AddYears(5)` so certs generated by
`install-hyperv-host.ps1` should not need rotation for 5 years.

---

## 8. Domain-Joined Hosts

Domain-joined Windows Server hosts are **out of scope for M1**. The WinRM service
account provisioning, Kerberos authentication configuration, and group policy
interactions required for domain membership add significant complexity that is not
tested in this milestone.

If your Hyper-V host is domain-joined, do not use this runbook. A domain-joined
onboarding procedure will be documented in a future milestone.
