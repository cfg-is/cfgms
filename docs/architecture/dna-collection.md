# DNA Collection Audit

Tracks which DNA attributes are collected on each platform, whether each implementation emits real data or stub values, and which gaps have been resolved.

**Status legend:**

| Symbol | Meaning |
|--------|---------|
| GREEN | Real value emitted by a platform-specific collector |
| YELLOW | Partially implemented (some edge cases return stub/empty) |
| RED/GAP | Stub or placeholder — not yet implemented |
| N/A | Not applicable on this platform |

**Sensitivity classifications:**

| Class | Meaning |
|-------|---------|
| `public` | Safe to log and display as-is |
| `tenant-sensitive` | RFC1918 topology, routing data, domain names — redact in multi-tenant logs |
| `pii` | Usernames, account names, domain account names — never log, treat as PII |

---

## Network Attributes

### Routing

| Attribute | Linux | Windows | macOS | Source |
|-----------|-------|---------|-------|--------|
| `default_gateway` | GREEN | GREEN | GREEN | Linux: `/proc/net/route`; Windows: `route print -4`; macOS: `route get default` |
| `ipv4_route_count` | GREEN | GREEN | GREEN | Linux: `/proc/net/route` (capped at 500); Windows: `route print -4` (capped at 500); macOS: `netstat -rn -f inet` |

**Linux note:** `/proc/net/route` stores addresses in host byte order (little-endian on x86/x64). The collector decodes the hex values to dotted-decimal before storing.

**Sensitivity:** IP/gateway values expose internal RFC1918 topology. Multi-tenant exposure is controlled by controller-side ACLs (dependency on the ACL story). Values are sanitised with `logging.SanitizeLogValue()` before storage.

### DNS

| Attribute | Linux | Windows | macOS | Source |
|-----------|-------|---------|-------|--------|
| `dns_servers` | GREEN | GREEN | GREEN | Linux: `/etc/resolv.conf`; Windows: registry `Tcpip\Parameters\Interfaces` per-adapter `DhcpNameServer`/`NameServer`; macOS: `scutil --dns` + `networksetup` |
| `dns_search_domains` | GREEN | N/A | GREEN | Linux: `/etc/resolv.conf` `search`/`domain` lines |
| `dns_domain` | N/A | GREEN | N/A | Windows: registry `Tcpip\Parameters` `Domain`/`DhcpDomain` |

**Linux note:** On systemd-resolved systems the nameserver is the stub `127.0.0.53` — this is expected and is stored as-is (not treated as an error).

**Truncation:** `dns_servers` joined string is truncated to 256 characters before storage.

**Sensitivity:** DNS server addresses and domain names expose internal routing data. Values are sanitised with `logging.SanitizeLogValue()` before storage.

### Firewall

| Attribute | Linux | Windows | macOS | Source |
|-----------|-------|---------|-------|--------|
| `ufw_firewall_state` | GREEN | N/A | N/A | Linux: `ufw status` (values: `active`, `inactive`) |
| `iptables_rule_count` | GREEN | N/A | N/A | Linux: `iptables -L --line-numbers` fallback when ufw is absent |
| `firewall_state` | GREEN | N/A | N/A | Linux: `unknown` when both ufw and iptables are unavailable or permission denied |
| `windows_firewall_domain_profile` | N/A | GREEN | N/A | Windows: `netsh advfirewall show allprofiles state` (values: `enabled`, `disabled`) |
| `windows_firewall_private_profile` | N/A | GREEN | N/A | Windows: `netsh advfirewall show allprofiles state` |
| `windows_firewall_public_profile` | N/A | GREEN | N/A | Windows: `netsh advfirewall show allprofiles state` |
| `macos_firewall_state` | N/A | N/A | GREEN | macOS: `defaults read /Library/Preferences/com.apple.alf globalstate` |
| `pfctl_rule_count` | N/A | N/A | GREEN | macOS: `pfctl -s rules` |

**Linux degradation order:**
1. `ufw status` → sets `ufw_firewall_state`
2. `iptables -L --line-numbers` → sets `iptables_rule_count`
3. Either unavailable or permission denied → sets `firewall_state=unknown`

---

## Hardware Attributes

Hardware collection status is managed by the hardware collectors (`LinuxHardwareCollector`, `WindowsHardwareCollector`, `DarwinHardwareCollector`). See the hardware collector implementations for full attribute lists.

---

## Software Attributes

Software collection status is managed by the software collectors. See the software collector implementations for full attribute lists.

---

## Security Attributes

| Attribute | Linux | Windows | macOS | Sensitivity | Source |
|-----------|-------|---------|-------|-------------|--------|
| `local_user_count` | GREEN | GREEN | N/A | public | Linux: `/etc/passwd`; Windows: `Get-LocalUser \| Measure-Object` (PowerShell `-File`) |
| `root_account_locked` | GREEN | N/A | N/A | public | Linux: `passwd -S root` (argv form; `/etc/shadow` not read) |
| `local_group_count` | GREEN | GREEN | N/A | public | Linux: `/etc/group`; Windows: `Get-LocalGroup \| Measure-Object` |
| `local_admins_count` | GREEN | GREEN | N/A | public | Linux: sudo/wheel group member count; Windows: `Administrators` group member count |
| `sudo_installed` | GREEN | N/A | N/A | public | Linux: presence of `sudo` binary |
| `suid_binary_count` | GREEN | N/A | N/A | public | Linux: `find` in `/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -maxdepth 3` with 10s timeout |
| `domain_joined` | GREEN | GREEN | N/A | public | Linux: `realm list` then `/etc/sssd/sssd.conf` / `/etc/winbind.conf`; Windows: registry `Tcpip\Parameters` `Domain` non-empty |
| `domain_name` | GREEN | GREEN | N/A | tenant-sensitive | Same sources; sanitised via `logging.SanitizeLogValue()` |
| `luks_encrypted_devices` | GREEN | N/A | N/A | public | Linux: `lsblk -o NAME,FSTYPE` counting `crypto_LUKS` |
| `luks_device_names` | GREEN | N/A | N/A | public | Linux: same source, comma-separated |
| `bitlocker_enabled` | N/A | GREEN | N/A | public | Windows: `manage-bde -status` with PowerShell `Get-BitLockerVolume` fallback |
| `bitlocker_volumes` | N/A | GREEN | N/A | public | Windows: protected volume drive letters, comma-separated |
| `av_products_detected` | GREEN | GREEN | N/A | public | Linux: process-name match (`clamd`, `falcond`, `ds_agent`); Windows: `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct` (client SKU only — empty on Server SKU; check `ProductType` registry) |
| `cert_root_count` | N/A | GREEN | N/A | public | Windows: certificate store enumeration; metadata only (Subject, Issuer, NotBefore, NotAfter, SHA-256 fingerprint, key-usage). Private-key bytes MUST NEVER appear. |
| `cert_intermediate_count` | N/A | GREEN | N/A | public | Windows: as above |
| `cert_personal_count` | N/A | GREEN | N/A | public | Windows: as above |
| `sip_status` | N/A | N/A | GREEN | public | macOS: `csrutil status` |
| `gatekeeper_status` | N/A | N/A | GREEN | public | macOS: `spctl --status` |
| `total_user_count` | N/A | N/A | GREEN | public | macOS: `dscl . list /Users` |
| `regular_user_count` | N/A | N/A | GREEN | public | macOS: regular (non-system) user count |
| `total_group_count` | N/A | N/A | GREEN | public | macOS: `dscl . list /Groups` |
| `keychain_count` | N/A | N/A | GREEN | public | macOS: `security list-keychains` |

**`av_products_detected` caveat:** best-effort; absence does not imply absence of AV. Process-name match is fingerprinting-friendly, not authoritative. On Windows Server SKUs `root/SecurityCenter2` returns empty and the value is `"none"`.

**Attribute sanitisation:** values that may contain identity or topology data MUST be passed through `logging.SanitizeLogValue()` before storage. Currently in scope:

- `domain_name` (may contain a domain name — tenant-sensitive)
- `av_products_detected` (product names may contain unusual characters on Windows)

---

## Must-Collect Attributes

The following attributes MUST be emitted by a compliant steward binary on each respective platform. Integration tests assert their presence.

### All Platforms

| Attribute Key | Expected Type |
|---------------|---------------|
| `runtime_os` | string (e.g. `linux`, `windows`, `darwin`) |
| `runtime_arch` | string (e.g. `amd64`, `arm64`) |
| `cpu_count` | integer string |
| `os` | string |

### Linux

| Attribute Key | Expected Type |
|---------------|---------------|
| `local_user_count` | integer string ≥ 1 |
| `local_group_count` | integer string ≥ 0 |
| `local_admins_count` | integer string ≥ 0 |
| `domain_joined` | `"true"` or `"false"` |
| `luks_encrypted_devices` | integer string ≥ 0 |
| `av_products_detected` | non-empty string (`"none"` if no AV found) |
| `sudo_installed` | `"true"` or `"false"` |

### Windows

| Attribute Key | Expected Type |
|---------------|---------------|
| `local_user_count` | integer string ≥ 1 |
| `local_group_count` | integer string ≥ 0 |
| `local_admins_count` | integer string ≥ 0 |
| `domain_joined` | `"true"` or `"false"` |
| `bitlocker_enabled` | `"true"` or `"false"` |
| `av_products_detected` | non-empty string (`"none"` on Server SKU if `root/SecurityCenter2` returns empty) |

### macOS

| Attribute Key | Expected Type |
|---------------|---------------|
| `total_user_count` | integer string ≥ 1 |
| `total_group_count` | integer string ≥ 0 |
| `sip_status` | `"enabled"`, `"disabled"`, or `"unknown"` |
| `gatekeeper_status` | non-empty string |

---

## Gap Tracking

Stories that resolved gaps in this document:

| Story | Gap Resolved |
|-------|-------------|
| #1946 | Linux and Windows routing, DNS, and firewall attributes implemented (previously RED/GAP) |
| #1939 | Linux and Windows security collectors implemented: `domain_joined`, `domain_name`, `luks_*`, `bitlocker_*`, `av_products_detected`, `local_admins_count` (previously RED/GAP) |
