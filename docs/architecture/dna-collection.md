# DNA Collection Audit

Tracks which DNA attributes are collected on each platform, whether each implementation emits real data or stub values, and which gaps have been resolved.

**Status legend:**

| Symbol | Meaning |
|--------|---------|
| GREEN | Real value emitted by a platform-specific collector |
| RED/GAP | Stub or placeholder — not yet implemented |
| N/A | Not applicable on this platform |

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

Security collection status is managed by the security collectors. See the security collector implementations for full attribute lists.

---

## Gap Tracking

Stories that resolved gaps in this document:

| Story | Gap Resolved |
|-------|-------------|
| #1946 | Linux and Windows routing, DNS, and firewall attributes implemented (previously RED/GAP) |
