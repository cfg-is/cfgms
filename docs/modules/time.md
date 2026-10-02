# time module

Manages host timezone and NTP/time-sync configuration.

## Rationale

Time skew breaks Kerberos authentication, TLS certificate validation, and log
correlation. Timezone and NTP configuration are therefore foundational
properties of every managed host — correct time is a precondition for most
other management operations. The `time` module declares authoritative ownership
over the `time` DNA object kind (ADR-016 clause 5), ensuring no other module
or manual change silently drifts the host clock configuration.

## Fields

| Field | Type | Description |
|-------|------|-------------|
| `timezone` | string | IANA timezone identifier (e.g. `UTC`, `America/Chicago`) |
| `ntp_servers` | list of strings | NTP server hostnames or IP addresses (sorted alphabetically) |
| `ntp_sync_enabled` | bool | Whether automatic NTP synchronisation is enabled |

`timezone` is required; `ntp_servers` may be empty; `ntp_sync_enabled` defaults
to `false` when not specified.

## Example DNA fragment

```yaml
timezone: America/Chicago
ntp_servers:
  - time1.example.com
  - time2.example.com
ntp_sync_enabled: true
```

## Platform behaviour

### Linux

- **Timezone**: stored in `/etc/timezone` (IANA name); runtime-applied via
  `timedatectl set-timezone`. Assumes systemd-timesyncd as the time-sync daemon.
- **NTP servers**: stored in `/etc/systemd/timesyncd.conf` under `[Time]\nNTP=`.
- **NTP sync enabled**: tracked via a CFGMS-managed comment in the same config
  file; runtime-applied via `timedatectl set-ntp`.
- When timedatectl is unavailable (containers, CI without systemd), file writes
  persist the desired state and take effect on next service start or boot.

### Windows

- **Timezone**: managed via `tzutil /s` (set) and `tzutil /g` (get).
  Windows timezone identifiers use Windows format (e.g. `Eastern Standard Time`),
  not IANA format. Pass the Windows identifier as the `timezone` field value.
- **NTP servers**: managed via `w32tm /config /manualpeerlist`.
- **NTP sync enabled**: managed via `w32tm /config /syncfromflags`.

### macOS

- **Timezone**: managed via `systemsetup -settimezone` / `-gettimezone`.
- **NTP server**: managed via `systemsetup -setnetworktimeserver` /
  `-getnetworktimeserver`. macOS supports only a single NTP server; if
  `ntp_servers` contains multiple entries only the first (alphabetically) is
  applied.
- **NTP sync enabled**: managed via `systemsetup -setusingnetworktime` /
  `-getusingnetworktime`.

## Security notes

- Requires root privileges on all platforms to write time configuration.
- Shells out to `timedatectl`, `tzutil.exe`, `w32tm.exe`, and `systemsetup`
  as declared in `module.yaml`'s `behavioral_envelope`.
- No credentials or secrets are handled by this module.

## Determinism

`Get` always returns `ntp_servers` sorted alphabetically. `AsMap()` is
byte-for-byte identical on repeated calls against unchanged state, satisfying
ADR-016 clause 4.
