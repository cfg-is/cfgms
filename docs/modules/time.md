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
| `ntp_source` | `manual` \| `domain` | Where time is synchronised from. Default `manual`. Windows only for `domain` |
| `ntp_reliable` | bool | Declare the host a reliable time source. Default `false`. Windows only |
| `hyperv_host_time_provider` | `enabled` \| `disabled` \| empty | Hyper-V guest time provider (`VMICTimeProvider`). Empty means unmanaged. Windows only |

`timezone` is required; `ntp_servers` may be empty; `ntp_sync_enabled` defaults
to `false` when not specified. Unknown `ntp_source` or `hyperv_host_time_provider`
values are rejected by validation. On Linux and macOS any non-default value of
`ntp_source`, `ntp_reliable` or `hyperv_host_time_provider` is rejected with an
invalid-input error.

`reliable` is no longer set implicitly. Earlier versions declared every Windows
host a reliable time source; that is correct only for the forest-root PDC
emulator. Hosts must now set `ntp_reliable: true` explicitly. Existing configs
that set only `ntp_servers` still converge, and now run with `/reliable:no`.

## Example DNA fragment

```yaml
timezone: America/Chicago
ntp_servers:
  - time1.example.com
  - time2.example.com
ntp_sync_enabled: true
```

## Example resource

A role config resource (full file: `docs/examples/role-configs/time-sync.cfg`):

```yaml
resources:
  - name: "time-sync"
    module: "time"
    config:
      timezone: "UTC"
      ntp_servers:
        - "time1.example.com"
        - "time2.example.com"
      ntp_sync_enabled: true
```

## Opting out

The module owns the `time` DNA object kind only for a host whose config
declares a `time` resource (ADR-016 clause 5). To leave time unmanaged — for
example where time comes from directory services or a hypervisor — declare no
`time` resource for that host or role. Omitting the resource leaves time
unmanaged.

`ntp_sync_enabled: false` is not an opt-out. It is a declared state: the host
is converged to NTP sync disabled. Because `timezone` is required, any declared
`time` resource must also set it.

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
- **Precedence**, in order:
  1. `ntp_sync_enabled: false` runs `/syncfromflags:no`; the other three fields
     are ignored for sync.
  2. `ntp_source: domain` runs `w32tm /config /syncfromflags:domhier /reliable:no /update`
     and ignores `ntp_servers`. Use it for domain members and non-PDC domain
     controllers.
  3. `ntp_source: manual` (default) uses `ntp_servers` (default peer
     `time.windows.com,0x9` when empty) and passes `/reliable:yes` only when
     `ntp_reliable: true`, `/reliable:no` otherwise.
- **Hyper-V guest time provider**: `hyperv_host_time_provider` sets the `Enabled`
  DWORD (`0` for `disabled`, `1` for `enabled`) at
  `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider`
  and restarts `w32time` only when the value changed. A domain controller
  running as a Hyper-V guest, the PDC emulator included, should set it to
  `disabled`; otherwise host time sync overrides the domain hierarchy. A host is
  a Hyper-V guest when `HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters`
  exists; on any other host the field is a no-op and `Get` reports it empty.
- **Read-back**: `Get` reports `ntp_source` from `Type` in
  `w32tm /query /configuration` (`NT5DS` is `domain`, `NTP` is `manual`),
  `ntp_reliable` from `AnnounceFlags` (bit `0x4` set means reliable) and
  `hyperv_host_time_provider` from the `Enabled` value on Hyper-V guests.

### macOS

- **Timezone**: managed via `systemsetup -settimezone` / `-gettimezone`.
- **NTP server**: managed via `systemsetup -setnetworktimeserver` /
  `-getnetworktimeserver`. macOS supports only a single NTP server; if
  `ntp_servers` contains multiple entries only the first (alphabetically) is
  applied.
- **NTP sync enabled**: managed via `systemsetup -setusingnetworktime` /
  `-getusingnetworktime`.

## Domain controller example

```yaml
resources:
  - name: "time-dc"
    module: "time"
    config:
      timezone: "UTC"
      ntp_sync_enabled: true
      ntp_source: domain
      hyperv_host_time_provider: disabled
```

## Security notes

- Requires root privileges on all platforms to write time configuration.
- Shells out to `timedatectl`, `tzutil.exe`, `w32tm.exe`, and `systemsetup`
  as declared in `module.yaml`'s `behavioral_envelope`. The Windows registry
  and Service Control Manager are accessed in-process, not through a shell.
- No credentials or secrets are handled by this module.

## Determinism

`Get` always returns `ntp_servers` sorted alphabetically. `AsMap()` is
byte-for-byte identical on repeated calls against unchanged state, satisfying
ADR-016 clause 4.
