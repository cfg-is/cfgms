# hostname module

Manages the host system name (computer name) and Windows workgroup.

## Rationale

The system hostname is a foundational host identity property: it appears in
certificate SANs, DNS records, log metadata, and service-discovery registrations.
Unmanaged drift — a rename from a manual `hostnamectl` call, an OS image clone
with a shared name, or a workgroup mismatch — cascades into authentication
failures, certificate validation errors, and monitoring gaps.

The `hostname` module declares authoritative ownership over the `hostname` DNA
object kind (ADR-016 clause 5). It is a **declare-once identity** module per
ADR-016 clause 1: the desired hostname is set once and held, not
continuously re-derived. Repeated `Set` calls with the same desired hostname
are idempotent no-ops and never trigger a rename or reboot.

## Fields

| Field | Type | Platforms | Description |
|-------|------|-----------|-------------|
| `hostname` | string | All | System/computer name (RFC 1123 label: alphanumeric + hyphens, no leading/trailing hyphen, max 253 chars) |
| `workgroup` | string | Windows only | NetBIOS workgroup name (alphanumeric, hyphen, underscore; max 15 chars). Absent on Linux and macOS fragments. |

`hostname` is required. `workgroup` is optional on Windows and absent on all
other platforms.

## Example DNA fragment

### Linux / macOS

```yaml
hostname: webserver-01
```

### Windows

```yaml
hostname: WEBSERVER01
workgroup: CORP
```

## Platform behaviour

### Linux

- **Read**: current hostname is read from `/etc/hostname`. If the file does not
  exist, `os.Hostname()` is used as a fallback (unmanaged hosts still report a
  value).
- **Write**: desired hostname is written to `/etc/hostname` (durable) and applied
  to the running kernel via `syscall.Sethostname` (runtime, no reboot required).
- **Workgroup**: not applicable; absent from the DNA fragment.

### macOS

- **Read**: `scutil --get HostName` returns the current BSD hostname.
- **Write**: `scutil --set HostName <name>` and `scutil --set ComputerName <name>`
  are both called to keep all macOS naming layers consistent.
- **Workgroup**: not applicable; absent from the DNA fragment.
- Requires admin privileges.

### Windows

- **Read hostname**: `os.Hostname()` (in-process).
- **Read workgroup**: `wmic computersystem get Workgroup /format:list`.
- **Write hostname**: `netdom renamecomputer <current> /newname:<new> /reboot:0 /force`.
  The `/reboot:0` flag suppresses the automatic reboot; the rename takes effect
  on the next manual reboot scheduled by the operator.
- **Write workgroup**: `wmic computersystem where name=<name> call JoinDomainOrWorkgroup`.
- Requires administrator privileges.

## Security notes

- Requires root/admin privileges on all platforms.
- Input is validated against RFC 1123 (hostname) and NetBIOS (workgroup) patterns
  before any system call or shell-out; no shell metacharacters pass through.
- Shells out to `scutil` (macOS), `wmic.exe` and `netdom.exe` (Windows) as
  declared in `module.yaml`'s `behavioral_envelope`. On Linux all operations
  are in-process (no shell-out).
- No credentials or secrets are handled by this module.

## Idempotency

`Set` checks the current hostname against the desired hostname before writing.
If they match, the function returns immediately without calling any system APIs.
This is especially important for declare-once identity: an accidental repeated
apply must not trigger a rename churn or, on Windows, an unintended reboot
notification.

## Determinism

`Get` always returns the same fields for the same unchanged host state.
`AsMap()` is byte-for-byte identical on repeated calls (ADR-016 clause 4).
The `workgroup` field is absent (not an empty string) on non-Windows platforms,
preventing a spurious cross-platform field-presence difference.
