# User Module

## Overview

The user module manages local OS user accounts and group membership on managed endpoints. It supports account creation, full-name management, group membership, and lock/disable state. Password setting is intentionally out of scope — the module observes whether an account has a password (`has_credential`, returned by `Get`) but never accepts, stores, or transmits password material.

## Implementation References

- Schema: [`features/modules/stdlib/user/module.yaml`](../../features/modules/stdlib/user/module.yaml)
- Implementation: [`features/modules/stdlib/user/module.go`](../../features/modules/stdlib/user/module.go)

## Platform Support

| Platform | Create | Modify | Delete | Lock | Groups | Tool used |
|----------|--------|--------|--------|------|--------|-----------|
| Linux    | ✓ | ✓ | ✓ | ✓ | ✓ | `useradd`, `usermod`, `userdel` |
| Windows  | ✓ | ✓ | ✓ | ✓ | ✓ | `net.exe` |
| macOS    | ✓ | ✓ | ✓ | ✓ | ✓ | `dscl`, `dseditgroup`, `pwpolicy` |

All write operations require the steward to run with Administrator / root privileges.

## Configuration

The resource ID is the OS-level username (e.g., `alice`, `svc-backup`).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `state` | string | **Yes** | `"present"` or `"absent"` |
| `full_name` | string | No | Display name / GECOS comment |
| `groups` | list of strings | No | Supplementary groups to assign |
| `locked` | bool | No | Lock/disable the account (default: `false`) |
| `has_credential` | bool | No | **Observed only** — never accepted by `Set`. Reports whether the OS considers the account to have a password. |

### `has_credential` (observed only)

`has_credential` is a read-only observed field returned by `Get`. It reports the OS-level password state:

- **Linux**: derived from `/etc/shadow` when readable (requires root); defaults to `false` when shadow is not accessible.
- **Windows**: `true` when `net user` reports `Password required: Yes`.
- **macOS**: always `false` in this version (shadow password inspection requires root and is out of scope).

`Set` silently ignores `has_credential` if it appears in the config. Password distribution through `cfg` has no secrets-distribution design yet and is explicitly deferred.

## Examples

### Create a service account

```yaml
modules:
  svc_backup:
    type: user
    config:
      state: present
      full_name: Backup Service Account
      groups:
        - backup
        - tape
      locked: false
```

### Ensure an account is locked (disabled)

```yaml
modules:
  old_employee:
    type: user
    config:
      state: present
      locked: true
```

### Remove an account

```yaml
modules:
  former_contractor:
    type: user
    config:
      state: absent
```

## Managed Fields

`GetManagedFields()` returns `["state", "full_name", "groups", "locked"]`. The `has_credential` field is excluded because it is observed-only.

## Security Notes

- All usernames and group names are validated against a strict pattern (`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`) before being passed to OS commands, preventing flag injection and command injection.
- The module never accepts, logs, stores, or transmits password material. `has_credential` is a read-only observation.
- On Linux, `userdel -r` removes the user's home directory. Ensure data is backed up before removing accounts.
- Group removal (removing a user from a group that is no longer in `groups`) is not performed in v1 to avoid disrupting groups managed outside `cfg`.

## Out of Scope

- Password setting/changing — requires a secrets-distribution design not yet landed.
- Domain / Active Directory user management — that is `extended/activedirectory`'s territory.
- Group creation — groups must already exist before being assigned.
