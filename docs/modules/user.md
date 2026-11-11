# User Module

## Overview

The user module manages local OS user accounts and group membership on managed endpoints. It supports account creation, full-name management, group membership, and lock/disable state. Password setting is intentionally out of scope — the module observes whether an account has a password (`has_credential`, returned by `Get`) but never accepts a password from configuration. On Windows, an account the module creates gets a random password generated in memory that nobody knows; it is never logged, stored or returned. Another channel must set a usable password before the account can log on interactively.

## Implementation References

- Schema: [`features/modules/stdlib/user/module.yaml`](../../features/modules/stdlib/user/module.yaml)
- Implementation: [`features/modules/stdlib/user/module.go`](../../features/modules/stdlib/user/module.go)

## Platform Support

| Platform | Create | Modify | Delete | Lock | Groups | Tool used |
|----------|--------|--------|--------|------|--------|-----------|
| Linux    | ✓ | ✓ | ✓ | ✓ | ✓ | `useradd`, `usermod`, `userdel` |
| Windows  | ✓ | ✓ | ✓ | ✓ | ✓ | `NetUserAdd`, `NetUserSetInfo` (account creation, in-process); `net.exe` (delete, and full name and enabled state of an existing account); `NetUserGetInfo`, `NetUserGetLocalGroups`, `NetLocalGroupAddMembers`, `NetLocalGroupDelMembers` (in-process) |
| macOS    | ✓ | ✓ | ✓ | ✓ | ✓ | `dscl`, `dseditgroup`, `pwpolicy` |

All write operations require the steward to run with Administrator / root privileges.

## Configuration

The resource ID is the OS-level username (e.g., `alice`, `svc-backup`).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `state` | string | **Yes** | `"present"` or `"absent"` |
| `full_name` | string | No | Display name / GECOS comment |
| `groups` | list of strings | No | Supplementary groups to assign. On Windows a non-empty list is exclusive; see Security Notes. |
| `locked` | bool | No | Lock/disable the account (default: `false`) |
| `has_credential` | bool | No | **Observed only** — never accepted by `Set`. Reports whether the OS considers the account to have a password. |

### `has_credential` (observed only)

`has_credential` is a read-only observed field returned by `Get`. It reports the OS-level password state:

- **Linux**: derived from `/etc/shadow` when readable (requires root); defaults to `false` when shadow is not accessible.
- **Windows**: `true` unless the account carries the "password not required" flag (`UF_PASSWD_NOTREQD`), read with `NetUserGetInfo`. An account the module creates is never marked password-not-required, so it reads `true`.
- **macOS**: always `false` in this version (shadow password inspection requires root and is out of scope).

`Set` silently ignores `has_credential` if it appears in the config.

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
- The module never accepts a password from configuration, and never logs, stores, returns or transmits password material. `has_credential` is a read-only observation.
- On Windows, a new account is created with `NetUserAdd` and a 32-character random password from `crypto/rand` that nobody knows, so no account is ever created with a blank password. The password exists only in memory for the call and its buffers are zeroed afterwards. A new account is added to the built-in Users group (S-1-5-32-545).
- On Linux, `userdel -r` removes the user's home directory. Ensure data is backed up before removing accounts.
- On Linux and macOS, group removal (removing a user from a group that is no longer in `groups`) is not performed in v1 to avoid disrupting groups managed outside `cfg`.
- On Windows, a non-empty `groups` list is exclusive: the user is added to every declared group and removed from every other group it is a direct member of. Two exceptions apply:
  - The built-in Users group (SID S-1-5-32-545, whatever its local name) is never removed.
  - Removal from the built-in Administrators group is refused, with an error, when no other member would keep the host administered (another group, a domain account, or an enabled local account). Deleted or unknown account SIDs left in the group do not count. The check covers group removal only. Deleting (`state: absent`) or disabling (`locked: true`) an account is not checked, because each needs an explicit declaration.

  An omitted or empty `groups` list leaves group membership unchanged. After applying, the account is read again, and a group list, disabled state or full name that still differs is an error. State is read through locale-independent APIs, so non-English systems report groups and the disabled state correctly.
- On Windows, group names follow the Windows local group naming rules instead of the pattern above. They may be up to 256 characters of any script and may include spaces, but not control characters, leading or trailing spaces, or any of `" / \ [ ] : ; | = , + * ? < > @`. So `Remote Desktop Users`, or a localized `Администраторы`, can be declared. They are passed to the Windows APIs in-process, never as command arguments.

## Out of Scope

- Setting or changing a usable password — requires a secrets-distribution design not yet landed. A Windows account the module creates has an unknown random password until another channel sets one.
- Domain / Active Directory user management — that is `extended/activedirectory`'s territory.
- Group creation — groups must already exist before being assigned.
