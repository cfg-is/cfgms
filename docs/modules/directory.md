# Directory Module Documentation

## Overview

The Directory Module manages filesystem directories on CFGMS-managed endpoints. It creates and configures directories while enforcing a security boundary through the required `allowed_base_path` field. Every OS call is routed through `pkg/security.ValidateAndCleanPath` to prevent path traversal attacks.

## Implementation References

- Schema: [`features/modules/directory/module.yaml`](../../features/modules/directory/module.yaml)
- Implementation: [`features/modules/directory/module.go`](../../features/modules/directory/module.go)

## Platform Support

| Platform | State management | Unix permissions | Ownership (`owner`/`group`) | Windows ACL |
|----------|-----------------|------------------|-----------------------------|-------------|
| Linux    | ✓ | ✓ (mode bits) | ✓ (`uid`/`gid` via `os.Chown`) | — |
| macOS    | ✓ | ✓ (mode bits) | ✓ (`uid`/`gid` via `os.Chown`) | — |
| Windows  | ✓ | — (returns error if set; use `windows_acl`) | — | ✓ (NTFS DACL) |

> **Note:** Directory deletion is not implemented. Passing `state: absent` to `Set()` returns an error (`operation not implemented`) — the directory is never created or deleted. To remove a directory, use the file module or a script module for the removal step.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Fields](#configuration-fields)
- [Security: AllowedBasePath](#security-allowedbasepath)
- [YAML Examples](#yaml-examples)
- [Migration Guide](#migration-guide)
- [Error Reference](#error-reference)

## Quick Start

```yaml
modules:
  app_logs:
    type: directory
    config:
      allowed_base_path: /var/app
      path: /var/app/logs
      state: present
      permissions: 0750
      owner: appuser
      group: appgroup
      recursive: true
```

## Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `allowed_base_path` | string | **Yes** | Absolute path that acts as the security boundary. All OS calls are validated to remain within this prefix. |
| `path` | string | Yes | Absolute path of the directory to manage. Must fall within `allowed_base_path`. |
| `state` | string | No | `"present"` (default) creates or ensures the directory exists. `"absent"` is returned by `Get()` when the directory does not exist; passing `state: absent` to `Set()` returns an explicit error — directory deletion is not supported (see [Deletion not supported](#deletion-not-supported)). |
| `permissions` | int | No | Unix permission bits as an integer (e.g., `0750`). **Not supported on Windows** — mutually exclusive with `windows_acl`. |
| `owner` | string | No | User name that should own the directory (Unix only). |
| `group` | string | No | Group name that should own the directory (Unix only). |
| `recursive` | bool | No | When `true`, creates missing parent directories with `os.MkdirAll`. When `false` (default), fails if the parent does not exist. |
| `windows_acl` | object | No | Windows NTFS ACL (owner + entries). **Windows only** — mutually exclusive with `permissions`. See [Windows ACL](#windows-acl). |

## Security: AllowedBasePath

`allowed_base_path` is a **required** field that defines the security boundary for all filesystem operations performed by this module instance.

### How it works

Before any `os.Stat`, `os.MkdirAll`, `os.Mkdir`, `os.Chmod`, or `os.Chown` call, the module passes the configured base path and the target path through `pkg/security.ValidateAndCleanPath`. This function:

1. Resolves the target path to an absolute clean path.
2. Verifies the result has the base path as a prefix.
3. Returns an error if the resolved path escapes the boundary.

This prevents `path` values containing `../` sequences (or equivalent) from reaching the OS.

### `mode` alias

The implementation also accepts `mode` as an alias for `permissions` (parsed as an octal string such as `"0755"`, or as an integer). The `permissions` field name is preferred in operator-facing YAML.

### Symlink limitation

`ValidateAndCleanPath` uses `filepath.Clean` and `filepath.Abs` but does **not** call `filepath.EvalSymlinks`. A symlink whose target points outside `allowed_base_path` is not blocked at the module level. Use OS-level controls (mount namespaces, chroot, SELinux/AppArmor policies) when symlink escapes are a threat in your environment.

### Validation order

`validate()` checks `allowed_base_path` **before** `path`. If `allowed_base_path` is missing or relative, `ErrAllowedBasePathRequired` is returned immediately, and `path` is never evaluated.

### Initialization via `Configure()`

`directoryModule` implements the `modules.Configurable` interface. The execution engine calls `Configure(desiredState)` before the `Get→Compare→Set→Verify` cycle begins. `Configure()` extracts `allowed_base_path` from the desired config and stores it in `configuredBasePath`, allowing `Get()` to validate resource paths before any `Set()` has run.

If `Configure()` is never called (or returns an error), `configuredBasePath` is empty and `Get()` returns `ErrAllowedBasePathRequired`. The engine surfaces this as a module configuration failure and does not proceed to `Set()`.

## YAML Examples

### Create a directory with custom permissions and ownership

```yaml
modules:
  data_dir:
    type: directory
    config:
      allowed_base_path: /srv/myapp
      path: /srv/myapp/data
      state: present
      permissions: 0700
      owner: myapp
      group: myapp
```

### Create nested directories (recursive)

```yaml
modules:
  log_dir:
    type: directory
    config:
      allowed_base_path: /var/log/myapp
      path: /var/log/myapp/audit/2026
      state: present
      permissions: 0750
      recursive: true
```

### Windows — directory creation (no Unix permissions)

On Windows, `permissions`, `owner`, and `group` are not supported. Omit them entirely:

```yaml
modules:
  app_data:
    type: directory
    config:
      allowed_base_path: C:\ProgramData\MyApp
      path: C:\ProgramData\MyApp\Logs
      state: present
      recursive: true
```

### Example: Create a log directory with ownership

**Use Case:** Ensure a service's log directory exists on every managed Linux endpoint, owned by the service account so the process can write logs without elevated privileges.

**Configuration:**

```yaml
modules:
  app_log_dir:
    type: directory
    config:
      allowed_base_path: /var/log/myapp
      path: /var/log/myapp
      state: present
      permissions: 0750
      owner: myapp
      group: myapp
      recursive: true
```

**Expected Outcome:** `/var/log/myapp` is created if it does not exist, with mode `0750` and ownership `myapp:myapp`. Parent directories are created automatically because `recursive: true` is set. Subsequent runs are idempotent — the directory is not re-created if it already matches the desired state.

### Deletion not supported

`Set()` does not support `state: absent`. Passing it returns:

```
directory deletion is not supported: operation not implemented
```

`Get()` still returns `state: absent` when the directory does not exist on disk — this is how the execution engine detects that `Set()` should be called to create it. The `state` field in `Get()` output is read-only state reporting, not a deletion request.

To remove a directory, use a script module or a dedicated removal workflow. Directory deletion via `os.RemoveAll` requires separate safety gating and is tracked as a future capability story.

## Windows ACL

The `windows_acl` field declares NTFS access control for the directory on Windows endpoints. It is mutually exclusive with `permissions` — you must use one or the other, not both. On non-Windows platforms, specifying `windows_acl` is a validation error.

### Schema

```yaml
windows_acl:
  owner: "DOMAIN\\User"          # optional; leave blank to keep the existing owner
  entries:
    - principal: "DOMAIN\\User"  # account name accepted by Windows LookupAccountName
      access: "FullControl"      # FullControl | ReadAndExecute | Modify | Write | Read
```

### Access levels

| Value | Effective Windows rights |
|-------|--------------------------|
| `FullControl` | `GENERIC_ALL` |
| `ReadAndExecute` | `GENERIC_READ \| GENERIC_EXECUTE` |
| `Modify` | `GENERIC_WRITE \| GENERIC_READ \| GENERIC_EXECUTE` |
| `Write` | `GENERIC_WRITE` |
| `Read` | `GENERIC_READ` |

### Example: Set Windows ACL on an application data directory

**Use Case:** Restrict a sensitive data directory to the service account and Administrators on Windows endpoints.

**Configuration:**

```yaml
modules:
  app_data_dir_windows:
    type: directory
    config:
      allowed_base_path: C:\ProgramData\MyApp
      path: C:\ProgramData\MyApp\Data
      state: present
      recursive: true
      windows_acl:
        owner: "BUILTIN\\Administrators"
        entries:
          - principal: "BUILTIN\\Administrators"
            access: FullControl
          - principal: "NT AUTHORITY\\SYSTEM"
            access: FullControl
          - principal: "NT AUTHORITY\\Authenticated Users"
            access: ReadAndExecute
```

**Expected Outcome:** `C:\ProgramData\MyApp\Data` is created if absent (with parent directories via `recursive: true`). The DACL grants `FullControl` to Administrators and SYSTEM, and `ReadAndExecute` to all authenticated users. Subsequent `Get()` calls return the actual NTFS ACL so the verifier can detect drift.

## Migration Guide

### Breaking change in CFGMS Story #876

The `allowed_base_path` field was added as a **required** field in Story #876. Existing directory module configurations that do not include this field will fail validation with:

```
AllowedBasePath is required and must be an absolute path; see docs/modules/directory.md
```

#### How to migrate

Add `allowed_base_path` to every directory module configuration block. Choose the narrowest absolute path that still contains all `path` values managed by that module instance.

**Before (fails after Story #876):**

```yaml
modules:
  app_logs:
    type: directory
    config:
      path: /var/app/logs
      state: present
      permissions: 0750
```

**After (valid):**

```yaml
modules:
  app_logs:
    type: directory
    config:
      allowed_base_path: /var/app
      path: /var/app/logs
      state: present
      permissions: 0750
```

#### Choosing `allowed_base_path`

- Use the narrowest directory that still covers all directories the module needs to manage.
- The value must be an absolute path (starts with `/` on Unix, drive letter on Windows).
- Avoid using `/` or `C:\` as the base path — this defeats the security boundary.
- Each logical application or service should have its own base path.

## Error Reference

| Error | Cause | Resolution |
|-------|-------|------------|
| `ErrAllowedBasePathRequired` | `allowed_base_path` is missing or not an absolute path | Add a valid absolute path for `allowed_base_path` |
| `ErrInvalidPath` | `path` is missing or not an absolute path | Set `path` to a valid absolute path |
| `ErrNotADirectory` | Target path exists but is a file, not a directory | Remove the file or choose a different `path` |
| `ErrRecursiveRequired` | Parent directory does not exist and `recursive` is `false` | Set `recursive: true` or create the parent first |
| `ErrInvalidOwner` | Specified `owner` user does not exist on the system | Create the user or correct the `owner` value |
| `ErrInvalidGroup` | Specified `group` does not exist on the system | Create the group or correct the `group` value |
| `ErrInvalidPermissions` | `permissions` value is outside `0`–`0777` | Use a valid Unix permission integer |
| `path security check failed` | `path` resolves outside `allowed_base_path` | Ensure `path` is within `allowed_base_path`; check for `../` sequences |
| `directory deletion is not supported` | `state: absent` was passed to `Set()` | Directory deletion is not implemented; use a script module or remove the `state: absent` field |
