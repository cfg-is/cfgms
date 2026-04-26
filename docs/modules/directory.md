# Directory Module Documentation

## Overview

The Directory Module manages filesystem directories on CFGMS-managed endpoints. It creates and configures directories while enforcing a security boundary through the required `allowed_base_path` field. Every OS call is routed through `pkg/security.ValidateAndCleanPath` to prevent path traversal attacks.

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
| `state` | string | No | `"present"` (default) creates or ensures the directory exists. `"absent"` is returned by `Get()` when the directory does not exist; `Set()` does not implement directory deletion. |
| `permissions` | int | No | Unix permission bits as an integer (e.g., `0750`). Ignored on Windows (NTFS uses ACLs). |
| `owner` | string | No | User name that should own the directory (Unix only). |
| `group` | string | No | Group name that should own the directory (Unix only). |
| `recursive` | bool | No | When `true`, creates missing parent directories with `os.MkdirAll`. When `false` (default), fails if the parent does not exist. |

## Security: AllowedBasePath

`allowed_base_path` is a **required** field that defines the security boundary for all filesystem operations performed by this module instance.

### How it works

Before any `os.Stat`, `os.MkdirAll`, `os.Mkdir`, `os.Chmod`, or `os.Chown` call, the module passes the configured base path and the target path through `pkg/security.ValidateAndCleanPath`. This function:

1. Resolves the target path to an absolute clean path.
2. Verifies the result has the base path as a prefix.
3. Returns an error if the resolved path escapes the boundary.

This prevents `path` values containing `../` sequences (or equivalent) from reaching the OS.

### Symlink limitation

`ValidateAndCleanPath` uses `filepath.Clean` and `filepath.Abs` but does **not** call `filepath.EvalSymlinks`. A symlink whose target points outside `allowed_base_path` is not blocked at the module level. Use OS-level controls (mount namespaces, chroot, SELinux/AppArmor policies) when symlink escapes are a threat in your environment.

### Validation order

`validate()` checks `allowed_base_path` **before** `path`. If `allowed_base_path` is missing or relative, `ErrAllowedBasePathRequired` is returned immediately, and `path` is never evaluated.

### What happens on `Get()` before `Set()`

`configuredBasePath` has no default value. If `Get()` is called before a successful `Set()`, the module returns `ErrAllowedBasePathRequired` wrapped with `ErrModuleNotReady`. The execution engine detects `ErrModuleNotReady` and skips the diff step, proceeding directly to `Set()`.

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
