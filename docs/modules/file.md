# File Module

## Overview

The file module manages file content, permissions, and ownership on managed endpoints. It enforces path-traversal protection via a required `allowed_base_path` field.

## Implementation References

- Schema: [`features/modules/file/module.yaml`](../../features/modules/file/module.yaml)
- Implementation: [`features/modules/file/implementation.go`](../../features/modules/file/implementation.go)

## Platform Support

| Platform | State management | Unix permissions | Ownership (`owner`/`group`) | Windows ACL |
|----------|-----------------|------------------|-----------------------------|-------------|
| Linux    | ✓ | ✓ (mode bits) | ✓ (`uid`/`gid` via `os.Chown`) | — |
| macOS    | ✓ | ✓ (mode bits) | ✓ (`uid`/`gid` via `os.Chown`) | — |
| Windows  | ✓ | — (returns error if set; use `windows_acl`) | Limited (user lookup only; `os.Chown` not called) | ✓ (NTFS DACL) |

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `state` | string | No | `"present"` (default) or `"absent"` |
| `content` | string | Yes (when present) | File content |
| `permissions` | int | No | Unix permission bits (e.g. `0644`). **Not supported on Windows** — mutually exclusive with `windows_acl`. |
| `owner` | string | No | File owner username |
| `group` | string | No | File group name |
| `allowed_base_path` | string | **Yes** | Absolute path that constrains all filesystem operations |
| `windows_acl` | object | No | Windows NTFS ACL (owner + entries). **Windows only** — mutually exclusive with `permissions`. See [Windows ACL](#windows-acl). |

## `allowed_base_path`

`allowed_base_path` is a required security field. Every OS call (read, write, remove, chown) is validated against this path to prevent path-traversal attacks. The value must be an absolute path set by the operator in YAML — there is no default.

If the field is absent or not an absolute path, the module returns `ErrAllowedBasePathRequired` and performs no filesystem operations.

**Note:** `allowed_base_path` uses `filepath.Clean` + `filepath.Abs` internally. Symlink escapes outside the base path are **not** blocked.

### Initialization via `Configure()`

`fileModule` implements the `modules.Configurable` interface. The execution engine calls `Configure(desiredState)` before the `Get→Compare→Set→Verify` cycle begins. `Configure()` extracts `allowed_base_path` from the desired config and stores it in `configuredBasePath`, allowing `Get()` to validate resource paths before any `Set()` has run.

If `Configure()` is never called (or returns an error), `configuredBasePath` is empty and `Get()` returns `ErrAllowedBasePathRequired`. The engine surfaces this as a module configuration failure and does not proceed to `Set()`.

### `path` in YAML examples

In the CFGMS module system, the file path is the **resource identifier** — it is passed to `Get()` and `Set()` as the `resourceID` parameter. The `path` field shown in YAML examples below is read by the CFGMS framework and used as the resource identifier; it is not stored inside the module's `FileConfig` struct. The `FileConfig` type does not have a `path` field.

### `mode` alias

The implementation also accepts `mode` as an alias for `permissions` (parsed as an octal string such as `"0644"`, or as an integer). The `permissions` field name is preferred in operator-facing YAML.

### Example: Ensure a configuration file exists with permissions and owner

**Use Case:** Deploy a systemd unit file to a managed path with explicit permissions and ownership.

**Configuration:**

```yaml
modules:
  my_service_unit:
    type: file
    config:
      allowed_base_path: /etc/systemd/system
      path: /etc/systemd/system/my-service.service
      state: present
      content: |
        [Unit]
        Description=My Service
      permissions: 0644
      owner: root
      group: root
```

**Expected Outcome:** `/etc/systemd/system/my-service.service` is created or updated with the specified content and mode `0644`, owned by `root:root`. The `allowed_base_path` constraint prevents any path outside `/etc/systemd/system` from being targeted.

### Example: Ensure a file is absent

**Use Case:** Remove a legacy configuration file that should no longer exist on managed endpoints.

**Configuration:**

```yaml
modules:
  remove_legacy_conf:
    type: file
    config:
      allowed_base_path: /etc/myapp
      path: /etc/myapp/legacy.conf
      state: absent
```

**Expected Outcome:** `/etc/myapp/legacy.conf` is deleted if it exists. If the file is already absent the module reports no change. No filesystem operation is attempted outside `/etc/myapp`.

### Example: Manage a file within a constrained base path

**Use Case:** Write an application configuration file while keeping the security boundary as narrow as possible — only the application's own config directory, not the entire `/etc` tree.

**Configuration:**

```yaml
modules:
  app_config:
    type: file
    config:
      allowed_base_path: /etc/myapp
      path: /etc/myapp/settings.yaml
      state: present
      content: |
        log_level: info
        listen_addr: 0.0.0.0:8080
      permissions: 0640
      owner: myapp
      group: myapp
```

**Expected Outcome:** `/etc/myapp/settings.yaml` is written with the provided content, mode `0640`, owned by `myapp:myapp`. Any attempt to resolve `path` to a location outside `/etc/myapp` (for example via `../` sequences) is rejected before any OS call is made.

## Windows ACL

The `windows_acl` field declares NTFS access control for the file on Windows endpoints. It is mutually exclusive with `permissions` — you must use one or the other, not both. On non-Windows platforms, specifying `windows_acl` is a validation error.

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

### Example: Set Windows ACL on a config file

**Use Case:** Restrict a sensitive configuration file to Administrators only on a Windows endpoint.

**Configuration:**

```yaml
modules:
  app_config_windows:
    type: file
    config:
      allowed_base_path: C:\ProgramData\MyApp
      path: C:\ProgramData\MyApp\settings.json
      state: present
      content: |
        {"log_level": "info"}
      windows_acl:
        owner: "BUILTIN\\Administrators"
        entries:
          - principal: "BUILTIN\\Administrators"
            access: FullControl
          - principal: "NT AUTHORITY\\SYSTEM"
            access: FullControl
```

**Expected Outcome:** `C:\ProgramData\MyApp\settings.json` is created with the specified content. The DACL is set to grant `FullControl` to `BUILTIN\Administrators` and `NT AUTHORITY\SYSTEM`. No Unix `permissions` field is needed or permitted alongside `windows_acl`. Subsequent `Get()` calls return the actual NTFS ACL so the verifier can detect drift.

## Migration

Existing configurations that omit `allowed_base_path` will fail validation after this change. Add the field pointing to the directory that contains the managed files:

Before:

```yaml
file:
  state: present
  content: "hello"
```

After:

```yaml
file:
  state: present
  content: "hello"
  allowed_base_path: /var/cfgms/managed
```

The resource ID (file path) must remain within `allowed_base_path`. Attempts to reference paths outside the base path are rejected with an error.
