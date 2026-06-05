# File Module

## Overview

The file module manages files, directories, and symlinks on managed endpoints. The resource type is selected with the `type:` field (`file` (default), `directory`, `symlink`). It enforces path-traversal protection via a required `allowed_base_path` field.

## Implementation References

- Schema: [`features/modules/file/module.yaml`](../../features/modules/file/module.yaml)
- Implementation: [`features/modules/file/implementation.go`](../../features/modules/file/implementation.go)

## Platform Support

| Platform | `type: file` | `type: directory` | `type: symlink` | Unix permissions | Windows ACL |
|----------|-------------|-------------------|-----------------|------------------|-------------|
| Linux    | ✓ | ✓ | stub | ✓ (mode bits) | — |
| macOS    | ✓ | ✓ | stub | ✓ (mode bits) | — |
| Windows  | ✓ | ✓ | stub | — (use `windows_acl`) | ✓ (NTFS DACL) |

`type: symlink` returns `ErrNotImplemented` on all platforms and is reserved for a future release.

## Configuration

| Field | Type | Applies to | Required | Description |
|-------|------|-----------|----------|-------------|
| `type` | string | all | No | `"file"` (default), `"directory"`, or `"symlink"` |
| `state` | string | all | No | `"present"` (default) or `"absent"` |
| `allowed_base_path` | string | all | **Yes** | Absolute path constraining all filesystem operations |
| `content` | string | file | No | File content (when `state: present`) |
| `permissions` | int | file, directory | No | Unix permission bits (e.g. `0644`). **Not supported on Windows** — mutually exclusive with `windows_acl`. |
| `owner` | string | file, directory | No | Owner username |
| `group` | string | file, directory | No | Group name |
| `windows_acl` | object | file, directory | No | Windows NTFS ACL. **Windows only** — mutually exclusive with `permissions`. |
| `path` | string | directory | No | Path to create when `type: directory` |
| `recursive` | bool | directory | No | Create missing parent directories (default: false) |

## `type: file` (default)

When `type` is absent or `"file"`, the module manages file content, permissions, and ownership. The resource ID passed by the framework is the file path.

### Example: deploy a configuration file

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

### Example: remove a legacy file

```yaml
modules:
  remove_legacy_conf:
    type: file
    config:
      allowed_base_path: /etc/myapp
      path: /etc/myapp/legacy.conf
      state: absent
```

## `type: directory`

When `type: directory`, the module manages directory existence, permissions, and ownership. The `path` field (or the resource ID) identifies the target directory. When `recursive: true`, missing parent directories are created with the same permissions.

### Example: create a directory with permissions

```yaml
modules:
  app_data_dir:
    type: file
    config:
      type: directory
      allowed_base_path: /var/myapp
      path: /var/myapp/data
      state: present
      permissions: 0750
      owner: myapp
      group: myapp
```

### Example: create a directory hierarchy

```yaml
modules:
  log_dir:
    type: file
    config:
      type: directory
      allowed_base_path: /var/log/myapp
      path: /var/log/myapp/archive/2026
      state: present
      recursive: true
      permissions: 0755
```

## `allowed_base_path`

`allowed_base_path` is a required security field. Every OS call (read, write, remove, chown, mkdir) is validated against this path to prevent path-traversal attacks. The value must be an absolute path set by the operator in YAML — there is no default.

If the field is absent or not an absolute path, the module returns `ErrAllowedBasePathRequired` and performs no filesystem operations.

`allowed_base_path` uses `filepath.Clean` + `filepath.Abs` internally. Symlink escapes outside the base path are **not** blocked.

### Initialization via `Configure()`

`fileModule` implements the `modules.Configurable` interface. The execution engine calls `Configure(desiredState)` before the `Get→Compare→Set→Verify` cycle. `Configure()` extracts `allowed_base_path` and stores it in `configuredBasePath`, allowing `Get()` to validate resource paths before any `Set()` has run.

## Windows ACL

The `windows_acl` field declares NTFS access control on Windows endpoints. It is mutually exclusive with `permissions` and applies to both `type: file` and `type: directory`.

### Schema

```yaml
windows_acl:
  owner: "DOMAIN\\User"
  entries:
    - principal: "DOMAIN\\User"
      access: "FullControl"   # FullControl | ReadAndExecute | Modify | Write | Read
```

### Example: restrict a config file to Administrators (Windows)

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

## Migration from standalone `directory` module

The `directory` module has been merged into the `file` module. Existing configs using `type: directory` in the framework continue to work — the factory maps the `"directory"` module name to the file module. To update configs explicitly:

Before:
```yaml
modules:
  data_dir:
    type: directory
    config:
      path: /var/myapp/data
      permissions: 0750
```

After:
```yaml
modules:
  data_dir:
    type: file
    config:
      type: directory
      allowed_base_path: /var/myapp
      path: /var/myapp/data
      state: present
      permissions: 0750
```
