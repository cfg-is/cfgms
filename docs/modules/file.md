# File Module

## Overview

The file module manages file content, permissions, and ownership on managed endpoints. It enforces path-traversal protection via a required `allowed_base_path` field.

## Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `state` | string | No | `"present"` (default) or `"absent"` |
| `content` | string | Yes (when present) | File content |
| `permissions` | int | No | Unix permission bits (e.g. `0644`). Not supported on Windows. |
| `owner` | string | No | File owner username |
| `group` | string | No | File group name |
| `allowed_base_path` | string | **Yes** | Absolute path that constrains all filesystem operations |

## `allowed_base_path`

`allowed_base_path` is a required security field. Every OS call (read, write, remove, chown) is validated against this path to prevent path-traversal attacks. The value must be an absolute path set by the operator in YAML — there is no default.

If the field is absent or not an absolute path, the module returns `ErrAllowedBasePathRequired` and performs no filesystem operations.

**Note:** `allowed_base_path` uses `filepath.Clean` + `filepath.Abs` internally. Symlink escapes outside the base path are **not** blocked.

### Example

```yaml
file:
  state: present
  content: |
    [Unit]
    Description=My Service
  permissions: 0644
  allowed_base_path: /var/cfgms/managed
```

## Migration

Existing configurations that omit `allowed_base_path` will fail validation after this change. Add the field pointing to the directory that contains the managed files:

```yaml
# Before
file:
  state: present
  content: "hello"

# After
file:
  state: present
  content: "hello"
  allowed_base_path: /var/cfgms/managed
```

The resource ID (file path) must remain within `allowed_base_path`. Attempts to reference paths outside the base path are rejected with an error.
