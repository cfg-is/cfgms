# Directory Module

## Purpose and scope

The Directory module is responsible for managing system directories across different operating systems. It provides functionality to:

- Create and manage directories with specific permissions and ownership
- Validate directory configurations against desired states
- Support recursive directory creation
- Handle platform-specific directory operations

This module is essential for setting up and maintaining directory structures in a configuration management system, ensuring consistent directory permissions and ownership across the infrastructure.

## Configuration options

The module accepts configuration in YAML format with the following options:

```yaml
path: /path/to/directory        # Required: Absolute path to the directory
permissions: 0755              # Required: Directory permissions in octal format
owner: username                # Optional: Username that should own the directory
group: groupname              # Optional: Group that should own the directory
recursive: false              # Optional: Whether to create parent directories
```

### Configuration Fields

- `path` (required): The absolute path to the directory
  - Must be a valid absolute path
  - Must not be empty
  - Must be within allowed system directories

- `permissions` (required): The directory permissions in octal format
  - Must be between 0 and 0777
  - Common values:
    - 0755: User can read/write/execute, others can read/execute
    - 0750: User can read/write/execute, group can read/execute
    - 0700: Only user can read/write/execute

- `owner` (optional): The username that should own the directory
  - Must be a valid system user
  - Requires appropriate privileges to change ownership

- `group` (optional): The group that should own the directory
  - Must be a valid system group
  - Requires appropriate privileges to change group ownership

- `recursive` (optional): Whether to create parent directories
  - Default: false
  - If true, creates all parent directories with the same permissions

## Usage examples

### Basic Directory Creation

```yaml
path: /etc/myapp
permissions: 0755
```

### Directory with Custom Ownership

```yaml
path: /var/log/myapp
permissions: 0750
owner: myapp
group: myapp
```

### Recursive Directory Creation

```yaml
path: /opt/myapp/logs/2023
permissions: 0755
recursive: true
```

### Application Data Directory

```yaml
path: /var/lib/myapp/data
permissions: 0700
owner: myapp
group: myapp
recursive: true
```

## Known limitations

1. **Platform Differences**:
   - Windows has limited support for POSIX permissions
   - Some Unix systems may restrict group ownership changes
   - Symbolic link handling varies by platform

2. **Permission Restrictions**:
   - Cannot set permissions higher than the process's capabilities
   - Cannot change ownership without appropriate privileges
   - Some filesystems may not support all permission bits

3. **Path Limitations**:
   - Paths must be absolute
   - Some special characters may cause issues
   - Maximum path length varies by platform

4. **Ownership Management**:
   - Changing ownership requires root/administrator privileges
   - Not all platforms support all ownership operations
   - Group ownership may be restricted on some systems

## Security considerations

1. **Permission Management**:
   - Default permissions (0755) provide read/execute access to all users
   - Consider using more restrictive permissions (0750 or 0700) for sensitive directories
   - Validate permissions before applying them
   - Be cautious with world-writable permissions (0777)

2. **Ownership Controls**:
   - Changing ownership requires elevated privileges
   - Verify user/group existence before attempting ownership changes
   - Consider security implications of directory ownership
   - Use principle of least privilege when setting ownership

3. **Path Validation**:
   - Validate paths to prevent directory traversal attacks
   - Ensure paths are within allowed directories
   - Sanitize user-provided paths
   - Be cautious with symbolic links

4. **Error Handling**:
   - All operations are idempotent
   - Failed operations are logged with appropriate context
   - Sensitive information is not logged
   - Proper error messages help identify security issues

5. **Recursive Operations**:
   - Be cautious with recursive operations
   - Validate parent directory permissions
   - Consider implications of inherited permissions
   - Monitor for potential security issues during recursive creation

## Features

- Create and manage directories
- Set directory permissions
- Set directory ownership (user and group)
- Recursive directory creation
- Cross-platform support (Linux, macOS, Windows)
- Idempotent operations

## Platform Support

### Linux/macOS

- Full support for all features
- Proper handling of user/group ownership
- Unix-style permissions

### Windows

- Basic directory management
- Limited ownership support (only current user)
- Windows-style permissions

## Error Handling

The module provides specific error types for common failure scenarios:

- `ErrInvalidPath`: Invalid directory path
- `ErrPermissionDenied`: Insufficient permissions
- `ErrNotADirectory`: Path exists but is not a directory
- `ErrRecursiveRequired`: Operation requires recursive flag
- `ErrInvalidOwner`: Invalid owner specified
- `ErrInvalidGroup`: Invalid group specified
