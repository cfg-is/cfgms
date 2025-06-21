# Package Module

## Purpose and scope

The Package module provides a unified interface for managing system packages across different package managers. It abstracts away the differences between package managers (apt, yum, dnf, pacman, brew, chocolatey, winget) and provides a consistent way to install, update, and remove packages.

The module's scope includes:

- Package installation and removal
- Version management
- Package updates
- Dependency management
- Cross-platform support
- Package manager auto-detection
- Retry and timeout handling
- Security considerations

## Platform Support

### Windows

- **Winget**: Microsoft's official package manager (preferred)
- **Chocolatey**: Alternative package manager with broader package selection

### macOS

- **Homebrew**: Primary package manager for macOS

### Linux

- **APT**: Debian/Ubuntu based systems
- **YUM/DNF**: RedHat/CentOS/Fedora based systems
- **Pacman**: Arch Linux based systems

## Configuration options

The module accepts the following configuration options in YAML format:

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| name | string | Yes | Name of the package to manage (1-128 chars, alphanumeric, `-`, `.`, `_`) |
| state | string | Yes | Desired state (`present` or `absent`) |
| version | string | No | Specific version to install (`latest` or version number) |
| update | boolean | No | Whether to update if already installed (default: false) |
| dependencies | []string | No | List of package dependencies to install |
| manager | string | No | Package manager to use (auto-detected if not specified) |
| options | object | No | Additional package manager specific options |
| force | boolean | No | Force operation even if dangerous (default: false) |
| allow_untrusted | boolean | No | Allow untrusted packages (default: false) |
| timeout | integer | No | Operation timeout in seconds (default: 300) |
| retry | object | No | Retry configuration for failed operations |

### Retry Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| attempts | integer | No | Number of retry attempts (default: 3, max: 10) |
| delay | integer | No | Delay between retries in seconds (default: 5, max: 300) |

## Version Management

### Latest Version

```yaml
modules:
  package:
    nginx:
      state: "present"
      version: "latest"  # Installs the latest GA version available
```

### Specific Version

```yaml
modules:
  package:
    nginx:
      state: "present"
      version: "1.18.0"  # Installs specific version
```

### Auto-Update with Optional Maintenance Window

```yaml
modules:
  package:
    nginx:
      state: "present"
      version: "1.18.0"  # Minimum version
      update: true       # Will check for updates every config validation
      # Optional: Specify maintenance window to restrict updates to specific times
      maintenance:
        window: "default"  # Use named maintenance window
        # OR specify inline schedule
        schedule: "0 2 * * *"  # Daily at 2 AM
        duration: "2h"
        timezone: "UTC"
```

## Behavior Rules

1. **Latest Version**
   - `version: "latest"` installs the latest GA version available
   - No automatic updates after initial installation
   - No maintenance window required

2. **Specific Version**
   - `version: "1.18.0"` installs that specific version
   - No automatic updates unless `update: true` is set
   - If `update: true` is set without a maintenance window:
     - Will check for updates every time the config test runs
     - Will update if a newer version is available
     - Will not update if current version is newer than minimum

3. **Auto-Update with Maintenance Window**
   - Requires `update: true` to be set
   - Uses `version` as minimum allowed version
   - If maintenance window is specified:
     - Will only update during the specified window
     - Will not update outside the window
   - Will not update if current version is newer than minimum

## Usage examples

### Basic Package Installation

```yaml
name: nginx
state: present
version: latest
```

### Install Specific Version

```yaml
name: redis
state: present
version: "6.2.6"
```

### Remove Package

```yaml
name: htop
state: absent
```

### Install with Dependencies

```yaml
name: nodejs
state: present
version: latest
dependencies:
  - npm
  - build-essential
```

### Force Update Package

```yaml
name: postgresql
state: present
version: latest
update: true
force: true
```

### Package with Custom Options

```yaml
name: mysql-server
state: present
version: "8.0"
options:
  root_password: "secure123"
  data_dir: "/data/mysql"
```

### Installation with Retry

```yaml
name: docker-ce
state: present
version: latest
retry:
  attempts: 5
  delay: 10
```

### Windows-specific Examples

#### Using Winget
```yaml
name: Microsoft.VisualStudioCode
state: present
version: latest
manager: winget
```

#### Using Chocolatey
```yaml
name: vscode
state: present
version: latest
manager: chocolatey
```

## Known limitations

1. Platform-specific limitations:
   - Not all package managers support version rollback
   - Package names may differ between platforms
   - Some package managers don't support version pinning
   - Update behavior varies by package manager
   - Winget package names use a different format (Publisher.Package)

2. Performance considerations:
   - Package operations can be slow
   - Network dependency for package downloads
   - Large packages may timeout with default settings

3. Technical limitations:
   - Cannot manage packages that require interactive installation
   - Some package managers require system restarts
   - Package verification methods vary by platform
   - Limited support for source-based installations

## Security considerations

1. Authentication and Authorization:
   - Requires root/administrator privileges
   - Access should be restricted through RBAC
   - Package operations are logged for audit
   - Package sources should be trusted

2. Input Validation:
   - Package names are strictly validated
   - Version strings are verified
   - Options are sanitized
   - Dependencies are checked

3. Best Practices:
   - Avoid untrusted package sources
   - Use version pinning for stability
   - Regular security updates
   - Backup system before major changes

4. Platform Security:
   - Uses secure package transport (HTTPS)
   - Verifies package signatures
   - Respects system security policies
   - Handles sensitive data securely

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-20
- **Status**: Draft
