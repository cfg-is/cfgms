# Steward Configuration (hostname.cfg)

## Overview

The Steward configuration file (`hostname.cfg`) defines how the Steward operates in standalone mode. The file uses YAML format but has a `.cfg` extension and is named after the device hostname.

## Configuration File Locations

The Steward searches for configuration files in the following priority order:

1. **Command-line specified**: `--config /path/to/hostname.cfg`
2. **Environment variable**: `CFGMS_CONFIG=/path/to/hostname.cfg`
3. **Default locations** (searched in order per platform):
   - `./<hostname>.cfg` (current working directory — all platforms)
   - Linux: `/etc/cfgms/<hostname>.cfg`, `/usr/local/etc/cfgms/<hostname>.cfg`, `~/.config/cfgms/<hostname>.cfg`, `~/.cfgms/<hostname>.cfg`
   - macOS: `/Library/Application Support/cfgms/<hostname>.cfg`, `/usr/local/etc/cfgms/<hostname>.cfg`, `~/Library/Application Support/cfgms/<hostname>.cfg`, `~/.cfgms/<hostname>.cfg`
   - Windows: `%PROGRAMDATA%\cfgms\<hostname>.cfg`, `%USERPROFILE%\.cfgms\<hostname>.cfg`

## Configuration Format

```yaml
# hostname.cfg - Steward standalone configuration
steward:
  id: "hostname-steward"
  mode: "standalone"               # "standalone" or "controller"

  # Logging settings
  logging:
    level: "info"                  # "debug", "info", "warn", or "error"
    format: "text"                 # "text" or "json"

  # Module discovery paths (searched in order, in addition to built-in paths)
  module_paths:
    - "./modules"
    - "/opt/cfgms/modules"          # Linux/macOS
    - "C:\\Program Files\\cfgms\\modules"  # Windows

  # How often the steward re-converges against the cfg (default: 30m)
  converge_interval: "30m"

  # Error handling behavior
  error_handling:
    module_load_failure: "continue"   # "continue", "warn", or "fail"
    resource_failure: "warn"          # "continue", "warn", or "fail"
    configuration_error: "fail"       # "continue", "warn", or "fail"

# Resource configurations
resources:
  - name: "web-directories"
    module: "directory"
    config:
      path: "/var/www"
      owner: "www-data"
      permissions: 755
      recursive: true
      
  - name: "nginx-config"
    module: "file"
    config:
      path: "/etc/nginx/nginx.conf"
      content: |
        user www-data;
        worker_processes auto;
        
        events {
            worker_connections 1024;
        }
        
        http {
            include /etc/nginx/mime.types;
            default_type application/octet-stream;
            
            sendfile on;
            keepalive_timeout 65;
            
            include /etc/nginx/conf.d/*.conf;
            include /etc/nginx/sites-enabled/*;
        }
      owner: "root"
      group: "root"
      permissions: 644

  - name: "firewall-web"
    module: "firewall"
    config:
      rules:
        - name: "allow-http"
          port: 80
          protocol: "tcp"
          action: "allow"
          source: "0.0.0.0/0"
          destination: "0.0.0.0/0"
        - name: "allow-https" 
          port: 443
          protocol: "tcp"
          action: "allow"
          source: "0.0.0.0/0"
          destination: "0.0.0.0/0"

  - name: "required-packages"
    module: "package"
    config:
      packages:
        - name: "nginx"
          state: "installed"
          version: "latest"
        - name: "git"
          state: "installed"
        - name: "curl"
          state: "installed"
```

## Configuration Sections

### Steward Section

**Basic Settings:**

- `id`: Unique identifier for this Steward instance (defaults to the system hostname)
- `mode`: Operation mode — `standalone` (local config files) or `controller` (connected to controller)

**Logging:**

- `logging.level`: Logging verbosity (`debug`, `info`, `warn`, `error`); default `info`
- `logging.format`: Log output format (`text` or `json`); default `text`

**Module Discovery:**

- `module_paths`: Additional directories to search for modules beyond built-in locations

**Convergence:**

- `converge_interval`: How often the steward re-converges against the config (e.g. `30m`, `5m`, `1h`); default `30m`

**Error Handling:**

- `module_load_failure`: How to handle module loading failures
  - `continue`: Skip failed modules, continue with available ones (default)
  - `warn`: Log a warning and continue
  - `fail`: Stop execution if any module fails to load
- `resource_failure`: How to handle errors during resource execution
  - `continue`: Continue with remaining resources after errors
  - `warn`: Log a warning and continue (default)
  - `fail`: Stop execution on any resource error
- `configuration_error`: How to handle configuration validation errors
  - `fail`: Stop execution on validation errors (default)
  - `warn`: Log a warning and continue
  - `continue`: Skip invalid configurations, process valid ones

### Resources Section

The `resources` section contains an array of resource configurations. Each resource specifies:

- `name`: Unique name for the resource
- `module`: Module to use for managing this resource
- `config`: Module-specific configuration (varies by module)

**Resource Configuration Notes:**

- Only fields specified in `config` will be managed by the Steward
- The module's `GetManagedFields()` determines which fields can be managed
- Other system settings discovered by `Get()` will be left unchanged

## Platform-Specific Considerations

### Linux

- System config path: `/etc/cfgms/<hostname>.cfg`
- Module paths: `/opt/cfgms/modules/`
- Use forward slashes in paths
- Owner/group settings supported for file and directory modules

### macOS

- System config path: `/Library/Application Support/cfgms/<hostname>.cfg`
- Module paths: `/opt/cfgms/modules/` or custom `module_paths`
- Use forward slashes in paths
- Owner/group settings supported for file and directory modules

### Windows

- System config path: `C:\ProgramData\cfgms\<hostname>.cfg`
- Module paths: `C:\Program Files\cfgms\modules\`
- Use double backslashes in paths: `"C:\\path\\to\\file"`
- Limited owner/group support (owner only)

## Validation

The Steward validates configuration files on startup:

1. **YAML Syntax**: Ensures valid YAML format
2. **Schema Validation**: Validates required sections and fields
3. **Module Availability**: Ensures all referenced modules are available
4. **Resource Configuration**: Uses module's `ConfigState.Validate()` for resource-specific validation

## Examples

### Minimal Configuration

```yaml
steward:
  id: "web-server-01"

resources:
  - name: "web-dir"
    module: "directory"
    config:
      path: "/var/www"
      permissions: 755
```

### Development Configuration

```yaml
steward:
  id: "dev-machine"
  logging:
    level: "debug"
  module_paths:
    - "./local-modules"
    - "./modules"
  converge_interval: "5m"
  error_handling:
    module_load_failure: "fail"
    configuration_error: "fail"

resources:
  - name: "dev-tools"
    module: "package"
    config:
      packages:
        - name: "git"
        - name: "vim"
        - name: "curl"
```

## Related Documentation

- [Module Interface](modules/interface.md): Module interface and ConfigState details
- [Module System](modules/README.md): Available modules overview
