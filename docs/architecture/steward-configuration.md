# Steward Configuration (hostname.cfg)

## Overview

The Steward configuration file (`hostname.cfg`) defines how the Steward operates in standalone mode. The file uses YAML format but has a `.cfg` extension and is named after the device hostname.

## Configuration File Locations

The Steward searches for configuration files in the following priority order:

1. **Command-line specified**: `--config /path/to/hostname.cfg`
2. **Environment variable**: `CFGMS_CONFIG=/path/to/hostname.cfg`
3. **Default locations**:
   - `./<hostname>.cfg` (current directory)
   - `/etc/cfgms/<hostname>.cfg` (Linux/macOS)
   - `C:\ProgramData\cfgms\<hostname>.cfg` (Windows)

## Configuration Format

```yaml
# hostname.cfg - Steward standalone configuration
steward:
  name: "hostname-steward"
  log_level: "info"
  
  # Module discovery paths (searched in order)
  module_paths:
    - "./modules"
    - "/opt/cfgms/modules"          # Linux/macOS
    - "C:\\Program Files\\cfgms\\modules"  # Windows
  
  # Error handling behavior
  error_handling:
    module_load_failure: "continue"        # "continue" or "fail"
    config_validation_failure: "fail"      # "fail" or "continue"
    runtime_error_behavior: "continue"     # "continue" or "fail"
  
  # Execution settings
  execution:
    mode: "apply"                    # "apply", "check", or "drift"
    timeout: "300s"                  # Default operation timeout
    retry_attempts: 3                # Number of retry attempts for transient errors
    retry_delay: "5s"               # Delay between retry attempts

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
- `name`: Unique identifier for this Steward instance
- `log_level`: Logging verbosity (`debug`, `info`, `warn`, `error`)

**Module Discovery:**
- `module_paths`: List of directories to search for modules (searched in order)

**Error Handling:**
- `module_load_failure`: How to handle module loading failures
  - `continue`: Skip failed modules, continue with available ones (default)
  - `fail`: Stop execution if any module fails to load
- `config_validation_failure`: How to handle configuration validation errors
  - `fail`: Stop execution on validation errors (default)
  - `continue`: Skip invalid configurations, process valid ones
- `runtime_error_behavior`: How to handle runtime errors during execution
  - `continue`: Continue with remaining modules after errors (default)
  - `fail`: Stop execution on any runtime error

**Execution Settings:**
- `mode`: Execution mode
  - `apply`: Execute Set operations to achieve desired state (default)
  - `check`: Execute Get operations and compare (dry-run)
  - `drift`: Execute Get operations to detect configuration drift
- `timeout`: Default timeout for module operations
- `retry_attempts`: Number of retry attempts for transient errors
- `retry_delay`: Delay between retry attempts

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

### Linux/macOS
- Configuration files stored in `/etc/cfgms/`
- Modules installed in `/opt/cfgms/modules/`
- Use forward slashes in paths
- Owner/group settings supported for file and directory modules

### Windows
- Configuration files stored in `C:\ProgramData\cfgms\`
- Modules installed in `C:\Program Files\cfgms\modules\`
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
  name: "web-server-01"

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
  name: "dev-machine"
  log_level: "debug"
  module_paths:
    - "./local-modules"
    - "./modules"
  error_handling:
    module_load_failure: "fail"
    config_validation_failure: "fail"
  execution:
    mode: "check"  # Dry-run mode for development

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

- [Standalone Steward Architecture](modules/standalone-steward.md): Complete architecture overview
- [Module Interface](modules/interface.md): Module interface and ConfigState details
- [Module Development](modules/development.md): Guide for developing new modules