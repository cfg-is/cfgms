# Module Examples

This directory contains examples of how to configure modules in CFGMS. Unlike traditional configuration management systems, CFGMS modules are written in Go and don't require separate configuration files.

## Module Configuration Approach

In CFGMS, module configurations are integrated directly into the main configuration files:

1. **Base Configuration** (`base.cfg`): Contains default module settings that apply to all endpoints
2. **Group Configuration** (`groups.cfg`): Contains module settings for specific groups of endpoints
3. **Endpoint Configuration** (`endpoint.cfg`): Contains endpoint-specific module settings

## Example Module Configurations

### File Module

```yaml
# In base.cfg
modules:
  file:
    defaults:
      mode: "0644"
      owner: "root"
      group: "root"
      backup: true
    files:
      "/etc/hosts":
        content: |
          127.0.0.1 localhost
          ::1 localhost ip6-localhost ip6-loopback

# In groups.cfg
groups:
  web_servers:
    match:
      roles:
        - "web"
    settings:
      modules:
        file:
          "/etc/nginx/nginx.conf":
            source: "templates/nginx/base.conf"
            mode: "0644"
            owner: "root"
            group: "root"
            validate: "nginx -t"
            vars:
              worker_processes: "auto"
              worker_connections: 1024

# In endpoint.cfg
modules:
  file:
    "/etc/nginx/nginx.conf":
      source: "templates/nginx/prod.conf"
      vars:
        worker_processes: 8
        worker_connections: 2048
```

### Service Module

```yaml
# In base.cfg
modules:
  service:
    defaults:
      state: "running"
      enabled: true
    services:
      sshd:
        state: "running"
        config:
          port: 22
          permit_root_login: "no"
          password_authentication: "no"

# In groups.cfg
groups:
  web_servers:
    match:
      roles:
        - "web"
    settings:
      modules:
        service:
          nginx:
            state: "running"
            config:
              worker_processes: "auto"
              worker_connections: 1024
          redis:
            state: "running"
            config:
              maxmemory: "2gb"
              maxmemory-policy: "allkeys-lru"

# In endpoint.cfg
modules:
  service:
    nginx:
      state: "running"
      config:
        worker_processes: 8
        worker_connections: 2048
        keepalive_timeout: 65
        gzip: true
```

## Module Implementation

Modules in CFGMS are implemented in Go and must implement the following interfaces:

1. **Get**: Returns the current configuration of the resource
2. **Set**: Updates the resource configuration to match the specification
3. **Test**: Validates if the current configuration matches the specification
4. **Monitor** (Optional): Implements event-driven monitoring to detect changes

For more information on module implementation, see the [Module System Documentation](../../modules/README.md).

## Version Information

- Version: 1.0
- Last Updated: 2024-04-20
- Status: Draft

