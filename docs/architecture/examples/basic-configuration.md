# Basic Configuration Examples

## Core Configuration

```yaml
# System-wide settings
global:
  log_level: info
  data_dir: /var/lib/cfgms
  version: "1.0"

# Controller configuration
controller:
  listen_addr: ":8443"
  cert_file: "/etc/cfgms/cert.pem"
  key_file: "/etc/cfgms/key.pem"
  ca_file: "/etc/cfgms/ca.pem"

# Outpost configuration
outpost:
  name: "outpost-1"
  controller_addr: "controller.example.com:8443"
  cert_file: "/etc/cfgms/outpost-cert.pem"
  key_file: "/etc/cfgms/outpost-key.pem"
  ca_file: "/etc/cfgms/ca.pem"

# Steward configuration
steward:
  name: "steward-1"
  outpost_addr: "outpost.example.com:8443"
  cert_file: "/etc/cfgms/steward-cert.pem"
  key_file: "/etc/cfgms/steward-key.pem"
  ca_file: "/etc/cfgms/ca.pem"
  heartbeat_interval: "30s"
  reconnect_timeout: "5s"
```

## Module Configuration

```yaml
# Module definitions
modules:
  file_module:
    - path: /etc/myapp/config.ini
      content: |
        [database]
        host = {{ .Vars.db_host }}
        port = 5432
      mode: "0644"
      owner: root
      group: root
      monitor:
        enabled: true
        interval: 5m

  service_module:
    - name: myapp
      ensure: running
      enable: true
      dependencies:
        - file_module:/etc/myapp/config.ini

# Variables
vars:
  db_host: "db.example.com"
  environment: "production"
```

## Multi-tenancy Configuration

```yaml
# Tenant configuration
tenant:
  id: "client1"
  parent: "msp1"
  path: "msp1/client1"
  config_overrides:
    modules:
      service_module:
        - name: myapp
          ensure: running
          environment:
            DB_HOST: "client1-db.example.com"

# RBAC configuration
rbac:
  roles:
    - name: admin
      permissions:
        - "*"
    - name: operator
      permissions:
        - "read:*"
        - "write:service_module"
```

## Workflow Configuration

```yaml
# Workflow definition
workflows:
  backup_workflow:
    name: "Database Backup"
    steps:
      - name: "Check database status"
        module: database_module
        action: check_status
        params:
          db_name: "{{ .Vars.db_name }}"
        on_failure:
          action: notify
          params:
            message: "Database status check failed"

      - name: "Perform backup"
        module: database_module
        action: backup
        params:
          db_name: "{{ .Vars.db_name }}"
          backup_path: "{{ .Vars.backup_path }}"
        retry:
          attempts: 3
          delay: 5m

# Workflow variables
vars:
  db_name: "myapp_production"
  backup_path: "/backups"
```

## Version Information

- Version: 1.0
- Last Updated: 2024-04-11
- Status: Draft
