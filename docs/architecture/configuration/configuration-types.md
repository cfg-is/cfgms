# Configuration Types

## Overview

CFGMS uses a simple configuration model that focuses on declarative configuration files (`.cfg` files) that define the desired state for resources, where a single configuration file can contain settings for multiple modules and resources.

## Core Configuration Files

The primary configuration type in CFGMS is the `.cfg` file, which contains declarative specifications of desired state for one or more resources.

### Structure

A typical `.cfg` file has the following structure:

```yaml
# Metadata
metadata:
  name: "webserver-config"
  description: "Configuration for web servers"
  version: "1.0"
  applies_to:
    dna:
      role: "webserver"
      os: "linux"

# Module configurations
modules:
  # File module configuration
  file:
    - path: "/etc/nginx/nginx.conf"
      content: |
        user nginx;
        worker_processes auto;
        error_log /var/log/nginx/error.log;
        pid /run/nginx.pid;
      mode: "0644"
      owner: "root"
      group: "root"
    
    - path: "/etc/nginx/conf.d/default.conf"
      content: |
        server {
            listen 80;
            server_name example.com;
            root /var/www/html;
        }
      mode: "0644"
      owner: "root"
      group: "root"
  
  # Service module configuration
  service:
    - name: "nginx"
      ensure: "running"
      enable: true
      dependencies:
        - "file:/etc/nginx/nginx.conf"
        - "file:/etc/nginx/conf.d/default.conf"
  
  # User module configuration
  user:
    - name: "nginx"
      ensure: "present"
      system: true
      shell: "/sbin/nologin"
  
  # Package module configuration
  package:
    - name: "nginx"
      ensure: "present"
      version: "1.20.1"

# Variables
vars:
  nginx_worker_processes: "auto"
  nginx_error_log: "/var/log/nginx/error.log"

# Include other configuration files
include:
  - "common/security.cfg"
  - "environments/production.cfg"
```

### Key Components

1. **Metadata** - Information about the configuration, including targeting criteria
2. **Module Configurations** - Settings for specific modules
3. **Variables** - Reusable values that can be referenced throughout the configuration
4. **Includes** - References to other configuration files

## Targeting

Configurations can be targeted to specific endpoints using DNA properties:

```yaml
metadata:
  applies_to:
    dna:
      role: "webserver"  # Apply to endpoints with role=webserver
      os: "linux"        # Apply to Linux endpoints
      environment: "production"  # Apply to production environment
```

Targeting can use:

- Exact matches
- Regular expressions
- Lists of values
- Negation (e.g., `os: "!windows"`)

## Workflow Files

Workflows are defined in separate `.wrkflo` files:

```yaml
# Workflow metadata
metadata:
  name: "deploy-application"
  description: "Deploy a new application version"
  version: "1.0"

# Workflow steps
steps:
  - name: "backup-database"
    module: "database"
    action: "backup"
    params:
      database: "{{ .vars.database_name }}"
      backup_path: "/backups/{{ .vars.database_name }}_{{ .now | date 'YYYY-MM-DD' }}.sql"
  
  - name: "deploy-application"
    module: "application"
    action: "deploy"
    params:
      app_name: "{{ .vars.app_name }}"
      version: "{{ .vars.app_version }}"
      environment: "{{ .vars.environment }}"
  
  - name: "run-migrations"
    module: "database"
    action: "migrate"
    params:
      database: "{{ .vars.database_name }}"
      migration_path: "{{ .vars.migration_path }}"
  
  - name: "verify-deployment"
    module: "application"
    action: "health-check"
    params:
      app_name: "{{ .vars.app_name }}"
      timeout: 300

# Error handling
on_error:
  - name: "notify-failure"
    module: "notification"
    action: "send"
    params:
      message: "Deployment failed: {{ .error }}"
      channel: "{{ .vars.notification_channel }}"
```

## System Configuration

System-level configurations are stored in the `system/` directory and define the behavior of CFGMS itself:

```yaml
# System configuration
system:
  controller:
    host: "controller.example.com"
    port: 8443
    log_level: "info"
  
  storage:
    type: "file"
    file:
      base_dir: "/cfgms"
      git:
        enabled: true
        remote: "git@github.com:org/cfgms.git"
  
  security:
    auth:
      type: "oauth2"
      provider: "azure-ad"
    
    tls:
      cert_path: "/etc/cfgms/certs"
      key_path: "/etc/cfgms/keys"
```

## Version Information

- **Document Version:** 1.0
- **Last Updated:** 2024-04-07
- **Status:** Draft
