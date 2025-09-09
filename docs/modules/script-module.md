# Script Module Documentation

## Overview

The Script Module provides cross-platform script execution capabilities for CFGMS, supporting Windows (PowerShell, CMD) and Unix-like systems (Bash, Zsh, Python). It implements the standard CFGMS module interface with comprehensive audit logging and security features.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Configuration Options](#configuration-options)
- [Security Features](#security-features)
- [Execution Environment](#execution-environment)
- [Audit and Monitoring](#audit-and-monitoring)
- [API Integration](#api-integration)
- [Examples](#examples)

## Basic Usage

### Module Configuration

The script module follows the standard CFGMS ConfigState interface:

```yaml
script:
  content: |
    #!/bin/bash
    echo "Hello from CFGMS!"
    echo "Current user: $(whoami)"
  shell: bash
  timeout: 30s
  description: "Basic system information script"
  signing_policy: none
```

### Supported Shells

| Platform | Supported Shells |
|----------|------------------|
| Linux/macOS | `bash`, `zsh`, `python` |
| Windows | `powershell`, `cmd` |

## Configuration Options

### Core Configuration

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `content` | string | Yes | The script content to execute |
| `shell` | string | Yes | Shell/interpreter to use |
| `timeout` | duration | No | Maximum execution time (default: 30s) |
| `description` | string | No | Human-readable description |
| `working_dir` | string | No | Working directory for execution |
| `environment` | map | No | Environment variables |
| `signing_policy` | string | No | Script signing requirement |

### Security Configuration

```yaml
script:
  content: |
    # This script requires validation
    Get-Service | Where-Object Status -eq Running
  shell: powershell
  signing_policy: required
  signature:
    algorithm: RSA-SHA256
    signature: "base64-encoded-signature"
    public_key: "-----BEGIN PUBLIC KEY-----..."
    thumbprint: "cert-thumbprint-optional"
```

### Environment Variables

```yaml
script:
  content: |
    echo "Backup path: $BACKUP_PATH"
    echo "Log level: $LOG_LEVEL"
  shell: bash
  environment:
    BACKUP_PATH: /var/backups
    LOG_LEVEL: INFO
```

## Security Features

### Signing Policies

1. **None** (`none`): No signature validation
2. **Optional** (`optional`): Validate signature if present
3. **Required** (`required`): Signature must be present and valid

### Supported Algorithms

- RSA with SHA-256 (`RSA-SHA256`)
- ECDSA with SHA-256 (`ECDSA-SHA256`)

### Example with Signature

```yaml
script:
  content: |
    # Production deployment script
    systemctl restart my-service
  shell: bash
  signing_policy: required
  signature:
    algorithm: RSA-SHA256
    signature: "MEQCIBxQ7..."
    public_key: |
      -----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
      -----END PUBLIC KEY-----
```

## Execution Environment

### Process Management

- **Timeout Handling**: Graceful termination with SIGTERM, followed by SIGKILL
- **Resource Isolation**: Each script runs in its own process
- **Working Directory**: Configurable working directory (defaults to system temp)
- **Environment**: Clean environment with configurable variables

### Output Capture

- **Stdout**: Captured and returned in execution results
- **Stderr**: Captured separately for error analysis
- **Exit Code**: Process exit code for success/failure determination

## Audit and Monitoring

### Execution Records

Every script execution generates a comprehensive audit record:

```json
{
  "id": "audit-record-uuid",
  "steward_id": "steward-123",
  "resource_id": "backup-script",
  "execution_time": "2025-07-28T10:30:00Z",
  "duration": 5000,
  "status": "completed",
  "exit_code": 0,
  "script_config": {
    "shell": "bash",
    "timeout": 30000,
    "content_hash": "sha256:abc123...",
    "content_length": 256,
    "signing_policy": "none"
  },
  "metrics": {
    "start_time": "2025-07-28T10:30:00Z",
    "end_time": "2025-07-28T10:30:05Z",
    "duration": 5000,
    "process_id": 12345
  },
  "user_id": "admin",
  "tenant_id": "tenant-456"
}
```

### Performance Metrics

Aggregated metrics include:
- **Success Rate**: Percentage of successful executions
- **Average Duration**: Mean execution time
- **Shell Usage**: Distribution of shell usage
- **Failure Analysis**: Common failure patterns

## API Integration

### REST API Endpoints

The script module integrates with CFGMS REST API:

```bash
# List script executions
GET /api/v1/stewards/{id}/scripts/executions?since=2025-07-28T00:00:00Z

# Get specific execution
GET /api/v1/stewards/{id}/scripts/executions/{execution_id}

# Get performance metrics
GET /api/v1/stewards/{id}/scripts/metrics?since=2025-07-27T00:00:00Z

# Get current script status
GET /api/v1/stewards/{id}/scripts/status

# Retry failed execution
POST /api/v1/stewards/{id}/scripts/executions/{execution_id}/retry
```

### Query Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `since` | Filter executions since timestamp | `2025-07-28T00:00:00Z` |
| `until` | Filter executions until timestamp | `2025-07-28T23:59:59Z` |
| `status` | Filter by execution status | `completed`, `failed`, `running` |
| `resource_id` | Filter by script resource | `backup-script` |
| `user_id` | Filter by executing user | `admin` |
| `limit` | Limit number of results | `50` |
| `offset` | Pagination offset | `100` |

## Examples

### 1. System Information Script

```yaml
modules:
  system_info:
    type: script
    config:
      content: |
        #!/bin/bash
        echo "=== System Information ==="
        echo "Hostname: $(hostname)"
        echo "Uptime: $(uptime)"
        echo "Disk Usage:"
        df -h / | tail -1
        echo "Memory Usage:"
        free -h | grep '^Mem:'
      shell: bash
      timeout: 10s
      description: "Collect basic system information"
```

### 2. Windows Service Management

```yaml
modules:
  service_check:
    type: script
    config:
      content: |
        # Check critical services status
        $services = @('Spooler', 'BITS', 'Themes')
        foreach ($service in $services) {
            $status = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($status) {
                Write-Output "$service : $($status.Status)"
            } else {
                Write-Output "$service : Not Found"
            }
        }
      shell: powershell
      timeout: 15s
      description: "Check status of critical Windows services"
```

### 3. Database Backup Script

```yaml
modules:
  db_backup:
    type: script
    config:
      content: |
        #!/bin/bash
        set -e
        
        BACKUP_DIR="${BACKUP_PATH}/$(date +%Y%m%d)"
        mkdir -p "$BACKUP_DIR"
        
        echo "Starting database backup to $BACKUP_DIR"
        mysqldump -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" > "$BACKUP_DIR/backup.sql"
        
        if [ $? -eq 0 ]; then
            echo "Backup completed successfully"
            gzip "$BACKUP_DIR/backup.sql"
        else
            echo "Backup failed"
            exit 1
        fi
      shell: bash
      timeout: 300s
      environment:
        BACKUP_PATH: /var/backups/mysql
        DB_USER: backup_user
        DB_PASS: "${SECRET:db_backup_password}"
        DB_NAME: production_db
      description: "Automated database backup with compression"
      signing_policy: required
```

### 4. Python System Audit

```yaml
modules:
  security_audit:
    type: script
    config:
      content: |
        import os
        import json
        import subprocess
        from datetime import datetime
        
        def check_file_permissions():
            sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
            results = {}
            
            for file_path in sensitive_files:
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    results[file_path] = {
                        'permissions': oct(stat.st_mode)[-3:],
                        'owner': stat.st_uid,
                        'group': stat.st_gid
                    }
            
            return results
        
        def main():
            audit_result = {
                'timestamp': datetime.now().isoformat(),
                'hostname': os.uname().nodename,
                'file_permissions': check_file_permissions()
            }
            
            print(json.dumps(audit_result, indent=2))
        
        if __name__ == '__main__':
            main()
      shell: python
      timeout: 60s
      description: "Security audit using Python"
```

### 5. Configuration Validation

```yaml
modules:
  config_validate:
    type: script
    config:
      content: |
        # Validate nginx configuration
        nginx -t
        if [ $? -eq 0 ]; then
            echo "Nginx configuration is valid"
            
            # Check if reload is needed
            if [ -f /var/run/nginx.pid ]; then
                echo "Reloading nginx configuration"
                nginx -s reload
            else
                echo "Starting nginx"
                systemctl start nginx
            fi
        else
            echo "Nginx configuration is invalid"
            exit 1
        fi
      shell: bash
      timeout: 30s
      description: "Validate and reload nginx configuration"
      signing_policy: optional
```

## Best Practices

### 1. Script Design

- **Idempotent Operations**: Design scripts to be safely run multiple times
- **Error Handling**: Use `set -e` in bash scripts for early failure detection
- **Clear Output**: Provide informative output for monitoring and debugging
- **Resource Cleanup**: Clean up temporary files and resources

### 2. Security

- **Principle of Least Privilege**: Run scripts with minimal required permissions
- **Input Validation**: Validate all external inputs and environment variables
- **Sensitive Data**: Use CFGMS secret management for passwords and keys
- **Code Signing**: Use signing for production and critical scripts

### 3. Performance

- **Appropriate Timeouts**: Set realistic timeouts based on expected execution time
- **Resource Management**: Monitor CPU and memory usage for long-running scripts
- **Parallel Execution**: Use parallel execution for independent operations
- **Caching**: Cache expensive operations when possible

### 4. Monitoring

- **Comprehensive Logging**: Use structured logging for better searchability
- **Metrics Collection**: Track execution metrics for performance optimization
- **Alert Configuration**: Set up alerts for script failures and performance issues
- **Regular Audits**: Review script execution patterns and audit logs

## Troubleshooting

### Common Issues

1. **Timeout Errors**
   - Increase timeout value
   - Optimize script performance
   - Break long operations into smaller chunks

2. **Permission Denied**
   - Check script execution permissions
   - Verify user has required system permissions
   - Review signing policy configuration

3. **Shell Not Available**
   - Verify shell is installed on target system
   - Check shell path and availability
   - Use cross-platform compatible commands

4. **Environment Variable Issues**
   - Verify environment variable names and values
   - Check for special characters that need escaping
   - Use CFGMS secret management for sensitive values

### Debug Mode

Enable debug logging for detailed execution information:

```yaml
script:
  content: |
    set -x  # Enable bash debug mode
    echo "Debug: Starting script execution"
    # Your script content here
  shell: bash
  timeout: 30s
```

## Integration with CFGMS

### Module Registration

The script module is automatically registered with the CFGMS module system:

```go
// Automatic registration in module factory
func init() {
    modules.RegisterModule("script", script.New)
}
```

### Steward Integration

Scripts are executed through the steward's module system:

1. Configuration received from controller
2. Script module validates configuration
3. Executor prepares execution environment
4. Script runs with monitoring and timeout
5. Results and audit data sent to controller

### Workflow Integration

Scripts can be integrated into CFGMS workflows:

```yaml
workflow:
  name: "System Maintenance"
  steps:
    - name: "pre_checks"
      type: task
      module: script
      config:
        content: "systemctl status critical-service"
        shell: bash
    
    - name: "maintenance"
      type: task
      module: script
      config:
        content: "apt update && apt upgrade -y"
        shell: bash
        timeout: 600s
    
    - name: "post_checks"
      type: task
      module: script
      config:
        content: "systemctl status critical-service"
        shell: bash
```

## Future Enhancements

- **Container Execution**: Support for containerized script execution
- **Resource Limits**: CPU and memory limits for script execution
- **Script Library**: Shared script repository with versioning
- **Advanced Monitoring**: Real-time execution monitoring and metrics
- **Interactive Scripts**: Support for scripts requiring user input