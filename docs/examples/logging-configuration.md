# CFGMS Logging Provider Configuration Examples

This document provides configuration examples for the CFGMS global logging provider system implemented in v0.5.0.

## Overview

CFGMS now uses a pluggable logging provider architecture that supports:

- **File-based logging** (default) - Zero-dependency time-series logging with rotation
- **TimescaleDB logging** - High-performance PostgreSQL extension for time-series data
- **Future providers** - Extensible architecture for additional backends

## Configuration Structure

```yaml
controller:
  # ... other controller config ...
  
  logging:
    provider: "file"              # Provider name: "file", "timescale" (future)
    level: "INFO"                 # Log level: DEBUG, INFO, WARN, ERROR, FATAL
    service_name: "cfgms-controller"
    component: "controller"
    
    # Performance settings
    batch_size: 100               # Batch size for bulk writes
    flush_interval: "5s"          # Auto-flush interval
    async_writes: true            # Enable asynchronous writes
    buffer_size: 1000             # Internal buffer size
    
    # Multi-tenant settings
    tenant_isolation: true        # Enable tenant isolation in logs
    enable_correlation: true      # Enable correlation ID tracking
    enable_tracing: true          # Enable OpenTelemetry integration
    
    # Retention settings
    retention_days: 30            # Days to keep logs
    compress_logs: true           # Enable log compression
    
    # Provider-specific configuration
    config:
      directory: "/var/log/cfgms"
      file_prefix: "cfgms"
      max_file_size: 104857600    # 100MB
      max_files: 10
      compress_rotated: true
```

## Provider Examples

### File Provider (Default)

**Basic Configuration:**

```yaml
controller:
  logging:
    provider: "file"
    level: "INFO"
    config:
      directory: "/var/log/cfgms"
      file_prefix: "cfgms"
      max_file_size: 104857600    # 100MB
      retention_days: 30
```

**Production Configuration:**

```yaml
controller:
  logging:
    provider: "file"
    level: "WARN"                 # Production: only warnings and errors
    service_name: "cfgms-prod"
    component: "controller"
    batch_size: 500               # Larger batches for performance
    flush_interval: "10s"         # Less frequent flushing
    async_writes: true
    tenant_isolation: true
    enable_correlation: true
    config:
      directory: "/var/log/cfgms"
      file_prefix: "cfgms-prod"
      max_file_size: 536870912    # 512MB files
      max_files: 20
      retention_days: 90
      compress_rotated: true
      compression_level: 6        # Balanced compression
```

**Development Configuration:**

```yaml
controller:
  logging:
    provider: "file"
    level: "DEBUG"                # Development: all log levels
    service_name: "cfgms-dev"
    component: "controller"
    batch_size: 10                # Small batches for immediate feedback
    flush_interval: "1s"          # Frequent flushing
    async_writes: false           # Synchronous for debugging
    config:
      directory: "./logs"         # Local directory
      file_prefix: "cfgms-dev"
      max_file_size: 10485760     # 10MB files
      max_files: 5
      retention_days: 7
      compress_rotated: false     # No compression for easier reading
```

### Syslog Subscriber (Enterprise Integration)

**Event-based syslog forwarding for enterprise log aggregation systems**

```yaml
controller:
  logging:
    provider: "file"                  # Primary storage (required)
    config:
      directory: "/var/log/cfgms"
      retention_days: 30
    
    # Syslog subscriber configuration (optional)
    subscribers:
      - type: "syslog"
        enabled: true
        config:
          network: "udp"              # "udp", "tcp", "unix"
          address: "syslog.company.com:514"
          facility: "daemon"          # "daemon", "local0-7", etc.
          tag: "cfgms-controller"
          levels: ["ERROR", "WARN", "INFO"]  # Filter levels
          structured_data: true       # Include CFGMS fields as structured data
```

**Example Syslog Output (RFC5424 format):**

```
<165>1 2024-01-15T10:30:00.000Z cfgms-controller-01 cfgms 1234 controller_INFO [cfgms tenant_id="tenant-123" session_id="sess-456" request_id="req-789"] Request processed successfully
```

**Production Configuration with Multiple Subscribers:**

```yaml
controller:
  logging:
    provider: "timescale"            # High-performance primary storage
    config:
      host: "localhost"
      database: "cfgms_logs"
    
    # Multiple subscribers for different enterprise systems
    subscribers:
      # Send all logs to company SIEM
      - type: "syslog"
        enabled: true
        config:
          network: "tcp"
          address: "splunk-collector.company.com:514"
          enable_tls: true
          facility: "local0"
          tag: "cfgms-prod"
          levels: ["INFO", "WARN", "ERROR", "FATAL"]
          structured_data: true
          
      # Send critical alerts to monitoring system
      - type: "syslog"
        enabled: true
        config:
          network: "udp"
          address: "monitoring.company.com:514"
          facility: "daemon" 
          tag: "cfgms-alerts"
          levels: ["ERROR", "FATAL"]   # Only critical events
```

### TimescaleDB Provider

**High-Performance Time-Series Logging with PostgreSQL Compatibility**

```yaml
controller:
  logging:
    provider: "timescale"
    level: "INFO"
    service_name: "cfgms-enterprise"
    component: "controller"
    batch_size: 1000              # Large batches for time-series performance
    flush_interval: "30s"
    async_writes: true
    tenant_isolation: true
    config:
      host: "timescale.example.com"
      port: 5432
      database: "cfgms_logs"
      username: "cfgms_logger"
      password: "${CFGMS_LOG_DB_PASSWORD}"  # Environment variable
      ssl_mode: "require"
      table_name: "log_entries"
      schema_name: "public"
      chunk_interval: "7d"         # TimescaleDB chunk size (7 days)
      compression_after: "7d"      # Compress chunks after 7 days
      retention_after: "30d"       # Auto-delete chunks after 30 days
      batch_size: 1000
      max_connections: 20
      create_schema: true
```

**Production Configuration:**

```yaml
controller:
  logging:
    provider: "timescale"
    level: "WARN"                 # Production: warnings and errors only
    service_name: "cfgms-prod"
    component: "controller"
    batch_size: 2000              # High-performance batches
    flush_interval: "60s"         # Less frequent flushing for performance
    async_writes: true
    tenant_isolation: true
    enable_correlation: true
    config:
      host: "${CFGMS_TIMESCALEDB_HOST}"
      port: 5432
      database: "cfgms_logs_prod"
      username: "cfgms_logger"
      password: "${CFGMS_LOG_DB_PASSWORD}"
      ssl_mode: "verify-full"     # Production: strict SSL
      table_name: "log_entries"
      chunk_interval: "1d"        # Daily chunks for high volume
      compression_after: "24h"    # Aggressive compression
      retention_after: "90d"      # 90-day retention
      compression_ratio: 15       # High compression ratio
      batch_size: 2000
      max_connections: 50
      connection_timeout: "30s"
      query_timeout: "60s"
```

**Development Configuration:**

```yaml
controller:
  logging:
    provider: "timescale"
    level: "DEBUG"                # Development: all log levels
    service_name: "cfgms-dev"
    component: "controller"
    batch_size: 100               # Smaller batches for immediate feedback
    flush_interval: "5s"          # Frequent flushing
    async_writes: false           # Synchronous for debugging
    config:
      host: "localhost"
      port: 5432
      database: "cfgms_logs_dev"
      username: "cfgms_logger"
      password: "dev_password"
      ssl_mode: "disable"         # Development: no SSL
      table_name: "log_entries"
      chunk_interval: "6h"        # Smaller chunks for development
      compression_after: "1h"     # Quick compression
      retention_after: "7d"       # Short retention for development
      batch_size: 50
      max_connections: 5
      create_schema: true
```

## Environment Variables

You can override logging configuration using environment variables:

```bash
# Provider selection
export CFGMS_LOGGING_PROVIDER="file"

# Basic settings
export CFGMS_LOG_LEVEL="INFO"
export CFGMS_LOGGING_SERVICE_NAME="cfgms-prod"
export CFGMS_LOGGING_COMPONENT="controller"

# Legacy compatibility
export CFGMS_CERT_PATH="/etc/cfgms/certs"
export CFGMS_STORAGE_PROVIDER="database"
```

## Module Integration Examples

### Using ModuleLogger in Your Code

```go
package mymodule

import (
    "context"
    "github.com/cfgis/cfgms/pkg/logging"
)

type MyModule struct {
    logger *logging.ModuleLogger
}

func NewMyModule() *MyModule {
    // Create module-specific logger
    logger := logging.ForModule("mymodule").
        WithField("version", "1.0.0").
        WithField("component", "business-logic")
    
    return &MyModule{
        logger: logger,
    }
}

func (m *MyModule) ProcessRequest(ctx context.Context, tenantID string, request *Request) error {
    // Add tenant context for this operation
    logger := m.logger.WithTenant(tenantID).WithSession(request.SessionID)
    
    logger.InfoCtx(ctx, "Processing request", 
        "request_id", request.ID,
        "user_id", request.UserID,
        "operation", request.Operation,
    )
    
    if err := m.validateRequest(request); err != nil {
        logger.ErrorCtx(ctx, "Request validation failed",
            "request_id", request.ID,
            "error", err.Error(),
            "validation_rules", request.ValidationRules,
        )
        return err
    }
    
    logger.InfoCtx(ctx, "Request processed successfully",
        "request_id", request.ID,
        "processing_time", "150ms",
    )
    
    return nil
}
```

### Legacy Logger Compatibility

```go
// Existing code continues to work
logger := logging.NewLogger("info")
logger.Info("Legacy message", "key", "value")

// New code can use the global factory
moduleLogger := logging.ForComponent("legacy-service")
moduleLogger.Info("Enhanced message", "enhanced", true)
```

## Performance Characteristics

### File Provider

- **Throughput**: ~50,000 entries/second
- **Latency**: <5ms per entry
- **Storage**: ~10:1 compression ratio with GZIP
- **Memory**: <50MB for typical workloads
- **Best for**: Single-server deployments, development, edge locations

### TimescaleDB Provider

- **Throughput**: ~100,000+ entries/second with batch writes
- **Latency**: <2ms per entry (database network latency dependent)
- **Storage**: 10:1-20:1 compression ratio with native compression
- **Memory**: <100MB for typical workloads (plus database memory)
- **Query Performance**: Sub-second for time-range queries with proper indexing
- **Scalability**: Horizontal scaling with distributed TimescaleDB
- **Best for**: Enterprise deployments, high-volume logging, complex analytics

### Comparative Performance

| Feature | File Provider | TimescaleDB Provider |
|---------|--------------|---------------------|
| Setup Complexity | Low | Medium |
| Infrastructure Requirements | None | PostgreSQL + TimescaleDB |
| Query Performance | Good (file parsing) | Excellent (SQL queries) |
| Real-time Analytics | Limited | Excellent |
| Multi-tenant Queries | Good | Excellent |
| Compression | GZIP (10:1) | Native (10:1-20:1) |
| Retention Management | File rotation | Automated policies |
| High Availability | File system dependent | Database clustering |
| Backup/Recovery | File system tools | Database tools |

## Migration Guide

### From Legacy Logging

1. **Immediate**: Existing `logging.NewLogger()` calls continue to work
2. **Enhanced**: Use `logging.ForModule()` for structured module logging
3. **Configuration**: Add logging section to controller config
4. **Gradual**: Migrate modules one by one to use ModuleLogger

### Best Practices

1. **Use module loggers** for consistent context
2. **Set appropriate log levels** for production vs development  
3. **Include tenant context** for multi-tenant deployments
4. **Use structured fields** rather than string interpolation
5. **Configure retention policies** based on compliance requirements

## Troubleshooting

### Provider Not Available

```
Error: logging provider 'file' not available: cannot create log directory
```

**Solution**: Ensure the log directory exists and is writable

### High Memory Usage

```
Warning: Logging buffer growing rapidly
```  

**Solution**: Reduce batch_size or decrease flush_interval

### Performance Issues

```
Warning: Logging write latency >100ms
```

**Solution**: Enable async_writes and increase batch_size

## Monitoring and Observability

The logging system provides operational statistics via the REST API:

```bash
# Get logging statistics
curl http://localhost:8080/api/v1/system/logging/stats

# Response example
{
  "provider": "file",
  "total_entries": 15420,
  "entries_last_hour": 234,
  "storage_size_bytes": 5242880,
  "write_latency_ms": 2.3,
  "error_rate": 0.001,
  "disk_usage_percent": 15.2
}
```
