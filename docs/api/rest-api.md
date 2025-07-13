# CFGMS REST API Documentation

The CFGMS controller provides a REST API for external system integration and management operations. The API runs alongside the gRPC services and provides HTTP endpoints for common operations.

## Base URL

By default, the REST API runs on port 9080:
```
http://localhost:9080/api/v1
```

## Authentication

All API endpoints (except `/health`) require authentication via API key. API keys can be provided in two ways:

### X-API-Key Header
```bash
curl -H "X-API-Key: your-api-key" http://localhost:9080/api/v1/stewards
```

### Authorization Bearer Token
```bash
curl -H "Authorization: Bearer your-api-key" http://localhost:9080/api/v1/stewards
```

## Response Format

All API responses follow a standard format:

### Success Response
```json
{
  "data": { ... },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Error Response
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": "Optional additional details"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

## Endpoints

### Health Check

#### GET /api/v1/health
Check the health status of the CFGMS controller.

**Authentication:** None required

**Response:**
```json
{
  "data": {
    "status": "healthy",
    "version": "0.2.0",
    "timestamp": "2025-01-12T10:30:00Z",
    "services": {
      "controller": "healthy",
      "configuration": "healthy",
      "rbac": "healthy",
      "certificate_manager": "healthy",
      "tenant_manager": "healthy",
      "rbac_manager": "healthy"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Steward Management

#### GET /api/v1/stewards
List all registered stewards.

**Authentication:** Required

**Response:**
```json
{
  "data": [
    {
      "id": "steward-001",
      "status": "connected",
      "last_seen": "2025-01-12T10:29:30Z",
      "version": "0.2.0",
      "metrics": {
        "cpu_usage": "45%",
        "memory_usage": "512MB"
      },
      "dna": {
        "hostname": "server-001",
        "os": "linux",
        "architecture": "x86_64",
        "attributes": {
          "hostname": "server-001",
          "os": "linux",
          "architecture": "x86_64",
          "kernel_version": "5.4.0"
        },
        "collected_at": "2025-01-12T10:25:00Z"
      }
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/stewards/{id}
Get information about a specific steward.

**Authentication:** Required

**Parameters:**
- `id` (path): Steward ID

**Response:**
```json
{
  "data": {
    "id": "steward-001",
    "status": "connected",
    "last_seen": "2025-01-12T10:29:30Z",
    "version": "0.2.0",
    "metrics": {
      "cpu_usage": "45%",
      "memory_usage": "512MB"
    },
    "dna": {
      "hostname": "server-001",
      "os": "linux",
      "architecture": "x86_64",
      "attributes": {
        "hostname": "server-001",
        "os": "linux",
        "architecture": "x86_64"
      },
      "collected_at": "2025-01-12T10:25:00Z"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/stewards/{id}/dna
Get DNA information for a specific steward.

**Authentication:** Required

**Parameters:**
- `id` (path): Steward ID

**Response:**
```json
{
  "data": {
    "hostname": "server-001",
    "os": "linux",
    "architecture": "x86_64",
    "attributes": {
      "hostname": "server-001",
      "os": "linux",
      "architecture": "x86_64",
      "kernel_version": "5.4.0",
      "memory_total": "8GB"
    },
    "collected_at": "2025-01-12T10:25:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Configuration Management

#### GET /api/v1/stewards/{id}/config
Get configuration for a specific steward.

**Authentication:** Required

**Parameters:**
- `id` (path): Steward ID
- `modules` (query, optional): Comma-separated list of module names to filter

**Response:**
```json
{
  "data": {
    "steward_id": "steward-001",
    "version": "1.0.0",
    "config": {
      "directory": {
        "/etc/app": {
          "owner": "app",
          "group": "app",
          "mode": "755"
        }
      },
      "file": {
        "/etc/app/config.yml": {
          "content": "key: value",
          "owner": "app",
          "group": "app",
          "mode": "644"
        }
      }
    },
    "updated_at": "2025-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/stewards/{id}/config/validate
Validate configuration for a steward.

**Authentication:** Required

**Parameters:**
- `id` (path): Steward ID

**Request Body:**
```json
{
  "config": {
    "directory": {
      "/etc/app": {
        "owner": "app",
        "group": "app",
        "mode": "755"
      }
    }
  },
  "version": "1.0.0"
}
```

**Response:**
```json
{
  "data": {
    "valid": true,
    "errors": [],
    "metadata": {
      "validation_time": "50ms",
      "modules_validated": "2"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### Certificate Management

#### GET /api/v1/certificates
List certificates.

**Authentication:** Required

**Parameters:**
- `steward_id` (query, optional): Filter certificates by steward ID

**Response:**
```json
{
  "data": [
    {
      "serial_number": "123456789",
      "common_name": "steward-001",
      "steward_id": "steward-001",
      "is_valid": true,
      "expires_at": "2026-01-12T10:30:00Z",
      "days_until_expiration": 365,
      "needs_renewal": false
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/certificates/provision
Provision a new certificate for a steward.

**Authentication:** Required

**Request Body:**
```json
{
  "steward_id": "steward-001",
  "common_name": "steward-001.example.com",
  "organization": "Example Org",
  "validity_days": 365
}
```

**Response:**
```json
{
  "data": {
    "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...",
    "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
    "serial_number": "123456789",
    "expires_at": "2026-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### RBAC Management

#### GET /api/v1/rbac/permissions
List available permissions.

**Authentication:** Required

**Parameters:**
- `resource_type` (query, optional): Filter permissions by resource type

**Response:**
```json
{
  "data": [
    {
      "id": "steward.register",
      "name": "Register Steward",
      "description": "Allow steward registration",
      "resource_type": "steward",
      "actions": ["create", "read"]
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/rbac/roles
List roles.

**Authentication:** Required

**Parameters:**
- `tenant_id` (query, optional): Filter roles by tenant ID

**Response:**
```json
{
  "data": [
    {
      "id": "admin",
      "name": "Administrator",
      "description": "Full administrative access",
      "permissions": ["steward.register", "config.manage"],
      "tenant_id": "default",
      "created_at": "2025-01-01T00:00:00Z",
      "updated_at": "2025-01-01T00:00:00Z"
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/rbac/roles
Create a new role.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Config Manager",
  "description": "Manage configurations",
  "permissions": ["config.read", "config.write"],
  "tenant_id": "default"
}
```

**Response:**
```json
{
  "data": {
    "id": "config-manager",
    "name": "Config Manager",
    "description": "Manage configurations",
    "permissions": ["config.read", "config.write"],
    "tenant_id": "default",
    "created_at": "2025-01-12T10:30:00Z",
    "updated_at": "2025-01-12T10:30:00Z"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

### API Key Management

#### GET /api/v1/api-keys
List API keys.

**Authentication:** Required

**Response:**
```json
{
  "data": [
    {
      "id": "key-001",
      "name": "Default Admin Key",
      "permissions": ["stewards:read", "stewards:write"],
      "created_at": "2025-01-12T10:00:00Z",
      "expires_at": null,
      "tenant_id": "default"
    }
  ],
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### POST /api/v1/api-keys
Create a new API key.

**Authentication:** Required

**Request Body:**
```json
{
  "name": "Monitoring Key",
  "permissions": ["stewards:read", "health:read"],
  "expires_at": "2026-01-12T10:30:00Z",
  "tenant_id": "default"
}
```

**Response:**
```json
{
  "data": {
    "id": "key-002",
    "name": "Monitoring Key",
    "permissions": ["stewards:read", "health:read"],
    "created_at": "2025-01-12T10:30:00Z",
    "expires_at": "2026-01-12T10:30:00Z",
    "tenant_id": "default",
    "key": "base64-encoded-api-key-here"
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

**Note:** The actual API key is only returned upon creation. Store it securely as it cannot be retrieved later.

### Monitoring

CFGMS provides comprehensive monitoring capabilities through dedicated endpoints. These endpoints enable integration with external monitoring systems like Prometheus, Grafana, ELK stack, and others.

#### GET /api/v1/monitoring/health
System health overview including service status and resource utilization.

**Authentication:** Required

**Response:**
```json
{
  "data": {
    "status": "healthy",
    "timestamp": "2025-01-12T10:30:00Z",
    "services": {
      "controller": "healthy",
      "configuration_service": "healthy",
      "monitoring_service": "healthy"
    },
    "resource_usage": {
      "cpu_percent": 25.5,
      "memory_bytes": 134217728,
      "goroutines": 156
    },
    "uptime_seconds": 86400
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/metrics
System performance metrics in a format suitable for time-series databases.

**Authentication:** Required

**Response:**
```json
{
  "data": {
    "timestamp": "2025-01-12T10:30:00Z",
    "system": {
      "cpu_percent": 25.5,
      "memory_bytes": 134217728,
      "disk_usage_bytes": 1073741824,
      "network_bytes_received": 524288000,
      "network_bytes_sent": 262144000,
      "goroutines": 156,
      "gc_cycles": 42,
      "heap_objects": 125000
    },
    "application": {
      "stewards_connected": 45,
      "configurations_served": 150,
      "api_requests_total": 1250,
      "grpc_requests_total": 3500,
      "errors_total": 5
    },
    "export_status": {
      "prometheus": "active",
      "otlp": "disabled",
      "elasticsearch": "error"
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/resources
Resource utilization metrics for stewards and system components.

**Authentication:** Required

**Parameters:**
- `steward_id` (query, optional): Filter metrics by specific steward
- `since` (query, optional): RFC3339 timestamp to filter metrics since

**Response:**
```json
{
  "data": {
    "timestamp": "2025-01-12T10:30:00Z",
    "controller": {
      "cpu_percent": 25.5,
      "memory_bytes": 134217728,
      "connections": 45
    },
    "stewards": [
      {
        "id": "steward-001",
        "cpu_percent": 15.2,
        "memory_bytes": 67108864,
        "disk_usage_bytes": 536870912,
        "last_updated": "2025-01-12T10:29:30Z"
      }
    ],
    "aggregated": {
      "total_stewards": 45,
      "avg_cpu_percent": 18.7,
      "total_memory_bytes": 3019898880
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/logs
Recent system logs with filtering and correlation capabilities.

**Authentication:** Required

**Parameters:**
- `level` (query, optional): Filter by log level (debug, info, warn, error)
- `component` (query, optional): Filter by component (controller, steward, monitoring)
- `correlation_id` (query, optional): Filter by correlation ID
- `limit` (query, optional): Maximum number of logs to return (default: 100, max: 1000)
- `since` (query, optional): RFC3339 timestamp to filter logs since

**Response:**
```json
{
  "data": {
    "logs": [
      {
        "timestamp": "2025-01-12T10:29:45Z",
        "level": "info",
        "component": "controller",
        "message": "Steward registered successfully",
        "correlation_id": "req-123e4567-e89b-12d3-a456-426614174000",
        "metadata": {
          "steward_id": "steward-001",
          "operation": "steward.register"
        }
      }
    ],
    "total_count": 1,
    "has_more": false
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/traces
Distributed tracing information for request correlation and debugging.

**Authentication:** Required

**Parameters:**
- `correlation_id` (query, optional): Filter by correlation ID
- `operation` (query, optional): Filter by operation name
- `limit` (query, optional): Maximum number of traces to return (default: 50, max: 500)
- `since` (query, optional): RFC3339 timestamp to filter traces since

**Response:**
```json
{
  "data": {
    "traces": [
      {
        "trace_id": "550e8400e29b41d4a716446655440000",
        "correlation_id": "req-123e4567-e89b-12d3-a456-426614174000",
        "operation": "steward.register",
        "start_time": "2025-01-12T10:29:45.123456Z",
        "duration_ms": 150.5,
        "status": "ok",
        "spans": [
          {
            "span_id": "7a085853722dc6c2",
            "operation": "validate_certificate",
            "start_time": "2025-01-12T10:29:45.125000Z",
            "duration_ms": 45.2,
            "status": "ok"
          }
        ],
        "metadata": {
          "steward_id": "steward-001",
          "component": "controller"
        }
      }
    ],
    "total_count": 1,
    "has_more": false
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/events
System events and alerts for operational awareness.

**Authentication:** Required

**Parameters:**
- `severity` (query, optional): Filter by severity (info, warning, error, critical)
- `component` (query, optional): Filter by component
- `limit` (query, optional): Maximum number of events to return (default: 100, max: 1000)
- `since` (query, optional): RFC3339 timestamp to filter events since

**Response:**
```json
{
  "data": {
    "events": [
      {
        "id": "evt-550e8400-e29b-41d4-a716-446655440001",
        "timestamp": "2025-01-12T10:29:45Z",
        "severity": "warning",
        "component": "monitoring",
        "event_type": "export_failure",
        "message": "Failed to export metrics to Elasticsearch",
        "metadata": {
          "exporter": "elasticsearch",
          "error": "connection timeout",
          "retry_count": 3
        }
      }
    ],
    "total_count": 1,
    "has_more": false
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

#### GET /api/v1/monitoring/config
Current monitoring system configuration and export status.

**Authentication:** Required

**Response:**
```json
{
  "data": {
    "enabled": true,
    "collection_interval": "30s",
    "retention_period": "7d",
    "exporters": {
      "prometheus": {
        "enabled": true,
        "endpoint": "http://prometheus:9090/api/v1/write",
        "status": "active",
        "last_export": "2025-01-12T10:29:30Z",
        "export_count": 1250,
        "error_count": 0
      },
      "otlp": {
        "enabled": false,
        "endpoint": "http://jaeger:14268/api/traces"
      },
      "elasticsearch": {
        "enabled": true,
        "endpoint": "http://elasticsearch:9200",
        "status": "error",
        "last_export": "2025-01-12T10:25:15Z",
        "export_count": 500,
        "error_count": 15,
        "last_error": "connection timeout"
      }
    },
    "telemetry": {
      "enabled": true,
      "service_name": "cfgms-controller",
      "sample_rate": 1.0,
      "correlation_tracking": true
    }
  },
  "timestamp": "2025-01-12T10:30:00Z"
}
```

## Error Codes

| Code | Description |
|------|-------------|
| `MISSING_API_KEY` | API key not provided |
| `INVALID_API_KEY` | API key is invalid |
| `EXPIRED_API_KEY` | API key has expired |
| `MISSING_STEWARD_ID` | Steward ID parameter is required |
| `STEWARD_NOT_FOUND` | Steward with given ID not found |
| `INVALID_JSON` | Request body contains invalid JSON |
| `SERVICE_UNAVAILABLE` | Required service is not available |
| `INTERNAL_ERROR` | Internal server error |
| `NOT_IMPLEMENTED` | Feature not yet implemented |

## Getting Started

1. **Start the controller:**
   ```bash
   ./bin/controller
   ```

2. **Check health:**
   ```bash
   curl http://localhost:9080/api/v1/health
   ```

3. **Get the default API key from the controller logs:**
   Look for a log message like:
   ```
   Generated default API key id=xxx key=yyy
   ```

4. **List stewards:**
   ```bash
   curl -H "X-API-Key: your-api-key" http://localhost:9080/api/v1/stewards
   ```

## Configuration

The REST API server can be configured via environment variables:

- `CFGMS_HTTP_LISTEN_ADDR`: HTTP listen address (default: `127.0.0.1:9080`)

## Security Considerations

- Always use HTTPS in production
- Rotate API keys regularly
- Use least-privilege permissions for API keys
- Monitor API access logs
- Consider rate limiting for production deployments