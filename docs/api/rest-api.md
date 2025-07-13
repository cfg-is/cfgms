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