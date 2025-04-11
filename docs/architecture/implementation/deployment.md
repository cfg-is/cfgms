# Deployment

This document describes the deployment options and considerations for CFGMS, explaining the various deployment models and best practices.

## Deployment Models

CFGMS supports several deployment models:

### Single Controller

The simplest deployment model with a single Controller:

```txt
[Controller] --- [Steward 1]
            |-- [Steward 2]
            |-- [Steward 3]
            `-- [Steward N]
```

Suitable for:

- Small to medium deployments
- Single organization
- Up to 10,000 Stewards

### Hierarchical Controllers

A hierarchical deployment model with multiple Controllers:

```txt
[Root Controller] --- [Controller 1] --- [Steward 1.1]
                 |                   `-- [Steward 1.N]
                 |
                 `-- [Controller 2] --- [Steward 2.1]
                                   `-- [Steward 2.N]
```

Suitable for:

- Large deployments
- Multiple organizations
- Geographic distribution
- More than 10,000 Stewards

### Outpost-based

A deployment model using Outposts for proxy and caching:

```txt
[Controller] --- [Outpost 1] --- [Steward 1.1]
            |                `-- [Steward 1.N]
            |
            `-- [Outpost 2] --- [Steward 2.1]
                            `-- [Steward 2.N]
```

Suitable for:

- Network segmentation
- Bandwidth optimization
- Edge computing
- IoT deployments

## Deployment Requirements

### Controller Requirements

Minimum requirements for a Controller:

```yaml
resources:
  cpu: 2 cores
  memory: 2GB
  disk: 20GB

network:
  ports:
    - 8080: HTTP API
    - 8443: HTTPS API
    - 9090: gRPC
    - 9443: gRPC (TLS)

dependencies:
  - git
  - leveldb
```

### Steward Requirements

Minimum requirements for a Steward:

```yaml
resources:
  cpu: 1 core
  memory: 100MB
  disk: 1GB

network:
  # No open ports required
  # All connections are initiated by the Steward
  outbound_connections:
    - 9443: gRPC (TLS) to Controller/Outpost

dependencies:
  none
```

### Outpost Requirements

Minimum requirements for an Outpost:

```yaml
resources:
  cpu: 1 core
  memory: 200MB
  disk: 5GB

network:
  ports:
    - 9090: gRPC
    - 9443: gRPC (TLS)
    - 8080: HTTP Cache
    - 8443: HTTPS Cache

dependencies:
  none
```

## Deployment Configuration

### Controller Configuration

```yaml
controller:
  # Server configuration
  server:
    host: 0.0.0.0
    api_port: 8443
    grpc_port: 9443
    metrics_port: 9090

  # Storage configuration
  storage:
    type: git
    path: /var/lib/cfgms/config
    backup_path: /var/lib/cfgms/backup

  # Security configuration
  security:
    cert_file: /etc/cfgms/certs/server.crt
    key_file: /etc/cfgms/certs/server.key
    ca_file: /etc/cfgms/certs/ca.crt

  # Logging configuration
  logging:
    level: info
    format: json
    output: /var/log/cfgms/controller.log

  # Metrics configuration
  metrics:
    enabled: true
    prometheus: true
```

### Steward Configuration

```yaml
steward:
  # No listening ports required
  # All connections are initiated by the Steward
  
  # Controller configuration
  controller:
    host: controller.cfgms.local
    port: 9443
    ca_file: /etc/cfgms/certs/ca.crt
    # Connection settings
    connection:
      # Maintain persistent connection for instant command processing
      persistent: true
      # How often to attempt reconnection if connection is lost
      retry_interval: 30s
      # Maximum backoff time between retries
      max_backoff: 5m
      # Heartbeat interval to keep connection alive
      heartbeat_interval: 30s
      # Connection timeout
      timeout: 10s

  # Security configuration
  security:
    cert_file: /etc/cfgms/certs/steward.crt
    key_file: /etc/cfgms/certs/steward.key

  # Logging configuration
  logging:
    level: info
    format: json
    output: /var/log/cfgms/steward.log

  # Metrics configuration
  metrics:
    enabled: true
    prometheus: true
```

### Outpost Configuration

```yaml
outpost:
  # Server configuration
  server:
    host: 0.0.0.0
    grpc_port: 9443
    cache_port: 8443

  # Controller configuration
  controller:
    host: controller.cfgms.local
    port: 9443
    ca_file: /etc/cfgms/certs/ca.crt

  # Cache configuration
  cache:
    path: /var/lib/cfgms/cache
    max_size: 10GB
    ttl: 1h

  # Security configuration
  security:
    cert_file: /etc/cfgms/certs/outpost.crt
    key_file: /etc/cfgms/certs/outpost.key

  # Logging configuration
  logging:
    level: info
    format: json
    output: /var/log/cfgms/outpost.log

  # Metrics configuration
  metrics:
    enabled: true
    prometheus: true
```

## Deployment Process

### Initial Deployment

1. **Prepare Infrastructure**

   ```bash
   # Create directories
   mkdir -p /etc/cfgms/certs
   mkdir -p /var/lib/cfgms/{config,backup,cache}
   mkdir -p /var/log/cfgms
   ```

2. **Generate Certificates**

   ```bash
   # Generate CA
   cfgms cert create-ca \
     --common-name "CFGMS CA" \
     --out-cert /etc/cfgms/certs/ca.crt \
     --out-key /etc/cfgms/certs/ca.key

   # Generate Controller certificate
   cfgms cert create \
     --ca-cert /etc/cfgms/certs/ca.crt \
     --ca-key /etc/cfgms/certs/ca.key \
     --common-name "controller.cfgms.local" \
     --out-cert /etc/cfgms/certs/server.crt \
     --out-key /etc/cfgms/certs/server.key
   ```

3. **Deploy Controller**

   ```bash
   # Install Controller
   cfgms controller install \
     --config /etc/cfgms/controller.yaml

   # Start Controller
   systemctl start cfgms-controller
   ```

4. **Deploy Stewards**

   ```bash
   # Install Steward
   cfgms steward install \
     --config /etc/cfgms/steward.yaml \
     --controller controller.cfgms.local:9443

   # Start Steward
   systemctl start cfgms-steward
   ```

### Upgrades

1. **Controller Upgrade**

   ```bash
   # Stop Controller
   systemctl stop cfgms-controller

   # Backup data
   cp -r /var/lib/cfgms/config /var/lib/cfgms/backup/

   # Upgrade Controller
   cfgms controller upgrade

   # Start Controller
   systemctl start cfgms-controller
   ```

2. **Steward Upgrade**

   ```bash
   # Upgrade Steward
   cfgms steward upgrade \
     --controller controller.cfgms.local:9443

   # Restart Steward
   systemctl restart cfgms-steward
   ```

## Deployment Best Practices

1. **Security**
   - Use TLS for all communications
   - Rotate certificates regularly
   - Follow principle of least privilege
   - Implement proper access controls
   - Ensure Stewards initiate all connections (no open ports)

2. **High Availability**
   - Deploy multiple Controllers
   - Use load balancers
   - Implement proper failover
   - Monitor system health

3. **Backup and Recovery**
   - Regular backups of configuration
   - Test recovery procedures
   - Document recovery process
   - Monitor backup status

4. **Monitoring**
   - Monitor system metrics
   - Set up alerts
   - Track performance
   - Log important events

5. **Documentation**
   - Document deployment process
   - Maintain configuration files
   - Track changes
   - Document troubleshooting steps

## Version Information

- **Version**: 1.0
- **Last Updated**: 2024-04-07
- **Status**: Draft
