# CFGMS Monitoring Examples

This directory contains example configurations for setting up comprehensive monitoring for CFGMS using various popular monitoring tools.

## Files Overview

### Core Monitoring Stack
- **`docker-compose.yml`** - Complete monitoring stack with Docker Compose
- **`prometheus.yml`** - Prometheus configuration for metrics collection
- **`cfgms_alerts.yml`** - Prometheus alerting rules for CFGMS
- **`alertmanager.yml`** - AlertManager configuration for alert routing
- **`grafana-dashboard.json`** - Grafana dashboard for CFGMS metrics
- **`grafana-datasources.yml`** - Grafana datasource configuration

### Log Management
- **`filebeat.yml`** - Filebeat configuration for log collection
- **`elasticsearch-template.json`** - Elasticsearch index template for CFGMS logs

## Quick Start

### 1. Complete Monitoring Stack

Deploy the complete monitoring stack with Docker Compose:

```bash
# Clone the repository and navigate to examples
cd docs/examples/monitoring

# Start the monitoring stack
docker-compose up -d

# Verify services are running
docker-compose ps
```

This will start:
- CFGMS Controller on `http://localhost:9080`
- Prometheus on `http://localhost:9090`
- Grafana on `http://localhost:3000` (admin/cfgms-monitoring)
- Elasticsearch on `http://localhost:9200`
- Kibana on `http://localhost:5601`
- Jaeger on `http://localhost:16686`
- AlertManager on `http://localhost:9093`

### 2. Individual Component Setup

#### Prometheus Only
```bash
# Start Prometheus with CFGMS configuration
docker run -d \
  --name cfgms-prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  -v $(pwd)/cfgms_alerts.yml:/etc/prometheus/cfgms_alerts.yml \
  prom/prometheus:latest
```

#### Grafana Only
```bash
# Start Grafana with datasource configuration
docker run -d \
  --name cfgms-grafana \
  -p 3000:3000 \
  -v $(pwd)/grafana-datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml \
  -v $(pwd)/grafana-dashboard.json:/etc/grafana/provisioning/dashboards/cfgms.json \
  grafana/grafana:latest
```

## Configuration Details

### Environment Variables

The Docker Compose setup uses these key environment variables for CFGMS:

```bash
# Telemetry configuration
CFGMS_TELEMETRY_ENABLED=true
CFGMS_TELEMETRY_SERVICE_NAME=cfgms-controller
CFGMS_TELEMETRY_OTLP_ENDPOINT=http://jaeger:14268/api/traces

# Monitoring configuration
CFGMS_MONITORING_ENABLED=true
CFGMS_MONITORING_COLLECTION_INTERVAL=30s
CFGMS_EXPORT_PROMETHEUS_ENABLED=true
CFGMS_EXPORT_ELASTICSEARCH_ENABLED=true
```

### Prometheus Configuration

The Prometheus configuration scrapes metrics from:
- CFGMS Controller API (`/api/v1/monitoring/metrics`)
- CFGMS Health endpoint (`/api/v1/monitoring/health`)

### Alert Rules

The alert rules monitor:
- High CPU/memory usage
- Controller availability
- Steward connection issues
- Configuration failures
- Certificate expiration
- Export system health

### Grafana Dashboard

The dashboard includes panels for:
- System overview (connected stewards, active configs)
- Resource usage (CPU, memory)
- Request rates and error rates
- Response time percentiles
- Export status monitoring

## Customization

### Adding Custom Metrics

To add custom application metrics:

1. Update the CFGMS controller to expose new metrics
2. Add corresponding Prometheus alert rules in `cfgms_alerts.yml`
3. Create Grafana panels in the dashboard JSON

### Modifying Alert Thresholds

Edit `cfgms_alerts.yml` to adjust alert conditions:

```yaml
- alert: CFGMSHighCPUUsage
  expr: cfgms_cpu_percent > 80  # Adjust threshold here
  for: 5m                       # Adjust duration here
```

### Configuring External Endpoints

For production deployments, update endpoints in:
- `prometheus.yml` - Update target addresses
- `docker-compose.yml` - Configure external network access
- `alertmanager.yml` - Set up proper SMTP/Slack endpoints

## Security Considerations

### Production Deployment

For production use:

1. **Enable TLS**: Configure HTTPS for all web interfaces
2. **Authentication**: Set up proper authentication for Grafana/Prometheus
3. **Network Security**: Use proper firewall rules and network segmentation
4. **Secrets Management**: Use Docker secrets or external secret management
5. **API Keys**: Generate and rotate CFGMS API keys regularly

### Sample Secure Configuration

```yaml
# Example secure Prometheus configuration
- job_name: 'cfgms-controller'
  scheme: https
  tls_config:
    ca_file: /etc/ssl/certs/ca.pem
    cert_file: /etc/ssl/certs/client.pem
    key_file: /etc/ssl/private/client.key
  basic_auth:
    username: monitoring
    password_file: /etc/prometheus/api-key
```

## Troubleshooting

### Common Issues

#### Metrics Not Appearing
```bash
# Check CFGMS controller logs
docker logs cfgms-controller

# Verify Prometheus scraping
curl http://localhost:9090/api/v1/targets

# Test CFGMS metrics endpoint
curl -H "X-API-Key: your-key" http://localhost:9080/api/v1/monitoring/metrics
```

#### Export Failures
```bash
# Check export status
curl -H "X-API-Key: your-key" http://localhost:9080/api/v1/monitoring/config

# Review export errors
curl -H "X-API-Key: your-key" \
  "http://localhost:9080/api/v1/monitoring/logs?component=monitoring&level=error"
```

#### Dashboard Not Loading
```bash
# Check Grafana logs
docker logs cfgms-grafana

# Verify datasource configuration
curl admin:cfgms-monitoring@localhost:3000/api/datasources
```

### Performance Tuning

For high-volume deployments:

1. **Adjust Collection Intervals**: Increase intervals to reduce load
2. **Configure Retention**: Set appropriate data retention periods
3. **Use Sampling**: Reduce trace sampling rates for high-traffic systems
4. **Scale Components**: Use multiple Prometheus instances for large fleets

## Integration with CI/CD

### Automated Deployment

Example GitLab CI configuration:

```yaml
deploy_monitoring:
  stage: deploy
  script:
    - docker-compose -f docs/examples/monitoring/docker-compose.yml up -d
    - ./scripts/wait-for-services.sh
    - ./scripts/import-grafana-dashboard.sh
  only:
    - main
```

### Health Checks

Monitor deployment success:

```bash
#!/bin/bash
# wait-for-services.sh
for service in prometheus grafana elasticsearch jaeger; do
  until curl -f http://localhost:${service}_port/health; do
    echo "Waiting for $service..."
    sleep 5
  done
done
```

## Related Documentation

- [CFGMS Monitoring Guide](../monitoring.md) - Complete monitoring documentation
- [REST API Reference](../api/rest-api.md) - API documentation including monitoring endpoints
- [Architecture Overview](../architecture.md) - System architecture details