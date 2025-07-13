# CFGMS Monitoring Guide

CFGMS provides comprehensive monitoring capabilities including distributed tracing, structured logging, system metrics collection, and third-party integration support. This guide covers the monitoring architecture, configuration, and usage.

## Overview

The monitoring system is built on three core components:

1. **OpenTelemetry Foundation** - Distributed tracing with correlation IDs
2. **Enhanced Logging** - JSON-structured logs with trace correlation
3. **System Monitor** - Metrics collection and third-party export

## Architecture

### OpenTelemetry Integration

CFGMS uses OpenTelemetry for distributed tracing across all components:

- **Trace Propagation**: Correlation IDs flow through gRPC calls
- **Span Management**: Automatic span creation with CFGMS-specific attributes
- **Context Correlation**: Links traces with structured logs
- **Export Support**: OTLP, Jaeger, and custom exporters

### Logging Enhancement

Structured logging with correlation tracking:

- **JSON Format**: Machine-readable log output
- **Correlation IDs**: Link related operations across services
- **Component Tagging**: Clear component identification
- **Centralized Collection**: Compatible with ELK, Fluentd, etc.

### System Monitoring

Real-time system metrics and health monitoring:

- **Resource Metrics**: CPU, memory, disk, network usage
- **Application Metrics**: Request counts, error rates, performance
- **Health Checks**: Service status and connectivity monitoring
- **Export Pipeline**: Push metrics to external systems

## Configuration

### Environment Variables

Configure monitoring through environment variables:

```bash
# Enable/disable telemetry
export CFGMS_TELEMETRY_ENABLED=true

# Service identification
export CFGMS_TELEMETRY_SERVICE_NAME="cfgms-controller"
export CFGMS_TELEMETRY_SERVICE_VERSION="v0.2.0"
export CFGMS_TELEMETRY_ENVIRONMENT="production"

# OpenTelemetry collector endpoint
export CFGMS_TELEMETRY_OTLP_ENDPOINT="http://jaeger:14268/api/traces"

# Sampling rate (0.0 to 1.0)
export CFGMS_TELEMETRY_SAMPLE_RATE="0.1"

# Monitoring configuration
export CFGMS_MONITORING_ENABLED=true
export CFGMS_MONITORING_COLLECTION_INTERVAL="30s"
export CFGMS_MONITORING_RETENTION_PERIOD="7d"
```

### Programmatic Configuration

Configure monitoring in code:

```go
// Basic telemetry setup
config := telemetry.DefaultConfig("cfgms-controller", "v0.2.0")
config.OTLPEndpoint = "http://jaeger:14268/api/traces"
config.SampleRate = 0.1

tracer, cleanup, err := telemetry.Initialize(ctx, config)
if err != nil {
    log.Fatal(err)
}
defer cleanup()

// Monitoring system setup
monitorConfig := &monitoring.Config{
    Enabled:            true,
    CollectionInterval: 30 * time.Second,
    RetentionPeriod:    7 * 24 * time.Hour,
    ExportConfig: monitoring.ExportConfig{
        Prometheus: monitoring.PrometheusConfig{
            Enabled:  true,
            Endpoint: "http://prometheus:9090/api/v1/write",
        },
        OTLP: monitoring.OTLPConfig{
            Enabled:  true,
            Endpoint: "http://jaeger:14268/api/traces",
        },
        Elasticsearch: monitoring.ElasticsearchConfig{
            Enabled:  true,
            Endpoint: "http://elasticsearch:9200",
            Index:    "cfgms-logs",
        },
    },
}

monitor, err := monitoring.NewSystemMonitor(monitorConfig)
if err != nil {
    log.Fatal(err)
}
```

## Usage

### Distributed Tracing

#### Creating Traced Operations

```go
// Start a new span
ctx, span := tracer.Start(ctx, "steward.registration")
defer span.End()

// Add attributes
span.SetAttributes(
    telemetry.AttributeString("steward.id", stewardID),
    telemetry.AttributeString("tenant.id", tenantID),
)

// Record errors
if err != nil {
    span.RecordError(err)
    span.SetStatus(telemetry.StatusError, err.Error())
}
```

#### Correlation ID Management

```go
// Generate correlation ID
correlationID := telemetry.GenerateCorrelationID()
ctx = telemetry.WithCorrelationID(ctx, correlationID)

// Extract correlation ID
correlationID := telemetry.GetCorrelationID(ctx)

// Ensure correlation ID exists
ctx = telemetry.EnsureCorrelationID(ctx)
```

### Structured Logging

```go
import "github.com/cfgis/cfgms/pkg/logging"

// Get logger with correlation
logger := logging.GetLogger()

// Log with correlation ID from context
logger.InfoCtx(ctx, "Operation completed", 
    "steward_id", stewardID,
    "duration_ms", duration.Milliseconds(),
)

// Manual correlation ID
logger.Info("Manual log entry",
    "correlation_id", correlationID,
    "component", "controller",
)
```

### Metrics Collection

```go
// Collect system metrics
metrics := monitor.CollectMetrics(ctx)

// Access specific metrics
cpuUsage := metrics.System.CPUPercent
memoryUsage := metrics.System.MemoryBytes
stewardCount := metrics.Application.StewardsConnected

// Custom metrics
monitor.RecordCustomMetric("custom.operation.count", 1)
monitor.RecordCustomMetric("custom.operation.duration", duration.Seconds())
```

## REST API Monitoring

CFGMS provides REST endpoints for monitoring data access:

### Health Status
```bash
curl -H "X-API-Key: your-key" \
  http://localhost:9080/api/v1/monitoring/health
```

### System Metrics
```bash
curl -H "X-API-Key: your-key" \
  http://localhost:9080/api/v1/monitoring/metrics
```

### Recent Logs
```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:9080/api/v1/monitoring/logs?level=error&limit=50"
```

### Trace Information
```bash
curl -H "X-API-Key: your-key" \
  "http://localhost:9080/api/v1/monitoring/traces?correlation_id=req-123"
```

## Third-Party Integration

### Prometheus Integration

Configure Prometheus to scrape CFGMS metrics:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'cfgms-controller'
    static_configs:
      - targets: ['cfgms-controller:9080']
    metrics_path: '/api/v1/monitoring/metrics'
    scrape_interval: 30s
```

### Grafana Dashboard

Example Grafana dashboard queries:

```promql
# CPU Usage
rate(cfgms_cpu_seconds_total[5m])

# Memory Usage
cfgms_memory_bytes

# Steward Connections
cfgms_stewards_connected_total

# Error Rate
rate(cfgms_errors_total[5m])
```

### ELK Stack Integration

Configure Filebeat for log collection:

```yaml
# filebeat.yml
filebeat.inputs:
- type: container
  paths:
    - '/var/lib/docker/containers/*/*.log'
  processors:
    - add_docker_metadata: ~

output.elasticsearch:
  hosts: ['elasticsearch:9200']
  index: "cfgms-logs-%{+yyyy.MM.dd}"
```

### Jaeger Tracing

Configure Jaeger for distributed tracing:

```yaml
# jaeger.yml
query:
  base-path: /jaeger
  
collector:
  otlp:
    grpc:
      endpoint: 0.0.0.0:14250
    http:
      endpoint: 0.0.0.0:14268
```

## Monitoring Best Practices

### Correlation Tracking

1. **Always use correlation IDs**: Ensure every operation has a correlation ID
2. **Propagate context**: Pass context through all function calls
3. **Link logs and traces**: Use correlation IDs to connect logs with traces

### Error Handling

1. **Record errors in spans**: Use `span.RecordError()` for proper error tracking
2. **Set span status**: Mark spans as error status when failures occur
3. **Log with context**: Include correlation IDs in error logs

### Performance Monitoring

1. **Monitor key metrics**: Track CPU, memory, and request latency
2. **Set up alerts**: Configure alerts for critical thresholds
3. **Use sampling**: Adjust sampling rates based on traffic volume

### Security Considerations

1. **Sanitize logs**: Never log sensitive information
2. **Secure endpoints**: Protect monitoring endpoints with authentication
3. **Network security**: Use TLS for external monitoring connections

## Troubleshooting

### Common Issues

#### High Memory Usage
```bash
# Check memory metrics
curl -H "X-API-Key: key" http://localhost:9080/api/v1/monitoring/metrics

# Look for memory leaks in logs
curl -H "X-API-Key: key" \
  "http://localhost:9080/api/v1/monitoring/logs?component=monitoring&level=warn"
```

#### Missing Traces
```bash
# Verify telemetry configuration
curl -H "X-API-Key: key" http://localhost:9080/api/v1/monitoring/config

# Check trace export status
curl -H "X-API-Key: key" \
  "http://localhost:9080/api/v1/monitoring/events?component=monitoring"
```

#### Export Failures
```bash
# Check exporter status
curl -H "X-API-Key: key" http://localhost:9080/api/v1/monitoring/config

# Review export errors
curl -H "X-API-Key: key" \
  "http://localhost:9080/api/v1/monitoring/logs?level=error&component=monitoring"
```

### Debug Mode

Enable debug logging for detailed monitoring information:

```bash
export CFGMS_LOG_LEVEL=debug
export CFGMS_TELEMETRY_SAMPLE_RATE=1.0
```

## Performance Impact

### Resource Usage

Monitoring has minimal performance impact:

- **CPU Overhead**: ~2-5% additional CPU usage
- **Memory Overhead**: ~10-20MB additional memory
- **Network Overhead**: Depends on export frequency and volume

### Optimization Tips

1. **Adjust sampling rates**: Use lower rates in high-traffic environments
2. **Configure retention**: Set appropriate retention periods for data
3. **Batch exports**: Use batching for external system exports
4. **Monitor exporters**: Ensure export targets can handle the load

## Related Documentation

- [REST API Documentation](api/rest-api.md) - Complete API reference
- [Architecture Overview](architecture.md) - System architecture details
- [Development Guide](development/guides/getting-started.md) - Development setup