# Logging Configuration Examples

These are `logging.LoggingConfig` payloads consumed at the application wiring
boundary, not a complete controller or steward boot document. Check the
[boot config schema](../reference/config-schema.md) before choosing an enclosing
key; do not wrap them in a fabricated `controller.logging` hierarchy.

## File provider

```yaml
provider: file
level: INFO
service_name: cfgms-controller
component: main
batch_size: 100
flush_interval: 5s
async_writes: true
buffer_size: 1000
tenant_isolation: true
enable_correlation: true
config:
  directory: /var/log/cfgms
  file_prefix: cfgms
  max_file_size: 104857600
  max_files: 10
  retention_days: 30
  compress_rotated: true
```

The file provider must be registered by the application, and the directory must
be writable by its service identity. File retention/compression keys are
provider-specific; a field in the manager config is not a promise that every
provider implements it. Defaults and accepted settings are defined in
[FileConfig](../../pkg/logging/providers/file/plugin.go).

## Local system log subscriber

Add to the logging payload when the service wires configured subscribers:

```yaml
subscribers:
  - type: systemlog
    enabled: true
    config:
      tag: cfgms-steward
      collapse_window: 1h
      levels: [WARN, ERROR, FATAL]
```

This targets the local system log/Event Log. A remote `syslog` subscriber is a
different type. See the [subscriber reference](../../pkg/logging/README.md#local-system-log-subscriber-systemlog)
for platform behavior, failure handling and secret-safe messages.

For Timescale configuration, use the actual
[provider configuration/validation](../../pkg/logging/providers/timescale/plugin.go)
and provision its database separately. Do not copy the old examples' credentials
or treat their throughput numbers as measured capacity.

[Logging integration](../development/logging-architecture-guide.md) owns logger
initialization, context, sanitization and module injection. Changes to deployment
wiring must verify the enclosing schema and provider before being presented as
runnable boot configuration.
