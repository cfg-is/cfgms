# Integrating CFGMS Logging

Use the central logging provider for components and resource modules. This guide
owns integration and structured-field rules; [pkg/logging](../../pkg/logging/README.md)
owns sanitization/redaction helpers and subscriber details, and the
[configuration examples](../examples/logging-configuration.md) own deployment payloads.

## Initialize at the service boundary

Applications select/register their logging provider and initialize it once;
resource operations use the resulting logger rather than invent another provider.
The actual module import path is `github.com/cfgis/cfgms`.

```go
import (
    "github.com/cfgis/cfgms/pkg/logging"
    _ "github.com/cfgis/cfgms/pkg/logging/providers/file"
)

func initializeLogging() error {
    cfg := logging.DefaultLoggingConfig("controller", "main")
    cfg.Config = map[string]interface{}{"directory": "/var/log/cfgms"}
    if err := logging.InitializeGlobalLogging(cfg); err != nil {
        return err
    }
    logging.InitializeGlobalLoggerFactory("controller", "main")
    return nil
}
```

Use the application's configured paths and handle initialization/flush/close
errors at its lifecycle boundary. Reinitialization closes the previous manager;
it is not an operation to perform for each request. See
[`LoggingManager`](../../pkg/logging/manager.go) for batching, flush and close behavior.

## Context and structured fields

Use `logging.ForComponent` or `logging.ForModule` and context-aware methods:

```go
logger := logging.ForModule("file")
logger.InfoCtx(ctx, "Applying configuration",
    "operation", "file_set",
    "resource_id", logging.SanitizeLogValue(resourceID))
if err != nil {
    logger.ErrorCtx(ctx, "Configuration failed",
        "operation", "file_set",
        "resource_id", logging.SanitizeLogValue(resourceID),
        "error_code", "FILE_SET_FAILED",
        "error", logging.SanitizeLogValue(err.Error()))
}
```

- Include a stable `operation` and, when applicable, `resource_id`.
- Error/fatal records need an actionable `error_code` and sanitized error detail.
- Significant completion records should identify the outcome and measured duration
  when available. Debug fields must not become an alternate route for secrets.
- Preserve authenticated tenant/session/correlation context. Use the existing
  helpers in [context_keys.go](../../pkg/logging/context_keys.go) and
  [injection.go](../../pkg/logging/injection.go), not new string context keys.
- Sanitize request-derived values **and errors**, including wrapped errors from
  stores/transports. A sanitized ID beside a raw error does not make that error safe.
- Never log passwords, private keys, bearer credentials or resolved script secrets.
  Use `RedactedID` for opaque identifiers under its documented contract; the
  development-only unredacted gate is not a production default.

Tenant tagging is **not authorization**. `ExtractTenantFromContext` and
`WithTenant` help attribute logs; an empty logging tenant never grants unrestricted
access. Authorization must use the relevant security context and fail closed.

## In-process module injection

[`modules.LoggingInjectable`](../../features/modules/logging_injection.go) defines
`SetLogger(logging.Logger) error` and `GetLogger() (logging.Logger, bool)`.
`DefaultLoggingSupport` supplies these methods and `GetEffectiveLogger(fallback)`
for modules that embed it. It does not itself implement Module.Get/Set.

The [steward factory](../../features/steward/factory/factory.go) attempts injection
for compatible in-process instances. Use a fallback when an instance is
constructed independently. The default helper stores its logger without an
internal synchronization lock: inject before concurrent operations, or provide
appropriate synchronization if implementing runtime replacement.

This Go interface does not cross an out-of-process module socket. An external
module follows the [module wire/process contract](../architecture/modules/interface.md);
do not infer that its process shares the host's logger pointer or global state.

## Validate an integration

Use real logging providers/capturing helpers in tests. Check operation and tenant
attribution, redaction/control-character handling, injected and fallback paths,
and initialization/write/flush failures relevant to the caller. Existing tests
beside `pkg/logging` and the module factory establish their bounded contracts;
provider availability or a tenant field alone is not proof of authorization.

For local Unix service visibility and Windows Event Log behavior, use the
[systemlog subscriber reference](../../pkg/logging/README.md#local-system-log-subscriber-systemlog).
Do not confuse it with the remote-network `syslog` subscriber.
