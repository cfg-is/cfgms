# ADR-005: Logging Interface for Transport Providers

**Status:** Accepted  
**Date:** 2026-05-04  
**Issue:** #1154  
**Epic:** #726 — adopt pkg/logging consistently

---

## Context

`pkg/controlplane` and `pkg/dataplane` are the two gRPC-over-QUIC transport providers
that form the backbone of controller-steward communication. Both providers contain a
`*slog.Logger` field that is assigned directly (e.g., `slog.Default()`) at construction
time rather than being injected through the established CFGMS central provider system.

Concretely:

- `pkg/controlplane/providers/grpc/provider.go:78` — `logger *slog.Logger`
- `pkg/dataplane/providers/grpc/provider.go:80` — `logger *slog.Logger`

This violates two rules from [ADR-001](001-central-provider-compliance-enforcement.md):

1. **Central provider rule**: `pkg/logging` is the designated logging central provider.
   Any component that needs structured logging must use `logging.Logger`, not a raw
   `*slog.Logger`.
2. **Pluggable by default rule**: Central providers are pluggable so that different
   backends (file, TimescaleDB, etc.) can be wired at startup. A hard-coded `*slog.Logger`
   dependency pins the transport layer to a specific implementation, bypassing the
   provider registry entirely.

The practical consequences of the current state are:

- Transport provider log output is invisible to the `pkg/logging` routing layer (tenant
  isolation, correlation ID injection, provider-specific sinks).
- Log level, format, and destination are controlled by the global `slog` default rather
  than by the operator-configured `pkg/logging` setup.
- The `make check-architecture` enforcement target cannot flag `*slog.Logger` usage in
  transport code because the import (`log/slog`) is not yet in its deny list — meaning
  the violation is silent.

### What logging.Logger provides over *slog.Logger

| Capability | `*slog.Logger` | `logging.Logger` |
|---|---|---|
| Structured key-value logging | Yes | Yes |
| Context-aware correlation IDs | No | Yes (`*Ctx` variants) |
| Tenant-isolated log routing | No | Yes (via provider registry) |
| Pluggable backends (file / TSDB) | No | Yes |
| `make check-architecture` compliance | No | Yes |
| `pkg/logging.NoopLogger` for tests | No | Yes (zero deps) |

---

## Decision

`pkg/controlplane` and `pkg/dataplane` **must** accept a `logging.Logger` injected via
their `Configure()` method, replacing the `*slog.Logger` field.

### Interface

The target interface is `logging.Logger` from `pkg/logging/logger.go`:

```go
type Logger interface {
    Debug(msg string, keysAndValues ...interface{})
    Info(msg string, keysAndValues ...interface{})
    Warn(msg string, keysAndValues ...interface{})
    Error(msg string, keysAndValues ...interface{})
    Fatal(msg string, keysAndValues ...interface{})

    DebugCtx(ctx context.Context, msg string, keysAndValues ...interface{})
    InfoCtx(ctx context.Context, msg string, keysAndValues ...interface{})
    WarnCtx(ctx context.Context, msg string, keysAndValues ...interface{})
    ErrorCtx(ctx context.Context, msg string, keysAndValues ...interface{})
    FatalCtx(ctx context.Context, msg string, keysAndValues ...interface{})
}
```

### Injection mechanism

Callers pass `"logger"` as a key in the `Configure(config map[string]interface{})` call:

```go
err := provider.Configure(map[string]interface{}{
    "logger": myLoggingLogger,  // logging.Logger
    // ... other keys
})
```

The provider asserts the value to `logging.Logger`; if absent or wrong type it falls back
to `logging.NewNoopLogger()` rather than panicking.

### No slog bridge

No adapter between `*slog.Logger` and `logging.Logger` is needed. The codebase is
pre-production and the transport providers have no public stable API contract that
external consumers depend on. A hard breaking change (remove `*slog.Logger`, add
`logging.Logger`) is the correct approach. Migration shims add permanent dead weight and
mask the underlying violation.

### Scope

This ADR covers only:

- `pkg/controlplane/providers/grpc/provider.go` (Story #1155)
- `pkg/dataplane/providers/grpc/provider.go` (Story #1156)

It does **not** require changes to any other package, and does not change the
`pkg/logging` implementation.

### Accepted bootstrap exception

`pkg/logging/interfaces/provider.go` contains four `fmt.Printf` calls at lines 363, 372,
377, and 403 that emit registration-time diagnostics directly to stdout. These are an
**accepted exception** for the entire epic and must not be removed:

> The logging registry cannot route its own registration prints through the system it is
> initialising. Replacing them with `logging.Logger` would create a circular
> initialisation dependency. They are intentionally retained as-is.

No other `fmt.Printf` / `log.Printf` / `slog` bypass in transport code qualifies for
this exception.

---

## Consequences

### Positive

1. Transport provider logs are routed through `pkg/logging` and gain tenant isolation,
   correlation ID injection, and configurable backends at zero call-site cost.
2. Tests can inject `logging.NewNoopLogger()` instead of a real logger, removing the
   implicit dependency on the global slog default.
3. `make check-architecture` can be extended to deny `log/slog` imports in transport
   code, giving automated enforcement of this decision.
4. Consistency: every CFGMS component that uses structured logging will speak the same
   interface, reducing the number of logging patterns developers must understand.

### Negative

1. **Breaking change**: Any caller that constructs a transport provider and passes a
   `*slog.Logger` in `Configure()` must be updated. Because the codebase is
   pre-production this is acceptable.
2. **Minor boilerplate**: Providers must add a type-assertion and a nil-guard for the
   injected logger in `Configure()`.

### Neutral

- `logging.Logger` method signatures differ from `*slog.Logger` (no `With()`, no
  `Handler()`). Transport providers that use `With()` for sub-loggers must be rewritten
  to pass structured fields directly to the log call. This is a desirable simplification,
  not a loss.

---

## Alternatives Considered

### Keep *slog.Logger, wrap it at call sites

Wrap every `slog.Logger` call in a small adapter that implements `logging.Logger`. This
satisfies the interface rule without changing provider internals.

**Rejected:** An adapter is a permanent indirection layer that exists only to paper over
the architectural violation. It hides the `*slog.Logger` dependency behind a thin shim
and prevents `make check-architecture` from detecting it.

### Extend logging.Logger to embed *slog.Logger

Add an `Unwrap() *slog.Logger` method to the interface so providers could extract the
underlying slog handler.

**Rejected:** Leaks the `slog` implementation detail into the central provider interface.
Defeats the purpose of the abstraction and blocks future backends that are not
`slog`-based.

### Defer to a later refactor

Accept the current state and log a TODO to clean it up after the codebase stabilises.

**Rejected:** The longer the `*slog.Logger` field lives in the transport providers, the
more callers hard-code against it and the more expensive the change becomes. Addressing
it now (Stories #1155 and #1156) costs one PR per provider.

---

## References

- [ADR-001](001-central-provider-compliance-enforcement.md) — Central Provider Compliance Enforcement
- Epic #726 — adopt pkg/logging consistently — remove fmt.Printf / log.Printf / slog bypass
- Story #1155 — controlplane: adopt logging.Logger in grpc provider
- Story #1156 — dataplane: adopt logging.Logger in grpc provider
- `pkg/logging/logger.go` — `logging.Logger` interface definition
- `pkg/logging/interfaces/provider.go` — bootstrap exception (lines 363, 372, 377, 403)
