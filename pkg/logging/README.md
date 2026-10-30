# pkg/logging

Structured logging package for CFGMS. Provides log-injection–safe helpers, correlation ID injection, and a pluggable provider backend.

## Helpers

### SanitizeLogValue

Replaces all Unicode control characters (C0, DEL, C1) with underscores and truncates values exceeding 1024 bytes. Use for arbitrary user-supplied strings (path segments, query parameters, header values).

```go
logger.Info("request received", "steward_id", logging.SanitizeLogValue(stewardID))
```

### RedactedID

Truncates an opaque identifier to an 8-character prefix followed by `…` (U+2026). Applies `SanitizeLogValue` to the prefix so control characters cannot leak. Use for session IDs, bearer tokens, correlation IDs, or any high-entropy identifier where the full value must not appear in production logs.

```go
logger.Info("session opened", "session_id", logging.RedactedID(sessionID))
// output: session_id=abc12345…
```

**Contract:**

| Input length | Output |
|---|---|
| 0 | `""` (unchanged) |
| 1–8 bytes | full value + `…` |
| 9+ bytes | first 8 bytes (sanitized) + `…` |

When `SensitiveLogConfig.UnredactedSensitiveValues` is `true`, the full sanitized value is returned without truncation (see debug gate below).

**When to use `RedactedID` vs `SanitizeLogValue`:**

- `SanitizeLogValue` — general-purpose; strips control characters and truncates long strings. Does not shorten the value.
- `RedactedID` — for high-entropy secrets and identifiers where the full value must not appear in logs even in normal operation. Truncates to 8 chars by design.

## Redacting Sensitive Identifiers

## SensitiveLogConfig and the Debug Gate

`SensitiveLogConfig` is a package-level configuration struct that gates unredacted debug logging behind an explicit opt-in. The default zero value keeps redaction enabled.

```go
type SensitiveLogConfig struct {
    // UnredactedSensitiveValues, when true, causes RedactedID to return the
    // full value rather than the 8-char prefix. Development only.
    // Default: false.
    UnredactedSensitiveValues bool
}
```

**Accessors:**

```go
logging.SetSensitiveLogConfig(logging.SensitiveLogConfig{UnredactedSensitiveValues: true})
cfg := logging.GetSensitiveLogConfig()
```

Both accessors are safe for concurrent use (protected by `sync.RWMutex`).

**Debug gate pattern** — enable full IDs only in development via explicit configuration:

```go
if cfg.Debug {
    logging.SetSensitiveLogConfig(logging.SensitiveLogConfig{UnredactedSensitiveValues: true})
}
```

Never set `UnredactedSensitiveValues: true` in production code paths or as a default value.

## Local System Log Subscriber (`systemlog`)

`pkg/logging/subscribers/systemlog` writes to the local system log so a steward
that cannot reach the controller (for example, no usable identity) still leaves
its reason where a local admin looks. It is registered in the manager as
subscriber type `systemlog`, separate from the remote-network `syslog` subscriber.

| Platform | Backend |
|----------|---------|
| Windows | Event Log via `golang.org/x/sys/windows/svc/eventlog`; the source is registered on first use (needs SYSTEM/elevation) |
| Linux | Local syslog socket via `log/syslog` (daemon facility) |
| macOS | Local syslog socket via `log/syslog`; the socket feeds the unified log (surfacing there is not asserted by tests) |

Configuration keys: `tag` (syslog tag / Event Log source, default `cfgms-steward`),
`collapse_window` (duration, default `1h`), `levels` (entry levels forwarded by
`HandleLogEntry`, default `WARN`, `ERROR`, `FATAL`), and `network`/`address`
(Unix only, a non-default syslog socket).

`Initialize` returns an error, never panics, when the backend cannot be opened;
`Available()` then reports `false` with the reason so callers can fall back to stderr.

`WriteOnce(level, key, message)` writes at `LevelInfo`, `LevelWarning` or
`LevelError` and drops a message identical to the previous one (same key) inside
the collapse window, so a retry loop does not flood the log. Messages are
sanitized: control characters are replaced, length is bounded, and values that
look like secrets (`password=`, `token=`, bearer values, PEM blocks, long opaque
strings) are replaced with `[REDACTED]`. Pass fixed text plus a short reason, never credentials.
