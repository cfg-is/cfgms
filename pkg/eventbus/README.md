# pkg/eventbus

In-process fan-out for `pkg/logging` entries, with a clear swap path to NATS JetStream.

## Interface

```go
// pkg/eventbus/interfaces/bus.go
type EventBus interface {
    Publish(entry interfaces.LogEntry)
    Subscribe(sub interfaces.LoggingSubscriber)
    Close() error
}
```

`Publish` is non-blocking: if the internal buffer is full the entry is dropped and an
internal counter is incremented. Primary persistence (`LoggingManager.WriteEntry`) is
unaffected by drops — entries are persisted before `Publish` is called.

## Channel provider (default)

`pkg/eventbus/providers/channel` is the in-process implementation used today. It
preserves the semantics that existed in `LoggingManager` before extraction:

- **Best-effort delivery** — drop-on-full, no backpressure to the write path.
- **`DroppedCount()` accessor** — observable drop counter for alerting.
- **Parallel subscriber dispatch** — each subscriber runs in its own goroutine with a
  per-handler timeout (default 5 s) so a slow subscriber cannot block others.
- **Runtime `Subscribe`** — safe to call after the bus has started; the subscriber
  receives entries published after the call returns.

### Creating a bus

```go
import channelBus "github.com/cfgis/cfgms/pkg/eventbus/providers/channel"

bus := channelBus.New(bufSize) // bufSize matches LoggingConfig.BufferSize
```

## How LoggingManager uses EventBus

`LoggingManager` holds an `EventBus`. On every successful `WriteEntry` call it invokes
`bus.Publish(entry)`. Config-declared subscribers (e.g. syslog) are registered via
`bus.Subscribe` during initialization. Additional subscribers can be attached at any
time via `manager.AddSubscriber(sub)`.

## NATS swap path (deferred to #2051)

When fleet volume demands a durable broker, implement a NATS JetStream provider that
satisfies `EventBus`:

```go
// pkg/eventbus/providers/nats/provider.go
type NATSBus struct { ... }
func (b *NATSBus) Publish(entry interfaces.LogEntry) { ... }
func (b *NATSBus) Subscribe(sub interfaces.LoggingSubscriber) { ... }
func (b *NATSBus) Close() error { ... }
```

Wire it into `NewLoggingManager` instead of `channelBus.New`. No `WriteEntry` call sites
change — the swap is one implementation, not a refactor of 39+ callers.

## Future subscribers

Attach via `LoggingManager.AddSubscriber` or by extending `LoggingConfig.Subscribers`:

- `features/siem` correlation engine (dead code today — #2135 §9)
- `features/workflow/trigger.SIEMProcessor` (starved today — #2135 §9)
- OpenTelemetry OTLP exporter (export path, not internal wire schema — ADR-005)
