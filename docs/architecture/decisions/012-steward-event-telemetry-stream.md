# ADR-012: Steward Event/Telemetry Stream to Controller

**Status:** Accepted

**Date:** 2026-06-23

**Deciders:** Founder, Architecture

**Related:** [005](005-logging-interface-for-transport-providers.md) (logging interface — `LogEntry` is the wire format), [006](006-module-packaging-and-distribution.md) (modules are out-of-process; informs the crash-isolation argument), [007](007-controller-upgrade-and-state-externalization.md) (SaaS-cluster externalization — where the durable broker backend lands). Epic: #2135. Stories: this ADR + the P1 set decomposed under #2135. Consumes monitor-fire events from #2110 (module Monitor).

---

## Context

The steward today reports almost nothing about what it actually does. It sends a heartbeat (`StatusOK`/`StatusError`), a per-config `ConfigStatusReport` (`features/steward/client/client_transport.go:1118` `publishConfigStatus`, gated by the `config.status.report` permission), and DNA sync. There is no first-class feed of *events*: which resources it enforced, what a script printed, or when a monitor fired. The only steward-logs API is the reverse direction — `GET /api/v1/stewards/{id}/logs` exists as a handler (`features/controller/api/handlers_stewards.go:691`) but returns **Not Implemented**.

Operators managing 50k+ endpoints need live, per-steward visibility: every convergence action, every script's output, and every monitor that fires. The founder's framing (2026-06-23): *"The steward should pass an event stream/logging back to the controller when it has to take a convergence action, pass back script output. When monitors fire (watching logs, service/process/daemon status, and eventually RAM/CPU/disk)."*

A verify-first codebase review on 2026-06-23 established the ground truth this ADR is built on, because the epic's framing assumed reuse of components that turn out to be unwired:

- **`LogStream` RPC is proto-only.** `rpc LogStream(stream LogEntry)` is declared (`api/proto/transport/transport.proto:55`) but the controller's `compositeTransportServer` falls through to the `Unimplemented` base for it (`features/controller/server/composite_handler.go:18`). No server handler exists.
- **`features/siem` (the correlation engine) is dead code.** `NewSIEMEngine`, `NewStreamProcessor`, and its stream ingress `ProcessLogStream` (`features/siem/siem_engine.go:268`) have **zero callers outside the package's own tests** — `ProcessLogStream` has zero callers including tests. No production package imports `features/siem`.
- **`features/workflow/trigger.SIEMProcessor` is a second, distinct construct — wired but starved.** It *is* constructed at controller startup (`features/controller/server/server.go:1294` → `NewControllerTriggerManager` → `siemProcessor`), but its feed `ProcessLogEntry` has zero live callers and it carries its own private `LogEntry` type. It is a log-pattern→workflow-trigger integration, not a per-steward event store.
- **The convergence path has no per-call timeout.** `executor.ExecuteResource` (`features/steward/execution/executor.go:178`) calls `module.Get` (`:250`), `module.Set` (`:304`), and `verifyChanges`/`module.Get` (`:316`/`:391`) with the ambient `ctx`. A module that hangs mid-`Set` wedges the run silently and never sends a `ConfigStatusReport` — a silent failure with no event.

So end-to-end nothing produces, transports, ingests, persists, or surfaces a steward event feed today. The substrate exists as disconnected parts; the pipe is empty at every joint. These decisions span multiple stories; settling them here means implementers have no open design questions.

---

## Decision

### 1. Wire format is `pkg/logging.LogEntry` — reuse, do not invent a schema

The **internal** event is the existing `logging.LogEntry` (`pkg/logging/interfaces/provider.go:50`): RFC5424/syslog-shaped plus CFGMS context (`ServiceName`/`Component`/`TenantID`) plus `CorrelationID`/`TraceID`/`SessionID`. Detection↔outcome correlation uses the existing **`CorrelationID`**. OpenTelemetry remains an **export** format at egress (OTLP exporter in `features/monitoring/export/`, ADR-005), **not** the internal wire schema. No new internal event schema is created.

**Wire vs internal.** The `LogStream` RPC carries `transportpb.LogEntry` (`api/proto/transport/data.proto:94`), which today has only `steward_id`/`level`/`message`/`timestamp`/`fields`. Because `CorrelationID` is the load-bearing mechanism of the two-event model, it is **promoted to a first-class proto field** (`correlation_id`, field 6) rather than smuggled through the free-form `fields` map — a one-line proto change + `make proto-gen`, cheap pre-release and self-documenting. All other structured context (`resource_id`, `event_kind`, `action`, `duration_ms`, exit codes, etc.) travels in the `fields` map. **`tenant_id` is deliberately NOT a wire field** — see §4. A small adapter maps `transportpb.LogEntry` ↔ `interfaces.LogEntry` (controller-side decode in the handler; steward-side encode in the emitter).

### 2. Two correlated events — detection and outcome — never one combined event

Detection and response are emitted as **two events sharing one `CorrelationID`**, not one combined event:

- **Detection event** — emitted the instant a monitor fires, **before** convergence runs, **owned by the steward** (not the module), on a **buffered, out-of-band event channel** that does not share a goroutine or process with module execution. Carries the `CorrelationID`.
- **Outcome event** — emitted when the convergence check **completes, times out, or errors**; same `CorrelationID`; carries action / result / duration.

**Why not one combined event:** a combined event shares fate with the thing being observed. If a module crashes or wedges during convergence, a single combined event emits *nothing* — detection and response both lost — exactly when a steward is unhealthy. The two-event model makes that failure a **first-class, queryable signal**: a detection with no outcome within the timeout window = "monitor fired, convergence never completed." Because modules are out-of-process (ADR-006), a module crash cannot take down the steward's emitter or lose the already-emitted detection event.

**Volume control:** the detect/outcome pair applies **only to convergence-triggering monitors** (the #2110 resource-change→reconcile case). A **pure-observability monitor** (perf, plain log-watch) has no response and emits a **single data event**. The "one logical event" view is reconstructed **at the controller** by `CorrelationID` (render-as-one + roll up), never by suppressing at the source.

### 3. Transport is the existing `LogStream` RPC — implement the server handler; steward stays thin

The steward emits `LogEntry` events over the already-declared `LogStream(stream LogEntry)` RPC on the single mTLS channel. This epic **implements the controller-side server handler** (today it falls through to `Unimplemented`) and the steward-side client emitter (mirroring the existing `publishConfigStatus` event-publish path). **No streaming agent or broker is installed on the steward** — the endpoint-TCB / single-mTLS-channel / signed-execution-model cost is the hard line from the epic's build-vs-buy analysis. Every byte on the steward still arrives via one of the four declared execution paths (ADR-006 / CLAUDE.md).

### 4. Scoped `steward.event.log` permission, CN-matched at ingestion

A new `steward.event.log` permission is added to the `steward.service` role (`features/rbac/defaults.go`, alongside `config.status.report`). It is **emit-only** — it grants no read of any steward's events. At ingestion the controller **CN-matches** the streamed events to the authenticated mTLS peer — a steward can only report its **own** events, mirroring the DNA identity model (`ErrStewardIdentityMismatch`, `features/controller/transport/errors.go:11`). CN extraction **fails closed**: an empty or unavailable peer CN is rejected, never treated as a wildcard match. **`TenantID` is server-derived** at ingestion from the authenticated peer's fleet-registry record — it is never read from the wire or the `fields` map, so a compromised steward cannot stamp another tenant's events. No cross-steward or cross-tenant reporting is possible even from a compromised host.

### 5. Reuse `LoggingManager` as the sink; extract its fan-out into a pluggable `EventBus`

The controller already has the substrate: `LoggingManager` (`pkg/logging/manager.go`) persists every entry via the pluggable `LoggingProvider` (`file`/`timescale`), exposes `QueryTimeRange`, **and** fans out to subscribers. A verify-first review confirmed it does exactly what a bespoke "event bus + log-writer consumer" would — so we **reuse it rather than build a parallel sink**, and the `LogStream` handler (§3) simply calls `LoggingManager.WriteEntry`, which persists *and* fans out. The `GET /api/v1/stewards/{id}/logs` surface reads back via `QueryTimeRange`. A **dedicated `LoggingManager` instance** carries ingested steward events, kept separate from the controller's own application logs so per-steward queries don't co-mingle.

The one change required for pluggability: `LoggingManager`'s fan-out is today an in-process `eventChan`/`eventLoop` with config-time subscribers. We **extract that fan-out into a pluggable `EventBus` interface** (`pkg/eventbus`, Publish/Subscribe; default in-process Go-channel provider that lifts the existing channel/drop-on-full/parallel-dispatch logic) and add a runtime `AddSubscriber`. This is a **localized refactor** — the fan-out internals are referenced only inside `manager.go`; the 39+ `ForModule` write-path callers are untouched.

- **Zero new Go-module dependencies;** the channel provider is the default and preserves today's best-effort drop-on-full semantics.
- **NATS JetStream is the documented swap-in** for the SaaS-cluster deployment (#2051 / ADR-007) — landed later as its own dependency-justified `EventBus` provider. Because the bus is now an interface behind `LoggingManager`, that swap changes **one implementation, not any `WriteEntry` call site**. Adopting NATS now is rejected: it adds a broker dependency and lifecycle to the single-node controller before fleet volume demands it.
- **Future subscribers** (SIEM correlation, workflow triggers) attach via `AddSubscriber` without touching the producer.

This makes detection↔outcome correlation, persistence, and (later) alerting independent consumers of one feed, while reusing the existing logging facade rather than duplicating it — and keeps the NATS swap a one-provider change.

### 6. Bounded / back-pressured stream — a compromised steward cannot flood the controller

The ingestion path is **bounded** by a real **per-steward token-bucket rate-limit with drop-with-counter** (dropped-event count is itself observable). This is *not* `TenantQueue` (`features/controller/transport/tenant_queue.go`), which is a per-tenant **concurrency semaphore** — a single open `LogStream` holds one slot, so a flood *inside* one stream is unguarded by it; a genuine rate-limit is required. Admission control runs on the `LogStream` handler, upstream of the bus, and the channel bus itself drops-with-counter when full (OOM-resistant). 

**Secret handling — redaction, not just control-char sanitization.** Streamed script stdout/stderr and log content are **secret-redacted** before emission and again defense-in-depth at persistence: a denylist redaction over values and `fields` (the `pkg/audit` `RedactedKeys`/`redactMap` pattern, `pkg/audit/manager.go`), emitting `[REDACTED]`. **`logging.SanitizeLogValue()` is NOT secret redaction** — it only strips C0/C1/DEL control chars + truncates (CWE-117 log-injection, `pkg/logging/sanitize.go:105`); it is applied *in addition to* redaction, not instead of it. Banned-patterns rules apply to any on-host log/script handling.

### 7. Per-call convergence timeout → `did-not-finish (timeout)` outcome event

`executor.ExecuteResource` wraps each per-resource `module.Get` / `module.Set` / `verifyChanges` call in a **deadline** (`context.WithTimeout` on the ambient `ctx`). A hung module produces a **timeout error → an `outcome = did-not-finish (timeout)` event** correlated by `CorrelationID` to its detection event — turning today's silent wedge into two logged, queryable events. Errors that **do** return continue to reuse the existing `handleResourceError` → `ConfigStatusReport` → `StatusError` heartbeat path; this decision only adds the timeout case.

### 8. Relationship to #2110 (module Monitor) — one Monitor abstraction, two sinks

#2110's `Monitor` detects a managed-resource change and triggers a **targeted reconcile**. This epic's **observability monitors** (log watch, service/process/daemon status, and later perf) **watch and report** — same lightweight-OS-hook listener philosophy, but the output is an **event on the stream**, not a reconcile. They are the **same Monitor abstraction with a "report" sink added alongside the "reconcile" sink**. A convergence-triggering monitor emits the detection event (this epic) *and* drives the reconcile (#2110); a pure-observability monitor only emits. Monitor-fire reporting is **generic** — any monitor (module-declared or standalone monitor-module), not a fixed set of types. P2 builds the observability monitors on this seam; this ADR fixes the seam so P2/P3 are additive.

### 9. The two existing SIEM constructs are future subscribers, not P1 work

Neither `features/siem` (dead) nor `trigger.SIEMProcessor` (starved) is wired in P1. They become **future subscribers** on the event bus (§5) if and when alerting/correlation earns a live consumer. Consolidating or retiring one of them is **separate cleanup**, flagged but explicitly **out of scope for #2135** — it is not a P1 blocker, and #2135 must not be gated on reviving dead code that has no other consumer.

---

## Consequences

**Positive:**
- The steward gains a first-class, scoped, queryable event feed reusing existing transport + `LogEntry` + Timescale; the steward emission stays thin and within the four declared execution paths.
- The two-event model converts a steward's worst failure mode (module wedge during convergence) from a silent gap into a queryable "detection-without-outcome" signal.
- The pluggable bus lets persistence, correlation, and triggers evolve as independent consumers; the single-node default carries no new dependencies, and the SaaS-cluster broker is a clean, deferred swap.

**Negative / accepted costs:**
- The Go-channel bus is in-process and non-durable: events in flight at a controller crash are lost until the NATS backend lands. Acceptable for single-node; durability is a #2051 concern.
- Two SIEM constructs remain in the tree as dead/starved code until the separate consolidation runs. Flagged, deliberately deferred.

**Phasing:** **P1** = event-stream plumbing (scoped permission + CN-matched ingestion + pluggable bus + a log-writer consumer persisting via the configured `LoggingProvider` + `GET .../logs` surface reading via `QueryTimeRange` + back-pressure) + convergence-action detection/outcome events + the per-call convergence timeout + script-output streaming. **P2** = log/service/process/daemon observability monitors firing onto the stream (extends #2110). **P3** = system performance telemetry (RAM/CPU/disk). The stream is designed so P2/P3 are additive — new event sources and new subscribers, no producer changes.
