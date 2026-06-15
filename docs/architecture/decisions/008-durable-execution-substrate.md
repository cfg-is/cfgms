# ADR-008: Durable Execution Substrate for the Workflow Engine

**Status:** Accepted

**Date:** 2026-06-15

**Deciders:** Founder, Architecture

**Related:** [007](007-controller-upgrade-and-state-externalization.md) (state externalization / shared relational datastore), [006](006-module-packaging-and-distribution.md) (workflow module kind), [001](001-central-provider-compliance-enforcement.md) (central-provider compliance), [003](003-storage-data-taxonomy.md) (storage data taxonomy)

---

## Context

The workflow engine (`features/workflow`) is the controller-side runtime for the **workflow** module kind defined in ADR-006: it brings the steward Get/Set convergence model to cloud/SaaS APIs, and it is the automation surface for registration approval, drift-response policy, and third-party integration.

What is built today is substantial but lopsided. The engine implements ~21k lines of a **declarative workflow interpreter**: 25+ step types (control flow, loops, try/catch/finally, fan-out/fan-in, sync primitives, HTTP/API/webhook, nested + composite workflows), a cron/webhook/SIEM trigger subsystem, versioned definitions persisted via `pkg/storage`, a SaaS provider registry, and a breakpoint debugger.

The part that is **not** built is the hard part — durable execution. Execution state lives in an in-memory map (`features/workflow/engine.go`: `executions map[string]*WorkflowExecution`). A controller restart or HA failover loses every in-flight run. There is no general durable job queue, no crash recovery, and no resume-from-failed-step.

This directly contradicts the documented design:

- `docs/architecture/operating-model.md` asserts a **"durable job queue (controller-side)"** that *"survives controller restarts and leader failover"* and backs *"fanout, retries, deferred operations, and HA failover replay."* — this primitive does not exist in code.
- `docs/architecture/controller-operating-model.md` requires execution to *"resume or re-run from any failed node without restarting entire workflow"* — impossible with in-memory state across a restart.

Building durable execution by hand — deterministic replay, checkpointing, exactly-once/idempotent recovery, a durable queue, crash-recovery races — is the genuinely hard, easy-to-get-wrong part of this space. It is also not differentiating work for CFGMS.

Two project facts shape the options:

1. **ADR-007 already commits the controller to externalizing durable state to "a managed relational datastore"** as the prerequisite for host/container blue-green upgrades. A relational database is therefore a dependency the project has already decided to take on; it is not new burden introduced solely by the workflow engine.
2. **CFGMS workflows are declarative data, not code.** Workflows are authored as definitions (visual builder / YAML), parsed, versioned in `pkg/storage`, and interpreted at runtime. This is unlike code-first durable-execution frameworks where each workflow author writes the durable function.

## Decision

### 1. Introduce a durable-execution central provider

Add a new pluggable central provider (working name `pkg/orchestration`) whose interface is defined from CFGMS's **documented requirements** — enqueue a durable job, checkpoint a step, register a schedule, resume/cancel a run, await an external event — **not** from any single vendor's API. This keeps the contract ours and preserves substrate optionality (ADR-001 applies; `make check-architecture` governs).

### 2. First provider: DBOS (Go SDK), self-hosted on Postgres

The first and default provider is **DBOS Transact** via its official Go SDK (`github.com/dbos-inc/dbos-transact-golang`, MIT-licensed, in-process library, durable state in Postgres). DBOS supplies exactly the documented gap: durable workflows/steps via Postgres checkpointing, crash recovery / resume-from-last-step, durable queues with concurrency/priority/rate-limiting, cron with missed-interval backfill, per-step retries, idempotency/dedup keys, durable sleep, and events/messaging for human-in-the-loop. It requires no orchestration cluster — only Postgres.

We adopt DBOS knowing it is pre-1.0 and the Go SDK is the youngest of its SDKs. The MIT license and self-hostability mean there is no hard runtime dependency on the vendor's cloud; the provider abstraction is the hedge against maturity or scale limits.

### 3. The interpreter is one durable workflow; side effects are steps

The existing declarative interpreter is **kept**. We do not rewrite workflows as code. Instead, a single durable workflow function *is* the interpreter, and every side-effecting operation it performs (cloud API call, module Get/Set, HTTP request) is registered as a durable **step** whose output is checkpointed. Control flow is driven by the immutable workflow definition plus checkpointed step outputs.

This yields dev/prod parity by construction: the same definition flows through the same interpreter in both "just run" and "step-through debug" modes. The only place non-determinism can enter is the interpreter itself, which CFGMS owns. The following are **hard constraints** on the interpreter:

- Every input to a control-flow decision must come from the immutable workflow input or a checkpointed step output — never from ambient state (wall-clock, RNG, Go map-iteration order, env, goroutine timing). "Get current time", "list keys", etc. are wrapped as steps so their results are checkpointed and replay-stable.
- Parallel/fan-out execution uses the provider's durable concurrency primitives, not raw goroutines + `select`.
- A crash-mid-workflow recovery test is added to CI. Replay divergence surfaces as a loud error on recovery (DBOS raises an unexpected-step error when the replayed path does not match the checkpoint), so it must be exercised deliberately rather than trusted to dev runs.

### 4. Debugger boundary: inspect in durable mode, edit-and-continue in dev only

Stepping through a run, inspecting variables, and viewing per-step errors are supported in **both** modes. Runtime variable **mutation** (`UpdateVariable`) and `RollbackToStep` inject ambient state mid-run and would diverge on replay; these remain a **non-durable, dev-sandbox-only** capability. The current debugger (`features/workflow/debug_engine.go`), which today maintains a parallel state machine separate from the live engine, is refactored so dev mode is the same interpreter with a pause-at-step-boundary hook rather than a second execution path.

### 5. Own the per-attempt forensics

DBOS persists per-step **final** outcomes (output or terminal error) to its system schema, queryable by SQL or the Go API (`ListWorkflows`, `GetWorkflowSteps`). It does **not** durably record intermediate failed retry attempts of a step — a step that flakes and then succeeds is recorded as a clean success. To avoid the industry-standard "it fails 10% of the time and the logs don't say why" gap, the interpreter captures every retry attempt's error into the existing `StepResult.RetryAttempts` / `ExecutionTrace` structures and emits it to the `pkg/logging` provider keyed by the workflow run ID, before a step returns. Post-mortem then joins DBOS's durable orchestration record (what ran, final outcomes, where it stopped) with CFGMS's per-attempt trace (every transient failure, request/response, timing) on the run ID.

### 6. Database access pattern (reconciliation with ADR-007)

ADR-007 externalizes controller **business state** (DNA/fleet/config/audit) through the `pkg/storage` provider interfaces to a managed relational datastore. Durable-**execution** state (checkpoints, queues) is owned and managed directly by the DBOS library in its own `dbos` schema and is intentionally **not** routed through `pkg/storage` — abstracting checkpoints behind the storage interface would defeat the purpose of adopting a durable-execution library. These are two consumers of one Postgres instance with deliberately different access patterns. The direct-database access by the orchestration provider is a recorded exception under ADR-001 and is documented for `make check-architecture`.

## Consequences

- **The documented durable-job-queue primitive becomes real** without hand-building checkpointing/recovery. `docs/architecture/controller-operating-model.md` and `operating-model.md` are updated to point at this provider as the mechanism (doc-sync follow-up).
- **~80% of `features/workflow` is retained** — the interpreter, transforms, triggers, SaaS integration, and definition versioning have no durable-execution equivalent and stay. Net code removed is modest (cron-scheduler internals, ad-hoc retry/recovery scaffolding); the larger saving is the durable-execution machinery we do not write.
- **New mandatory dependency: Postgres** for any controller running workflows. Softened by ADR-007 already moving the controller toward a managed relational datastore for GA upgrades.
- **Capability narrowing:** edit-and-continue debugging is dev-only; durable runs are inspect-only. The interpreter carries a determinism discipline enforced by a crash-recovery CI test.
- **Forensics are a build requirement, not free:** per-attempt failure logging must be implemented in the interpreter/`pkg/logging`, or flaky-step diagnosis falls into the same gap as comparable tools.
- **Substrate optionality is preserved but not free:** porting to another substrate (e.g. Temporal) is a contained migration behind the provider interface, not a drop-in swap — DBOS (in-process, library-on-Postgres) and Temporal (external orchestration cluster) have fundamentally different programming models.
- **Vendor risk** from a pre-1.0 SDK and early-stage company is accepted, mitigated by the MIT license, self-hostability, and the provider abstraction. The exact DBOS Go error symbol for replay divergence and whether per-step *inputs* are persisted should be verified against the running schema during the spike.

## Alternatives considered

- **Hand-build durable execution** on top of `pkg/storage` — rejected. Deterministic replay, idempotent recovery, durable queues, and crash-recovery races are subtle and high-risk to implement correctly, and are not differentiating work. The in-memory engine is the status quo this ADR exists to replace.
- **Temporal / Cadence** — rejected as the first substrate. Battle-tested at large scale, but requires standing up and operating a separate orchestration cluster (server + datastore + worker fleet), which is heavier operationally than a library on the Postgres ADR-007 already mandates. Kept in reserve as a future provider behind the same interface if DBOS maturity or scale becomes a blocker.
- **Keep the in-memory engine** — rejected. It cannot satisfy the documented durability, HA-failover-replay, or resume-from-failed-node requirements, and silently loses in-flight work on restart.
