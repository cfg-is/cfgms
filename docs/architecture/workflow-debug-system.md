# Workflow Debugging

Developer reference for the workflow engine's debugging interfaces. The engine
constructs `DebugEngineImpl`; the HTTP adapter exists separately. A handler
method is not proof it is registered on the controller API.

## Components and scope

- [debug_types.go](../../features/workflow/debug_types.go): debug session, status,
  step action, breakpoint, variable and API-call contracts.
- [debug_engine.go](../../features/workflow/debug_engine.go): in-process session,
  stepping/breakpoint, variable inspection and history operations.
- [debug_api.go](../../features/workflow/debug_api.go): HTTP adapter methods;
  verify controller route registration and authorization before documenting a
  public endpoint or assuming it is available to operators.
- [engine.go](../../features/workflow/engine.go): construction/access through the
  workflow engine and execution integration.

## State, side effects and safety

A debug session carries an execution ID, current step, variables, breakpoints
and step/API history. Inspect the concrete method and its callers before claiming
that every execution path supports a stepping action, automatic interception or
persistent recovery. These are not the durable workflow-execution store.

`RollbackToStep` truncates local step history and restores a variable snapshot.
It does **not** undo changes already made to an endpoint, SaaS service or external
API. Replaying an API call or resuming a step can repeat external side effects;
use the same tenant authorization and approval rules as the actual operation.

## Verify changes

The adjacent `debug_test.go` and `debug_api_test.go` cover their bounded library
and adapter behavior. Test pause/stop/resume, missing session/step, variable
snapshots, errors and concurrent access for the path being changed. Separately
verify route wiring, authentication, tenant scoping and side effects before
claiming an operator-ready debugging feature. No universal latency, retention or
zero-loss resume guarantee follows from these helpers.

The [workflow contract](workflow-engine.md) owns execution semantics and
[ADR-008](decisions/008-durable-execution-substrate.md) records the durable
execution decision; neither should be inferred from a debug-history snapshot.
