# Script Module

The [script operator reference](../../../../docs/modules/script-module.md) owns
execute/stage actions, parameter bindings, effective signing, execution context
and examples. Use it instead of maintaining a second operator manual here.

Developer entry points:

- [Configuration parsing and action validation](config.go)
- [Get/Set, stage dispatch, result/audit handling](module.go)
- [Signing policy and trust configuration](signing.go)
- [Execution monitoring](execution_monitor.go)

`action: stage` records a library script as staged; it does not execute content.
Execution and signing tests beside these files establish the behavior of their
respective paths. Keep library/repository wiring and tenant context explicit
when constructing a module outside the normal steward runtime.
