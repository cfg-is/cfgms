# CFGMS Modules

Developer entry point for resource modules. Each implementation provides
`modules.Module`: `Get` returns `ConfigState`, and `Set` accepts desired
`ConfigState`. The steward performs comparison and convergence; the Go interface
has no `Test` method. The out-of-process wire service has its own contract.

## Read by task

- **Configure a resource:** [operator module index](../../docs/modules/README.md).
- **Implement a module:** [module architecture](../../docs/architecture/modules/README.md),
  [Go types](module.go), and [interface/wire contract](../../docs/architecture/modules/interface.md).
- **Declare a manifest:** [metadata types and validation](metadata.go). Declare
  exactly one executor (`steward`, `outpost` or `controller`); `workflow` is
  derived, not another independently selected executor.
- **Package and distribute:** [distribution contract](../../docs/architecture/modules/distribution.md).
- **Declare runtime behavior:** [behavioral envelope](../../docs/architecture/modules/behavioral-envelope.md).

## Source layout

`stdlib/` contains the standard endpoint resource set. `extended/` contains
additional modules; `hyperv/` implements Hyper-V management. Each module keeps
its manifest, configuration validation, implementation and tests near its source.
Do not infer identical filenames or platform coverage across modules.

`Get` output must be deterministic and omit ephemeral state from desired-state
comparison. Use the [conformance helpers](conformance/) for the DNA contract.
Keep source READMEs focused on local wiring and unique developer notes; link the
operator reference instead of copying its configuration tables.
