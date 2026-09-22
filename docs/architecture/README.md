# Architecture

Design documents for CFGMS. The contributor entry point is [ARCHITECTURE.md](../../ARCHITECTURE.md) at the repository root.

## Operating Models (required reading)

Consult these before changing steward or controller behaviour.

- [CFGMS Operating Model](operating-model.md) - Component roles, communication, and failure modes at runtime
- [Controller Operating Model](controller-operating-model.md) - Startup, fleet management, and orchestration
- [Steward Operating Model](steward-operating-model.md) - Convergence loop, modules, and DNA sync

## Design Documents

- [Provider Architecture](provider-architecture.md) - The pluggable central-provider pattern
- [Storage Architecture](storage-architecture.md) - Five-type storage taxonomy (ADR-003)
- [Git Backend Design](git-backend-design.md) - Design of the git storage backend (the git provider was removed in v0.10)
- [Communication Layer Migration](communication-layer-migration.md) - gRPC-over-QUIC transport architecture
- [Rollback Design](rollback-design.md) - Configuration rollback system
- [Workflow Debug System](workflow-debug-system.md) - Workflow debugging capabilities
- [DNA Collection Audit](dna-collection.md) - Documented vs implemented DNA attributes (epic #1932)
- [Steward Configuration](steward-configuration.md) - The `hostname.cfg` format and options
- [Security Review Harness](security-review-harness.md) - The multi-lab LLM security review harness

## Subdirectories

- [Architecture Decision Records](decisions/README.md) - Index of all ADRs
- [Module System](modules/README.md) - Module architecture, manifest fields, distribution, and behavioural envelope
