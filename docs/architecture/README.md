# Architecture

Design documents for CFGMS. The contributor entry point is [ARCHITECTURE.md](../../ARCHITECTURE.md) at the repository root.

## Read by task

Load the sections relevant to the change; these are reference documents, not a
requirement to read every operating model before doing any work.

| Task | Start here |
|------|------------|
| Understand component interaction and runtime boundaries | [System operating model](operating-model.md) |
| Change controller startup, orchestration or a controller-owned feature | Relevant section of the [controller model](controller-operating-model.md) and its accepted ADRs |
| Change convergence, module execution or endpoint DNA | Relevant section of the [steward model](steward-operating-model.md) and [module contract](modules/README.md) |
| Change persistence or backend configuration | [Storage architecture](storage-architecture.md), the provider interfaces and canonical boot config |
| Plan product or epic scope | [Vision](../product/vision.md) and [Product Planning](../development/product-planning.md) |

## Design Documents

- [Provider Architecture](provider-architecture.md) - The pluggable central-provider pattern
- [Storage Architecture](storage-architecture.md) - Five-type storage taxonomy (ADR-003)
- [Communication Layer Migration](communication-layer-migration.md) - gRPC-over-QUIC transport architecture
- [Rollback Design](rollback-design.md) - Configuration rollback system
- [Workflow Debug System](workflow-debug-system.md) - Workflow debugging capabilities
- [DNA Collection Audit](dna-collection.md) - Documented vs implemented DNA attributes (epic #1932)
- [Steward Configuration](steward-configuration.md) - The `hostname.cfg` format and options
- Security-review harness architecture — `.claude/skills/security-review/docs/harness-architecture.md` - The multi-lab LLM security review harness (moved out of docs/ to live beside the rest of the skill)

## Subdirectories

- [Architecture Decision Records](decisions/README.md) - Index of all ADRs
- [Module System](modules/README.md) - Module architecture, manifest fields, distribution, and behavioural envelope
