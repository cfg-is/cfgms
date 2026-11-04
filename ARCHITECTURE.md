# CFGMS Architecture

Contributor map to current component contracts. [The vision](docs/product/vision.md)
owns approved product direction; [the roadmap](docs/product/roadmap.md) distinguishes
release outcomes from existing foundations. Architecture diagrams or accepted
decisions alone do not establish released capability or measured scale.

## System Overview

- **Controller:** tenant-scoped API, fleet state, configuration resolution, workflow
  orchestration, SaaS integration and entity-graph services.
- **Steward:** endpoint identity/trust, observation, desired-state convergence,
  local module execution and the controller connection.
- **Outpost:** future network proxy/probe direction. It is not a required
  intermediary in the current controller–steward deployment.

| Change/task | Read first |
|---|---|
| Cross-component behavior and primitive boundaries | [Operating model](docs/architecture/operating-model.md) |
| Controller startup, config, dispatch, fleet or cluster behavior | [Controller operating model](docs/architecture/controller-operating-model.md) |
| Steward startup, convergence, observation or reconnect | [Steward operating model](docs/architecture/steward-operating-model.md) |
| Resolve inherited resources | [Inheritance guide](docs/guides/configuration-inheritance.md) |
| Change persistent data or a backend | [Storage architecture](docs/architecture/storage-architecture.md), [interfaces](pkg/storage/interfaces/README.md) |
| Extend a shared provider | [Provider architecture](docs/architecture/provider-architecture.md), [provider entry](pkg/README.md) |
| Implement/distribute a resource module | [Module architecture](docs/architecture/modules/README.md), [source entry](features/modules/README.md) |
| Change a workflow or trigger | [Workflow contract](docs/architecture/workflow-engine.md), [trigger package](features/workflow/trigger/README.md) |
| Change API/auth/tenant boundaries | [REST integration](docs/api/rest-api.md), [security architecture](docs/security/architecture.md), applicable accepted ADR |
| Change web UX | [Design system](docs/design/web-ui-design-system.md), [reference mockups](docs/design/mockups/README.md), [web entry](web/README.md) |

## Communication Architecture

The control/data services run over gRPC on QUIC with mTLS. Endpoint heartbeats,
commands, DNA and config synchronization share the configured UDP transport port,
normally `4433`. The external REST API and installer/binary distribution use HTTPS,
normally `9080/TCP`; one QUIC port does not mean all product traffic uses it.

Source boundaries are `pkg/controlplane/interfaces`, `pkg/dataplane/interfaces`
and `pkg/transport/quic`. The controller issues endpoints and stewards initiate
the connection. Reconnect/failure detection depends on configured timeouts and
routing, not a universal timing claim. Browser traffic follows its separate
[session and assurance contracts](docs/security/architecture.md).

Use [canonical controller config](docs/deployment/controller.cfg),
[steward config](docs/deployment/steward.cfg) and [schema](docs/reference/config-schema.md)
for actual field names. Observe the separate private metrics listener.

## Configuration and observed state

The controller resolves tenant, cluster, role and device layers, records source
metadata and delivers desired state. The steward compares/sets/verifies named
resources through modules. Later matching resource names replace whole blocks;
security floors have their own tightening rules.

DNA includes observations beyond managed resources. Module fragments, authority,
source/time and graph projection are governed by
[ADR-017](docs/architecture/decisions/017-dna-composition-and-sync.md),
[ADR-022](docs/architecture/decisions/022-entity-graph-model-and-access-contract.md)
and [ADR-024](docs/architecture/decisions/024-module-observation-vs-convergence.md).
Matching synchronization hashes do not establish fresh observation of every fact.

## Persistence and cluster service

Business, configuration, secrets, timeseries and blob interfaces have distinct
contracts. Business code imports interfaces, not concrete provider packages.
Git is an external editing/sync source, not the current durable backend.

Cluster nodes use shared durable stores and lease-backed authority under
[ADR-031](docs/architecture/decisions/031-controller-cluster-service-model.md).
Serving-node failover also needs endpoint routing; it is distinct from a leader
change. Persisted command/workflow/rollout state does not imply every interrupted
operation resumes automatically. Follow the selected runtime contract.

## Decisions and validation

[Accepted ADRs](docs/architecture/decisions/README.md) own relevant rationale and
constraints. Separate decision-time context, current implementation and future
intent. The current [workflow authority decision](docs/architecture/decisions/036-scoped-automation-grants-and-pre-approved-content.md)
must be reconciled explicitly before broader approved workflow intent is treated
as shipped authorization behavior.

Use [development setup](DEVELOPMENT.md), [test selection](docs/testing/testing-strategy.md)
and [release evidence](docs/testing/release-validation-checklist.md). These paths
replace copied build instructions and unmeasured capacity promises in architecture.
