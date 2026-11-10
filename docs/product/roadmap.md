# CFGMS Development Roadmap

The [vision](vision.md) owns product intent. This page owns release priorities,
existing-work pointers and remaining scope decisions. Issues own executable work;
[CHANGELOG.md](../../CHANGELOG.md) owns release history. Reconcile source and
current issue scope before scheduling: a release outcome is not a new build task,
and implementation is not proof of runtime verification or release readiness.

## Active SaaS release priorities

No dates or version numbers are assigned here. API-first delivery prioritizes a
cohesive web experience. Limited shipped module coverage is acceptable; silent
failures are not. Full CLI parity is deferred.

### Early beta

| Outcome | Existing foundation and next scope decision |
|---------|--------------------------------------------|
| Windows, macOS and Linux stewards | Reuse native-platform CI, installer and launcher recovery work. Verify install, upgrade and reconnect on the supported matrix rather than open another generic platform epic. |
| Interactive stored-DNA and live-query workspace | Fleet search/DNA views and catalog OSquery dispatch exist. [#5460](https://github.com/cfg-is/cfgms/issues/5460) defines the web catalog screen under #5300. Refine the full fleet-wide query journey, freshness and partial results without duplicating that story. |
| General read-only investigation agent | Reuse cockpit #2854, evidence cards and case updates. Define hypothesis/tool iteration, a shared operator input and open-question cards; existing findings rendering does not establish those capabilities. |
| Microsoft 365 integration | Reuse directory inventory/convergence and read surfaces under [#5497](https://github.com/cfg-is/cfgms/issues/5497). Exact beta operations remain a product scope decision. |

#### Early-beta delivery enablers

These do not add operator features. They are how merged changes are validated
continuously on a running deployment before beta users depend on them.

| Enabler | Existing work and boundary |
|---------|----------------------------|
| Continuous deployment to a test cell | [#5980](https://github.com/cfg-is/cfgms/issues/5980): a pull-based flow on the test cell's own infrastructure builds, signs with a test-cell key and deploys the newest green `develop` revision to the controller and, when steward code changed, the steward fleet, with automatic rollback. CI publishes no per-commit artifacts or signed releases. Steward auto-rollout depends on fix issues [#5976](https://github.com/cfg-is/cfgms/issues/5976) and [#5977](https://github.com/cfg-is/cfgms/issues/5977). Production deployment is out of scope. |
| Zero-downtime schema evolution | [#5978](https://github.com/cfg-is/cfgms/issues/5978): an N/N-1 expand/contract contract so schema changes ship under continuous rolling deploys. |
| Test-cell observability and alerting | [#5979](https://github.com/cfg-is/cfgms/issues/5979): signals, deploy markers, retained history and an alert sink that an agent operations session consumes. Thresholds are measured before they are set. |
| Continuous load and chaos | [#5981](https://github.com/cfg-is/cfgms/issues/5981) runs low-footprint virtual and real stewards against the test cell continuously. [#5982](https://github.com/cfg-is/cfgms/issues/5982) runs scheduled fault injection checked against steady-state hypotheses. |
| Agent user accounts | An AI agent that owns the test cell (deploys, exercises every user flow, runs high-velocity QA) acts as a **user**, not a machine principal: its own named account, roles, tenant and environment scope, audit records marked as agent, and a human able to disable it. A presence tap proves the account holder approved the action, not that a human is present; synced and password-manager passkeys are already allowed, so an agent's software passkey carries the same assurance. A later per-tenant policy may require hardware-bound passkeys, which would also exclude agent software passkeys. Needs its own ADR and planning session; reconcile with the ADR-036 §3 triage-agent framing. Continuous deployment itself uses the API-key rollout credential (ADR-036 Amendment 1). Not decomposed. |

The deploy agent, load harness and chaos runner live in the
[cfgms-tooling](https://github.com/cfg-is/cfgms-tooling) repository. Product
hooks stay in this repository. Test-cell environment details are kept out of
both.

### Launch

| Outcome | Remaining acceptance or scope boundary |
|---------|---------------------------------------|
| Reliable updates, queries and shipped operations | Preserve steward identity/connectivity through controller/steward updates. Agree measured quality targets for live queries and shipped modules/workflows. Verify failed/missed operations are visible with optional alerts; retry/error handling is composable. Advanced recovery is not a blanket V1 gate. |
| M365 onboarding/offboarding and licensing | User/group lifecycle, details, licensing and basic membership. Existing directory write story #5563 excludes licenses, deletion and password reset; define complete launch scenarios without silently enlarging that story. |
| PAX8 | Subscription visibility/audit and procurement/quantity changes as onboarding/offboarding workflow steps, subject to API capabilities and subscription terms. Establish connector ownership against existing work before filing more. |
| HaloPSA | Ticket/client/asset context for the cockpit, license-count reconciliation and configurable bidirectional alert lifecycle workflows. Halo embedding is exploratory, not a launch gate. |
| Authorized automation and investigation | Trigger/schedule scope, caller-bounded manual runs, revocation, delegated reuse and authorized MSP-wide workflows. Reconcile [#5421](https://github.com/cfg-is/cfgms/issues/5421) with [ADR-036](../architecture/decisions/036-scoped-automation-grants-and-pre-approved-content.md) and [ADR-025](../architecture/decisions/025-tenant-access-boundary.md); the epic covers approval foundations, not the triage agent or PSA connector. The vision owns incident/problem escalation, evergreen filters, read-only investigation and additive ticket-update rules. |

Halo knowledge base and Notion are the initial knowledge sources; exact release
timing remains open. Additional major PSA/documentation connectors are fast-follow
candidates, not automatic launch requirements.

### Existing implementation owners

Use these paths to ground planning rather than maintaining a parallel story-status
ledger here. Fetch current issue scope/status when acting on a reference.

- [Fleet overview](../../web/src/fleet/FleetOverview.tsx) filters the displayed
  page; [OSquery API](../../features/controller/api/handlers_osquery.go) dispatches
  catalog queries with per-steward rows/errors. Neither alone establishes the
  intended iterative workspace.
- [Cockpit view](../../web/src/cockpit/CockpitView.tsx),
  [investigation rail](../../web/src/cockpit/InvestigationRail.tsx) and
  [evidence canvas](../../web/src/cockpit/EvidenceCanvas.tsx) own current surfaces.
  Reconcile agent/input scope against existing #2854/#5421 work.
- [M365 inventory and convergence](../../features/controller/directory/),
  [directory web views](../../web/src/directory/) and
  [M365 modules](../../features/workflow/modules/m365/README.md) provide existing
  paths. #5561–5563 cover inventory/convergence/writes; #5557/#5558/#5565 cover
  API/CLI/web reads. #5566 covers browser one-time password reveal.
- [Launcher lifecycle](../../cmd/cfgms-steward-launcher/lifecycle_test.go) and
  [fleet upgrade tests](../../test/e2e/fleet/launcher_upgrade_test.go) cover recovery
  scenarios; inspect actual runs for release acceptance. [Execution persistence](../../features/workflow/engine_execution_store.go)
  provides workflow record infrastructure, not proof that every missed trigger or
  restart scenario is handled.
- #5549 covers drift controls through the wire and per-module overrides; it
  excludes per-resource overrides. Reconcile that remaining granularity with the
  vision instead of claiming the full control model is delivered.

### Deferred priorities

Outpost, DEX experiences, self-hosting and standalone steward product work, full
CLI parity and broader M365 coverage are deferred. Existing code and accepted
contracts remain reusable. Version/date assignments, numeric quality targets and
exact lifecycle actions require evidence and explicit scope decisions.

## Deferred capability direction

DEX should establish application/device baselines, experience timelines and
hardware recommendations based on observed performance. Scoring, correlation,
predictive recommendations and experience-driven remediation require measured
signals and validated collection overhead. Detailed collection technology and
numeric budgets need evidence before commitment. Cross-client aggregation needs
an explicit authorization and consent design.

Graph and temporal contracts already live in
[ADR-017](../architecture/decisions/017-dna-composition-and-sync.md),
[ADR-022](../architecture/decisions/022-entity-graph-model-and-access-contract.md)
and [ADR-023](../architecture/decisions/023-entity-graph-storage-shape.md).
These remain relevant to current queries and investigations; deferring DEX does
not defer existing graph contracts. Future simulation and expanded discovery
must build on those contracts rather than introduce a parallel model.

Outpost provides future network observation and proxy/cache capabilities.
Additional SaaS, PSA, RMM and knowledge connectors follow demand and beta feedback.
Candidates include broader M365 services, other cloud suites, ConnectWise Manage,
Autotask, SyncroMSP, ScreenConnect, Datto RMM, IT Glue and Hudu. These are actual
integration candidates, not launch commitments or examples of fictional clients.

## Unscheduled candidates requiring reconciliation

These preserve capability requests from the prior backlog without retaining its
stale claims about what is missing. They are not new unchecked build tasks.
Before scheduling, inspect current source, accepted decisions and open/closed
issues; remove candidates already delivered or covered elsewhere.

| Area | Candidate outcome and current source of constraints |
|------|----------------------------------------------------|
| Controller operations | Online backup/restore; steward recovery across controller peers consistent with ADR-007, ADR-013 and ADR-031. |
| Recovery and workflow debugging | Progressive rollback, health verification, resume/retry and live workflow debugging. Reuse current rollback and execution infrastructure; advanced recovery is not a blanket launch gate. |
| Configuration composition | Conditional inheritance, templates and expressions using DNA; reconcile existing DNA-filtered role matching before defining new behavior. |
| Credentials and trust | Local-user credential distribution/rotation, script publisher-chain verification, operator signing and enrollment proof. Check current secret/trust decisions and security work before declaring gaps. |
| Directory expansion | AD custom schema and broader directory operations beyond the existing #5497 scope, including comparing two directories (for example on-premises AD against M365) and OU hierarchy / domain DNA, both built on stored directory DNA; reconcile removed or renamed modules before proposing build work. |
| Operator administration | Terminal-session controls and credential-store coverage; inspect current API/CLI/web implementations rather than infer absence from old docs. |
| Module platform coverage | Backend-specific stdlib and runner coverage plus missing inventory facts, evaluated individually against current module code and tests. |
| Authorization | Effective role grants and revocation, reconciled with the current request path and scoped automation design. |
| Endpoint live operations | Process/service telemetry, control and remote shell: reuse existing asset tabs and epic #2738; assess remaining gaps from reachable code and current issue scope. |

## Release and architecture references

Use [Versioning Policy](../development/versioning-policy.md) for release rules,
[CHANGELOG.md](../../CHANGELOG.md) for released history, and
[LICENSING.md](../../LICENSING.md) for licensing. No new LTS or compatibility
promise is introduced by this roadmap.

Architecture belongs in [operating models](../architecture/README.md) and
[accepted decisions](../architecture/decisions/README.md), rather than duplicated
roadmap architecture sections. Epic readiness and verification terminology live
in [Product Planning](../development/product-planning.md).

## Capability Tags

Feature work is tagged with the **product capability that consumes it** — the end-in-mind, not the topic. Tags are **multi-valued**: a story that serves several capabilities carries all of them, and a multi-tag story is a signal that it is *foundational* — its schema/interface must satisfy every listed consumer at once. This is how the twin's and DEX's Tier-1 data-model commitments get built in early instead of retrofitted.

Controlled vocabulary (grows deliberately, not ad hoc):

- `cms` — core config management: desired-state convergence, drift, modules
- `twin` — digital twin: entity model, topology graph, temporal state, simulation
- `dex` — digital employee experience: endpoint experience signals, baselines, root-cause
- `workflow` — automation / workflow engine
- `directory` — identity & directory services (M365, AD/Entra)
- `web` — web UI and visualization surfaces
- `msp` — MSP tool integrations (PSA / RMM / documentation)

Applied going forward (backlog + future work); pure hygiene/infra (CI, refactors, security sweeps) carries no capability tag. Roadmap items carry these tags inline; the parallel **`cap:*` GitHub label namespace** (orthogonal to Projects-V2 work-queue state, purely descriptive, multi-valued) is live end-to-end — created by `/agent-setup`, applied at epic/story creation via `pipeline-helper.sh create-epic|create-story --cap`, inherited epic→story at decomposition (`.claude/agents/po.md` decomposition guidance, `ba.md`), and carried issue→PR by `lock-sweep`. A capability tag names the *consumer* of the work, never queue state. It coexists with the community **component** labels (`workflow`, `dna`, `security`, `api`, `modules` in `docs/development/issue-triage.md`), which are a distinct *topic* axis — cap = who consumes it, component = what it's about.
