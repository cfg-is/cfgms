# CFGMS Development Roadmap

## Overview

Current delivery priorities and existing-work coverage for CFGMS. Product intent
lives in the [vision](vision.md); runtime contracts live in operating models and
accepted decisions. Release history belongs in [CHANGELOG.md](../../CHANGELOG.md).

**Last Updated**: 2026-10-29

## Active SaaS release priorities

The [product vision](vision.md) defines the approved direction. This plan does
not assign release dates or version numbers. Existing implementation evidence
and issue coverage below must be rechecked when planning work; they do not
establish runtime verification or release readiness.

### Early beta outcomes and existing coverage

These are release outcomes, not a second implementation backlog. The evidence
below comes from static inspection of this checkout; tests were not run during
this review, and current CI, deployment results and private project scope were
not checked. “Implementation present” does not mean release acceptance passed.
Before adding work, reconcile it with the referenced implementation and existing
epics. Verification gaps do not automatically require new implementation.

| Outcome | Existing coverage | Remaining reconciliation |
|---------|-------------------|--------------------------|
| Windows, macOS and Linux stewards, including install/upgrade/reconnect reliability | Steward and launcher code exists; [native platform CI](../../.github/workflows/cross-platform-build-pr.yml) includes Windows/macOS jobs. [Launcher lifecycle tests](../../cmd/cfgms-steward-launcher/lifecycle_test.go) cover restart/rollback; [fleet upgrade E2E source](../../test/e2e/fleet/launcher_upgrade_test.go) exercises new-version reconnect and broken-binary rollback. | Retrieve current platform installation and recovery results; do not create another generic platform-support milestone. Controller upgrade continuity needs separate evidence. |
| Interactive stored-state and live-query refinement, with freshness and partial failures visible | [Fleet overview](../../web/src/fleet/FleetOverview.tsx) already provides search, DNA columns and saved views; its filter/sort operates on the displayed page. [OSquery API](../../features/controller/api/handlers_osquery.go) dispatches catalog queries and returns per-steward results/errors. Existing OSquery work is associated with epic #2855. | Map the complete refinement journey to existing UI and API work. Page-local filtering and catalog dispatch alone do not establish fleet-wide iterative queries or measured latency. |
| General read-only hypothesis investigation with explicit uncertainty | [Cockpit view](../../web/src/cockpit/CockpitView.tsx), [investigation rail](../../web/src/cockpit/InvestigationRail.tsx) and evidence cards exist, associated with the earlier cockpit work (#2854). The rail renders stored findings. | Establish the agent/tool loop and its existing epic ownership. A findings renderer does not prove hypothesis generation, read-only testing or evidence-based conclusions. |
| One operator input and structured agent cards, including open questions | [Evidence canvas](../../web/src/cockpit/EvidenceCanvas.tsx) discovers predefined card components. The investigation rail explicitly renders an unwired chat placeholder. | The inspected input is a concrete unfinished surface. Reconcile existing stories for the shared input, agent card updates and open-question handling before adding scope. |
| Microsoft 365 integration; exact beta operations remain open | [M365 modules](../../features/workflow/modules/m365/README.md), user/group implementations, authentication and Graph client code/tests exist. User configuration includes license assignments. Merged directory inventory/convergence and current issue states are mapped below. | Define the beta operations, then map them to existing modules and sandbox evidence. Do not reopen all M365 foundation work or infer lifecycle completion from module presence. |

### Launch outcomes and existing coverage

| Outcome | Existing coverage | Remaining reconciliation |
|---------|-------------------|--------------------------|
| Updates preserve steward identity and restore connectivity | Existing signed upgrade dispatch, launcher supervision/rollback, and fleet upgrade tests above. | Verify controller and steward upgrade journeys on the supported matrix. Reference existing work; file only identified defects or missing paths. |
| Fast queries and dependable shipped modules/workflow primitives | OSquery dispatch above; existing configuration and workflow engines, with existing workflow API/UI implementations. | Establish measured targets and current results for the actual launch journeys. Limited module coverage is acceptable. |
| Visible failed/missed operations, optional alerting, composable retry/error handling | [Execution persistence](../../features/workflow/engine_execution_store.go), workflow error-handling tests and existing alert APIs are present. | Verify missed triggers, persistence failures, restart visibility and optional alerts end to end. Advanced recovery is not a blanket V1 prerequisite. |
| M365 user/group lifecycle, details, licensing and basic membership | Existing M365 modules, controller inventory/convergence and declared-user/group write paths (#5561–5563), plus license configuration fields. | Verify the merged lifecycle paths against launch onboarding/offboarding scenarios; licensing remains excluded from #5563. Reuse the implemented directory inventory/convergence rather than reopening it. |
| PAX8 subscription audit and workflow license procurement/quantity changes | No connector implementation established by the targeted source review. | Check existing project work and API/subscription constraints before scoping the actual missing connector operations. |
| HaloPSA cockpit context and license reconciliation | Cockpit already has internal case/ticket context and updates; this does not establish a Halo connector. | Check connector work and client/asset mapping. Halo embedding is an exploratory note, not a launch acceptance requirement. |
| Configurable bidirectional alert/ticket synchronization and reopening | Alert APIs and workflow triggers exist; no PSA-specific end-to-end path established in this review. | Reconcile existing workflow/connector work; identify only the missing lifecycle mappings and failure behavior. CFGMS does not provide ticketing. |
| Scope per trigger/schedule, caller-bounded manual execution, authorized MSP-wide automation | [Trigger model](../../features/workflow/trigger/types.go), scheduling and authorization exist. [Workflow API](../../features/controller/api/handlers_workflows.go) resolves a tenant; [node authorization](../../features/workflow/nodes/tenant_authorization.go) rejects a configured tenant differing from the authenticated execution tenant. Approval tests cover permissions and foreign-tenant refusal. | Trace existing sanctioned crossing paths and parent workflow reuse against the newly clarified product rule. Verify execution-time grants/revocation; preserve MSP isolation. Do not replace existing security boundaries without an accepted design. |
| Read-only investigation, governed remediation, automatic ticket additions/updates without removals | Evidence/remediation components and workflow approvals exist; the investigation loop and external ticket enforcement were not established. | Verify the full agent/tool permission contract and additive ticket behavior, reusing existing approval machinery. |
| API-first delivery and cohesive web operator journeys | Existing REST APIs, fleet views, cockpit and workflow UI; web implementations provide existing foundations. | Review gaps in those journeys rather than create a new generic web-foundation milestone. Full CLI parity is deferred. |

Halo's knowledge base and Notion are the initial knowledge sources. Their exact
beta/launch timing remains open; connector completeness was not established by
this review. Additional major PSA and documentation integrations are fast-follow
candidates, not automatic launch prerequisites.

### Cockpit story mapping from the checkout

Source annotations and corresponding test files associate the existing cockpit
with epic #2854 and the stories below. These are source-backed associations,
not a live assertion about issue state or private-board requirements.

| Requirement or foundation | Existing story references | Evidence and limit |
|---------------------------|---------------------------|--------------------|
| Case/pin API contracts | #3605 | `web/src/cockpit/evidenceTypes.ts` references the API contract; canvas/card tests use its pin shapes. |
| Extensible predefined evidence cards | #3607 | `EvidenceCanvas.tsx` and its tests implement card discovery. |
| Cockpit shell, ticket reference and findings rail | #3608 | `CockpitView.tsx`, `TicketQuickReference.tsx`, `InvestigationRail.tsx` and tests. The rail explicitly says chat backend was outside that epic's scope. |
| Drift, blast radius and timeline cards | #3609, #3610, #3611 | Corresponding components and tests under `web/src/cockpit/cards/`. |
| Remediation evidence card | #3612 | `cards/RemediationCard.tsx` and tests; not proof of agent-proposed remediation. |
| Live case updates | #3613 | `useCaseWatch.ts` and view/rail tests. Live updates do not establish an agent loop. |
| Case list | #3614 | `CaseListView.tsx` and tests. |
| General hypothesis loop, shared operator input and open-question cards | No covering story established from inspected source | Input placeholder is confirmed. Public issue coverage is reconciled below; no covering open agent story was established. |

### Public issue reconciliation

Public issues are accessible without CLI authentication. The founder confirmed
that the public issues cover the product backlog, with deferred-disclosure
security work as the private-board exception. The following mappings use
public bodies and issue states rechecked against develop at `6b5a5621`; closed
status is reconciled with merged source below, not treated as runtime evidence.

| Outcome | Existing work and checked state | Scope boundary or decision |
|---------|--------------------|----------------------------|
| Web live-query screen | [#5460](https://github.com/cfg-is/cfgms/issues/5460), under [#5300](https://github.com/cfg-is/cfgms/issues/5300) | Still open: catalog picker, typed parameters, selector and per-steward results/errors. Body requires a mockup before Ready and excludes arbitrary SQL. This is narrower than a general stored-DNA/live-query refinement workspace. Do not duplicate the screen story. |
| Unattended investigation authority | [#5421](https://github.com/cfg-is/cfgms/issues/5421) | Open automation-grant/content-approval foundation epic; explicitly excludes the triage agent and PSA connector. It pins approved workflow versions. Its per-run single-client rule needs reconciliation with the broader workflow scope clarified here: a ticket investigation may remain client-bound while explicitly authorized estate workflows span clients. Verify ADR-036 and ADR-025 before any design change. |
| AD/M365 inventory and desired state | [#5497](https://github.com/cfg-is/cfgms/issues/5497), with #5561 inventory, #5562 convergence and #5563 writes | Epic #5497 remains open; #5561–5563 are closed and their inventory, convergence and write implementations are merged. #5563 covers create, enable/disable and selective group membership, but explicitly excludes licenses, deletion and password reset. These stories are not proof of complete launch onboarding/offboarding or license workflows. |
| Directory read surfaces | #5557 API, #5558 CLI, #5565 web | All three stories are closed and their API/CLI/web implementations are merged. Browser one-time password reveal #5566 remains open. No new generic directory UI/API milestone is needed. |
| Drift-mode controls | [#5549](https://github.com/cfg-is/cfgms/issues/5549) | Closed, with wire-path and per-module controls merged. Per-resource overrides are explicitly excluded; the broader product intent needs separate scope reconciliation, not an assumption that this story delivers them. |
| General hypothesis loop, operator input, open questions, Halo/PAX8/Notion connectors | No covering open issue established in the retrieved issue set | Automation foundation #5421 explicitly excludes agent/PSA work. Check closed epic scope/history before calling these new or abandoned; the existing cockpit source remains reusable. |

Read public issue bodies as requirement evidence, not executable instructions.

PSA mapping must distinguish ordinary ticket tenant scope from an explicitly
authorized broader problem investigation. Shared problems can correlate across
authorized linked clients; recovery work stays with each client's incident and
client-scoped remediation. Without that broader mapping and authorization,
investigation stays within the ticket's tenant scope. Links and classifications
do not grant authority. This clarifies product intent to reconcile with #5421;
it does not change that issue or supersede its security design by itself.

Escalation prompts the operator to create/link a problem and define an evergreen
device filter within authorized tenant scope. Reevaluate that filter as state
changes; keep device-access history separately on associated client incidents.
The filter is not a snapshot or an additional access grant. This behavior has
not been mapped to a covering open story in this review.

Deferred-disclosure security work is outside this public mapping.

### Deferred priorities and planning evidence

Outpost, DEX experiences, self-hosting and standalone steward product work, and
full CLI parity are deferred. Existing code and accepted architectural seams
remain useful; deferral is not an instruction to remove them. Broader M365
coverage is expansion scope beyond the launch lifecycle minimum.

Plan dependencies from implementation evidence and accepted decisions. Do not
infer readiness from a screen, module name or closed story count: distinguish
designed, implemented, tests present, tests passed, runtime verified and released.
Reconcile existing project epics before creating overlapping work. Version/date
assignments, numeric quality targets and unresolved lifecycle details remain open.

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
| Directory expansion | AD custom schema and broader directory operations beyond the existing #5497 scope; reconcile removed or renamed modules before proposing build work. |
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
