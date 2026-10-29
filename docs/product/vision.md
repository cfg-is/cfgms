# CFGMS Product Vision

> CFGMS manages your clients' Windows, Mac, Linux, and Microsoft 365 estates from one place, keeps every setting where you said it should be, auto-investigates problems, and answers questions about the whole fleet in seconds.

CFGMS is an open-source, multi-tenant management and monitoring platform for
managed service providers (MSPs). The current delivery priority is a hosted SaaS
service. Declarative configuration management, extensible modules and a workflow
engine provide the foundation for managing endpoints, SaaS resources,
directories, users and groups.

The central product outcomes are trustworthy visibility into current state and
fast investigation: technicians refine queries interactively, inspect related
resources through the DNA knowledge graph, and use an agentic troubleshooting
cockpit to investigate problems and propose remedies.

This page describes intended product behavior, not proof of implementation or
release readiness. It holds the intent. The [roadmap](roadmap.md) holds the plan. The
[decision records](../architecture/decisions/README.md) hold the decisions.

## The problem

A technician with a ticket has a symptom on one device. The cause is in a
dependency, a recent change, or the tenant's configuration, and each lives in
a different tool with its own login. The technician moves between monitoring,
ticketing, documentation, remote access and the configuration system to
assemble the case by hand. Senior people spend their day doing this for
routine tickets, and the fleet drifts while nobody is looking.

Existing configuration systems were built for one organisation's servers.
They assume a trusted network, a trusted host and a trusted administrator.
An MSP managing hundreds of client environments has none of those. Its
management plane is the one target that opens every client at once.

## Who it is for

**MSPs first.** Many clients on one platform, where tenancy, delegated access
and bounded blast radius are the product. Tenants nest: distributor, MSP,
client, site, with configuration inherited from root to leaf.

**Self-hosted IT teams and standalone operators.** These remain possible uses
of the code, but self-hosting and standalone steward product work are deferred
while the MSP SaaS launch takes priority.

**Operators of a hosted CFGMS service.** The same code as a multi-tenant cell
with a shared root of trust ([ADR-032](../architecture/decisions/032-saas-deployment-topology-and-trust.md)).
Single-root and multi-root are deployment shapes, not licence tiers.

## What CFGMS is

Three components:

- **Controller.** The control plane: configuration store, fleet state,
  tenancy, REST API, workflow engine, web UI. Runs on Linux and Windows.
  Linux is primary.
- **Steward.** The agent on every managed endpoint. It converges the host to
  its desired state, reports what it observes, and runs signed modules. Runs
  on Windows, Linux and macOS; all three are required from early beta.
- **Outpost.** A planned proxy for networks and devices that cannot host a
  steward. Not built yet.

The platform is API-first. The web interface is the primary launch experience;
the `cfg` command line remains available, with full interface parity deferred.

**DNA.** Modules report observed facts about resources even when their
configuration is not managed. Stewards collect endpoint facts; controller-side
modules collect SaaS and directory facts, including users and groups. Facts
retain their source module and observation time and form a hashable state record.
Only configuration explicitly governed by policy is enforced or monitored for
configuration drift.

Observation runs periodically and can respond to system hooks where available.
Stewards push observed changes and include a DNA hash in heartbeats so the
controller can detect missed synchronization and request a resync. A matching
hash establishes agreement with the steward's reported state; it does not make
an old observation fresh. Most information queries use controller-held DNA;
persistent connections support live endpoint queries when needed.

**Declarative configuration.** Continuous enforcement is the default, with
behavior configurable by resource and policy. Configuration cascades from MSP
root through clients, DNA-filtered groups and devices. Overlapping policies
resolve deterministically, and effective values should be traceable to their
sources. Exact precedence follows the configuration contract and implementation.
If desired state is wrong, remediation requires a reviewed and approved policy
change. If desired state is correct but enforcement failed, remediation restores
compliance without changing policy.

**Knowledge graph.** CFGMS links DNA records to each other: which server an
application depends on, which policy set a registry key, what changed on a
device last Tuesday. Directory identities, device usage, SaaS accounts and
licenses connect through the same graph while preserving the source observations.

**Zero trust.** Every internal connection is mutual-TLS gRPC over QUIC.
Modules are publisher-signed and verified end to end; the controller never
strips and re-signs. Secrets live in the OS keychain or encrypted at rest,
never in cleartext on disk, in any environment. The threat model assumes
managed hosts get compromised and administrator accounts get phished, and
bounds the damage when they do. Code that runs on endpoints looks like
ordinary administrative tooling: declared paths, signed binaries, no runtime
code composition.

**Modules.** Files, services, packages, scripts, firewall, patching, users,
certificate trust, time and hostname ship as the standard library in the
steward installer. Anything else can be added with an extended module, pulled on demand and trusted through the same signing chain.

**One binary.** Controller and steward are self-contained Go binaries. No
interpreter, no external runtime to patch.

## The three engines

**Live fleet query and execution.** Ask the fleet a question and get a live
answer from every endpoint at once. Which machines run the vulnerable
version? Who is logged in right now? Then act on the answer at the same
speed, across the whole fleet, when a fix cannot wait for a ringed rollout.

**The reactor.** A device drifts, a user is added, a certificate nears
expiry. The reactor matches each event against the reactions the
administrator declared and runs them.

**The workflow engine.** Multi-step processes built once and run for every
tenant: onboard a user, decommission a laptop, rotate a secret across a
client. Workflow modules run on the controller against cloud APIs. Steward
and outpost modules run where the resource is.

Workflow definitions are reusable logic. Each schedule or trigger supplies its
authorized execution scope; manual execution is bounded by the caller's
permissions. Automated grants are checked again at execution, including
revocation. Authorized automation may span an MSP's clients, but cannot cross
into another MSP. Editing shared definitions is controlled separately from
creating triggers or running them. Client-scoped users can run available parent
workflows only within their authorized scope.

Prebuilt workflows provide defaults for alert synchronization, approvals and
remediation. MSPs can adapt them and compose retry and error handling using the
same workflow primitives.

## Investigation and alert management

The **interactive query workspace** lets technicians build and refine questions
and results immediately, using stored state and live queries as appropriate.
Freshness, missing observations and partial results must be visible.

The **troubleshooting cockpit** starts from a problem description, alert or
external ticket. An agent ranks hypotheses, uses read-only queries against DNA
and endpoints to support or reject them, and revises its investigation as
evidence arrives. It identifies a cause when evidence supports one and makes
uncertainty explicit when it cannot establish a cause.

The operator has one chat-like input for descriptions, instructions and answers.
The agent responds through predefined visualization cards for hypotheses,
evidence, findings, proposed actions and open questions. Open questions request
information the agent cannot observe, such as visible indicators on a modem.
The operator answers through the shared input, and the agent updates its cards.

Investigation is read-only toward managed systems. Remedies reuse execution
modules, scripts and workflows under configured permissions and approval rules;
ad hoc scripts can be presented for review. The agent may automatically add
comments, associate assets and update external ticket information, but must not
automatically remove things.

CFGMS owns alert state and lifecycle, not a ticketing system. Modular PSA
connectors support configurable bidirectional synchronization: a cleared
condition can update or close a ticket, and ticket closure can close an alert,
with rules for reopening when the condition persists. The cockpit brings in
client and asset context and searches connected knowledge bases.

PSA mapping defines how client incidents link to a shared problem record and
how those records map to authorized tenant scope. Without an explicitly mapped
and authorized broader problem scope, investigation is limited to the ticket's
tenant scope. An MSP-level problem can correlate evidence across its authorized
linked clients; each client's impact and recovery work remains on its linked
incident, with client-scoped remediation and applicable approvals. A problem
link or ticket classification alone never grants additional access.

When evidence suggests a shared cause, the agent prompts the operator to create
or link a problem record and define its device filter and authorized tenant
scope. The filter is evergreen: it describes the problem conditions, such as an
installed update, and is reevaluated as state changes. It is not a device
snapshot and never extends the authorized tenant scope. Associated client
incidents separately retain a historical record of devices accessed during the
investigation, even when those devices no longer match the filter.

## Release priorities

**Early beta:** Windows, macOS and Linux endpoints, Microsoft 365 integration,
the interactive query workspace and the agentic troubleshooting cockpit. Exact
Microsoft 365 beta coverage remains to be scoped.

**Launch:** dependable updates that preserve steward connectivity, fast live
queries, reliable shipped configuration modules and workflow primitives, and
visible failed or missed operations with optional alerting. Limited module
coverage is acceptable; silent failures are not. Numeric quality targets require
measurement and explicit agreement.

Microsoft 365 launch scope includes user and group lifecycle, user details,
licensing and basic membership configuration. PAX8 supplies subscription
visibility and auditing, and license procurement or quantity changes as
onboarding/offboarding workflow steps, subject to provider capabilities and
subscription terms. HaloPSA is the first PSA connector, centered on ticket
context in the cockpit and license-count reconciliation. Embedding the cockpit
in a Halo ticket is an exploratory note, with no launch acceptance requirement. Halo's knowledge base
and Notion are the initial knowledge sources; exact delivery timing remains open.

**Later:** Outpost, DEX, additional connectors, self-hosting and standalone
steward product work, and full CLI parity. DEX should establish application and
device performance baselines and guide hardware decisions using measured user
experience rather than device age alone. Estimated productivity benefits need
supporting evidence.

Deferred graph and DEX direction is described in the
[roadmap](roadmap.md#deferred-capability-direction); detailed sequencing follows
current operator needs and accepted architecture contracts.

## Principles

- **The threat model is the product.** Design for the compromised host and
  the phished admin. No insecure defaults, in any environment.
- **API-first, web-prioritized delivery.** Expose capabilities through the API
  and prioritize cohesive web operator journeys for the SaaS launch.
- **Composable operations.** Reuse modules and workflow primitives for
  configuration, investigation and remediation, with explicit authorization.
- **Evidence before readiness claims.** Distinguish design, implementation,
  test results, end-to-end verification and released behavior.
- **Pluggable by default.** Storage, logging, secrets, directory and
  transport are providers with interchangeable backends, so one codebase
  runs as a self-hosted controller or a hosted cell.
- **Clean breaks before 1.0.** A breaking change with a clear error beats a
  migration shim.

## Licensing

All CFGMS code is AGPL-3.0. Self-hosting it to manage client environments is
covered by that licence. A commercial embedding licence is available for
third parties shipping CFGMS inside proprietary products. See
[LICENSING.md](../../LICENSING.md).
