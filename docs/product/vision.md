# CFGMS Product Vision

> CFGMS manages your clients' Windows, Mac, Linux, and Microsoft 365 estates from one place, keeps every setting where you said it should be, auto-investigates problems, and answers questions about the whole fleet in seconds.

CFGMS is an open-source current-state intelligence and configuration
management platform for managed service providers (MSPs) and IT teams that
run large fleets. It stands on two pillars: zero-trust configuration
management for Windows, macOS, Linux and Microsoft 365, and live query and
execution across every endpoint. Configuration management is one component of
current-state intelligence, not the whole of it; larger configuration systems
exist, and CFGMS does not compete on that axis alone. The target scale is
50,000 or more endpoints per deployment, across many tenants. The reactor and
the workflow engine act on what the two pillars know, through a knowledge
graph built from the DNA of every managed object.

This page holds the intent. The [roadmap](roadmap.md) holds the plan. The
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

**IT teams running their own fleet.** The same system as a single-root,
self-hosted deployment.

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
  on Windows, Linux and macOS. Windows is the first platform.
- **Outpost.** A planned proxy for networks and devices that cannot host a
  steward. Not built yet.

Administrators use the `cfg` command line and web UI served by the controller.

**DNA.** Every managed object has a deterministic, hashable record of its
state. Stewards converge to the desired DNA and report the observed DNA. The
controller keeps the history. Drift is the difference between the two, per
object, over time. Saving configuration deploys it. Safety comes from
targeting, rings and an emergency stop, not from throttling.

**Knowledge graph.** CFGMS links DNA records to each other: which server an
application depends on, which policy set a registry key, what changed on a
device last Tuesday. The three engines read from the graph and write back
to it.

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

## Where it is going

The **troubleshooting cockpit**: the screen that brings the assembled case
to the technician. A case starts from an affected device or application,
shows its dependencies and recent changes from the knowledge graph, names
the likely cause, and offers remediation through the same engines that made
the change.

The digital twin and Digital Employee Experience layers that follow are
sequenced in the [roadmap](roadmap.md#digital-twin--digital-employee-experience-dex--tiered-rollout),
which is also the record of what is built.

## Principles

- **The threat model is the product.** Design for the compromised host and
  the phished admin. No insecure defaults, in any environment.
- **The CLI is the interface.** Anything an administrator can do is a
  documented `cfg` command, not only an API route.
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
