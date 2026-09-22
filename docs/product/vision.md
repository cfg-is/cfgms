# CFGMS Product Vision

CFGMS is the Configuration Management System: an open-source, zero-trust
configuration management system for managed service providers (MSPs) and the
IT teams that run large fleets. It manages Windows, Linux and macOS endpoints
from one control plane, at a target scale of 50,000 or more endpoints per
deployment, across many tenants.

This document says why CFGMS exists, who it is for, what it is today, and the
direction it is building toward. The [roadmap](roadmap.md) holds the plan.
The [architecture decision records](../architecture/decisions/README.md) hold
the decisions. This page holds the intent those two serve.

## The problem

An MSP technician who gets a ticket does not have the problem in front of
them. They have a symptom on one device. The cause is somewhere in the
device's dependencies, in a recent change, or in the tenant's configuration,
and each of those lives in a different tool. Remote monitoring, ticketing,
documentation, remote access and the configuration system are separate
products with separate logins. The technician navigates between them to
assemble the case by hand. That navigation is the waste. Senior technicians
spend their day doing it for routine tickets, and the fleet's configuration
drifts while nobody is looking at it.

The configuration systems that exist today were built for a single
organisation's servers, not for one provider managing hundreds of client
environments. They assume a trusted network, a trusted host, a trusted
administrator. An MSP has none of those guarantees. Their management plane
is a high-value target: a compromised MSP controller compromises every
client at once.

## Who it is for

**Primary: MSPs.** A provider managing many clients from one platform,
where tenancy, delegated access and blast-radius bounds are the product,
not a feature. The tenant model is recursive: an MSP under a distributor,
clients under the MSP, sites under the client, with configuration
inherited root to leaf.

**Secondary: IT teams running their own fleet.** A single-root deployment
of the same system, self-hosted under the AGPL.

**Also: the operator of a hosted CFGMS service.** The same code runs as a
multi-tenant cell with a shared root of trust ([ADR-032](../architecture/decisions/032-saas-deployment-topology-and-trust.md)).
Single-root and multi-root are deployment shapes, not licence tiers.

## What CFGMS is

CFGMS is three cooperating components:

- **Controller** — the central control plane. Configuration store, fleet
  orchestration, tenancy, REST API, workflow engine, web UI. Runs on Linux
  and Windows; Linux is primary.
- **Steward** — the agent on every managed endpoint. Converges the host to
  its desired state, reports its observed state, and runs signed modules.
  Runs on Windows, Linux and macOS. Windows is the first platform.
- **Outpost** — a planned proxy for networks and devices that cannot host a
  steward. Not built yet.

Administrators use the `cfg` command line and the REST API. The web UI is
served by the controller and is in early development.

**Desired state, expressed as DNA.** Every managed object has a
deterministic, hashable representation of its state. Stewards converge to
the desired DNA, report the observed DNA, and the controller keeps the
history. Drift is the difference between the two, per object, over time.
Saving configuration is deploying it. Safety comes from targeting, rings and
an emergency stop, not from throttling.

**Zero trust, end to end.** Every internal connection is mutual-TLS gRPC
over QUIC. Modules are publisher-signed and verified end to end; the
controller never strips and re-signs. Secrets live in the OS keychain or
encrypted at rest, never in cleartext on disk, even in development. The
threat model assumes managed hosts may be compromised and administrator
accounts may be phished; rarely-touched settings bound the blast radius of
either. Code that runs on endpoints behaves like predictable administrative
tooling: declared paths, signed binaries, no runtime code composition.

**One binary, no runtime.** Controller and steward are self-contained Go
binaries. No interpreter, no external runtime to patch.

**Modules as the unit of management.** Files, services, packages, scripts,
firewall, patching, users, certificate trust, time and hostname ship as the
standard library in the steward installer. Everything else is an extended
module, pulled on demand and trusted through the same signing chain.

**Integrations as facts.** Microsoft 365, Active Directory and endpoint
management APIs are integrated where the code exists, and described only
where it does.

## Where it is going

The direction is the **troubleshooting cockpit**: the screen that brings the
assembled case to the technician instead of making them browse to it. A case
starts from an affected device or application, shows its dependencies and
recent changes, identifies the likely cause, and offers safe remediation
through the same configuration and workflow system that made the change.
Other tools report that something is wrong. CFGMS is built to connect the
symptom to the cause and fix it.

Two layers make that possible, and they are built in tiers on the DNA
foundation that exists today ([roadmap: tiered rollout](roadmap.md#digital-twin--digital-employee-experience-dex--tiered-rollout)):

- **Digital twin** — a live model of the estate: typed entities, their
  relationships, and their state over time. CFGMS already owns the
  expensive half, actuation and desired state, that observe-only twins
  lack.
- **Digital Employee Experience (DEX)** — knowing whether a user's
  experience on a device or application is degraded, and why, against fleet
  baselines, with remediation through configuration. DEX is the twin's
  first consumer.

Milestones, sequencing and what is built at any moment are in the roadmap.
This document does not claim any of that is built.

## Principles

- **The threat model is the product.** Design for the compromised host and
  the phished admin. No insecure defaults, ever, in any environment.
- **Docs describe what exists.** A capability is documented when it ships.
  What is coming lives in the roadmap.
- **The CLI is the interface.** Anything an administrator can do exists as
  a documented `cfg` command, not only as an API route.
- **Pluggable by default.** Storage, logging, secrets, directory and
  transport are central providers with interchangeable backends, so the
  same code runs as a single self-hosted controller or a hosted cell.
- **Pre-release means clean breaks.** Until 1.0, a breaking change with a
  clear error beats a migration shim.

## Non-goals

- CFGMS is not a ticketing or documentation system. It integrates with
  them; it does not replace them.
- CFGMS does not throttle configuration delivery as a safety mechanism.
  Safety is targeting, rings and the emergency stop.
- CFGMS does not run unsigned or composed code on endpoints, and offers no
  setting that makes it do so outside a development trust mode.

## Licensing

All CFGMS code is licensed under the AGPL-3.0. Self-hosting and using it to
manage client environments is covered by that licence. A commercial
embedding licence is available by private agreement for third parties
shipping CFGMS inside proprietary products. There is no separate
"commercial edition" and no feature gated behind one. See
[LICENSING.md](../../LICENSING.md).

---

**Status:** Draft for founder review, 2026-09-22. Replaces the 2024-04-07
draft.
