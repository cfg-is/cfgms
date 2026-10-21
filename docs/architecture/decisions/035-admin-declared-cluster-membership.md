# ADR-035: Admin-Declared Cluster Membership

**Status:** Accepted

**Date:** 2026-10-21

**Deciders:** Founder, Architecture

**Related:** Issue [#5343](https://github.com/cfg-is/cfgms/issues/5343). ADR-017 (cluster registry from steward DNA).

---

## Context

Cluster membership is derived from what each steward reports about itself: `clusterregistry.BuildRegistry` records a steward as a member of a cluster when its DNA carries a `cluster:<name>` fragment. The config cascade and role-owner reconciliation use that result. The threat model (`CLAUDE.md`) assumes stewards may run on compromised hosts, so a compromised steward can choose which `cluster-policies` layer it receives by emitting a fragment. The entity-graph path (`dnasync.ClusterMembership`) already requires a controller-side answer and production has no implementation.

## Decision

1. **Administrators declare cluster membership.** A declaration is the only source of authority for "steward S is a member of cluster C".
2. **DNA `cluster:<name>` fragments are evidence, not authority.** They are shown to administrators as candidates for declaration. A claim that does not match a declaration is ignored for every authorization purpose and is surfaced to administrators.
3. **Storage.** A declaration is a JSON document in `ConfigStore` (`pkg/storage/interfaces`) at `ConfigKey{TenantID: <cluster tenant>, Namespace: "cluster-members", Name: <clusterName>}`, listing the member steward IDs. This is the same pattern `role-policies` uses. No new storage interface is added; it works on the flatfile, sqlite and database providers.
4. **Tenant boundary.** A declared member counts only when the steward's fleet tenant equals the tenant of the declaration. A steward declared in a tenant other than its own is never a member.
5. **Fail closed.** The reader returns no errors. Any store error other than `ErrConfigNotFound`, and any malformed document, yields "not a member". A read fault never grants membership.
6. **Migration is an explicit adoption step.** Existing clusters become declared only when an administrator adopts them. There is no automatic import of DNA-derived membership, because that would turn existing self-claims into authority.

## Consequences

- The reader (`clusterregistry.DeclaredMembership`) satisfies `dnasync.ClusterMembership` structurally.
- Until follow-up stories wire it into the cascade, reconciliation and entity graph, behaviour is unchanged.
- Declared membership must be maintained by administrators; undeclared clusters have no members for authorization.

## Out of Scope

REST endpoints, the `cluster:manage-members` permission, the CLI, wiring into callers, and automatic discovery from hypervisor or cluster APIs are delivered by follow-up stories.
