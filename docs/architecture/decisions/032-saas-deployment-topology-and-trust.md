# ADR-032: SaaS Deployment Topology and Trust Hierarchy — Cells, Shared Root, Steward-Held Keys

**Status:** Accepted

**Date:** 2026-09-01

**Deciders:** Founder, Architecture

**Related:** Epic [#3752](https://github.com/cfg-is/cfgms/issues/3752) (this ADR is its design gate). ADR-031 (controller cluster service model — companion; a cell IS an
ADR-031 cluster). ADR-007 (shared PostgreSQL / blob / vault backend — the cell's
substrate). ADR-013 (steward–controller trust anchoring — amended here). ADR-021
(identity assurance — Amendment 5 restated here). ADR-025 (tenant access boundary —
ID grammar amended here). ADR-030 (secret material at rest — CA wording amended
here).

---

## Context

CFGMS SaaS must serve MSP tenants across jurisdictions and geographies from managed
infrastructure, while the same codebase continues to run as a single self-hosted
node for individual MSPs. Three properties are expensive or impossible to retrofit
and must be decided before the first production tenant or endpoint exists:

1. **The certificate trust root.** A steward pins its trust anchor at enrollment;
   moving to a different anchor is a wipe-and-re-enroll of the endpoint (ADR-013
   §4, enforced in the steward's trust-downgrade check). Whatever root the first
   beta endpoint pins is permanent for that endpoint.
2. **Tenant identity.** Tenant IDs today are unqualified DNS-label tokens, unique
   only within one deployment. Two deployments can mint the identical ID. Any
   future with more than one deployment — regions, federation, cross-deployment
   audit — collides. Retrofitting a qualifier after real tenants exist is a data
   migration.
3. **Where private keys are born.** The registration path today generates the
   steward's mTLS keypair on the controller, returns the private key in the
   registration response, and writes it to controller disk. This contradicts the
   project's own secret-handling rules, concentrates every endpoint's key material
   in one place, and is the largest data-residency liability in the system —
   larger than the CA topology itself.

Two further facts constrain the design. The current CA is a single self-signed
certificate created with a path-length constraint of zero — it is cryptographically
incapable of signing a subordinate CA, and the constraint is immutable once the
certificate exists. And steward TLS verification is standard chain validation
against a certificate pool (verified empirically): a steward that trusts a root
accepts any leaf chaining through any intermediate under that root. The enrollment
fingerprint pin applies at enrollment time only, never at handshake.

Cross-region write stretching is rejected on physics: synchronous replication taxes
every write with intercontinental latency; asynchronous replication breaks the
transactional delivery guarantee ADR-031 Decision 2 rests on. Regions therefore
replicate the system, not the database.

## Decisions

### Decision 1 — The SaaS unit of deployment is the cell

A **cell** is one complete CFGMS deployment: an ADR-031 controller cluster with its
own shared database, blob store, and vault, hosting one root tenant whose children
are MSP tenants. The beta deployment is cell #1, sized for the beta target
(~15–20k endpoints); it is not a prototype to be replaced but the first instance of
the permanent shape.

- **Endpoint count never forces a new cell.** One cell scales to the 50k+ design
  target by adding nodes (ADR-031). Cells are created for exactly two reasons:
  data-residency requirements and admin-latency geography.
- Cells share no runtime state. Cross-cell concerns (tenant→cell directory, admin
  routing, cross-cell operations view) are a thin layer above cells, deferred
  until a second cell is justified.
- **Single-root stands.** Each cell has exactly one root tenant; MSPs are children
  of it. The multi-root-in-one-deployment SaaS illustration in the controller
  operating model is redrawn as cells; the single-root statement in
  ARCHITECTURE.md is the picture that stands.

### Decision 2 — One offline root CA; one intermediate CA per region

- A single CFGMS SaaS **root CA** is created once, kept offline, and used only to
  sign regional intermediate CAs. It is the trust anchor every SaaS steward pins.
- Each region operates an **intermediate CA** whose private key and issuance
  records remain in-region (held in that region's vault, per ADR-030's model with
  "cluster CA" re-scoped to "regional intermediate"). Cells issue leaf
  certificates from their region's intermediate and distribute the leaf together
  with its intermediate as a chain.
- Because every steward trusts the shared root, endpoints in different regions
  trust each other's certificates, and a tenant can in principle move between
  cells without touching endpoints. The re-pointing mechanism (ADR-013 §4's
  signed update channel) remains designed-not-built; building it is scheduled
  work, not a beta prerequisite.
- **Hard prerequisite with a deadline:** the CA generation code must gain
  intermediate-capable path-length settings, chain-aware issuance and
  distribution, and external/offline-root import **before the SaaS root is
  created** — and the root must exist **before the first beta endpoint enrolls**.
  A root created from today's code can never sign an intermediate, and every
  endpoint enrolled against a wrong root is a future wipe-and-re-enroll.
- Compromise and rotation posture, accepted deliberately: root compromise is
  global (mitigated by the root being offline and signing rarely); root rotation
  is a fleet-wide event (rare); intermediate rotation is per-region and routine —
  an improvement over the current single-CA posture.
- Self-hosted deployments are unchanged: a self-generated single CA remains
  correct for one MSP running its own controller (ADR-013's sovereign multi-root
  boundary).

### Decision 3 — Tenant IDs gain a realm qualifier now

- Every tenant identity carries a **realm qualifier** naming its home deployment
  (cell), assigned before the first production tenant is created.
- The qualifier participates in identity, not in the intra-cell hierarchy: within
  a cell, path resolution and the ADR-025 access boundary operate on the
  unqualified subtree exactly as today. ADR-025's Amendment A1.1 grammar
  (single DNS-label token) is amended to define the qualified form and where each
  form is valid.
- Cross-cell surfaces (directory, audit aggregation, any future federation) use
  the qualified form exclusively; collisions become impossible by construction.

### Decision 4 — Steward private keys are born on the steward

- Enrollment becomes a signing request flow: the steward generates its mTLS
  keypair locally and submits the public key; the controller signs and returns
  the certificate chain. The signing primitive already exists in `pkg/cert`
  (`SignClientCertificateRequest`) and the steward already generates and submits
  an identity keypair at registration — the pattern is proven in-tree.
- The steward's private key never crosses the wire and is never present on the
  controller; the `client_key` field leaves the registration and refresh
  responses (ADR-011's refresh completion becomes the same signing flow).
- The controller-side certificate store retains certificates and metadata only —
  never private keys for steward credentials.
- ADR-021 Amendment 5's claim ("every credential this epic introduces is
  CSR-based" except the admin bootstrap bundle) becomes globally true: steward
  credentials join the CSR-only rule; the admin bootstrap bundle remains the one
  deliberate exception.

### Decision 5 — One home cell per tenant; cross-cell is read-only

- Every tenant subtree has exactly **one home cell**. All writes for a tenant
  route to its home cell. Cross-cell replication, where it ever exists, is
  read-only and version-pinned.
- Deferred direction, recorded and not designed here: a multi-region MSP is
  served by the home-cell model plus read-only cross-cell federation under a
  strict single-writer invariant, with a cell-aware front end that renders each
  region's data as it arrives. Admin session federation across cells is the first
  design item when this is picked up.

## Consequences

- Data residency is achieved by construction — a jurisdiction's cell holds its
  tenants' data, keys, and issuance records — rather than by policy fields
  (the existing declarative residency rules remain unenforced and unclaimed).
- Upgrade blast radius and canary become per-cell: a schema migration or bad
  release reaches one cell's tenants, and new releases can prove themselves on a
  low-stakes cell first. Within a cell, node-level rolling upgrade (ADR-007)
  is unchanged.
- The beta build is not throwaway: cell #1 plus the (trivial at N=1) directory
  layer is the end-state architecture.
- Certificate work lands in `pkg/cert` and the registration/refresh wire
  contract; endpoint-visible changes ride the normal enrollment flow, and
  existing pre-beta lab endpoints are wiped and re-enrolled once the root exists
  (pre-production, per the no-migration-tooling rule).
- The installer remains a single global artifact for beta; per-cell binding
  arrives with the second cell (registration tokens are already tenant-scoped
  and can become cell-scoped then).

## Out of scope / deferred

- Building a second cell, the tenant→cell directory service, admin routing, and
  the cross-cell operations view.
- The endpoint re-pointing channel (ADR-013 §4) — scheduled work, post-beta.
- Cross-region MSP federation and admin session federation (Decision 5's
  deferred direction).
- Root-CA ceremony tooling and custody procedure — an operations document, drafted
  when the root is created; the requirement (offline, signs intermediates only)
  is set here.

## Supersedes / amends

- **ADR-007** — addendum wording ":97 shared key vault for the CA" becomes "the
  region's vault holds the regional intermediate; the root is offline and never
  in any cluster vault."
- **ADR-013 (Amended)** — §2's "pin the CA" is re-scoped: the pinned anchor for
  SaaS is the shared root; leaves arrive as leaf+intermediate chains. §4's
  rotation channel gains regional-intermediate issuance as a first-class event.
  The sovereign self-hosted single-CA path is explicitly unchanged.
- **ADR-021 (Amended)** — Amendment 5 restated: CSR-only now covers steward
  credentials; the admin bootstrap bundle is the sole exception.
- **ADR-025 (Amended)** — A1.1 tenant-ID grammar gains the realm-qualified form;
  intra-cell validation is unchanged.
- **ADR-030 (Amended)** — "cluster CA backend" becomes "regional intermediate
  backend"; Raft-related upgrade steps were already retired by ADR-031.
- **ADR-011 (Amended)** — refresh completion issues certificates via the signing
  flow; no private key in the response.
- **steward-operating-model.md** — registration wire contract loses `client_key`;
  bootstrap-trust section describes root-anchor pinning and chain delivery.
- **controller-operating-model.md** — registration flow steps (generate-on-claim)
  rewritten for the signing flow; the multi-root SaaS platform illustration
  (§ around :1129) is redrawn as cells.
- **docs/operations/cluster-ca.md** — rewritten: cell init requests an
  intermediate from the root ceremony instead of self-generating the fleet root.
- **decisions/README.md** — gains ADR-032's row.
