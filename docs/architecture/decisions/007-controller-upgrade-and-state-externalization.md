# ADR-007: Controller Upgrade and State Externalization Strategy

**Status:** Accepted  
**Date:** 2026-06-15  
**Epic:** #2014 — Controller upgrade & state-externalization strategy  
**Supersedes (operationally):** the app-level port-swap blue/green model of epic #1917 (frozen, see Decision)

---

## Context

The controller must be upgradeable as features ship — eventually multiple versions a day under a GA DevOps workflow. Upgrade priorities, in order:

1. **Never lose data or steward identity/registration.**
2. **Be very easy** to operate.
3. Be **as close to zero downtime as feasible** without heavy engineering.

### What actually happens to a steward during an upgrade

Stewards connect over gRPC-over-QUIC with mTLS and reconnect with exponential backoff; convergence runs on a multi-minute loop. **No upgrade model preserves the live QUIC session** — in every approach the session drops and the steward reconnects. So priority (1) is not socket preservation; it is **state + identity continuity**: the post-upgrade controller must hold the same durable data, present a CA the steward already trusts, and recognize the steward's persisted registration. When those hold, a reconnect is invisible to convergence.

### The constraint that decides the model

The controller's durable state today is **local-disk, per-host**: a SQLite DNA/fleet store plus flatfile config/audit. This single fact determines what upgrade models are possible:

- **State stays local-disk** → upgrades must happen **on the same host** (restart, or two processes sharing the same files).
- **State externalized** to a shared datastore → a **fresh host or container** can serve immediately, which is the prerequisite for host/container-level blue/green.

### Why app-level port-swap was the wrong tool

Epic #1917 implemented blue/green as two controller processes on one host, swapping ownership of the canonical ports while sharing the same local storage. Running two controllers against one host's mutable local state is the hard, fragile part, and the approach accreted defects for exactly that reason:

- #2008 — the admin steward registry was not repopulated on reconnect.
- #2010 — the DNA store path was CWD-relative, so a candidate launched from a different working directory opened a different, empty store.
- #2012 — the cutover smoketest only checked object-presence, not real storage readiness.

It also never achieved graceful drain of the incumbent (the one-shot orchestrator cannot drain a process it did not spawn), so every cutover still required an external stop. The standard host/container blue/green pattern is **both simpler and better** — once state is externalized.

---

## Decision

### 1. Supported upgrade now: smoketest-gated in-place restart

Until state is externalized, the supported controller upgrade is an **in-place restart gated by a real-state smoketest**:

1. Stage the new binary.
2. Start it on side ports.
3. Probe `GET /api/v1/ready` — the real-state readiness check (round-trips durable storage; ADR introduced in #2012). Object-presence liveness (`/api/v1/health`) is not sufficient.
4. If ready, swap the binary and restart under the process supervisor (systemd unit or container restart). The new process reloads the **same** local storage.
5. If the new binary fails its readiness check (before or after restart), restart the **previous** binary.

This satisfies all three priorities today: no data/identity loss (same storage, same CA, same registration), trivial to operate, and downtime bounded by controller boot + registry warm-load (seconds at lab scale). It reuses the readiness gate already built and the keep-previous-binary rollback concept; it does **not** need the port-swap orchestrator.

### 2. GA target: host/container-level blue/green

The production/GA model is **host/container-level blue/green**: stand up a new controller instance on the new version behind a stable front end, health-gate it on `/api/v1/ready`, shift traffic, then drain and decommission the old instance. This is the standard, robust pattern that supports multi-version-a-day deploys and gives the best downtime characteristics with the least bespoke code.

It depends on three enablers, each independently shippable:

- **Externalized durable state** — move the DNA/fleet store, config, and audit off per-host local disk to a shared backend (a managed relational datastore plus an object/blob store) **through the existing `pkg/storage` provider interfaces**. This is the single biggest enabler; a fresh instance must be able to serve from shared state with no per-host data. (Likely its own epic.)
- **Stable steward-facing endpoint** — stewards target a stable DNS / L4 endpoint rather than a pinned host IP (`transport_address`), so traffic can move between instances. The controller advertises a stable external endpoint.
- **Shared/portable CA trust anchor** — the CA must be portable across instances (not auto-generated per host), so a new instance presents certificates stewards already trust and trusts the steward certificates already issued.

### 3. Freeze the app-level port-swap orchestrator (epic #1917)

The port-swap orchestrator (`features/controller/cutover`, `cfg controller upgrade run`) is **frozen**: experimental, not the supported production path, and not to receive further investment. Its useful concepts are retained elsewhere — the real-state smoketest (`/api/v1/ready`) and keep-previous-binary rollback live on in the restart-gated upgrade and the GA health gate. It may be removed once the restart-gated path is the documented default.

---

## Consequences

- **Now:** operators upgrade via a smoketest-gated restart; brief (seconds) downtime is accepted; no data or steward-identity loss. Bugs fixed en route to this decision (#2008, #2010, #2012) also harden the restart path and are reusable for the GA model — notably `/api/v1/ready` is exactly the health check a load balancer or container orchestrator uses for host-level blue/green.
- **GA:** once state is externalized, upgrades become standard rolling deployments behind a load balancer, with near-zero downtime and no bespoke orchestration. The investment is front-loaded into externalizing state rather than into the controller process-management layer.
- **Risk if deferred:** continuing to trap controller state on local disk is the thing that would force a large refactor later. Externalizing state through the storage-provider abstraction now (incrementally) is the hedge against that.

## Alternatives considered

- **App-level port-swap blue/green (epic #1917)** — rejected as the production path: complex, fragile against shared local mutable state, never achieved graceful drain, and superseded by host/container blue/green once state is externalized. Frozen, not deleted.
- **Long-lived supervisor daemon for true zero-downtime on a single host** — rejected for now: significant engineering for overlapped handoff (complicated by QUIC/UDP and shared-WAL storage), and unnecessary given zero-downtime is not a current requirement and the GA host-level model delivers near-zero downtime anyway.
- **Plain restart with no smoketest** — rejected: a broken new binary could take down the controller with no gate; the readiness smoketest plus keep-previous-binary rollback is a small, high-value addition.

---

## Addendum (2026-06-19): Two Deployment Models

**Decision:** The upgrade strategy splits by deployment model. The original framing of state externalization, portable CA, and stable endpoint as single-controller GA blue/green enablers is superseded.

### Single shared-nothing controller

The deployment target for self-hosted and small-scale operators is a **single shared-nothing controller**: no external database, no shared storage, no load balancer. The supported upgrade path for this model is **in-place restart only** — the smoketest-gated restart described in Decision §1 above (tracked under #2015).

Host-level blue/green and host-to-host state migration are **non-goals** for this model. There is no shared state to migrate and no second host to shift traffic to; the complexity of enabling those patterns is not justified by the deployment's operational profile.

### SaaS cluster

The deployment target for the managed SaaS offering is **cluster-by-default**: shared Postgres for the DNA/fleet store, shared blob storage for config and audit, and a shared key vault for the CA. In this model, blue/green is a **rolling cluster upgrade** — add a new node on the new version, drain the old node, decommission it — which is the standard pattern for any stateless-process cluster backed by shared durable storage. This is tracked under epic #2051.

### Reframing of prior enablers

The three enablers called out in Decision §2 (state externalization #2016, vault-sourced CA #2018, stable LB endpoint #2017) are **SaaS-cluster foundations** that make the rolling-cluster upgrade possible. They are not single-controller blue/green enablers. Implementing them on a single shared-nothing controller would add complexity with no operational benefit for that deployment model.

### App-level port-swap orchestrator

The app-level port-swap orchestrator (`features/controller/cutover`, `cfg controller upgrade run`, epic #2019) remains **frozen and experimental**. It is not the supported path for either deployment model. The supported single-controller upgrade path is in-place restart (Decision §1, #2015); the supported SaaS upgrade path is rolling cluster upgrade (#2051). The orchestrator may be removed once the restart-gated path is the documented default.
