# ADR-026: Reboot windows — device-scoped reboot gating with tenant inheritance and structured schedules

**Status:** Accepted

**Date:** 2026-07-22

**Deciders:** Founder, Architecture

**Related:** [016](016-steward-module-foundation.md) (module foundation — every module that can reboot a host consults this gate). [006](006-module-packaging-and-distribution.md) (module packaging — the gate is a steward-side capability, not a per-module reimplementation). [022](022-entity-graph-model-and-access-contract.md) / [023](023-entity-graph-storage-shape.md) (entity graph — a guest VM is a first-class device/asset, which this ADR depends on for VM-scoped windows). Epic #2898 (implements this ADR). The `patch` stdlib module (`features/modules/stdlib/patch`) whose fail-open window gate this ADR replaces.

---

## Context

### The gate exists in name only, and it fails open

CFGMS already has the *shape* of a reboot/maintenance gate, but it does nothing in production:

- `pkg/maintenance` **does not exist** — there is no central provider for windows.
- The only gate is a `WindowManager` interface local to the patch module
  (`features/modules/stdlib/patch/types.go:293`: `CanReboot`, `CanPerformMaintenance`,
  `GetNextWindow`, `IsInWindow`).
- Its **only implementation is test-only** — `InMemoryWindowManager` lives in
  `features/modules/stdlib/patch/inmemory_window_manager_test.go:47`. No production code
  constructs a `WindowManager`, so `m.windowManager` is `nil` on every real steward.
- The gate **fails open, twice**. `PatchModule.isInMaintenanceWindow`
  (`module.go:397-411`) and `canReboot` (`module.go:415-426`) each `return true` when the
  manager is `nil` *and* when the check errors:

  ```go
  if m.windowManager == nil {
      return true // "backwards compatibility"
  }
  inWindow, err := m.windowManager.IsInWindow(ctx, m.deviceID)
  if err != nil {
      // logs a warning, then:
      return true
  }
  ```

The net effect: **a declared reboot window silently permits every reboot, at any time.**
An operator who configures a window gets no protection and no error — the worst kind of
security control, one that looks present and isn't.

### The existing schedule model can't express real cadences

The only window type today is `TimeWindow` (`features/modules/stdlib/patch/upgrade.go:107-116`):
a `DaysOfWeek []int` list plus a start, scoped to Windows *version upgrades* only. It cannot
express **"the second Tuesday of each month"** — the shape of most vendor patch cadences —
because a day-of-week list has no ordinal-within-month concept. Standard 5-field cron has the
same gap. Any real reboot policy needs to name *"the nth weekday of the month."*

### Two words hid two different concepts each

- **"Maintenance window"** conflated reboot gating with everything else a maintenance pass
  might do (drift apply, config push). Those have different risk profiles and shouldn't share
  one gate.
- **"local"** (as in the workflow scheduler's timezone default) concealed **device** (an
  endpoint's own zone) versus **tenant default** (an MSP-account-level policy, inherited by
  descendants). Resolving "local" to the controller host's clock is wrong for a multi-tenant
  SaaS and disagrees across HA nodes.

### Threat-model framing

Per the CFGMS threat model, rarely-touched settings should *bound the blast radius* of admin
or controller compromise. A reboot is one of the highest-disruption declarative actions on a
fleet. The window is exactly such a bound — but only if it fails **closed** and cannot be
bypassed by a compromised admin through a convenient "emergency override" path.

## Decision

### 1. Name it `reboot_window`; it gates OS reboots only

The setting is `reboot_window`, not "maintenance window." It gates **OS reboots** — nothing
else. Drift apply and config push are not gated by it.

The **mechanism is general**: every module that can trigger a host reboot consults the gate
before doing so. The **v1 policy is narrow**: only reboots are gated. Widening later (e.g. a
"config-change window") is a *second window type alongside* `reboot_window`, never a
redefinition of it. This keeps each window's semantics stable and auditable.

### 2. Device-scoped — and a guest VM is a device

Windows attach to **devices**. A host and each of its guest VMs have **their own**
`reboot_window`.

- A `hyperv.vm` power-cycle operation consults the **guest's** window, not the host's.
- A **stewardless** guest (no agent inside it) still has a window; the **Hyper-V host's
  steward evaluates it on the guest's behalf** before performing the power-cycle. This is why
  the guest must be a first-class device/asset in the entity graph (ADR-022/023).
- A **forced** power-cycle counts as a reboot. Example: `Set-VM -MemoryStartupBytes` requires
  the guest to be off; taking it down to satisfy that request is a reboot and is gated.

### 3. Cascade with free override in both directions, gated by permission + audit

A window set at a tenant cascades to descendants, and a descendant (or the device) may
**override it in either direction** — looser *or* tighter. Override is controlled by
**permission and audit**, not by "narrower-only" lattice semantics.

The founder's decisive counter-example: a client that needs *tighter* patching — say Monday
**and** Thursday weekly — expresses it through **more frequent** windows. A "narrower-only"
rule rejects that as "wider." "Narrower" is ill-defined here because window **duration** and
patch **cadence** move in opposite directions: more windows can mean more reboots but each
smaller. The lattice can't encode the operator's intent; a permissioned, audited override can.

### 4. Resolution is `explicit → tenant default → device`; "local" is retired

"local" is replaced by two explicit concepts:

- **device** — the endpoint's own zone/policy.
- **tenant default** — an MSP-account-level policy, inherited root-to-leaf.

A value resolves in order: an **explicit** window on the object, else the **tenant default**,
else the **device**. The same fix applies to the workflow trigger scheduler: its timezone
default is the **tenant default → UTC**, never the controller host's local clock (tenant
default is *data*, so HA nodes agree by construction).

### 5. Structured YAML, not cron

The schedule is structured YAML:

- **`start` / `end`**, not a duration. A duration makes DST an edge case; wall-clock
  `start`/`end` make DST a non-question.
- **`after: {weekday, nth}`** and **`before:`** anchors express "nth weekday of month."
  `weekday:` always names the day the window **opens**.
- A **midnight-wrap** predicate is required (a window may open before and close after
  midnight).

Illustrative shape (not a frozen schema — the implementing epic finalizes field names):

```yaml
reboot_window:
  timezone: tenant-default        # explicit IANA zone overrides; else tenant default; else UTC
  windows:
    - after:  { weekday: tue, nth: 2 }   # opens 2nd Tuesday of the month
      start:  "01:00"
      end:    "05:00"                     # may wrap past midnight
```

### 6. No emergency override — by design

There is **no "reboot now, ignore the window" escape hatch** on the declarative path.
Declarative policies **obey** the window. Anything that legitimately needs to reboot outside a
window uses an **imperative path** — a script, a workflow, the `cfg` CLI, or a remote shell —
each of which already carries its own operator judgment, authentication, and audit trail.

This is a **security decision**, not an ergonomics oversight: an "emergency override" on the
declarative path is precisely the bypass a compromised or phished admin would reach for. Not
building it removes that bypass surface entirely, consistent with bounding admin-compromise
blast radius.

### Sequencing

Not urgent — there is no production fleet yet, so the fail-open gate is not currently
exposing anyone. It sequences **behind** the Entity Graph program (ADR-022/023, epics
#2851/#2852/#2853/#2854), which supplies "VMs as first-class assets" that Decision 2 depends
on. The gate must, however, be **replaced with a fail-closed implementation** as part of that
work — the current fail-open behavior must not survive into production.

## Consequences

- **Positive:** a declared window becomes a real, fail-closed control. Multi-tenant inheritance
  and per-device override match how MSPs actually run patch cadences. VM windows work even for
  stewardless guests. No declarative bypass for a compromised admin.
- **Cost:** requires a new central provider (a `reboot_window` / maintenance provider), a
  structured-schedule parser with ordinal-weekday + midnight-wrap semantics, a resolver
  implementing `explicit → tenant default → device` with cascade/override, and rewiring the
  patch module's gate from fail-open to fail-closed. The Hyper-V module must evaluate a guest's
  window on the host steward.
- **Migration:** the patch module's `WindowManager` fail-open branches
  (`module.go:399, 416`) are replaced; a `nil` manager or a check error must **deny** the
  reboot (fail closed), not allow it. `TimeWindow`'s day-list model is superseded by the
  structured schema.

## Alternatives considered

- **Cron expressions.** Rejected: standard 5-field cron cannot express "nth weekday of month,"
  the dominant real-world cadence.
- **Narrower-only override (lattice semantics).** Rejected: "narrower" is ill-defined when
  duration and cadence move oppositely; it rejects legitimate tighter-cadence intent. Replaced
  by permissioned, audited free override.
- **One "maintenance window" gating reboots, drift apply, and config push together.** Rejected:
  conflates controls with different risk profiles. A general mechanism with a narrow v1 policy,
  extended by *additional* window types, keeps each gate's semantics stable.
- **An emergency "reboot now" override on the declarative path.** Rejected: it is the exact
  bypass an admin-compromise threat would use. Imperative paths already provide the escape with
  their own judgment and audit.
- **Duration instead of `start`/`end`.** Rejected: makes DST an edge case; wall-clock
  `start`/`end` make it a non-question.
