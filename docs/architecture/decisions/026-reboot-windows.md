# ADR-026: Reboot Windows — device-scoped reboot gating with tenant inheritance and structured schedules

**Status:** Accepted (2026-07-22)

**Deciders:** Founder + Architecture session (2026-07-22)

**Related:** [ADR-016](016-steward-module-foundation.md) (module foundation — every module that can reboot a host consults this gate). [ADR-006](006-module-packaging-and-distribution.md) (module packaging — the gate is a steward-side capability, not a per-module reimplementation). [ADR-022](022-entity-graph-model-and-access-contract.md) / [ADR-023](023-entity-graph-storage-shape.md) (entity graph — a guest VM is a first-class device/asset, which this ADR depends on for VM-scoped windows). Epic #2898 (implements this ADR). The `patch` stdlib module (`features/modules/stdlib/patch`) whose fail-open window gate this ADR replaces.

---

## Context

CFGMS has no mechanism to gate reboots to declared time windows. The `patch` module accepted a `maintenance.window` field that silently did nothing until #2892 closed the noop by rejecting the field at validation. Every module that causes a reboot — `patch`, `hyperv.vm` power-cycles, driver installs — fires at any hour. MSPs cannot promise a client that servers only reboot inside an agreed window.

The design was settled in a founder + architecture session on 2026-07-22. This ADR records those decisions as the authoritative reference. Epic #2898 is the implementation plan; Stories #2975–#2979 and future stories in that epic all cite this document.

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

---

## Decisions

### Decision 1 — Name and scope: `reboot_window`, OS reboots only

The policy is named `reboot_window`. It gates **OS reboots only** — not drift apply, not
config-push fanout. The module-consult mechanism is general (every module checks the window
before rebooting); the v1 policy is reboots. Any future widening (maintenance windows for
non-reboot disruption) is a *separate window type alongside* `reboot_window`, never a
redefinition of a deployed field. This keeps each window's semantics stable and auditable.

### Decision 2 — Device-scoped; a guest VM is a device

One window per device, governing all activity on it. The Hyper-V host has its own window; each
guest VM has its own. `hyperv.vm` operations that power-cycle a guest consult **the guest's**
window. A stewardless VM's window is evaluated by the Hyper-V host's steward on the guest's
behalf. This is why the guest must be a first-class device/asset in the entity graph
(ADR-022/023). A forced guest power-cycle (e.g., `Set-VM -MemoryStartupBytes`, which requires
the guest off) counts as a reboot and is gated.

### Decision 3 — Inheritance: cascade with free override, controlled by permission + audit

Windows cascade down the tenant tree (root MSP default → children inherit). A child may
override **in either direction** — looser *or* tighter patch cadence. The control is a distinct
edit permission plus an audit event keyed to the cfg resource id — not a narrow-only lattice.

The founder's decisive counter-example: a client that needs *tighter* patching — say Monday
**and** Thursday weekly — expresses it through **more frequent** windows. A "narrower-only"
rule rejects that as "wider." "Narrower" is ill-defined because window **duration** and patch
**cadence** move in opposite directions: more windows can mean more reboots but each smaller.
The lattice can't encode the operator's intent; a permissioned, audited override can.

### Decision 4 — Timezone: `device` vs tenant default

The word "local" is retired. Resolution order: explicit timezone on the window → tenant default
(inherited) → `device` (endpoint's own zone). This same model repairs the workflow-trigger
scheduler (tenant default → UTC, not controller-host local; tenant default is *data*, so HA
nodes agree by construction). The `timezone` field in the schema is the window-level explicit
value only; empty means "not set at this level."

### Decision 5 — Notation: structured YAML, not cron

Cron cannot express "nth weekday of month" (vendor patch cadences) and names an instant, not
an interval. The schema uses `start`/`end` (makes DST handling a non-question) and
`after: {weekday, nth}` / `before: {weekday, nth}` anchors so the top-level `weekday:` always
names the day the window opens. No new Go module dependency. Semantics are anchored to RFC 5545
(RRULE) for the plain cases; the anchored `after:`/`before:` case is a deliberate,
more-legible divergence. A **midnight-wrap** predicate is required (a window may open before
and close after midnight).

### Decision 6 — No emergency override, by design

There is **no "reboot now, ignore the window" escape hatch** on the declarative path.
Declarative policies (modules, convergence) **obey** the window. Imperative paths (scripts,
workflows, `cfg` CLI, remote shell) carry their own operator judgment and are ungated —
eliminating any admin-compromise bypass surface. The resolved window is exposed as a readable
value in script/workflow context.

This is a **security decision**, not an ergonomics oversight: an "emergency override" on the
declarative path is precisely the bypass a compromised or phished admin would reach for. Not
building it removes that bypass surface entirely, consistent with bounding admin-compromise
blast radius.

### Sequencing

Not urgent — there is no production fleet yet, so the fail-open gate is not currently exposing
anyone. It sequences **behind** the Entity Graph program (ADR-022/023, epics
#2851/#2852/#2853/#2854), which supplies "VMs as first-class assets" that Decision 2 depends
on. The gate must, however, be **replaced with a fail-closed implementation** as part of that
work — the current fail-open behavior must not survive into production.

---

## Schema (authoritative)

```yaml
reboot_window:
  timezone: device             # omit to inherit tenant default; or an IANA zone e.g. "America/Chicago"
  schedules:
    - freq: monthly
      weekday: thursday        # the day the window OPENS
      after: { weekday: tuesday, nth: 2 }   # anchor; nth: -1 = last; before: also valid
      start: "02:00"
      end: "04:00"
    - freq: monthly
      weekday: thursday
      nth: 2                   # plain case: the 2nd Thursday
      start: "02:00"
      end: "06:00"
    - freq: weekly
      days: [saturday, sunday]
      start: "01:00"
      end: "06:00"
```

Field notes:
- `timezone`: empty = not set (inherit); `"device"` = use device's own zone; any IANA tz string = use that zone.
- `freq`: `"monthly"` or `"weekly"`.
- `weekday` (monthly): the day the window **opens** — always present for `freq: monthly`.
- `days` (weekly): list of weekday names — valid only with `freq: weekly`.
- `nth` (monthly): the Nth occurrence of `weekday` in the month. `-1` = last occurrence.
- `after` / `before` (monthly): anchor the window to the first occurrence of `weekday` after/before the Nth occurrence of the anchor weekday.
- `start` / `end`: 24h clock strings (`"HH:MM"`). `end: "24:00"` means end-of-day.

---

## Evaluation semantics (authoritative)

```
if end > start:   inWindow = start <= now.time <= end
else:             inWindow = now.time >= start || now.time <= end   # window wraps midnight
```

- The day selector applies to the **start** day.
- `end: "24:00"` = end-of-day (the window never wraps midnight in this case).
- For a midnight-wrapping window (`start > end`): if `now.time >= start`, check that today is the scheduled start day; if `now.time <= end`, check that yesterday was the scheduled start day.
- DST: `start`/`end` are wall-clock times, not durations, so DST falls out correctly. A window whose entire span falls inside a spring-forward skipped hour never opens that day — emit a **validation-time warning** (not an error). This cannot affect a normal multi-hour window.

---

## Validation rules (authoritative)

1. `nth` and `after`/`before` are mutually exclusive. With `freq: monthly` + `weekday:`, exactly one of `nth`, `after`, or `before` must be present.
2. `after`, `before`, and `nth` are valid **only** with `freq: monthly`. `days:` is valid **only** with `freq: weekly`.
3. **Same-weekday rule:** if the top-level `weekday:` equals the `after:` anchor weekday, the resolution is `anchor + 7 days` (after = strictly later). For `before:`, same weekday resolves to `anchor - 7 days`.
4. Offsets crossing a month boundary (e.g., the Thursday `after` the last Tuesday of January falls in February) are legal and well-defined — the anchor is an occurrence, not a calendar constraint.
5. Timezone must be empty, `"device"`, or a valid IANA timezone string; any other value is a validation error.
6. `start` and `end` must be valid `"HH:MM"` strings (or `"24:00"` for `end` only).

---

## Out of Scope

- **Gating anything other than reboots** — a future second window type, not this epic.
- **Cluster-aware reboot concurrency** (min-nodes-up, max-concurrent) — tracked in roadmap as "Cluster-Aware Patching."
- **`Remove-VMSwitch -Force`** and other non-reboot guest disruption — named known gap.
- **workflow-trigger scheduler DST/timezone fix** — surfaced during design, tracked separately.

---

## Consequences

### Positive

- A declared window becomes a real, fail-closed control.
- Every module has a single, testable check before rebooting.
- Multi-tenant inheritance and per-device override match how MSPs actually run patch cadences.
- VM windows work even for stewardless guests.
- No declarative bypass for a compromised admin.
- The `nth weekday` expression maps directly to vendor patch cadences (e.g., "second Tuesday" Patch Tuesday windows).
- No new Go module dependency; pure standard library.
- DST-safe by construction (`start`/`end` are wall-clock, not duration-based).

### Negative

- Requires a new central provider (`pkg/maintenance`), a structured-schedule parser with
  ordinal-weekday + midnight-wrap semantics, a resolver implementing
  `explicit → tenant default → device` with cascade/override, and rewiring the patch module's
  gate from fail-open to fail-closed. The Hyper-V module must evaluate a guest's window on the
  host steward.
- Monthly anchor computation is more complex than cron.
- Tenants that need per-device timezone resolution must wait for Story 2 (cascade + resolution).

### Migration

The patch module's `WindowManager` fail-open branches (`module.go:399, 416`) are replaced; a
`nil` manager or a check error must **deny** the reboot (fail closed), not allow it.
`TimeWindow`'s day-list model is superseded by the structured schema.

### Neutral

- Cron is explicitly rejected for this use case; the schema is purpose-built and not general-purpose.

---

## Alternatives Considered

### Cron expression syntax

Rejected. Cron cannot express "nth weekday of month," the primary use case (Patch Tuesday —
second Tuesday of the month). Cron also names an instant, not an interval, complicating
`start`/`end` semantics. No Go cron library in the dependency tree; adding one for this would
be disproportionate.

### Duration-based windows (start + duration)

Rejected. Duration makes DST ambiguous (does "2 hours" include or exclude the skipped hour?).
`start`/`end` wall-clock makes this a non-question.

### `before:` / `after:` as relative day offsets

Rejected. Named weekday + nth is more readable and maps directly to how MSPs express their
patch windows ("first Thursday after Patch Tuesday").

### Narrower-only override (lattice semantics)

Rejected: "narrower" is ill-defined when duration and cadence move oppositely; it rejects
legitimate tighter-cadence intent. Replaced by permissioned, audited free override.

### One "maintenance window" gating reboots, drift apply, and config push together

Rejected: conflates controls with different risk profiles. A general mechanism with a narrow v1
policy, extended by *additional* window types, keeps each gate's semantics stable.

### An emergency "reboot now" override on the declarative path

Rejected: it is the exact bypass an admin-compromise threat would use. Imperative paths already
provide the escape with their own judgment and audit.
