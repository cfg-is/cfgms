# Hyper-V cluster.cfg cascade + failover — live validation runbook

Manual reproduction steps for the fleet-e2e live validation of the cluster.cfg
cascade + owner-gated `hyperv.vm` convergence epic (**#2418**, stories
#2420–#2425). Pairs with the automated suite
`test/e2e/hyperv/cluster_cascade_test.go` (Issue **#2426**).

The automated suite proves the epic's **module-convergence** safety properties by
driving the real `hyperv` module (ps-host transport) as the node it runs on and
steering ownership with `Move-ClusterGroup`. This runbook covers (a) how to run
that suite live on the 3-node example-cluster cluster, and (b) the **controller cascade**
half (cluster.cfg → each member steward's effective config, and the *leave*
behavior) which is orchestrated outside the module and is validated by
observation.

---

## 1. Environment

Live bed: the **example-cluster** 3-node Hyper-V failover cluster (`lab.example.com`).

| Node | Role |
|------|------|
| `HV-HOST-01` | cluster member (also the CI/orchestrator host) |
| `HV-HOST-02` | cluster member |
| `HV-HOST-03` | cluster member |

- Shared storage: **CSV01** at `C:\ClusterStorage\CSV01` (the ha_role VM's VHD
  must be CSV-homed so it can fail over).
- Per-host external switch: `HVSwitch_1G`.
- The cluster name is `example-cluster` (this is `Get-Cluster` on any member; it is the
  value passed as `CFGMS_E2E_HYPERV_CLUSTER`).

### Privileges

Cluster cmdlets (`Get-Cluster`, `Get-ClusterGroup`, `Move-ClusterGroup`) and VM
lifecycle (`New-VM`, `Remove-VM`) require **cluster-administrator rights**. The
example-cluster stewards run as `LocalSystem`, whose node computer account has cluster
access (per the #2306 ruling — no gMSA/run-as). Run the suite either:

- from an **elevated** shell on a member node whose user is a cluster admin, or
- in the steward's **SYSTEM** context via `cfg steward exec` (SYSTEM has cluster
  access on example-cluster).

A non-admin shell cannot even read the cluster (`Get-Cluster` returns
"You do not have administrative privileges on the cluster") — the suite then
skips cleanly rather than failing.

---

## 2. Automated suite — run live on each node

The suite is build-tagged `e2e` (excluded from CI / `make test-complete`) and
skips unless `CFGMS_E2E_HYPERV_CLUSTER` is set and the host is a member of that
cluster.

Because a module instance's node identity is `os.Hostname()`, each invocation
faithfully represents **the node it runs on**. Run it **on all three nodes**
(elevated) to observe the full simultaneous choreography; each invocation steers
ownership so the local node plays every role under test in turn.

```powershell
# On each of HV-HOST-01, HV-HOST-02, HV-HOST-03 (elevated shell), from the repo root:
$env:CFGMS_E2E_HYPERV_CLUSTER = 'example-cluster'
# Optional overrides (defaults shown):
#   $env:CFGMS_E2E_HAROLE_VM = 'cfgms-e2e-ha-01'
#   $env:CFGMS_E2E_VHD_DIR   = 'C:\ClusterStorage\CSV01'
#   $env:CFGMS_E2E_SEED_DIR  = 'C:\cfgms\e2e-seed'   # must be host-LOCAL, not on CSV
#   $env:CFGMS_E2E_SWITCH    = 'HVSwitch_1G'
go test -tags e2e -v -run TestClusterCascade -timeout 30m ./test/e2e/hyperv/...
```

Via the SYSTEM exec channel instead (stdout is not streamed — redirect to a file
and read it back, per the exec-channel notes):

```powershell
cfg steward exec <steward-id-on-node> --shell powershell --command @'
$env:CFGMS_E2E_HYPERV_CLUSTER = "example-cluster"
cd C:\git\cfgms
go test -tags e2e -v -run TestClusterCascade -timeout 30m ./test/e2e/hyperv/... *>&1 |
  Out-File C:\ProgramData\cfgms\e2e-cluster-cascade.log
'@
```

### What each test asserts (and how it steers the cluster)

| Test | Steers | Asserts (epic AC) |
|------|--------|-------------------|
| `TestClusterCascade_SingleVMCreatedByOwner` | moves the **CNO** (`Cluster Group`) to the local node | the CNO owner's convergence **creates** the VM, registers the clustered role, and **exactly one** VM instance exists cluster-wide; the owner records no surface-and-wait skip |
| `TestClusterCascade_NonOwnersConverged` | creates the role on local, then moves the **role** to another node | the local (now non-hosting) member converges to a **no-op**, audits a `vm-set-skip-hosted-elsewhere`, creates **no** local duplicate, and the single instance stays on its real owner |
| `TestClusterCascade_FailoverHandoff` | hands the role to `other` (local starts a non-owner), then runs a **live** convergence loop while moving the role **to** then **away from** local | the **new owner** converges the role with zero operator action; the **previous owner** goes quiet (audited owner-gate skip, no lifecycle writes); a background cross-node poller proves **never two distinct VMIds** (no independent duplicate — a live-migration transient of the *same* VMId is allowed) and **never zero instances** (no gap) throughout the failover window |

Each test cleans up its VM + clustered role (`t.Cleanup` → `ccCleanupRole`).

### Expected outcome

All three `PASS` on each node. Any `2 instances` observation is a **duplicate-VM
regression** (the exact failure this epic prevents) and must block the epic.

---

## 3. Controller cascade + leave — observed validation

The module suite above proves owner-gated convergence. The **cascade** itself
(#2425: a cluster-scoped config document flows into each member steward's
effective config through the InheritanceResolver) is controller-side and is
validated by observation:

1. **Cascade in.** Author a cluster-scoped config `example-cluster.cfg` carrying one
   `hyperv.vm` resource with an `ha_role` (CSV-homed VHD). Push it via the
   controller.
2. **Observe fan-out.** On each of the 3 members, confirm the VM resource now
   appears in that steward's **effective configuration** (the same definition on
   all three) — e.g. via the steward's config dump / DNA surface.
3. **Observe single create.** Exactly one member (the CNO owner) creates and
   registers the role; the other two report it converged (hosted elsewhere). This
   is the live equivalent of `SingleVMCreatedByOwner` +
   `NonOwnersConverged` driven through the real controller push rather than a
   direct module `Set`.
4. **Leave.** Remove one node from cluster membership in the cascade (drop it from
   the cluster's member set). Confirm:
   - the cascaded VM definition **disappears** from that node's effective
     configuration, and
   - the still-clustered VM is **NOT deleted** — a dropped definition is not a
     `state: absent` demote, so no removal is issued; the VM keeps running on its
     current owner.

The safety guarantee under test in step 4 is that **cascade removal ≠
destruction**: a steward never deletes a clustered VM merely because a converge
cycle stopped including its definition. (Explicit demotion — removing `ha_role`
from a VM that is still in config — is the separate, role-only path proven by the
`#2372` unit tests: it removes the clustered role, never the VM.)

---

## 4. Layer 2 — idiomatic, controller-driven validation (#2577)

Section 3 above is observed manually. **Layer 2** makes the idiomatic path a
first-class validation: config is authored at the tenant/cluster scope, cascaded
by the controller, read by every member, with only the CNO acting — driven
through **cfgms config + the `cfg` admin CLI**, never `module.Set` and never raw
cluster cmdlets for anything under test (placement/membership). Raw cluster
cmdlets are used ONLY to observe, and OS tools ONLY to inject load.

### 4.1 Automated idiomatic suite

`test/e2e/hyperv/cluster_cascade_idiomatic_test.go` (build tag `e2e`, package
`hyperv_e2e`) drives the controller with the `cfg` CLI and observes each member's
effective config + the live cluster. It reuses the Layer-1 harness (`ccVMInstances`
et al.) and skips cleanly when the idiomatic controls are unset.

```powershell
# On a example-cluster member node, elevated (cluster admin) or via the SYSTEM exec channel:
$env:CFGMS_E2E_HYPERV_CLUSTER = 'example-cluster'
$env:CFGMS_E2E_CFG_BIN        = 'C:\git\cfgms\bin\cfg-dev.exe'
$env:CFGMS_E2E_ADMIN_BUNDLE   = 'C:\Users\cfg\admin.bundle.yaml'   # or CFGMS_ADMIN_BUNDLE
# NOTE: "cfg" here is this Windows host's local account name (HV-HOST-01),
# unrelated to the "cfg" SSH user retired in the 2026-07-31/08-01 rebuild.
# Lab VMs are reached over SSH as the `debian` user.
$env:CFGMS_E2E_MEMBER_IDS     = 'steward-1780659937223058807,steward-1782769671586775983,steward-1782769748587622286'
# Optional (defaults shown): CFGMS_E2E_HAROLE_VM=cfgms-e2e-ha-01, CFGMS_E2E_ROLE_TAG=e2e-ha-cluster
go test -tags e2e -v -run TestIdiomatic -timeout 20m ./test/e2e/hyperv/...
```

| Test | Drives (idiomatic) | Asserts |
|------|--------------------|---------|
| `TestIdiomaticCascade_IdenticalAcrossMembersSingleCreate` | reads each member's `cfg config show` | the cascaded `ha_role` VM is **identical** across all 3 members' effective config; exactly **one** VM cluster-wide (CNO create, no duplicate) |
| `TestIdiomaticPlacement_DeclaredConfigReflectedLive` | reads the CNO's effective `hyperv.cluster` `roles.<vm>` | the LIVE cluster reflects the declared `preferred_owners` (group owners, ordered), `possible_owners` (resource owners, set), `anti_affinity_class` (group class) |
| `TestIdiomaticLeave_DropsDefinitionKeepsVM` | `cfg steward tag rm` on a non-owner member | the VM definition **drops** from that member's effective config; the still-clustered VM is **NOT deleted** (single instance survives on its owner) |

The suite never authors the VM or its placement (those are under test); a bed that
has not been cascaded-in yet **skips** with a pointer here, rather than creating it.

### 4.2 Idiomatic cascade-in + single CNO create (AC1)

Authored as a role config whose selector is a tag on every member:

```bash
cfg role create e2e-ha-cluster --tenant infra-hyperv --selector "tag:e2e-ha-cluster" --config ha-vm.yaml
cfg steward tag add <each member steward-id> e2e-ha-cluster
# ha-vm.yaml resources: one hyperv.vm cfgms-e2e-ha-01 with ha_role.cluster_name: example-cluster,
# state: stopped, CSV-homed vhd_path C:\ClusterStorage\CSV01\cfgms-e2e-ha-01.vhdx.
```

Observe (`cfg config show <id>`) that all three members carry an **identical**
`cfgms-e2e-ha-01` `hyperv.vm` resource, and that exactly the CNO owner creates it
(`Get-VM -ComputerName <each node>` shows one distinct VMId cluster-wide). Live-
proven 2026-07-15 (all 3 members converge clean; owner "already in desired state",
both non-owners "managed on another node — compliant by delegation"; one VMId).

> **Note — role/tag changes do not bump the steward config version.** A steward
> won't re-pull a pure selector change until its version bumps. Force a re-pull
> with `cfg config upload <device.cfg> --steward <id>` (which bumps the version),
> then converge. Avoid triple rapid version bumps — overlapping converge passes
> race and transiently mis-report.

### 4.3 Declarative FC placement (AC2)

Author placement on the cluster-scoped `hyperv.cluster` resource (in this bed, on
the CNO's device config — `role_names` + `roles.<vm>`), then `cfg config upload`
to bump the version and re-pull:

```yaml
    - name: example-cluster
      module: hyperv.cluster
      config:
        name: example-cluster
        transport: ps-host
        role_names: [cfgms-e2e-ha-01]
        roles:
          cfgms-e2e-ha-01:
            preferred_owners: [HV-HOST-02, HV-HOST-01]   # ordered; Set-ClusterOwnerNode -Group
            possible_owners:  [HV-HOST-01, HV-HOST-02]   # restriction (excludes HV-HOST-03); -Resource
            anti_affinity_class: e2e-ha-affinity        # Set-ClusterGroup -AntiAffinityClass
```

Only the CNO owner reconciles (`reconcileRoleProperties`, `cluster.go`). Confirm
on the live cluster (read-only):

```powershell
(Get-ClusterOwnerNode -Cluster example-cluster -Group cfgms-e2e-ha-01).OwnerNodes.Name          # preferred, ordered
$r = @(Get-ClusterResource -Cluster example-cluster | Where-Object {
        [string]$_.OwnerGroup -eq 'cfgms-e2e-ha-01' -and [string]$_.ResourceType -eq 'Virtual Machine' })
(Get-ClusterOwnerNode -Cluster example-cluster -Resource $r[0].Name).OwnerNodes.Name             # possible, set
(Get-ClusterGroup -Cluster example-cluster -Name cfgms-e2e-ha-01).AntiAffinityClassNames         # class
```

Live-proven 2026-07-15 (v0.9.29): preferred `{HV-HOST-02, HV-HOST-01}`, possible
`{HV-HOST-01, HV-HOST-02}` (C3 excluded), anti-affinity `{e2e-ha-affinity}` — each
matching the declared config.

> **Bug the idiomatic path surfaced + fixed (#2577).** On the first push (v0.9.28)
> `possible_owners` silently did not apply while preferred/anti-affinity did. Root
> cause: `Cfgms-SetClusterRolePossibleOwners` resolved the VM resource with
> `$_.OwnerGroup.Name` / `$_.ResourceType.Name`, but on Windows Server 2025
> `Get-ClusterResource` returns those as plain **strings** (`.Name` is `$null`) —
> so the filter matched nothing and possible_owners was skipped with no error. The
> Layer-1 dispatch/reconcile tests use a fake transport, so they never saw the real
> object shape. Fixed with `[string]` coercion (robust for string OR object);
> guarded by `TestPreamble_PossibleOwnersFilterUsesStringCoercion`. Use the
> `[string]`-coerced `Where-Object` above when observing possible owners.

### 4.4 Re-balance under load — native dynamic optimization (AC3)

**Goal:** prove the idiomatic loop (config → cascade → converge → owner-gate) holds
through a **cluster-initiated** ownership change — the failover cluster's native VM
load balancer (`(Get-Cluster).AutoBalancerMode`, enabled by default; cfgms authors
no auto-balance property) moving the role under injected load, with **zero
cfgms/operator action** (no `Move-ClusterGroup`), and convergence following — no
duplicate, no gap.

Procedure:
0. **Prerequisite — a BOOTABLE ha_role VM.** The role must sustain as a *healthy*
   clustered VM to be a live-migration candidate. A VM with an empty/0-byte VHD
   (as the `#2426` cascade fixture uses — it only needs the role to *exist*) has no
   guest OS, so it has no heartbeat; failover-cluster health monitoring keeps the
   VM resource **Offline** and it cannot stay Online for the balancer to move.
   Provision a real bootable image into the ha_role VM first (a `source:` seed on
   the `hyperv.vm` resource), boot it, and confirm `Get-VM` shows a heartbeat
   before proceeding.
1. Confirm the balancer is on: `(Get-Cluster -Name example-cluster).AutoBalancerMode` (2 =
   load-balance on join + every 30 min) and `.AutoBalancerLevel` (1 = balance when
   a node exceeds 80%).
2. Ensure `possible_owners` for the role admits a target node with headroom (widen
   via the AC2 config if a prior restriction leaves no valid target).
3. Bring the role **Online** on a node, then inject sustained CPU/memory pressure on
   that node's host (OS tools — the ONLY raw-tool use here) until it crosses the
   balancer level.
4. With a background cross-node poller running (`ccVMInstances`: never 2 distinct
   VMIds, never 0), wait for the balancer to live-migrate the role to another node
   (up to the ~30-min evaluation cycle). Take no cfgms/operator action.
5. Assert: the new owner's convergence adopts the role; the previous owner goes
   quiet (owner-gate skip, no lifecycle writes); exactly one instance throughout.

> **example-cluster constraint (2026-07-15).** This bed is not ideal for the load path:
> the cfgms controller itself (`ctrl-node-01`) runs as a **clustered VM on these
> same nodes**, so stressing nodes to the Level-1 (80%) threshold risks migrating/
> disrupting the control plane; `HV-HOST-01` sits at ~100% memory from the CI VMs
> (no headroom to host the running role); and the balancer's 30-min evaluation
> makes a single-session result non-deterministic. Run AC3 on a bed where the
> controller is **not** a cluster VM and nodes have headroom. The cfgms code path
> exercised is identical to Layer-1 `FailoverHandoff` (the owner-gate reacts to
> whoever owns the role, transparent to what triggered the move); AC3 differs only
> in the *trigger* (cluster load balancer vs operator `Move-ClusterGroup`).

### 4.5 Idiomatic leave (AC4)

Drop a member from the cascade by removing its role tag; the definition disappears
from that member's effective config, the still-clustered VM is untouched:

```bash
cfg steward tag rm <member steward-id> e2e-ha-cluster
cfg config show <member steward-id>   # cfgms-e2e-ha-01 no longer present
```

Live-proven 2026-07-15 on HV-HOST-03 (non-owner): effective config `cfgms-e2e-ha-01`
occurrences 3 → 0; the VM survived unchanged (same VMId, present only on the owner
HV-HOST-01, one instance, clustered role still present). A dropped cascade
definition is not a `state: absent` demote — no removal is issued (no-prune: untag
≠ delete). Re-add the tag to restore full membership.

---

## 5. Cleanup / recovery

If a run is interrupted before `ccCleanupRole` runs, remove the test artifacts
manually (elevated, on any member):

```powershell
$c = 'example-cluster'; $role = 'cfgms-e2e-ha-01'
try { Remove-ClusterGroup -Cluster $c -Name $role -RemoveResources -Force } catch {}
foreach ($n in (Get-ClusterNode -Cluster $c).Name) {
  try {
    $vm = Get-VM -ComputerName $n -Name $role -ErrorAction Stop
    if ($vm) {
      $disks = (Get-VMHardDiskDrive -ComputerName $n -VMName $role).Path
      Remove-VM -ComputerName $n -Name $role -Force
      foreach ($d in $disks) { Remove-Item -Path $d -Force -ErrorAction SilentlyContinue }
    }
  } catch {}
}
```

Restore the CNO to its normal owner if a test left it moved:
`Move-ClusterGroup -Cluster example-cluster -Name 'Cluster Group' -Node <preferred>`.
