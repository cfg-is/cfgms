# Hyper-V cluster.cfg cascade + failover — live validation runbook

Manual reproduction steps for the fleet-e2e live validation of the cluster.cfg
cascade + owner-gated `hyperv.vm` convergence epic (**#2418**, stories
#2420–#2425). Pairs with the automated suite
`test/e2e/hyperv/cluster_cascade_test.go` (Issue **#2426**).

The automated suite proves the epic's **module-convergence** safety properties by
driving the real `hyperv` module (ps-host transport) as the node it runs on and
steering ownership with `Move-ClusterGroup`. This runbook covers (a) how to run
that suite live on the 3-node cfg-lab cluster, and (b) the **controller cascade**
half (cluster.cfg → each member steward's effective config, and the *leave*
behavior) which is orchestrated outside the module and is validated by
observation.

---

## 1. Environment

Live bed: the **cfg-lab** 3-node Hyper-V failover cluster (`lab.cfg.is`).

| Node | Role |
|------|------|
| `CFG-70-02` | cluster member (also the CI/orchestrator host) |
| `CFG-AB-02` | cluster member |
| `CFG-C3-02` | cluster member |

- Shared storage: **CSV01** at `C:\ClusterStorage\CSV01` (the ha_role VM's VHD
  must be CSV-homed so it can fail over).
- Per-host external switch: `HVSwitch_1G`.
- The cluster name is `cfg-lab` (this is `Get-Cluster` on any member; it is the
  value passed as `CFGMS_E2E_HYPERV_CLUSTER`).

### Privileges

Cluster cmdlets (`Get-Cluster`, `Get-ClusterGroup`, `Move-ClusterGroup`) and VM
lifecycle (`New-VM`, `Remove-VM`) require **cluster-administrator rights**. The
cfg-lab stewards run as `LocalSystem`, whose node computer account has cluster
access (per the #2306 ruling — no gMSA/run-as). Run the suite either:

- from an **elevated** shell on a member node whose user is a cluster admin, or
- in the steward's **SYSTEM** context via `cfg steward exec` (SYSTEM has cluster
  access on cfg-lab).

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
# On each of CFG-70-02, CFG-AB-02, CFG-C3-02 (elevated shell), from the repo root:
$env:CFGMS_E2E_HYPERV_CLUSTER = 'cfg-lab'
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
$env:CFGMS_E2E_HYPERV_CLUSTER = "cfg-lab"
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
| `TestClusterCascade_FailoverHandoff` | runs a **live** convergence loop while moving the role **to** then **away from** local | the **new owner** converges the role with zero operator action; the **previous owner** goes quiet (audited owner-gate skip, no lifecycle writes); a background cross-node poller proves **never 2** (no duplicate) and **never 0** (no gap) instances throughout the failover window |

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

1. **Cascade in.** Author a cluster-scoped config `cfg-lab.cfg` carrying one
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

## 4. Cleanup / recovery

If a run is interrupted before `ccCleanupRole` runs, remove the test artifacts
manually (elevated, on any member):

```powershell
$c = 'cfg-lab'; $role = 'cfgms-e2e-ha-01'
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
`Move-ClusterGroup -Cluster cfg-lab -Name 'Cluster Group' -Node <preferred>`.
