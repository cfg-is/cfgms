# Hyper-V role promotion (standalone → FC-role) — live validation runbook

Manual reproduction steps for the fleet-e2e live validation of the
workflow-driven Hyper-V role promotion epic (**#2657**, stories #2667/#2668/
#2670/#2671). Pairs with the automated suite
`test/e2e/hyperv/promote_role_test.go` (Issue **#2671**).

> **Cluster membership DNA — available on every member (story #2891).**
> The `promote-hv-role` workflow derives the target steward's cluster from its
> `cluster:*` DNA. Prior to story #2891, this DNA was emitted only on the node
> where `hyperv.cluster` was declared (the CNO owner), so the workflow could not
> derive the cluster for non-CNO stewards. Story #2891 decoupled cluster
> membership DNA from resource declaration: every cluster member now emits
> `cluster:<name>` DNA unconditionally via `Get-Cluster` (self-discovery, no
> `-Name` filter). The workflow therefore works for **any cluster member**, not
> only the CNO owner.

The epic promotes a **standalone** `hyperv.vm` into a cluster-wide, CNO-owned
**failover-cluster HA role** through three moving parts, driven by the
`promote-hv-role` workflow (`features/workflow/templates/promote-hv-role.yaml`):

1. **`set_ha_role`** step — writes the `ha_role` block into the target VM's
   device-scope config document (`stewards/<id>`) via
   `ConfigurationServiceV2.SetConfiguration`.
2. **the steward's own `hyperv`-module convergence** — on seeing `ha_role`, the
   module registers the clustered VM role
   (`registerClusteredRole` → `Add-ClusterVirtualMachineRole`), exactly once
   cluster-wide, gated on CNO ownership. **The workflow never calls the module
   directly** — it only writes config; the steward's convergence loop does the
   rest.
3. **`move_resource_to_cluster`** step — relocates the resource *definition* from
   device scope (`stewards/<id>`) to cluster scope
   (`cluster-policies/<clusterName>`), `Config` unchanged.

The automated suite proves the epic's success criteria end to end: a standalone
VM is promoted into exactly one CNO-owned HA role with its **storage path
untouched**, the resource lands in cluster scope and leaves device scope, and a
re-run against an already-promoted VM is a no-op.

---

## 1. Environment

Live bed: the **cfg-lab** 3-node Hyper-V failover cluster (`cluster.example.internal`).

| Node | Role |
|------|------|
| `HV-HOST-01` | cluster member (also the CI/orchestrator host) |
| `HV-HOST-02` | cluster member |
| `HV-HOST-03` | cluster member |

- Shared storage: **CSV01** at `C:\ClusterStorage\CSV01`. The promoted VM's VHD
  is CSV-homed from the start (a standalone VM can use CSV without being
  clustered), so **promotion never relocates storage** — the VHD path is
  identical before and after. This is the point of AC3.
- Per-host external switch: `HVSwitch_1G`.
- The cluster name is `cfg-lab` (`Get-Cluster` on any member; the value passed as
  `CFGMS_E2E_HYPERV_CLUSTER`).

### Privileges

Cluster cmdlets (`Get-Cluster`, `Get-ClusterGroup`, `Move-ClusterGroup`) and VM
lifecycle (`New-VM`, `Remove-VM`, `Add-ClusterVirtualMachineRole`) require
**cluster-administrator rights**. The cfg-lab stewards run as `LocalSystem`,
whose node computer account has cluster access (per the #2306 ruling — no
gMSA/run-as). Run the suite either:

- from an **elevated** shell on a member node whose user is a cluster admin, or
- in the steward's **SYSTEM** context via `cfg steward exec` (SYSTEM has cluster
  access on cfg-lab).

A non-admin shell cannot read the cluster (`Get-Cluster` returns
"You do not have administrative privileges on the cluster") — the suite then
skips cleanly rather than failing.

---

## 2. Automated suite — run live

The suite is build-tagged `e2e` (excluded from CI / `make test-complete`) and
skips unless `CFGMS_E2E_HYPERV_CLUSTER` is set and the host is a member of that
cluster.

Unlike the cluster-cascade suite, the choreography here is a **single-node
promotion** (standalone → clustered on the same owning node), so it is enough to
run it on **one** member node. The test steers the CNO owner to the local node so
its convergence performs both the create and the promote registration.

```powershell
# On a cfg-lab member node (elevated shell), from the repo root:
$env:CFGMS_E2E_HYPERV_CLUSTER = 'cfg-lab'
# Optional overrides (defaults shown):
#   $env:CFGMS_E2E_PROMOTE_VM = 'cfgms-e2e-promote-01'   # distinct from the cascade suite's VM
#   $env:CFGMS_E2E_VHD_DIR    = 'C:\ClusterStorage\CSV01'
#   $env:CFGMS_E2E_SEED_DIR   = 'C:\cfgms\e2e-seed'      # must be host-LOCAL, not on CSV
#   $env:CFGMS_E2E_SWITCH     = 'HVSwitch_1G'
go test -tags e2e -v -run TestPromoteHVRole -timeout 30m ./test/e2e/hyperv/...
```

Via the SYSTEM exec channel instead (stdout is not streamed — redirect to a file
and read it back, per the exec-channel notes):

```powershell
cfg steward exec <steward-id-on-node> --shell powershell --command @'
$env:CFGMS_E2E_HYPERV_CLUSTER = "cfg-lab"
cd C:\git\cfgms
go test -tags e2e -v -run TestPromoteHVRole -timeout 30m ./test/e2e/hyperv/... *>&1 |
  Out-File C:\ProgramData\cfgms\e2e-role-promotion.log
'@
```

### What each test asserts (and how it drives the promotion)

Per the story's Implementation Notes, the suite drives the two step executors
**directly** — constructed against a real flatfile-backed `ConfigStore` +
`ConfigurationServiceV2` (`pkg/testing.SetupTestStorage`, not an in-memory fake)
— and the real `hyperv` module directly (the same "drive the real component, not
a mock" approach the cluster-cascade suite uses). Standing up a full controller
process or the HTTP/CLI layer is out of scope for this story (that plumbing is
covered by S5/#2670's own unit tests); this suite proves the **convergence +
config-migration** behavior live.

| Test | Drives | Asserts (epic AC) |
|------|--------|-------------------|
| `TestPromoteHVRole_StandaloneToClusteredRole` | creates a standalone VM on the local (CNO-owner) node, then runs `set_ha_role` → module convergence → `move_resource_to_cluster` | the VM starts **not** a clustered role; after the sequence it is **exactly one** CNO-owned clustered role; the resource is **present in `cluster-policies/cfg-lab`** and **absent from `stewards/<id>`**; the VM's **VHD path is unchanged** throughout (no storage relocation) |
| `TestPromoteHVRole_ReRunIsNoOp` | reaches the promoted state, then re-runs `move_resource_to_cluster` and re-converges the module | the re-run is a **no-op**: the `cluster-policies` document is **byte-identical** (no duplicate write), the resource stays in cluster scope and out of device scope, and there is still **exactly one** clustered role on the same owner with the VHD still unmoved |

Each test cleans up its VM + clustered role (`t.Cleanup` → `ccCleanupRole`).

### Expected outcome

Both tests `PASS`. Any `2 instances` observation is a **duplicate-VM regression**
and must block the epic. A promoted resource that remains in `stewards/<id>` (or
never appears in `cluster-policies/cfg-lab`) is a **scope-migration failure**. A
changed VHD path is a **storage-relocation regression** (AC3).

**Live-proven 2026-07-16** on the cfg-lab cluster, run in the `HV-HOST-01` steward's
SYSTEM context via `cfg steward exec`:
`--- PASS: TestPromoteHVRole_StandaloneToClusteredRole (35.94s)` and
`--- PASS: TestPromoteHVRole_ReRunIsNoOp (39.46s)` — real `New-VM`, storage-location
convergence (`Move-VMStorage`), CNO-ownership probe, `Add-ClusterVirtualMachineRole`,
and the config-scope migration all exercised end to end; bed cleaned up on all three
nodes afterward.

> **Note — capture output with direct file redirection, not a pipeline.** Run
> `go test` under `Start-Process ... -RedirectStandardOutput <file> -RedirectStandardError <file> -Wait`
> (or redirect at the process level). Piping `go test` through `Tee-Object`/`Out-File`
> inside the SYSTEM exec session can lose the buffered tail (the PASS/FAIL summary)
> when the exec job's console is torn down at completion — and the exec job's own
> status line may read `failed` even when the test exited 0, so trust the redirected
> log, not the job status.

> **Note — the harness audit warnings are benign.** The suite builds its module with
> no `tenant_id` (`ccBuildModule`), so each cluster op logs
> `audit validation failed: tenant_id: tenant ID is required`. That is a
> test-harness artifact (a real steward supplies its tenant), not a product fault,
> and does not affect any assertion.

---

## 3. The fixed soak delay — what it is, and why it is not a convergence check

The production `promote-hv-role` workflow places a **fixed `delay` step (default
30s)** between `set_ha_role` and `move_resource_to_cluster`:

```
set_ha_role  →  delay 30s (soak)  →  move_resource_to_cluster
```

This soak is a **fixed wait, not an active convergence poll.** It exists only to
give the owning steward's convergence loop time to register the clustered role
before the resource definition is moved to cluster scope. It is a deliberate v1
simplification (epic #2657, grounding note 5), **accepted by the team lead**, for
two reasons:

1. **Correctness does not require it.** Moving the resource definition from
   `stewards/<id>` to `cluster-policies/<clusterName>` — with the *same* `ha_role`
   block already present — does not undo or race the owning steward's in-flight
   registration. The owning steward is itself a cluster member, so after the move
   it still sees the identical resource (now sourced from cluster scope) on its
   next converge tick and proceeds identically. The soak only makes the observable
   ordering tidy; it is not a safety interlock.
2. **An active convergence poll would be unreliable today.** DNA-based convergence
   reporting is a known-broken, unrelated gap (epic **#2520**), so a poll would
   have nothing trustworthy to wait on. The fixed delay avoids inventing one.

Because `set_ha_role` writes through `ConfigurationServiceV2.SetConfiguration`,
the steward receives an **immediate fan-out push** (Save = Deploy) rather than
waiting for its own poll interval, which makes the fixed-delay window tight and
conservative. For a slow cluster, increase the delay at execute time by passing an
updated workflow definition; the 30s default is intentionally conservative.

**In the automated suite** there is no wall-clock soak at all: the test itself
sequences the module convergence between the two config writes, which is exactly
the ordering the soak window exists to allow. Do **not** read the suite's lack of
a delay as a claim that the delay is unnecessary in production — read this section
so the simplification is not mistaken for an active convergence confirmation.

---

## 4. FC-cascade config invariant (Issue #3107)

The `promote-hv-role` workflow is the **only** path that creates clustered `hyperv.vm` resources (those carrying an `ha_role` block). Every promotion terminates with the `move_resource_to_cluster` step, so all clustered hyperv declarations land in `cluster-policies/<clusterName>` and never remain in device scope (`stewards/<stewardID>`).

**Why this invariant is load-bearing:** `GET /api/v1/clusters/{name}/reconciliation` derives its declared-resource set exclusively from `cluster-policies/<clusterName>` via `GetClusterDeclaredResources`. A `hyperv.vm` resource that carries `ha_role` but lives in device scope is **silently absent** from the reconciliation input — `Reconcile` never classifies it as `declared-but-missing`, `orphan-dead-owner`, or `split-brain`; it simply cannot see the resource. This is not an error surface — it is a silent blind spot.

**Verification (Issue #3107):** As of the shipping of this story, a `git grep` across all repo fixtures, test configs, and deployment examples confirms zero scattered device-scope clustered declarations. The fleet has been greenfield on this invariant since epics #2657/#2807 shipped. No migration tooling was needed or built.

**Authoring rules:**
- **Via workflow (normal path):** run `cfg workflow promote-hv-role` — this is the only supported way to promote a standalone VM into a cluster role. The workflow writes `ha_role` into device scope temporarily (the `set_ha_role` step) and then atomically relocates the resource to `cluster-policies/<clusterName>` (the `move_resource_to_cluster` step). The device-scope `ha_role` state exists only during the fixed soak window between the two steps.
- **Via direct config upload (bulk authoring):** use `cfg config upload` targeting `cluster-policies/<clusterName>` from the start. Never author a clustered resource directly into the device-scope `stewards/<id>` document — it will be accepted by the config service (there is no write-time guard) but will be invisible to all reconciliation and cascade machinery.

## 5. Cleanup / recovery

If a run is interrupted before `ccCleanupRole` runs, remove the test artifacts
manually (elevated, on any member):

```powershell
$c = 'cfg-lab'; $role = 'cfgms-e2e-promote-01'
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

The config-store artifacts (device- and cluster-scope documents) live in a
per-test `t.TempDir()` flatfile root and are removed automatically when the test
process exits — there is no persistent controller state to clean up.
