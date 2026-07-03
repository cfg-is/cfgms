# Hyper-V Cluster-Management Access Onboarding

The CFGMS steward runs as **LocalSystem**. To manage failover-cluster HA VM roles
(`hyperv.cluster` resources), the node's **computer account** must hold cluster
administrative access — LocalSystem authenticates to the cluster as that computer
account, and it has no cluster access by default. This is a one-time, privileged
grant per node.

The steward **detects** the missing grant and raises a controller-visible alert so
you know which nodes still need it — designed for fleet deployment where the
steward is installed by automation (RMM script, GPO startup script, image) across
many endpoints and the grants are done afterward.

## How the alert works

On every cluster read, the hyperv module runs a **read-only self-check**
(`Get-ClusterAccess`) asking: *does this node's computer account hold cluster
access?* The result is surfaced on the module's DNA:

| DNA key | Meaning |
|---|---|
| `cluster_access_ok` | `true` when this node holds cluster access (or is a standalone host, or the probe could not determine access — unknown never alerts); `false` on a confirmed missing grant |
| `cluster_access_remediation` | the exact `Grant-ClusterAccess` command to run, when `cluster_access_ok` is `false` |

`cluster_access_ok` is part of the cluster DNA signature, so a grant/revoke
**transitions the value and emits a DNA change** — the alert raises when access is
missing and **clears automatically** on the next check once the grant lands. No
manual reset.

A confirmed missing grant (`cluster_access_ok: false`) is the onboarding alert:
the node is a cluster member but cannot perform HA role operations until granted.

## Remediating (the one-time grant)

Run the remediation command from the alert on **any** cluster node, in a
cluster-admin session (the grant modifies the cluster security descriptor):

```powershell
Grant-ClusterAccess -Cluster <cluster> -User "<DOMAIN>\<NODE>$" -Full
```

- The account is the node's **computer account** (`DOMAIN\NODE$`) — LocalSystem
  presents as this over the network. No new identity, no gMSA, no stored
  credential: the steward stays LocalSystem.
- It's `-Full` because the module both reads and writes cluster state. The
  blast-radius controls are app-layer (CNO-owner gating, `allow_destructive` for
  teardown, per-op audit, `module_trust: strict`), not the identity.
- Effect is immediate for a direct computer-account grant (no Kerberos-ticket
  refresh needed, unlike an AD-group grant).

After the grant, the next cluster read flips `cluster_access_ok` to `true` and the
alert clears.

## Revocation

When a node is retired from cluster management, revoke its access so a
decommissioned node loses cluster admin:

```powershell
Remove-ClusterAccess -Cluster <cluster> -User "<DOMAIN>\<NODE>$"
```

Full machine decommission (disabling/deleting the computer account) revokes all of
its access instantly.

## Controller-orchestrated lifecycle (option 3)

Beyond the manual grant, the controller can **reconcile** cluster-management access
to the cluster's member set automatically. The hyperv module exposes a privileged
`ReconcileClusterAccess(cluster, desiredMembers)` action that:

1. reads the node computer accounts currently in the cluster ACL,
2. computes **grants** (a desired member whose account is not in the ACL) and
   **revokes** (an account whose node is no longer a member — drift, e.g. a
   retired or evicted node),
3. applies them via `Grant-ClusterAccess` / `Remove-ClusterAccess`, auditing each.

The controller invokes this as a **privileged lifecycle action** on a node whose
steward already holds cluster access (bootstrap: the first grant is manual, driven
by the onboarding alert above). It is **not** reachable from routine `hyperv.cluster`
Set convergence — `Grant-ClusterAccess` is a lateral-movement primitive and is kept
out of the cfg path deliberately. Grant/revoke of an already-consistent account is a
no-op, so the reconcile is idempotent and safe to run repeatedly.

Node retirement therefore revokes access two ways: the reconcile removes a
no-longer-member account from the ACL, and full machine decommission
(disabling/deleting the computer account) is the immediate, total revoke.

## Notes

- **Grant-ClusterAccess is never run by routine steward convergence** — it is a
  privileged onboarding/decommission action, deliberately kept out of the module's
  cfg path (it is a lateral-movement primitive). The module only *reads* access and
  *alerts*; a human/operator (or the controller's lifecycle orchestration) grants.
- Standalone (non-cluster) hosts never raise this alert.
