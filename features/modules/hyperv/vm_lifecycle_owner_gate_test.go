// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Issue #2422: role-owner gate on existing HA-role VM lifecycle convergence ──
//
// applyVMState (power/resize/NIC/storage-move) for an ha_role VM runs only on the
// node readResourceOwners reports as the role's current owner. A non-owner — most
// importantly the PREVIOUS owner right after a failover, whose local Get-VM view
// may transiently still show the VM — takes no lifecycle action and goes quiet;
// the new owner converges instead. A MISSING owner entry (role not yet registered:
// the first-time promote of an existing standalone VM) does NOT skip — local
// possession decides. Standalone VMs never consult the cluster at all.

// TestApplyVMState_NonOwner_GoesQuiet (REQUIRED, #2422): a post-failover state —
// the VM is present locally but readResourceOwners reports a DIFFERENT node as the
// role owner — issues zero write PS calls of any kind and returns nil. The only
// transport call is the ownership probe itself; the skip is audited.
func TestApplyVMState_NonOwner_GoesQuiet(t *testing.T) {
	const vmName = "ha-failover-vm"
	const cluster = "lab-hv"

	// One transport call only: the ownership probe. Anything beyond it (storage
	// move, NIC reconcile, promote/demote, stop/resize/start) violates the gate.
	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"owners":{"ha-failover-vm":"NODE2"}}`, // role owned by the OTHER node
	}}
	m := vmModuleWithTransport(transport, "t-2422")
	m.nodeHostname = "NODE1"
	mgr, store := newFakeAuditManager(t)
	m.auditMgr = mgr
	m.stewardID = "steward-2422"

	// desired diverges from current in every actionable way (power, CPU, memory)
	// so an UNGATED convergence would issue multiple writes — the zero-call
	// assertion below is only meaningful because the drift is real.
	desired := &VMConfig{
		Name:     vmName,
		CPUCount: 4,
		MemoryMB: 8192,
		HARole:   &HARoleConfig{ClusterName: cluster},
	}
	current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "stopped"}

	require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "running"))

	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 1, callCount,
		"a non-owner must issue exactly one call (the ownership probe) and no lifecycle writes")
	assert.Equal(t, 0, countCmd(transport, psStartVM), "no power change on a non-owner")
	assert.Equal(t, 0, countCmd(transport, psStopVM), "no power change on a non-owner")
	assert.Equal(t, 0, countCmd(transport, psSetVMProcessor), "no resize on a non-owner")
	assert.Equal(t, 0, countCmd(transport, psSetVMMemory), "no resize on a non-owner")
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole), "no membership mutation on a non-owner")

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	skips := auditEntriesByActionCT(store.captured(), "vm-lifecycle-skip-not-owner")
	require.Len(t, skips, 1, "the non-owner lifecycle skip must be audited")
}

// TestApplyVMState_Owner_ConvergesNormally (REQUIRED, #2422): when this node is
// the owner (or the role is not yet registered anywhere), the gate does not skip
// and existing convergence runs unchanged. Two sub-cases:
//   - first-time promote: desired.HARole != nil, current.HARole == nil, owner map
//     has NO entry for the VM (role not yet registered) → the promote path
//     (registerClusteredRole) is reached.
//   - steady owner: this node IS the reported owner → a pending resize is applied.
func TestApplyVMState_Owner_ConvergesNormally(t *testing.T) {
	const cluster = "lab-hv"

	t.Run("first_time_promote_missing_owner_entry", func(t *testing.T) {
		const vmName = "ha-promote-existing-vm"
		// call0: gate probe — role absent cluster-wide (no entry ⇒ do NOT skip).
		// calls 1-4: registerClusteredRole on the CNO owner (this node).
		transport := &testWinRMTransport{perCallOutputs: []string{
			`{"owners":{}}`,     // gate: role not yet registered → local possession decides
			`{"owner":"NODE1"}`, // reconcileRoleMembership: CNO owner
			`{"owners":{}}`,     // reconcileRoleMembership: role owners
			`{"owner":"NODE1"}`, // reconcileRoleMembership: audit cnoOwner re-read
			``,                  // Add-ClusterVirtualMachineRole
		}}
		m := vmModuleWithTransport(transport, "t-2422")
		m.nodeHostname = "NODE1"

		desired := &VMConfig{
			Name:     vmName,
			CPUCount: 2,
			MemoryMB: 4096,
			HARole:   &HARoleConfig{ClusterName: cluster},
		}
		current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "stopped"} // HARole nil

		require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "stopped"))

		assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
			"a missing owner entry must NOT skip — the first-time promote path must register the role")
	})

	t.Run("steady_owner_applies_resize", func(t *testing.T) {
		const vmName = "ha-owned-vm"
		// call0: gate probe — this node owns the role → do NOT skip; convergence runs.
		transport := &testWinRMTransport{perCallOutputs: []string{
			`{"owners":{"ha-owned-vm":"NODE1"}}`, // gate: this node IS the owner
		}}
		m := vmModuleWithTransport(transport, "t-2422")
		m.nodeHostname = "NODE1"

		desired := &VMConfig{
			Name:     vmName,
			CPUCount: 4, // resize vs current
			MemoryMB: 4096,
			HARole:   &HARoleConfig{ClusterName: cluster},
		}
		// current already a member (HARole non-nil) so the promote/demote switch is a no-op.
		current := &VMConfig{
			Name:     vmName,
			CPUCount: 2,
			MemoryMB: 4096,
			State:    "running",
			HARole:   &HARoleConfig{ClusterName: cluster},
		}

		require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "running"))

		assert.Equal(t, 1, countCmd(transport, psSetVMProcessor),
			"the reported owner must converge normally — the CPU resize must be applied")
		assert.Equal(t, 1, countCmd(transport, psStartVM),
			"the owner's resize ends with a start back to the desired running state")
		assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
			"an already-registered member is not re-promoted")
	})
}

// TestApplyVMState_StandaloneVM_NoOwnerQuery (REQUIRED, #2422): a standalone VM
// (desired.HARole == nil) never invokes the owner check — readResourceOwners is
// not called at all — and existing convergence (here, a resize) still runs.
func TestApplyVMState_StandaloneVM_NoOwnerQuery(t *testing.T) {
	const vmName = "standalone-vm"

	transport := &testWinRMTransport{} // no cluster outputs needed — none must be requested
	m := vmModuleWithTransport(transport, "t-2422")
	m.nodeHostname = "NODE1"
	m.clusterName = "lab-hv" // even on a cluster-scoped module, a non-HA VM must not query

	desired := &VMConfig{Name: vmName, CPUCount: 4, MemoryMB: 4096} // HARole nil
	current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "running"}

	require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "running"))

	assert.Equal(t, 0, countCmd(transport, psGetClusterResourceOwner),
		"a standalone VM must never issue a cluster ownership query")
	assert.Equal(t, 1, countCmd(transport, psSetVMProcessor),
		"standalone convergence is unchanged — the CPU resize must still be applied")
}

// TestApplyVMState_OwnerQueryError_SkipsQuietly (#2422 implementation note): a
// transient readResourceOwners failure is fail-safe-QUIET — it neither blocks a
// legitimate owner nor lets a non-owner act. The cycle skips (return nil, warn),
// issuing no lifecycle writes; the next tick retries once the probe recovers.
// This deliberately differs from #2421's fail-safe-LOUD (which propagates) because
// this call runs on every tick of every existing HA VM, where a hard error would
// spam the steward error state on a known-transient condition.
func TestApplyVMState_OwnerQueryError_SkipsQuietly(t *testing.T) {
	const vmName = "ha-probe-flaky-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{
		perCallOutputs: []string{``},
		perCallErrors:  []error{errors.New("cluster service down")},
	}
	m := vmModuleWithTransport(transport, "t-2422")
	m.nodeHostname = "NODE1"

	desired := &VMConfig{
		Name:     vmName,
		CPUCount: 4,
		MemoryMB: 8192,
		HARole:   &HARoleConfig{ClusterName: cluster},
	}
	current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "stopped"}

	require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "running"),
		"a transient ownership-probe error must not surface as a steward error")

	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 1, callCount,
		"a probe error must skip the cycle after exactly one call — no lifecycle writes")
	assert.Equal(t, 0, countCmd(transport, psStartVM))
	assert.Equal(t, 0, countCmd(transport, psSetVMProcessor))
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole))
}

// TestApplyVMState_UnresolvedOwner_GoesQuiet (#2422): the owner map has an entry
// for the VM but the owner string is empty — Get-ClusterGroup reports "" for a
// role with no current OwnerNode, the in-flight-failover settle window. Every
// member reads "" and goes quiet, so no two nodes ever converge the same role
// while ownership is unsettled; it self-heals once the cluster settles an owner.
// This is the safe bias (fail-safe-quiet), locked in against a future "empty ⇒
// proceed on local possession" change that would risk double-action.
func TestApplyVMState_UnresolvedOwner_GoesQuiet(t *testing.T) {
	const vmName = "ha-unsettled-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"owners":{"ha-unsettled-vm":""}}`, // registered role, no current owner (settling)
	}}
	m := vmModuleWithTransport(transport, "t-2422")
	m.nodeHostname = "NODE1"

	desired := &VMConfig{
		Name:     vmName,
		CPUCount: 4,
		MemoryMB: 8192,
		HARole:   &HARoleConfig{ClusterName: cluster},
	}
	current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "stopped"}

	require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "running"))

	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 1, callCount,
		"an unresolved (empty) owner must skip after exactly one call — no lifecycle writes")
	assert.Equal(t, 0, countCmd(transport, psStartVM))
	assert.Equal(t, 0, countCmd(transport, psSetVMProcessor))
}

// TestApplyVMState_OutOfScopeCluster_ErrorsWithoutTransport (#2422): an ha_role
// naming a cluster outside the module's cluster_name scope cap (S5) fails LOUD
// with ErrClusterNotDeclared and issues ZERO transport calls — the same
// "no transport for an out-of-scope cluster" invariant clusterOwnershipHelper /
// reconcileRoleMembership / getCluster enforce. A scope mismatch is a persistent
// misconfiguration, not a transient probe failure, so it errors rather than
// taking the fail-safe-quiet path.
func TestApplyVMState_OutOfScopeCluster_ErrorsWithoutTransport(t *testing.T) {
	const vmName = "ha-rogue-lifecycle-vm"

	transport := &testWinRMTransport{} // any transport call is a violation
	m := vmModuleWithTransport(transport, "t-2422")
	m.nodeHostname = "NODE1"
	m.clusterName = "lab-hv" // scope cap

	desired := &VMConfig{
		Name:     vmName,
		CPUCount: 4,
		MemoryMB: 8192,
		HARole:   &HARoleConfig{ClusterName: "rogue-cluster"}, // out of scope
	}
	current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "stopped"}

	err := m.applyVMState(context.Background(), vmName, vmName, desired, current, "running")
	require.ErrorIs(t, err, ErrClusterNotDeclared,
		"an out-of-scope ha_role.cluster_name must fail loud with the scope-cap sentinel")

	transport.mu.Lock()
	callCount := len(transport.calls)
	transport.mu.Unlock()
	assert.Equal(t, 0, callCount,
		"the scope cap must reject before any transport call — no out-of-scope cluster query")
}
