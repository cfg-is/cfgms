// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Issue #2372: single-surface ha_role convergence ───────────────────────────
//
// A VM's cluster-role membership is a fully convergent hyperv.vm setting:
// declaring ha_role promotes on any path (existing VM, plain create,
// source-provisioned), removing it demotes (role removed, VM intact), and
// hyperv.cluster no longer offers a second membership surface.

// ─── getVM cluster-role membership probe ───────────────────────────────────────

// TestGetVM_ClusterRoleProbe_MemberReported verifies getVM populates HARole on
// the returned VMConfig when the module-level cluster_name scope is configured
// and the VM appears in the cluster's VirtualMachine group owner map.
func TestGetVM_ClusterRoleProbe_MemberReported(t *testing.T) {
	const vmName = "ha-probe-vm"
	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "running", 2, 4096), // psGetVM
		`{"owners":{"ha-probe-vm":"NODE1"}}`,   // membership probe
	}}
	m := vmModuleWithTransport(transport, "t-probe")
	m.clusterName = "lab-hv"

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	require.NotNil(t, cfg.HARole, "a clustered VM must report HARole from the probe")
	assert.Equal(t, "lab-hv", cfg.HARole.ClusterName)
}

// TestGetVM_ClusterRoleProbe_NonMemberNil verifies a VM absent from the owner
// map reports a nil HARole.
func TestGetVM_ClusterRoleProbe_NonMemberNil(t *testing.T) {
	const vmName = "plain-vm"
	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "running", 2, 4096),
		`{"owners":{}}`,
	}}
	m := vmModuleWithTransport(transport, "t-probe")
	m.clusterName = "lab-hv"

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Nil(t, cfg.HARole)
}

// TestGetVM_ClusterRoleProbe_SkippedWithoutScope verifies the probe is skipped
// entirely (no extra transport call) when no module-level cluster_name is set —
// no HA-role drift is observable without a cluster scope, and non-cluster hosts
// must not issue cluster queries.
func TestGetVM_ClusterRoleProbe_SkippedWithoutScope(t *testing.T) {
	const vmName = "standalone-vm"
	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "running", 2, 4096),
	}}
	m := vmModuleWithTransport(transport, "t-probe")

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Nil(t, cfg.HARole)
	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Len(t, transport.calls, 1, "no cluster probe without a cluster_name scope")
}

// TestGetVM_ClusterRoleProbe_ErrorDegrades verifies a failing membership probe
// degrades to HARole=nil without failing the VM read: promote is idempotent, so
// a missed membership converges on a later cycle rather than breaking Get.
func TestGetVM_ClusterRoleProbe_ErrorDegrades(t *testing.T) {
	const vmName = "degraded-vm"
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON(vmName, "running", 2, 4096), ``},
		perCallErrors:  []error{nil, errors.New("cluster service down")},
	}
	m := vmModuleWithTransport(transport, "t-probe")
	m.clusterName = "lab-hv"

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err, "a probe failure must not fail the VM read")
	assert.Nil(t, cfg.HARole)
}

// ─── Issue #2420: cluster-wide existence gate for ha_role VMs ──────────────────
//
// The identical hyperv.vm resource with ha_role cascades to every member
// steward. A steward where the VM is locally absent but the clustered role is
// already registered cluster-wide (owned by ANY node) must never create a
// duplicate VM — it converges as a no-op with an audit skip.

// TestGetVM_AbsentButClusteredRole_ReportsHARole (REQUIRED, #2420): a VM absent
// via the local Get-VM fake but present in the readResourceOwners fake result
// returns HARole non-nil on the absent VMConfig — the probe now runs on the
// absent path too, so setVM can see "this role exists somewhere".
func TestGetVM_AbsentButClusteredRole_ReportsHARole(t *testing.T) {
	const vmName = "ghost-ha-vm"
	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"found":false}`,                    // psGetVM: locally absent
		`{"owners":{"ghost-ha-vm":"NODE2"}}`, // membership probe: registered cluster-wide
	}}
	m := vmModuleWithTransport(transport, "t-2420")
	m.clusterName = "lab-hv"

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Equal(t, "absent", cfg.State)
	require.NotNil(t, cfg.HARole,
		"a locally-absent VM whose name is a registered clustered role must report HARole")
	assert.Equal(t, "lab-hv", cfg.HARole.ClusterName)
}

// TestGetVM_AbsentWithoutScope_NoProbe: the absent path issues no cluster probe
// when no module-level cluster_name is configured — non-cluster hosts keep the
// exact pre-#2420 single-call behavior.
func TestGetVM_AbsentWithoutScope_NoProbe(t *testing.T) {
	const vmName = "ghost-plain-vm"
	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"found":false}`,
	}}
	m := vmModuleWithTransport(transport, "t-2420")

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Equal(t, "absent", cfg.State)
	assert.Nil(t, cfg.HARole)
	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Len(t, transport.calls, 1, "no cluster probe without a cluster_name scope")
}

// TestSetVM_HARoleAlreadyClusterWide_SkipsCreate (REQUIRED, #2420): setVM with
// ha_role declared, VM locally absent, and the clustered role already
// registered cluster-wide (owned by a DIFFERENT node) performs no create action
// and returns nil — for BOTH the plain-lifecycle path and the source
// (provisioning) path. The skip is audited as vm-set-skip-hosted-elsewhere.
func TestSetVM_HARoleAlreadyClusterWide_SkipsCreate(t *testing.T) {
	const vmName = "ha-elsewhere-vm"
	const cluster = "lab-hv"

	// Two transport calls total: getVM + membership probe. Anything beyond that
	// (New-VM, provisioning, ownership reads) violates the gate.
	newTransport := func() *testWinRMTransport {
		return &testWinRMTransport{perCallOutputs: []string{
			`{"found":false}`,                        // getVM: locally absent
			`{"owners":{"ha-elsewhere-vm":"NODE2"}}`, // probe: role hosted elsewhere
		}}
	}

	t.Run("plain_lifecycle_path", func(t *testing.T) {
		transport := newTransport()
		m := vmModuleWithTransport(transport, "t-2420")
		m.clusterName = cluster
		m.nodeHostname = "NODE1"
		mgr, store := newFakeAuditManager(t)
		m.auditMgr = mgr
		m.stewardID = "steward-2420"

		require.NoError(t, m.Set(context.Background(), "vm:"+vmName, &VMConfig{
			Name:       vmName,
			MemoryMB:   4096,
			CPUCount:   2,
			VHDPath:    `C:\VMs\ha-elsewhere-vm.vhdx`,
			SwitchName: "Default Switch",
			Generation: 2,
			State:      "running",
			HARole:     &HARoleConfig{ClusterName: cluster},
		}))

		assert.Equal(t, 0, countCmd(transport, psCreateVM),
			"the existence gate must prevent any New-VM on a non-hosting node")
		transport.mu.Lock()
		callCount := len(transport.calls)
		transport.mu.Unlock()
		assert.Equal(t, 2, callCount,
			"gate must fire right after getVM+probe — no further transport calls")

		require.NoError(t, m.auditMgr.Flush(context.Background()))
		skips := auditEntriesByActionCT(store.captured(), "vm-set-skip-hosted-elsewhere")
		require.Len(t, skips, 1, "the skip must be audited")
	})

	t.Run("source_path", func(t *testing.T) {
		transport := newTransport()
		m := vmModuleWithTransport(transport, "t-2420")
		m.clusterName = cluster
		m.nodeHostname = "NODE1"

		require.NoError(t, m.Set(context.Background(), "vm:"+vmName, &VMConfig{
			Name:       vmName,
			MemoryMB:   4096,
			CPUCount:   2,
			VHDPath:    `C:\VMs\ha-elsewhere-vm.vhdx`,
			SwitchName: "Default Switch",
			Generation: 2,
			State:      "running",
			HARole:     &HARoleConfig{ClusterName: cluster},
			Source: &SourceConfig{
				Image:      `C:\images\debian.raw`,
				OSFamily:   "linux",
				Completion: CompletionConfig{Mode: "steward-registration", Timeout: "10m"},
			},
		}))

		assert.Equal(t, 0, countCmd(transport, psCreateVM),
			"the gate must fire before applySourceGated ever provisions")
		transport.mu.Lock()
		callCount := len(transport.calls)
		transport.mu.Unlock()
		assert.Equal(t, 2, callCount,
			"gate must fire right after getVM+probe — no provisioning calls")
	})
}

// TestSetVM_StandaloneVM_UnaffectedByGate (REQUIRED, #2420): a VM with
// HARole == nil still creates normally when locally absent — the new gate never
// fires for non-HA VMs, even on a cluster-scoped module.
func TestSetVM_StandaloneVM_UnaffectedByGate(t *testing.T) {
	const vmName = "plain-create-vm"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"found":false}`, // getVM: locally absent
		`{"owners":{}}`,   // probe: not a clustered role anywhere
		``,                // New-VM: create succeeds
		``,                // Cfgms-SetVMHome: config-home move (#2411)
	}}
	m := vmModuleWithTransport(transport, "t-2420")
	m.clusterName = "lab-hv"
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, &VMConfig{
		Name:       vmName,
		MemoryMB:   2048,
		CPUCount:   2,
		VHDPath:    `C:\VMs\plain-create-vm.vhdx`,
		SwitchName: "Default Switch",
		Generation: 2,
		State:      "stopped",
	}))

	assert.Equal(t, 1, countCmd(transport, psCreateVM),
		"a standalone (non-HA) VM must still be created when locally absent")
}

// ─── Issue #2421: CNO-owner creates cluster-wide-missing HA role VMs ───────────
//
// When ha_role is declared and the role does not exist ANYWHERE in the cluster
// yet (locally absent AND current.HARole == nil per the #2420 probe), only the
// steward currently owning the CNO group proceeds to create/provision; every
// other member records an audit skip and returns nil. Non-owners converge once
// the owner creates it (their next getVM sees the registered role, #2420 gate).

// TestSetVM_ClusterWideAbsentRole_NonOwnerSurfacesAndWaits (REQUIRED, #2421):
// role absent cluster-wide and this node does NOT own the CNO → zero
// New-VM/provisioning transport calls, setVM returns nil, and the skip is
// audited — for BOTH the plain-lifecycle path and the source path.
func TestSetVM_ClusterWideAbsentRole_NonOwnerSurfacesAndWaits(t *testing.T) {
	const vmName = "ha-first-vm"
	const cluster = "lab-hv"

	// Five transport calls total: getVM + membership probe (role absent
	// everywhere), then the ownership helper's CNO-owner read + role-owner map
	// + the audit cnoOwner re-read. Anything beyond that (New-VM, provisioning)
	// violates the gate.
	newTransport := func() *testWinRMTransport {
		return &testWinRMTransport{perCallOutputs: []string{
			`{"found":false}`,   // getVM: locally absent
			`{"owners":{}}`,     // getVM probe: role absent cluster-wide
			`{"owner":"NODE2"}`, // ownership helper: another node owns the CNO
			`{"owners":{}}`,     // ownership helper: role owners
			`{"owner":"NODE2"}`, // audit cnoOwner re-read
		}}
	}

	t.Run("plain_lifecycle_path", func(t *testing.T) {
		transport := newTransport()
		m := vmModuleWithTransport(transport, "t-2421")
		m.clusterName = cluster
		m.nodeHostname = "NODE1"
		mgr, store := newFakeAuditManager(t)
		m.auditMgr = mgr
		m.stewardID = "steward-2421"

		require.NoError(t, m.Set(context.Background(), "vm:"+vmName, &VMConfig{
			Name:       vmName,
			MemoryMB:   4096,
			CPUCount:   2,
			VHDPath:    `C:\VMs\ha-first-vm.vhdx`,
			SwitchName: "Default Switch",
			Generation: 2,
			State:      "running",
			HARole:     &HARoleConfig{ClusterName: cluster},
		}))

		assert.Equal(t, 0, countCmd(transport, psCreateVM),
			"a non-CNO-owner must never issue New-VM for a first-ever ha_role create")
		transport.mu.Lock()
		callCount := len(transport.calls)
		transport.mu.Unlock()
		assert.Equal(t, 5, callCount,
			"gate must stop after getVM+probe+ownership reads — no mutation calls")

		require.NoError(t, m.auditMgr.Flush(context.Background()))
		skips := auditEntriesByActionCT(store.captured(), "vm-set-skip-not-cno-owner")
		require.Len(t, skips, 1, "the non-owner skip must be audited")
	})

	t.Run("source_path", func(t *testing.T) {
		transport := newTransport()
		m := vmModuleWithTransport(transport, "t-2421")
		m.clusterName = cluster
		m.nodeHostname = "NODE1"

		require.NoError(t, m.Set(context.Background(), "vm:"+vmName, &VMConfig{
			Name:       vmName,
			MemoryMB:   4096,
			CPUCount:   2,
			VHDPath:    `C:\VMs\ha-first-vm.vhdx`,
			SwitchName: "Default Switch",
			Generation: 2,
			State:      "running",
			HARole:     &HARoleConfig{ClusterName: cluster},
			Source: &SourceConfig{
				Image:      `C:\images\debian.raw`,
				OSFamily:   "linux",
				Completion: CompletionConfig{Mode: "steward-registration", Timeout: "10m"},
			},
		}))

		assert.Equal(t, 0, countCmd(transport, psCreateVM),
			"the owner gate must fire before applySourceGated ever provisions")
		transport.mu.Lock()
		callCount := len(transport.calls)
		transport.mu.Unlock()
		assert.Equal(t, 5, callCount,
			"gate must stop after getVM+probe+ownership reads — no provisioning calls")
	})
}

// TestSetVM_ClusterWideAbsentRole_OwnerCreates (REQUIRED, #2421): same
// preconditions, but this node DOES own the CNO → the existing create path
// (createVM + registerClusteredRole) proceeds exactly as before this story.
func TestSetVM_ClusterWideAbsentRole_OwnerCreates(t *testing.T) {
	const vmName = "ha-first-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"found":false}`,   // getVM: locally absent
		`{"owners":{}}`,     // getVM probe: role absent cluster-wide
		`{"owner":"NODE1"}`, // ownership helper (#2421 gate): this node owns the CNO
		`{"owners":{}}`,     // ownership helper: role owners
		``,                  // New-VM
		``,                  // Cfgms-SetVMHome: config-home move (#2411)
		`{"owner":"NODE1"}`, // registerClusteredRole ownership helper: CNO owner
		`{"owners":{}}`,     // registerClusteredRole ownership helper: role owners
		`{"owner":"NODE1"}`, // registerClusteredRole audit cnoOwner re-read
		``,                  // Add-ClusterVirtualMachineRole
	}}
	m := vmModuleWithTransport(transport, "t-2421")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, &VMConfig{
		Name:       vmName,
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    `C:\VMs\ha-first-vm.vhdx`,
		SwitchName: "Default Switch",
		Generation: 2,
		State:      "stopped",
		HARole:     &HARoleConfig{ClusterName: cluster},
	}))

	assert.Equal(t, 1, countCmd(transport, psCreateVM),
		"the CNO owner must perform the first-ever create")
	assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
		"the created VM must still be registered as a clustered role")
}

// TestSetVM_ClusterOwnershipHelperError_PropagatesAsSetError (REQUIRED, #2421):
// a transport error from clusterOwnershipHelper is returned as a setVM error —
// never silently swallowed into a skip (fail-safe).
func TestSetVM_ClusterOwnershipHelperError_PropagatesAsSetError(t *testing.T) {
	const vmName = "ha-first-vm"
	const cluster = "lab-hv"

	// readCNOOwner reports a valid owner, then the role-owner read fails —
	// clusterOwnershipHelper returns that error.
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":false}`,   // getVM: locally absent
			`{"owners":{}}`,     // getVM probe: role absent cluster-wide
			`{"owner":"NODE2"}`, // ownership helper: CNO owner read
			``,                  // ownership helper: role owners — errors below
		},
		perCallErrors: []error{nil, nil, nil, errors.New("cluster service down")},
	}
	m := vmModuleWithTransport(transport, "t-2421")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	err := m.Set(context.Background(), "vm:"+vmName, &VMConfig{
		Name:       vmName,
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    `C:\VMs\ha-first-vm.vhdx`,
		SwitchName: "Default Switch",
		Generation: 2,
		State:      "running",
		HARole:     &HARoleConfig{ClusterName: cluster},
	})
	require.Error(t, err,
		"an ownership-helper failure must fail the Set, not silently skip")
	assert.Contains(t, err.Error(), "cluster service down")
	assert.Equal(t, 0, countCmd(transport, psCreateVM),
		"no create may proceed when ownership could not be determined")
}

// TestSetVM_ClusterWideAbsentRole_ScopeCapErrorPropagates (#2421): an
// out-of-scope ha_role.cluster_name fails the Set with ErrClusterNotDeclared
// (S5 scope cap) — never a silent skip, never a create.
func TestSetVM_ClusterWideAbsentRole_ScopeCapErrorPropagates(t *testing.T) {
	const vmName = "ha-rogue-vm"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"found":false}`, // getVM: locally absent
		`{"owners":{}}`,   // getVM probe (module scope): role absent cluster-wide
	}}
	m := vmModuleWithTransport(transport, "t-2421")
	m.clusterName = "lab-hv"
	m.nodeHostname = "NODE1"

	err := m.Set(context.Background(), "vm:"+vmName, &VMConfig{
		Name:       vmName,
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    `C:\VMs\ha-rogue-vm.vhdx`,
		SwitchName: "Default Switch",
		Generation: 2,
		State:      "running",
		HARole:     &HARoleConfig{ClusterName: "rogue-cluster"},
	})
	require.ErrorIs(t, err, ErrClusterNotDeclared)
	assert.Equal(t, 0, countCmd(transport, psCreateVM))
}

// ─── AC1 (REQUIRED TEST): promote / demote an existing VM, idempotent ─────────

// TestSetVM_HARole_PromoteExistingVM: adding ha_role to an already-created VM
// registers the clustered role on the next converge.
func TestSetVM_HARole_PromoteExistingVM(t *testing.T) {
	const vmName = "ha-promote-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "stopped", 2, 4096), // getVM: VM exists
		`{"owners":{}}`,                        // getVM probe: not a member
		`{"owners":{}}`,                        // #2422 lifecycle owner gate: role not yet registered → proceed (first-time promote)
		`{"owner":"NODE1"}`,                    // ownership helper: CNO owner
		`{"owners":{}}`,                        // ownership helper: role owners
		`{"owner":"NODE1"}`,                    // audit cnoOwner re-read
		``,                                     // Add-ClusterVirtualMachineRole
	}}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, mapConfigState{
		"name":      vmName,
		"memory_mb": 4096,
		"cpu_count": 2,
		"vhd_path":  `C:\VMs\ha-promote-vm.vhdx`,
		"state":     "stopped",
		"ha_role":   map[string]interface{}{"cluster_name": cluster},
	}))

	assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
		"ha_role on an existing VM must register the clustered role")
	assert.Equal(t, 0, countCmd(transport, psRemoveVM), "promote must not touch the VM")
}

// TestSetVM_HARole_DemoteRemovesRoleOnly: removing ha_role from a previously-HA
// vm resource demotes — the clustered role is removed, the VM is untouched, and
// no operator opt-in flag is required (the demote path never deletes the VM).
func TestSetVM_HARole_DemoteRemovesRoleOnly(t *testing.T) {
	const vmName = "ha-demote-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "stopped", 2, 4096), // getVM: VM exists
		`{"owners":{"ha-demote-vm":"NODE1"}}`,  // getVM probe: member
		`{"owner":"NODE1"}`,                    // ownership helper: CNO owner
		`{"owners":{"ha-demote-vm":"NODE1"}}`,  // ownership helper: role owners
		`{"owner":"NODE1"}`,                    // audit cnoOwner re-read
		``,                                     // Remove-ClusterGroup
	}}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, mapConfigState{
		"name":      vmName,
		"memory_mb": 4096,
		"cpu_count": 2,
		"vhd_path":  `C:\VMs\ha-demote-vm.vhdx`,
		"state":     "stopped",
		// no ha_role key — desired state is standalone
	}))

	assert.Equal(t, 1, countCmd(transport, psRemoveClusterResource),
		"removing ha_role must remove the clustered role")
	assert.Equal(t, 0, countCmd(transport, psRemoveVM),
		"demote is role-only — the VM must never be deleted")
}

// TestSetVM_HARole_PromoteIdempotent: an already-registered member with ha_role
// still declared performs no membership mutation (and no ownership reads).
func TestSetVM_HARole_PromoteIdempotent(t *testing.T) {
	const vmName = "ha-steady-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "stopped", 2, 4096), // getVM: VM exists
		`{"owners":{"ha-steady-vm":"NODE1"}}`,  // getVM probe: already a member
		`{"owners":{"ha-steady-vm":"NODE1"}}`,  // #2422 lifecycle owner gate: this node owns the role → proceed
	}}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, mapConfigState{
		"name":      vmName,
		"memory_mb": 4096,
		"cpu_count": 2,
		"vhd_path":  `C:\VMs\ha-steady-vm.vhdx`,
		"state":     "stopped",
		"ha_role":   map[string]interface{}{"cluster_name": cluster},
	}))

	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"an already-registered member must not re-register")
	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource))
	transport.mu.Lock()
	defer transport.mu.Unlock()
	assert.Len(t, transport.calls, 3,
		"steady state must be exactly getVM + probe + #2422 owner gate — no membership machinery")
}

// TestSetVM_HARole_DemoteIdempotent: a VM that is already standalone with no
// ha_role declared performs no membership mutation.
func TestSetVM_HARole_DemoteIdempotent(t *testing.T) {
	const vmName = "plain-steady-vm"

	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "stopped", 2, 4096),
		`{"owners":{}}`,
	}}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = "lab-hv"
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, mapConfigState{
		"name":      vmName,
		"memory_mb": 4096,
		"cpu_count": 2,
		"vhd_path":  `C:\VMs\plain-steady-vm.vhdx`,
		"state":     "stopped",
	}))

	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource))
	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole))
}

// ─── AC3 (REQUIRED TEST): non-CNO-owner nodes no-op ────────────────────────────

// TestSetVM_HARole_NonOwnerNoop: promote on a non-CNO-owner node performs no
// membership mutation and returns nil — coordination, not authorization.
func TestSetVM_HARole_NonOwnerNoop(t *testing.T) {
	const vmName = "ha-nonowner-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "stopped", 2, 4096), // getVM: VM exists
		`{"owners":{}}`,                        // getVM probe: not a member
		`{"owners":{}}`,                        // #2422 lifecycle owner gate: role not registered → proceed (first-time promote)
		`{"owner":"NODE2"}`,                    // ownership helper: another node owns CNO
		`{"owners":{}}`,                        // ownership helper: role owners
		`{"owner":"NODE2"}`,                    // audit cnoOwner re-read
	}}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "vm:"+vmName, mapConfigState{
		"name":      vmName,
		"memory_mb": 4096,
		"cpu_count": 2,
		"vhd_path":  `C:\VMs\ha-nonowner-vm.vhdx`,
		"state":     "stopped",
		"ha_role":   map[string]interface{}{"cluster_name": cluster},
	}))

	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"a non-owner node must not mutate cluster membership")
}

// ─── AC2 (REQUIRED TEST): source-provisioned VM registered by finalizing ──────

// TestFinalizeProvision_HARole_RegistersBeforeFinalizing: a source-provisioned
// VM with ha_role declared is registered as a clustered role during finalize —
// no later than the record's installing → finalizing transition (ready is
// controller-side, #2050, and never observed here).
func TestFinalizeProvision_HARole_RegistersBeforeFinalizing(t *testing.T) {
	ctx := context.Background()
	const vmName = "ha-src-vm"
	const cluster = "lab-hv"

	store := NewMemProvisionStore()
	started := time.Now().UTC().Add(-10 * time.Minute)
	require.NoError(t, store.SetProvision(ctx, &ProvisionRecord{
		VMName:        vmName,
		State:         ProvisionStateInstalling,
		CorrelationID: vmName,
		StartedAt:     started,
		UpdatedAt:     started,
	}))

	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSON(vmName, "running", 2, 4096), // vmIsRunning → getVM
		`{"owners":{}}`,                        // getVM probe (cluster scope set)
		``,                                     // Dismount-VHD (detach seed)
		``,                                     // Remove-Item (seed VHDX)
		``,                                     // Remove-Item (answer ISO)
		`{"owner":"NODE1"}`,                    // ownership helper: CNO owner
		`{"owners":{}}`,                        // ownership helper: role owners
		`{"owner":"NODE1"}`,                    // audit cnoOwner re-read
		``,                                     // Add-ClusterVirtualMachineRole
	}}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"
	m.provisionStore = store

	cfg := &VMConfig{
		Name:    vmName,
		VHDPath: `C:\VMs\ha-src-vm.vhdx`,
		HARole:  &HARoleConfig{ClusterName: cluster},
		Source: &SourceConfig{
			Image:      `C:\images\debian.raw`,
			OSFamily:   "linux",
			Completion: CompletionConfig{Mode: "steward-registration", Timeout: "10m"},
		},
	}

	require.NoError(t, m.finalizeProvision(ctx, vmName, vmName, cfg))

	assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
		"finalize must register the declared ha_role")

	rec, err := store.GetProvision(ctx, vmName)
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateFinalizing, rec.State,
		"registration happens no later than the finalizing transition")
}

// TestFinalizeProvision_HARole_RegistrationFailureRetries: a failed registration
// keeps the record at installing so the next converge cycle retries finalize —
// the record must not advance past a VM that should be HA but is not.
func TestFinalizeProvision_HARole_RegistrationFailureRetries(t *testing.T) {
	ctx := context.Background()
	const vmName = "ha-src-fail-vm"
	const cluster = "lab-hv"

	store := NewMemProvisionStore()
	started := time.Now().UTC().Add(-10 * time.Minute)
	require.NoError(t, store.SetProvision(ctx, &ProvisionRecord{
		VMName:        vmName,
		State:         ProvisionStateInstalling,
		CorrelationID: vmName,
		StartedAt:     started,
		UpdatedAt:     started,
	}))

	transport := &testWinRMTransport{
		perCallOutputs: []string{
			hostVMJSON(vmName, "running", 2, 4096), // vmIsRunning → getVM
			`{"owners":{}}`,                        // getVM probe
			``,                                     // Dismount-VHD
			``,                                     // Remove-Item (seed)
			``,                                     // Remove-Item (iso)
			`{"owner":"NODE1"}`,                    // CNO owner
			`{"owners":{}}`,                        // role owners
			`{"owner":"NODE1"}`,                    // audit re-read
			``,                                     // Add — errors below
		},
		perCallErrors: []error{nil, nil, nil, nil, nil, nil, nil, nil, errors.New("cluster add failed")},
	}
	m := vmModuleWithTransport(transport, "t-ha")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"
	m.provisionStore = store

	cfg := &VMConfig{
		Name:    vmName,
		VHDPath: `C:\VMs\ha-src-fail-vm.vhdx`,
		HARole:  &HARoleConfig{ClusterName: cluster},
		Source: &SourceConfig{
			Image:      `C:\images\debian.raw`,
			OSFamily:   "linux",
			Completion: CompletionConfig{Mode: "steward-registration", Timeout: "10m"},
		},
	}

	require.Error(t, m.finalizeProvision(ctx, vmName, vmName, cfg))

	rec, err := store.GetProvision(ctx, vmName)
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, rec.State,
		"a failed HA registration must keep the record at installing for retry")
}

// ─── AC4: hyperv.cluster no longer offers a second membership surface ─────────

// TestSetCluster_RoleNamesNoLongerAddRoles: a hyperv.cluster resource naming a
// role that does not exist performs NO membership mutation — role creation
// lives exclusively on hyperv.vm ha_role.
func TestSetCluster_RoleNamesNoLongerAddRoles(t *testing.T) {
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"owner":"NODE1"}`, // ownership helper: CNO owner
		`{"owners":{}}`,     // ownership helper: role owners (role absent)
		`{"owner":"NODE1"}`, // audit cnoOwner re-read
	}}
	m := vmModuleWithTransport(transport, "t-cluster")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "cluster:"+cluster, mapConfigState{
		"name":       cluster,
		"role_names": []interface{}{"some-vm"},
	}))

	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"hyperv.cluster must no longer create VM roles — ha_role on hyperv.vm is the single surface")
}

// TestSetCluster_AbsentMembershipSurfaceRemoved: the destructive role-removal
// surface on hyperv.cluster is gone — state:absent on role_names errors with
// the single-surface sentinel and issues no PS mutation.
func TestSetCluster_AbsentMembershipSurfaceRemoved(t *testing.T) {
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"owner":"NODE1"}`,
		`{"owners":{"some-vm":"NODE1"}}`,
		`{"owner":"NODE1"}`,
	}}
	m := vmModuleWithTransport(transport, "t-cluster")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	err := m.Set(context.Background(), "cluster:"+cluster, mapConfigState{
		"name":              cluster,
		"role_names":        []interface{}{"some-vm"},
		"state":             "absent",
		"allow_destructive": true,
	})
	require.ErrorIs(t, err, ErrRoleMembershipNotClusterManaged)
	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"the removed surface must not issue Remove-ClusterGroup")
}

// TestSetCluster_PropertiesStillReconciledForExistingRole: narrowing the surface
// keeps hyperv.cluster's cluster-scoped concern — placement/scheduling property
// reconcile (#2306) — for roles that already exist.
func TestSetCluster_PropertiesStillReconciledForExistingRole(t *testing.T) {
	const cluster = "lab-hv"

	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"owner":"NODE1"}`,              // ownership helper: CNO owner
		`{"owners":{"some-vm":"NODE1"}}`, // ownership helper: role exists
		`{"owner":"NODE1"}`,              // audit cnoOwner re-read
		``,                               // Set-ClusterOwnerNode (preferred owners)
	}}
	m := vmModuleWithTransport(transport, "t-cluster")
	m.clusterName = cluster
	m.nodeHostname = "NODE1"

	require.NoError(t, m.Set(context.Background(), "cluster:"+cluster, mapConfigState{
		"name":       cluster,
		"role_names": []interface{}{"some-vm"},
		"roles": map[string]interface{}{
			"some-vm": map[string]interface{}{
				"preferred_owners": []interface{}{"NODE1", "NODE2"},
			},
		},
	}))

	assert.Equal(t, 1, countCmd(transport, psSetClusterRolePreferredOwners),
		"property reconcile for existing roles stays on hyperv.cluster")
}
