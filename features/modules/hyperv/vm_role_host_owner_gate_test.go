// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// reconcileRoleMembership gates work on an EXISTING VM's clustered role on HOST
// ownership, not CNO ownership: the node that runs the VM promotes/demotes its
// role, because Add/Remove-ClusterVirtualMachineRole resolve the VM node-locally
// (only its host can act). The CNO gate is reserved for ownerless cluster tasks
// (creating a brand-new clustered VM — the vm.go create path). These tests pin
// the inversion both ways.

// TestRoleMembership_HostOwner_NonCNO_Promotes is the core fix: a node that
// HOSTS the VM but does NOT own the CNO still promotes it. Under the old
// CNO-ownership gate this silently skipped, so a VM on any non-CNO node could
// never be promoted via config.
func TestRoleMembership_HostOwner_NonCNO_Promotes(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE2"}`,                      // helper: CNO owner is NODE2 — this node (NODE1) does NOT own the CNO
			`{"owners":{}}`,                          // helper: resource owners → web-01 not yet a clustered role
			hostVMJSON("web-01", "running", 2, 4096), // host probe: NODE1 HOSTS web-01
			``,                                       // Add-ClusterVirtualMachineRole → success
		},
	}
	m, store := clusterTestModule(t, transport) // m.nodeHostname == "NODE1"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	err := m.reconcileRoleMembership(context.Background(), "lab-hv", "web-01", "present", false)
	require.NoError(t, err)

	assert.Equal(t, 1, countCmd(transport, psAddClusterVMRole),
		"the hosting node must promote its local VM even though it does NOT own the CNO")

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var createEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-create" {
			createEvt = e
		}
	}
	require.NotNil(t, createEvt, "a create audit event must be recorded on the hosting node")
	require.NotNil(t, createEvt.Changes)
	assert.Equal(t, true, createEvt.Changes.After["created"])
}

// TestRoleMembership_NotHost_Skips is the other half of the inversion: even the
// CNO-owner node does NOT promote a VM it does not host — the gate is host
// ownership, not CNO ownership. It records a host-gated skip and issues no
// cluster write. (Another node hosts the VM and owns its reconcile.)
func TestRoleMembership_NotHost_Skips(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // helper: this node (NODE1) DOES own the CNO ...
			`{"owners":{"web-01":"NODE2"}}`, // ... but the VM's role is owned/hosted by NODE2
			`{"found":false}`,               // host probe: NODE1 does NOT host web-01
		},
	}
	m, store := clusterTestModule(t, transport) // m.nodeHostname == "NODE1"
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	err := m.reconcileRoleMembership(context.Background(), "lab-hv", "web-01", "present", false)
	require.NoError(t, err, "a non-host must return nil — coordination, not authorization")

	assert.Equal(t, 0, countCmd(transport, psAddClusterVMRole),
		"a node that does not host the VM must issue no Add — even when it owns the CNO")
	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"a non-host must issue no Remove")

	require.NoError(t, m.auditMgr.Flush(context.Background()))
	var skipEvt *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "cluster-set-skip" {
			skipEvt = e
		}
	}
	require.NotNil(t, skipEvt, "a host-gated skip audit event must be recorded")
	require.NotNil(t, skipEvt.Changes)
	assert.Equal(t, false, skipEvt.Changes.After["hosts_vm"], "the skip must record hosts_vm: false")
	assert.Equal(t, true, skipEvt.Changes.After["skipped"])
}

// TestRoleMembership_NotHost_Demote_Skips verifies the host gate also guards the
// demote path: a node that does not host the VM issues no Remove even with
// allowDestructive true.
func TestRoleMembership_NotHost_Demote_Skips(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"owner":"NODE1"}`,             // helper: this node owns the CNO
			`{"owners":{"web-01":"NODE2"}}`, // role hosted by NODE2
			`{"found":false}`,               // host probe: NODE1 does NOT host web-01
		},
	}
	m, _ := clusterTestModule(t, transport)
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	err := m.reconcileRoleMembership(context.Background(), "lab-hv", "web-01", "absent", true)
	require.NoError(t, err, "a non-host demote is a coordinated no-op")
	assert.Equal(t, 0, countCmd(transport, psRemoveClusterResource),
		"a non-host must issue no Remove even on the destructive path")
}
