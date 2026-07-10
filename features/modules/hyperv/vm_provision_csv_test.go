// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Issue #2447: cluster-visible (CSV) provisioning record for ha_role VMs ─────
//
// storeFor routes an ha_role+CSV VM's provisioning record to the cluster-visible
// CSV store so a mid-provision CNO failover reads the in-progress record and
// surfaces-and-waits (ADR-009 A1.4 Option A) instead of creating a duplicate.

// errProvisionStore is a ProvisionStore whose every operation fails — used to
// prove the fail-loud (CSV) vs swallow (host-local) asymmetry.
type errProvisionStore struct{ err error }

func (e errProvisionStore) GetProvision(context.Context, string) (*ProvisionRecord, error) {
	return nil, e.err
}
func (e errProvisionStore) SetProvision(context.Context, *ProvisionRecord) error { return e.err }
func (e errProvisionStore) DeleteProvision(context.Context, string) error        { return e.err }
func (e errProvisionStore) ListProvisions(context.Context) ([]*ProvisionRecord, error) {
	return nil, e.err
}

const csvVHDPath = `C:\ClusterStorage\CSV01\vol\ha-vm.vhdx`

// TestStoreFor_RoutesHARoleCSVToInjectedStore (AC1): only an ha_role VM whose VHD
// is on a CSV routes to the injected CSV store; every other shape keeps the
// configured host-local store.
func TestStoreFor_RoutesHARoleCSVToInjectedStore(t *testing.T) {
	host := NewMemProvisionStore()
	csv := NewMemProvisionStore()
	m := &hypervModule{provisionStore: host, csvProvisionStore: csv}

	haCSV := &VMConfig{Name: "ha", VHDPath: csvVHDPath, HARole: &HARoleConfig{ClusterName: "lab-hv"}}
	assert.Same(t, csv, m.storeFor(haCSV), "ha_role + CSV vhd → CSV store")

	plain := &VMConfig{Name: "plain", VHDPath: `C:\VMs\plain.vhdx`}
	assert.Same(t, host, m.storeFor(plain), "non-ha_role → host-local store")

	haNonCSV := &VMConfig{Name: "ha2", VHDPath: `C:\VMs\ha2.vhdx`, HARole: &HARoleConfig{ClusterName: "lab-hv"}}
	assert.Same(t, host, m.storeFor(haNonCSV), "ha_role but non-CSV vhd → host-local store")

	assert.Same(t, host, m.storeFor(nil), "nil cfg → host-local store")
}

// haCSVSourceModule wires a module as the CNO owner (NODE1) of an ha_role+CSV
// source VM whose role does not yet exist cluster-wide, with the given CSV store
// injected. The transport answers the 4 reads on the create path up to (but not
// including) any New-VM: getVM(absent) + membership probe(empty) + CNO owner +
// role owners. Any New-VM beyond that is a gate violation.
func haCSVSourceModule(t *testing.T, csvStore ProvisionStore) (*hypervModule, *testWinRMTransport, *fakeAuditStore) {
	t.Helper()
	transport := &testWinRMTransport{perCallOutputs: []string{
		`{"found":false}`,   // getVM: locally absent
		`{"owners":{}}`,     // getVM membership probe: role absent cluster-wide
		`{"owner":"NODE1"}`, // #2421 ownership helper: this node owns the CNO
		`{"owners":{}}`,     // #2421 ownership helper: role owners
	}}
	m := vmModuleWithTransport(transport, "t-2447")
	m.clusterName = "lab-hv"
	m.nodeHostname = "NODE1"
	m.seedDir = `C:\cfgms\seed` // host-local (satisfies the ha_role CSV seed rule)
	m.csvProvisionStore = csvStore
	mgr, store := newFakeAuditManager(t)
	m.auditMgr = mgr
	m.stewardID = "steward-2447"
	return m, transport, store
}

func haCSVSourceVM() *VMConfig {
	return &VMConfig{
		Name:       "ha-vm",
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    csvVHDPath,
		SwitchName: "Default Switch",
		Generation: 2,
		State:      "running",
		HARole:     &HARoleConfig{ClusterName: "lab-hv"},
		Source: &SourceConfig{
			Image:      `C:\images\debian.raw`,
			OSFamily:   "linux",
			Completion: CompletionConfig{Mode: "steward-registration", Timeout: "10m"},
		},
	}
}

// TestSetVM_FailoverMidProvision_NewOwnerSurfacesAndWaits (REQUIRED, #2447): a new
// CNO owner converging an ha_role source VM whose CSV record shows another node's
// in-flight attempt (installing) issues ZERO create/provision transport calls and
// audits the surface-and-wait skip — the duplicate a mid-provision failover would
// otherwise cause.
func TestSetVM_FailoverMidProvision_NewOwnerSurfacesAndWaits(t *testing.T) {
	ctx := context.Background()

	// The cluster-visible record another node wrote mid-provision, seeded in the
	// CSV-routed store this (new-owner) node reads.
	csv := NewMemProvisionStore()
	require.NoError(t, csv.SetProvision(ctx, &ProvisionRecord{
		VMName:        "ha-vm",
		State:         ProvisionStateInstalling,
		CorrelationID: "ha-vm",
		StartedAt:     time.Now().UTC().Add(-5 * time.Minute),
		UpdatedAt:     time.Now().UTC().Add(-5 * time.Minute),
	}))

	m, transport, store := haCSVSourceModule(t, csv)

	require.NoError(t, m.Set(ctx, "vm:ha-vm", haCSVSourceVM()),
		"surface-and-wait is a clean no-op, never an error")

	assert.Equal(t, 0, countCmd(transport, psCreateVM),
		"the new owner must NOT create — the CSV record shows an in-flight attempt elsewhere")

	require.NoError(t, m.auditMgr.Flush(ctx))
	skips := auditEntriesByActionCT(store.captured(), "vm-provision-skip-in-progress-elsewhere")
	require.Len(t, skips, 1, "the surface-and-wait skip must be audited")
}

// TestSetVM_CSVRecordReadError_FailsLoud (REQUIRED, #2447): an unreadable CSV
// record propagates as a setVM error and no VM is created — creation must never
// proceed while cluster-visible record state is unknown.
func TestSetVM_CSVRecordReadError_FailsLoud(t *testing.T) {
	ctx := context.Background()
	m, transport, _ := haCSVSourceModule(t, errProvisionStore{err: errors.New("csv record unreadable")})

	err := m.Set(ctx, "vm:ha-vm", haCSVSourceVM())
	require.Error(t, err, "an unreadable cluster-visible record must fail the Set, not be swallowed")
	assert.Contains(t, err.Error(), "csv record unreadable")
	assert.Equal(t, 0, countCmd(transport, psCreateVM),
		"no create may proceed while CSV record state is unknown")
}

// TestProvision_NonHARole_UsesConfiguredStore (REQUIRED, #2447): non-ha_role
// provisioning touches ONLY the configured host-local store — nothing is written
// under .cfgms-provision — AND the host-local read keeps its swallow-on-error
// semantics (a GetProvision error yields (false, nil), so the create path
// proceeds). Regression guard for both the routing predicate and the fail-loud
// scope boundary.
func TestProvision_NonHARole_UsesConfiguredStore(t *testing.T) {
	ctx := context.Background()

	// Routing: a non-ha_role accessor call writes to the host-local store and
	// never touches the injected CSV store's directory.
	home := t.TempDir()
	host := NewMemProvisionStore()
	m := &hypervModule{provisionStore: host, csvProvisionStore: newCSVProvisionStore(home)}

	plain := &VMConfig{Name: "plain-vm", VHDPath: `C:\VMs\plain-vm.vhdx`}
	rec, err := m.loadOrInitProvision(ctx, plain, "plain-vm")
	require.NoError(t, err)
	require.NoError(t, m.advanceProvision(ctx, plain, "plain-vm", rec, ProvisionStateCreating))

	got, err := host.GetProvision(ctx, "plain-vm")
	require.NoError(t, err, "the non-ha_role record must land in the configured host-local store")
	assert.Equal(t, ProvisionStateCreating, got.State)
	assert.NoDirExists(t, filepath.Join(home, csvProvisionSubdir),
		"a non-ha_role VM must write nothing under .cfgms-provision")

	// Fail-loud scope boundary: a host-local read error is SWALLOWED (false, nil),
	// unchanged from before #2447 — only the CSV store fails loud.
	mErr := &hypervModule{provisionStore: errProvisionStore{err: errors.New("host store down")}}
	own, err := mErr.isOwnIncompleteAttempt(ctx, plain)
	require.NoError(t, err, "a host-local read error must NOT fail loud (preserved swallow semantics)")
	assert.False(t, own, "a swallowed host-local error reports no in-progress attempt → create proceeds")
}

// TestProvisionRecordsForSweep_IncludesCSVRecords (#2447): the stale-seed-media
// TTL sweep must see ha_role+CSV records too — they live in the CSV store, not the
// host-local one, so a host-local-only list would silently stop TTL-sweeping
// join-token-bearing seed media for exactly the ha_role class this story targets.
func TestProvisionRecordsForSweep_IncludesCSVRecords(t *testing.T) {
	ctx := context.Background()

	host := NewMemProvisionStore()
	require.NoError(t, host.SetProvision(ctx, ccsRecord("plain-vm", ProvisionStateInstalling)))

	csv := NewMemProvisionStore()
	require.NoError(t, csv.SetProvision(ctx, ccsRecord("ha-vm", ProvisionStateInstalling)))

	m := &hypervModule{
		provisionStore:    host,
		csvProvisionStore: csv,
		vms:               make(map[string]VMConfig),
	}
	// The ha_role+CSV VM is in the module's converge cache, so the sweep must
	// consult its CSV store.
	m.vms["ha-vm"] = VMConfig{Name: "ha-vm", VHDPath: csvVHDPath, HARole: &HARoleConfig{ClusterName: "lab-hv"}}

	names := map[string]bool{}
	for _, r := range m.provisionRecordsForSweep(ctx) {
		names[r.VMName] = true
	}
	assert.True(t, names["plain-vm"], "host-local records must be swept")
	assert.True(t, names["ha-vm"], "ha_role+CSV records must be swept (regression: #2447)")
}

// TestSetVM_FailoverMidProvision_CSVRecordDir confirms the production path (no
// injected store) computes the CSV record directory from the VM's CSV home via
// vmHomeDir — dir(vhd_path)/.cfgms-provision — not filepath.Dir (Issue #2044).
func TestSetVM_FailoverMidProvision_CSVRecordDir(t *testing.T) {
	m := &hypervModule{provisionStore: NewMemProvisionStore()}
	store := m.storeFor(&VMConfig{Name: "ha-vm", VHDPath: csvVHDPath, HARole: &HARoleConfig{ClusterName: "lab-hv"}})
	csv, ok := store.(*csvProvisionStore)
	require.True(t, ok, "ha_role+CSV must resolve to a *csvProvisionStore in production")
	assert.Equal(t, `C:\ClusterStorage\CSV01\vol`, csv.homeDir,
		"the record home must be dir(vhd_path) via vmHomeDir, not filepath.Dir")
}
