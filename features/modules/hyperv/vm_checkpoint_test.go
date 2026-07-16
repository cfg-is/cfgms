// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Issue #2626: checkpoint-aware disk comparison ─────────────────────────────
//
// A Hyper-V checkpoint layers a differencing disk (.avhdx) as the VM's ACTIVE
// disk; the configured base .vhdx becomes the read-only root of the parent chain.
// Cfgms-GetVM / psGetVM resolve that chain to its ROOT (walking Get-VHD.ParentPath)
// and report the checkpoint count, so a checkpointed VM — still on its configured
// disk — does not falsely drift on vhd_path. The chain-root resolution runs in
// PowerShell (live-verified); these tests exercise the Go-side parse + the
// observed-only field contract.

// TestGetVM_ReportsChainRootVHDPathAndCheckpointCount (REQUIRED, #2626): getVM
// with a result whose Path is the (already chain-root-resolved) base .vhdx and a
// non-zero CheckpointCount reports the base as VHDPath and surfaces the checkpoint
// count as observed state.
func TestGetVM_ReportsChainRootVHDPathAndCheckpointCount(t *testing.T) {
	const vmName = "cp-vm"
	// The JSON Cfgms-GetVM emits for a running VM with 3 checkpoints: Path is the
	// resolved chain root (the base .vhdx), NOT the active .avhdx.
	js := `{"found":true,"Name":"cp-vm","MemoryStartupBytes":4294967296,"ProcessorCount":4,"Generation":2,"Path":"C:\\VMs\\cp-vm.vhdx","ConfigurationLocation":"C:\\VMs","CheckpointCount":3,"SwitchName":"","SwitchNames":[],"State":"Running"}`
	transport := &testWinRMTransport{perCallOutputs: []string{js}}
	m := vmModuleWithTransport(transport, "t-cp")

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Equal(t, `C:\VMs\cp-vm.vhdx`, cfg.VHDPath,
		"VHDPath must be the disk-chain root, never the active .avhdx differencing disk")
	assert.Equal(t, 3, cfg.CheckpointCount,
		"the checkpoint count must be surfaced as observed state")
}

// TestGetVM_WrongChainRoot_PreservesDrift (REQUIRED, #2626): when the disk-chain
// root differs from the declared vhd_path, the observed VHDPath equals the root
// (not the declared path), so the standard executor field comparison detects real
// drift. The PowerShell side resolves to the root; Go faithfully reports it.
func TestGetVM_WrongChainRoot_PreservesDrift(t *testing.T) {
	const vmName = "wrong-root-vm"
	const declaredPath = `C:\VMs\vm.vhdx`
	// The chain root resolved by PS is a DIFFERENT disk — real drift.
	js := `{"found":true,"Name":"wrong-root-vm","MemoryStartupBytes":2147483648,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\other.vhdx","ConfigurationLocation":"C:\\VMs","CheckpointCount":0,"SwitchName":"","SwitchNames":[],"State":"Running"}`
	transport := &testWinRMTransport{perCallOutputs: []string{js}}
	m := vmModuleWithTransport(transport, "t-wrong")

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Equal(t, `C:\VMs\other.vhdx`, cfg.VHDPath,
		"VHDPath must equal the chain root reported by PS, not the declared path")
	assert.NotEqual(t, declaredPath, cfg.VHDPath,
		"a VM on the wrong base disk must still report drift (VHDPath != declared vhd_path)")
}

// TestGetVM_GetVHDFailure_FallsBackToRawPath (REQUIRED, #2626): when Get-VHD fails
// during chain-root resolution (non-VHD disk, inaccessible path, permission error),
// the PowerShell catch block falls back to the raw active-disk path and returns it
// as Path in the JSON. Go must faithfully surface that raw path as VHDPath (no panic,
// no field drop, no silent reinterpretation). This exercises the fallback contract for
// the catch-block degradation path.
func TestGetVM_GetVHDFailure_FallsBackToRawPath(t *testing.T) {
	const vmName = "snap-vm"
	// Get-VHD failed; PS fell back to the raw active-disk path (a .avhdx).
	// CheckpointCount=1 so the operator can see there is a checkpoint even in
	// the degraded case.
	js := `{"found":true,"Name":"snap-vm","MemoryStartupBytes":2147483648,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\cp-vm-snap.avhdx","ConfigurationLocation":"C:\\VMs","CheckpointCount":1,"SwitchName":"","SwitchNames":[],"State":"Running"}`
	transport := &testWinRMTransport{perCallOutputs: []string{js}}
	m := vmModuleWithTransport(transport, "t-fallback")

	cfg, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err)
	assert.Equal(t, `C:\VMs\cp-vm-snap.avhdx`, cfg.VHDPath,
		"when Get-VHD chain resolution fails, VHDPath must be the raw active-disk path returned by PS")
	assert.Equal(t, 1, cfg.CheckpointCount,
		"CheckpointCount must be surfaced even in the fallback (degraded) case")
}

// TestVMConfig_CheckpointCount_ObservedOnly (REQUIRED, #2626): CheckpointCount is
// on the DNA/Get surface (AsMap) but is NOT a managed field, so it can never
// register as drift — matching the ConfigLocation contract.
func TestVMConfig_CheckpointCount_ObservedOnly(t *testing.T) {
	cfg := &VMConfig{Name: "x", VHDPath: `C:\VMs\x.vhdx`, CheckpointCount: 2}

	assert.Equal(t, 2, cfg.AsMap()["checkpoint_count"],
		"checkpoint_count must be exposed on the AsMap/DNA surface")
	assert.NotContains(t, cfg.GetManagedFields(), "checkpoint_count",
		"checkpoint_count must be absent from GetManagedFields so it never counts as drift")
}

// ─── Issue #2627: declarative checkpoint policy (merge-to-clean) ────────────────
//
// Cleanup MERGES stray checkpoints (Remove-VMSnapshot folds the differencing disk
// into its parent — non-destructive; never Restore/revert). Opt-in: absent block =
// observe-only (#2626 default). These tests exercise the Go-side policy resolution,
// merge-set selection, and the transport calls reconcileCheckpoints issues.

// snapshotListJSON builds the psGetVMSnapshots payload for a set of checkpoints,
// matching the JSON the PowerShell emits (Name + UTC ISO-8601 CreationTime).
func snapshotListJSON(t *testing.T, snaps ...vmSnapshot) string {
	t.Helper()
	parts := make([]string, 0, len(snaps))
	for _, s := range snaps {
		parts = append(parts, fmt.Sprintf(`{"Name":%q,"CreationTime":%q}`,
			s.Name, s.CreationTime.UTC().Format(time.RFC3339Nano)))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// mergedSnapshotNames returns the checkpoint names passed to Remove-VMSnapshot
// (the merge primitive), in call order. psArgs are recorded in sorted-key order,
// so for {Name, SnapshotName} the snapshot name is args[1].
func mergedSnapshotNames(calls []winRMCall) []string {
	var names []string
	for _, c := range calls {
		if c.scriptBlock == psRemoveVMSnapshot && len(c.args) == 2 {
			if s, ok := c.args[1].(string); ok {
				names = append(names, s)
			}
		}
	}
	return names
}

// TestCheckpointReconcile_PolicyNone_MergesAllOldestFirst (REQUIRED, AC1): a
// policy: none config merges every checkpoint (post-converge count = 0),
// oldest-first.
func TestCheckpointReconcile_PolicyNone_MergesAllOldestFirst(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []vmSnapshot{
		{Name: "cp-old", CreationTime: base},
		{Name: "cp-mid", CreationTime: base.Add(24 * time.Hour)},
		{Name: "cp-new", CreationTime: base.Add(48 * time.Hour)},
	}
	transport := &testWinRMTransport{perCallOutputs: []string{snapshotListJSON(t, snaps...)}}
	m := vmModuleWithTransport(transport, "t-cp-none")

	require.NoError(t, m.reconcileCheckpoints(context.Background(), "cp-vm", &CheckpointPolicy{Policy: "none"}))

	assert.Equal(t, psGetVMSnapshots, transport.calls[0].scriptBlock,
		"reconcile must first LIST checkpoints")
	assert.Equal(t, []string{"cp-old", "cp-mid", "cp-new"}, mergedSnapshotNames(transport.calls),
		"policy none must merge ALL checkpoints, oldest-first (post-converge count = 0)")
	assert.Len(t, transport.calls, 4, "exactly one list + three merges")
}

// TestCheckpointReconcile_MaxZero_MergesAll (REQUIRED, AC1): max: 0 is equivalent
// to policy: none — merge all.
func TestCheckpointReconcile_MaxZero_MergesAll(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []vmSnapshot{
		{Name: "a", CreationTime: base},
		{Name: "b", CreationTime: base.Add(time.Hour)},
	}
	transport := &testWinRMTransport{perCallOutputs: []string{snapshotListJSON(t, snaps...)}}
	m := vmModuleWithTransport(transport, "t-cp-max0")

	zero := 0
	require.NoError(t, m.reconcileCheckpoints(context.Background(), "cp-vm", &CheckpointPolicy{Max: &zero}))
	assert.Equal(t, []string{"a", "b"}, mergedSnapshotNames(transport.calls),
		"max: 0 must merge all checkpoints (equivalent to policy: none)")
}

// TestCheckpointReconcile_MaxN_RetainsNewestMergesRest (REQUIRED, AC2): max: N
// retains the newest N and merges the rest, oldest-first.
func TestCheckpointReconcile_MaxN_RetainsNewestMergesRest(t *testing.T) {
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []vmSnapshot{
		{Name: "cp1", CreationTime: base},
		{Name: "cp2", CreationTime: base.Add(1 * time.Hour)},
		{Name: "cp3", CreationTime: base.Add(2 * time.Hour)},
		{Name: "cp4", CreationTime: base.Add(3 * time.Hour)},
		{Name: "cp5", CreationTime: base.Add(4 * time.Hour)},
	}
	transport := &testWinRMTransport{perCallOutputs: []string{snapshotListJSON(t, snaps...)}}
	m := vmModuleWithTransport(transport, "t-cp-max")

	three := 3
	require.NoError(t, m.reconcileCheckpoints(context.Background(), "cp-vm",
		&CheckpointPolicy{Policy: "retain", Max: &three}))

	assert.Equal(t, []string{"cp1", "cp2"}, mergedSnapshotNames(transport.calls),
		"max: 3 must retain the newest 3 (cp3–cp5) and merge the oldest 2, oldest-first")
}

// TestCheckpointsToMerge_MaxAge_RetainsYoungerMergesOlder (REQUIRED, AC2): max_age
// retains checkpoints younger than the window and merges older ones, oldest-first.
// The age comparison is time-injected here for determinism.
func TestCheckpointsToMerge_MaxAge_RetainsYoungerMergesOlder(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	snaps := []vmSnapshot{
		{Name: "old-2d", CreationTime: now.Add(-48 * time.Hour)},
		{Name: "old-25h", CreationTime: now.Add(-25 * time.Hour)},
		{Name: "young-1h", CreationTime: now.Add(-1 * time.Hour)},
	}
	merge := checkpointsToMerge(snaps, &CheckpointPolicy{Policy: "retain", MaxAge: "24h"}, now)

	names := make([]string, 0, len(merge))
	for _, s := range merge {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"old-2d", "old-25h"}, names,
		"max_age: 24h must merge checkpoints older than 24h (oldest-first) and retain younger ones")
}

// TestCheckpointReconcile_NoPolicy_ObserveOnly (REQUIRED, AC3): an absent (nil) or
// empty checkpoints block issues NO PowerShell at all — no Get-VMSnapshot, no
// Remove-VMSnapshot. This is the #2626 observe-only default.
func TestCheckpointReconcile_NoPolicy_ObserveOnly(t *testing.T) {
	transport := &testWinRMTransport{}
	m := vmModuleWithTransport(transport, "t-cp-observe")

	require.NoError(t, m.reconcileCheckpoints(context.Background(), "cp-vm", nil))
	require.NoError(t, m.reconcileCheckpoints(context.Background(), "cp-vm", &CheckpointPolicy{}))

	assert.Empty(t, transport.calls,
		"observe-only (absent/empty checkpoints block) must issue NO PowerShell — no list, no merge")
}

// TestVMConfig_Validate_CheckpointRetainWithoutBounds (REQUIRED, AC4): policy:
// retain with neither max nor max_age fails Validate with ErrInvalidCheckpointPolicy;
// a bound (or policy none) validates.
func TestVMConfig_Validate_CheckpointRetainWithoutBounds(t *testing.T) {
	bare := &VMConfig{Name: "cp-vm", CheckpointPolicy: &CheckpointPolicy{Policy: "retain"}}
	assert.ErrorIs(t, bare.Validate(), ErrInvalidCheckpointPolicy,
		"policy retain with no max/max_age must be rejected fail-closed")

	three := 3
	assert.NoError(t, (&VMConfig{Name: "cp-vm",
		CheckpointPolicy: &CheckpointPolicy{Policy: "retain", Max: &three}}).Validate())
	assert.NoError(t, (&VMConfig{Name: "cp-vm",
		CheckpointPolicy: &CheckpointPolicy{Policy: "retain", MaxAge: "24h"}}).Validate())
	assert.NoError(t, (&VMConfig{Name: "cp-vm",
		CheckpointPolicy: &CheckpointPolicy{Policy: "none"}}).Validate())

	// A malformed max_age duration is also rejected.
	assert.ErrorIs(t, (&VMConfig{Name: "cp-vm",
		CheckpointPolicy: &CheckpointPolicy{Policy: "retain", MaxAge: "not-a-duration"}}).Validate(),
		ErrInvalidCheckpointPolicy)
}

// TestCheckpointReconcile_NeverRestores (REQUIRED, AC5): cleanup is merge-only —
// no code path ever issues Restore-VMSnapshot (revert is out of scope, destructive).
func TestCheckpointReconcile_NeverRestores(t *testing.T) {
	// Static guarantee on the PS primitives.
	assert.NotContains(t, psRemoveVMSnapshot, "Restore-VMSnapshot")
	assert.NotContains(t, psGetVMSnapshots, "Restore-VMSnapshot")
	assert.Contains(t, psRemoveVMSnapshot, "Remove-VMSnapshot",
		"cleanup must MERGE via Remove-VMSnapshot (folds the differencing disk into its parent)")

	// Dynamic guarantee: a full merge-all reconcile issues only list + Remove.
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	snaps := []vmSnapshot{
		{Name: "cp1", CreationTime: base},
		{Name: "cp2", CreationTime: base.Add(time.Hour)},
	}
	transport := &testWinRMTransport{perCallOutputs: []string{snapshotListJSON(t, snaps...)}}
	m := vmModuleWithTransport(transport, "t-cp-restore")

	require.NoError(t, m.reconcileCheckpoints(context.Background(), "cp-vm", &CheckpointPolicy{Policy: "none"}))
	for _, c := range transport.calls {
		assert.NotContains(t, c.scriptBlock, "Restore-VMSnapshot",
			"no reconcile path may ever issue Restore-VMSnapshot")
	}
}

// TestCheckpointPolicy_ManagedFieldDrivesConvergence (#2627 convergence trigger):
// checkpoint_policy is a MANAGED field (so a declared policy drifts vs getVM's
// empty observed value and drives setVM), while an absent policy emits "" on both
// sides — preserving the #2626 observe-only default (no false drift).
func TestCheckpointPolicy_ManagedFieldDrivesConvergence(t *testing.T) {
	assert.Contains(t, (&VMConfig{}).GetManagedFields(), "checkpoint_policy",
		"checkpoint_policy must be a managed field so a declared policy triggers Set")

	// Observed side (getVM never sets CheckpointPolicy) → empty canonical string.
	observed := &VMConfig{Name: "cp-vm", CheckpointCount: 3}
	assert.Equal(t, "", observed.AsMap()["checkpoint_policy"],
		"getVM output has no policy ⇒ empty ⇒ no drift when the config declares none (observe-only)")

	// Desired side with a policy → non-empty canonical string ⇒ drifts vs observed "".
	three := 3
	desired := &VMConfig{Name: "cp-vm", CheckpointPolicy: &CheckpointPolicy{Policy: "retain", Max: &three}}
	assert.Equal(t, "retain:max=3", desired.AsMap()["checkpoint_policy"])
	assert.NotEqual(t, observed.AsMap()["checkpoint_policy"], desired.AsMap()["checkpoint_policy"],
		"a declared policy must differ from the observed empty value so Set (reconcile) runs")
}
