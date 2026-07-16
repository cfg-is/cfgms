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

// hostVMJSONWithCheckpoints builds a psGetVM response for a VM with the given
// observed checkpoint count (the field getVM reads for count-based compliance).
func hostVMJSONWithCheckpoints(name string, count int) string {
	return fmt.Sprintf(`{"found":true,"Name":%q,"MemoryStartupBytes":2147483648,"ProcessorCount":2,"Generation":2,"Path":"C:\\VMs\\%s.vhdx","ConfigurationLocation":"C:\\VMs","CheckpointCount":%d,"SwitchName":"","SwitchNames":[],"State":"Running"}`, name, name, count)
}

// TestGetVM_CheckpointEcho_CompliantEchoesNoncompliantDrifts (#2627, the
// false-drift fix): getVM echoes the authored `checkpoints` block on the Get
// surface ONLY when the live set complies with the policy, so a compliant VM
// matches desired (no drift) while a VM with stray checkpoints omits the key and
// drifts (→ reconcile). No declared policy ⇒ no `checkpoints` key at all
// (observe-only, #2626). This is the policy-aware-Get behaviour that eliminates
// the every-cycle false drift.
func TestGetVM_CheckpointEcho_CompliantEchoesNoncompliantDrifts(t *testing.T) {
	desired := map[string]interface{}{"policy": "none"}

	// Compliant: 0 checkpoints under policy none → echo the block → no drift.
	mc := vmModuleWithTransport(&testWinRMTransport{
		perCallOutputs: []string{hostVMJSONWithCheckpoints("cp-vm", 0)}}, "t-echo-clean")
	mc.desiredCheckpointsRaw = desired
	cc, err := mc.getVM(context.Background(), "cp-vm")
	require.NoError(t, err)
	assert.Equal(t, desired, cc.AsMap()["checkpoints"],
		"a compliant VM must echo the desired checkpoints block so it compares equal (no false drift)")

	// Non-compliant: 2 checkpoints under policy none → omit the block → drift.
	md := vmModuleWithTransport(&testWinRMTransport{
		perCallOutputs: []string{hostVMJSONWithCheckpoints("cp-vm", 2)}}, "t-echo-dirty")
	md.desiredCheckpointsRaw = desired
	cd, err := md.getVM(context.Background(), "cp-vm")
	require.NoError(t, err)
	_, present := cd.AsMap()["checkpoints"]
	assert.False(t, present,
		"a VM with stray checkpoints must omit the block so it drifts vs desired and triggers reconcile")

	// Observe-only (no stashed policy): getVM never emits a checkpoints key.
	mo := vmModuleWithTransport(&testWinRMTransport{
		perCallOutputs: []string{hostVMJSONWithCheckpoints("cp-vm", 5)}}, "t-echo-observe")
	co, err := mo.getVM(context.Background(), "cp-vm")
	require.NoError(t, err)
	_, present = co.AsMap()["checkpoints"]
	assert.False(t, present,
		"no declared policy ⇒ getVM emits no checkpoints key (observe-only #2626 default, drift-free)")
}

// TestGetVM_CheckpointEcho_MaxAgeFetchesSnapshotList (#2627): a max_age policy
// can't be judged from the count alone, so getVM issues a second call
// (psGetVMSnapshots) to evaluate per-snapshot ages. A wide window ⇒ all retained
// ⇒ compliant ⇒ echo.
func TestGetVM_CheckpointEcho_MaxAgeFetchesSnapshotList(t *testing.T) {
	desired := map[string]interface{}{"policy": "retain", "max_age": "100000h"}
	snapJSON := snapshotListJSON(t, vmSnapshot{Name: "cp1", CreationTime: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)})
	transport := &testWinRMTransport{perCallOutputs: []string{
		hostVMJSONWithCheckpoints("cp-vm", 1), // 1st: psGetVM
		snapJSON,                              // 2nd: psGetVMSnapshots (max_age needs times)
	}}
	m := vmModuleWithTransport(transport, "t-echo-age")
	m.desiredCheckpointsRaw = desired
	cfg, err := m.getVM(context.Background(), "cp-vm")
	require.NoError(t, err)
	assert.Equal(t, desired, cfg.AsMap()["checkpoints"],
		"a checkpoint within the max_age window is retained ⇒ compliant ⇒ echo")
	assert.Equal(t, psGetVMSnapshots, transport.calls[1].scriptBlock,
		"a max_age policy must fetch the snapshot list to judge compliance")
}

// TestParseCheckpointPolicyMap (#2627, QA gap): the executor-map parse path,
// including the JSON-sourced float64 max and the explicit-max:0-vs-unset *int
// distinction that the whole feature hinges on.
func TestParseCheckpointPolicyMap(t *testing.T) {
	assert.Nil(t, parseCheckpointPolicyMap(nil))
	assert.Nil(t, parseCheckpointPolicyMap(map[string]interface{}{}), "empty block ⇒ nil (observe-only)")

	// float64 (JSON/executor-sourced) max survives as *int.
	p := parseCheckpointPolicyMap(map[string]interface{}{"policy": "retain", "max": float64(3)})
	require.NotNil(t, p)
	require.NotNil(t, p.Max)
	assert.Equal(t, 3, *p.Max)

	// Explicit max: 0 ⇒ *int &0 (merge-all), distinct from absent.
	pz := parseCheckpointPolicyMap(map[string]interface{}{"max": 0})
	require.NotNil(t, pz)
	require.NotNil(t, pz.Max)
	assert.Equal(t, 0, *pz.Max)
	assert.True(t, resolveCheckpointAction(pz).mergeAll, "explicit max: 0 resolves to merge-all")

	// max_age only ⇒ implicit retain with Max nil (no count bound).
	pa := parseCheckpointPolicyMap(map[string]interface{}{"max_age": "24h"})
	require.NotNil(t, pa)
	assert.Nil(t, pa.Max)
	assert.Equal(t, "24h", pa.MaxAge)
}

// TestVMConfig_FromYAML_CheckpointsMaxZeroVsUnset (#2627, QA gap): the YAML parse
// path must preserve the explicit-max:0-vs-unset distinction end to end.
func TestVMConfig_FromYAML_CheckpointsMaxZeroVsUnset(t *testing.T) {
	var withZero VMConfig
	require.NoError(t, withZero.FromYAML([]byte("name: v\ncheckpoints:\n  max: 0\n")))
	require.NotNil(t, withZero.CheckpointPolicy)
	require.NotNil(t, withZero.CheckpointPolicy.Max, "explicit max: 0 must parse as *int &0, not nil")
	assert.Equal(t, 0, *withZero.CheckpointPolicy.Max)
	assert.True(t, resolveCheckpointAction(withZero.CheckpointPolicy).mergeAll, "max: 0 ⇒ merge-all")

	var withAge VMConfig
	require.NoError(t, withAge.FromYAML([]byte("name: v\ncheckpoints:\n  policy: retain\n  max_age: 24h\n")))
	require.NotNil(t, withAge.CheckpointPolicy)
	assert.Nil(t, withAge.CheckpointPolicy.Max, "unset max must parse as nil (no count bound), distinct from max: 0")
	assert.Equal(t, "24h", withAge.CheckpointPolicy.MaxAge)
}

// TestParseVMSnapshots_Shapes (#2627, QA gap): empty/array/single-object payloads
// and an unparsable CreationTime (kept as a zero-time snapshot, not dropped).
func TestParseVMSnapshots_Shapes(t *testing.T) {
	for _, empty := range []string{"", "  ", "null", "[]"} {
		s, err := parseVMSnapshots(empty)
		require.NoError(t, err)
		assert.Empty(t, s, "empty payload %q ⇒ no snapshots", empty)
	}

	// Single object — PS collapses a 1-element array to a bare object.
	s, err := parseVMSnapshots(`{"Name":"only","CreationTime":"2026-07-01T00:00:00Z"}`)
	require.NoError(t, err)
	require.Len(t, s, 1)
	assert.Equal(t, "only", s[0].Name)
	assert.False(t, s[0].CreationTime.IsZero())

	// Array of two.
	s, err = parseVMSnapshots(`[{"Name":"a","CreationTime":"2026-07-01T00:00:00Z"},{"Name":"b","CreationTime":"2026-07-02T00:00:00Z"}]`)
	require.NoError(t, err)
	require.Len(t, s, 2)

	// Unparsable CreationTime ⇒ zero time, snapshot still retained.
	s, err = parseVMSnapshots(`[{"Name":"weird","CreationTime":"not-a-time"}]`)
	require.NoError(t, err)
	require.Len(t, s, 1)
	assert.True(t, s[0].CreationTime.IsZero(), "an unparsable timestamp keeps the snapshot with a zero time")
}

// TestCheckpointsToMerge_BothBounds (#2627, QA warning): with max AND max_age set,
// a checkpoint is retained only if it satisfies BOTH bounds; anything violating
// either is merged, oldest-first.
func TestCheckpointsToMerge_BothBounds(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	snaps := []vmSnapshot{
		{Name: "old-outside-n", CreationTime: now.Add(-72 * time.Hour)}, // beyond newest-2 AND too old
		{Name: "old-inside-n", CreationTime: now.Add(-48 * time.Hour)},  // within newest-2 but too old
		{Name: "young-inside-n", CreationTime: now.Add(-1 * time.Hour)}, // within newest-2 and young
	}
	two := 2
	merge := checkpointsToMerge(snaps, &CheckpointPolicy{Policy: "retain", Max: &two, MaxAge: "24h"}, now)

	names := make([]string, 0, len(merge))
	for _, s := range merge {
		names = append(names, s.Name)
	}
	assert.Equal(t, []string{"old-outside-n", "old-inside-n"}, names,
		"retained only if within newest-N AND younger than max_age; violating either bound is merged, oldest-first")
}
