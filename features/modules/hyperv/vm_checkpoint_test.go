// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"testing"

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
