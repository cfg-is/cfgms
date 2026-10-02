// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// callUsed reports whether any recorded transport call used the given script.
func callUsed(transport *testWinRMTransport, script string) bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, c := range transport.calls {
		if c.scriptBlock == script {
			return true
		}
	}
	return false
}

// TestVMRename_OldExistsNewAbsent_RenamesInPlace is the core #2776 behavior: when
// the desired VM name is absent but old_name names an existing VM, the module
// renames it in place (Rename-VM) rather than creating a new VM.
func TestVMRename_OldExistsNewAbsent_RenamesInPlace(t *testing.T) {
	const oldName = "cfgms-ci-lin-01"
	const newName = "lab-lin-01"

	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":false}`,                       // call0: getVMLocal(newName) → absent
			hostVMJSON(oldName, "stopped", 2, 4096), // call1: getVMLocal(oldName) → found
			``,                                      // call2: Rename-VM (psRenameVM)
			hostVMJSON(newName, "stopped", 2, 4096), // call3: getVMLocal(newName) after rename → found
		},
	}
	m := vmModuleWithTransport(transport, "t")

	cfg := &VMConfig{Name: newName, OldName: oldName, State: "stopped", MemoryMB: 4096, CPUCount: 2, Generation: 2}
	require.NoError(t, m.Set(context.Background(), "vm:"+newName, cfg))

	require.True(t, callUsed(transport, psRenameVM), "expected a Rename-VM transport call")
	assert.False(t, callUsed(transport, psCreateVM), "must NOT create a new VM when renaming")

	// The rename call carries both the old and the new name (via ArgumentList).
	transport.mu.Lock()
	defer transport.mu.Unlock()
	for _, c := range transport.calls {
		if c.scriptBlock == psRenameVM {
			assert.Contains(t, c.args, oldName)
			assert.Contains(t, c.args, newName)
		}
	}
}

// TestVMRename_NewAlreadyExists_Idempotent verifies the rename is a no-op once the
// VM already has the desired name: no Rename-VM call, no duplicate.
func TestVMRename_NewAlreadyExists_Idempotent(t *testing.T) {
	const oldName = "cfgms-ci-lin-01"
	const newName = "lab-lin-01"

	transport := &testWinRMTransport{
		perCallOutputs: []string{
			hostVMJSON(newName, "stopped", 2, 4096), // call0: getVMLocal(newName) → already exists
		},
	}
	m := vmModuleWithTransport(transport, "t")

	cfg := &VMConfig{Name: newName, OldName: oldName, State: "stopped", MemoryMB: 4096, CPUCount: 2, Generation: 2}
	require.NoError(t, m.Set(context.Background(), "vm:"+newName, cfg))

	assert.False(t, callUsed(transport, psRenameVM), "no rename once the VM already has the desired name")
	assert.False(t, callUsed(transport, psCreateVM), "no create when the VM already exists")
}

// TestRenameFromOldName_OldAbsent_NoOp verifies renameFromOldName is a clean no-op
// when the old-named VM does not exist (so the caller creates the new VM fresh).
func TestRenameFromOldName_OldAbsent_NoOp(t *testing.T) {
	transport := &testWinRMTransport{output: `{"found":false}`} // getVMLocal(old) → absent
	m := vmModuleWithTransport(transport, "t")

	cfg := &VMConfig{Name: "lab-lin-01", OldName: "cfgms-ci-lin-01"}
	renamed, err := m.renameFromOldName(context.Background(), cfg, "lab-lin-01")
	require.NoError(t, err)
	assert.False(t, renamed, "no rename when the old VM is absent")
	assert.False(t, callUsed(transport, psRenameVM))
}

// TestRenameFromOldName_MigratesProvisionRecord verifies the provisioning record
// follows the rename (old_name → name), so the renamed VM is not treated as
// unprovisioned.
func TestRenameFromOldName_MigratesProvisionRecord(t *testing.T) {
	const oldName = "cfgms-ci-lin-01"
	const newName = "lab-lin-01"
	ctx := context.Background()

	transport := &testWinRMTransport{
		perCallOutputs: []string{
			hostVMJSON(oldName, "stopped", 2, 4096), // call0: getVMLocal(oldName) → found
			``,                                      // call1: Rename-VM
		},
	}
	m := vmModuleWithTransport(transport, "t")

	// Seed a provisioning record under the OLD name.
	store := m.storeFor(&VMConfig{})
	require.NoError(t, store.SetProvision(ctx, &ProvisionRecord{VMName: oldName, State: ProvisionStateReady}))

	cfg := &VMConfig{Name: newName, OldName: oldName}
	renamed, err := m.renameFromOldName(ctx, cfg, newName)
	require.NoError(t, err)
	require.True(t, renamed)

	// Record now lives under the new name, and the old record is gone.
	rec, err := store.GetProvision(ctx, newName)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, newName, rec.VMName)

	_, err = store.GetProvision(ctx, oldName)
	assert.Error(t, err, "the old-named provisioning record must be removed after migration")
}

// TestVMConfig_Validate_InvalidOldName verifies old_name is held to the same
// VM-name allowlist as name.
func TestVMConfig_Validate_InvalidOldName(t *testing.T) {
	c := &VMConfig{Name: "lab-lin-01", OldName: "bad name!", Generation: 2}
	assert.ErrorIs(t, c.Validate(), ErrInvalidVMName)

	ok := &VMConfig{Name: "lab-lin-01", OldName: "cfgms-ci-lin-01", Generation: 2}
	assert.NoError(t, ok.Validate())
}
