// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// recordingAuditStore is a REAL business.AuditStore — a flat-file store rooted in
// t.TempDir(), obtained through pkg/storage/interfaces — with one method
// intercepted for observation. Every interface method is the real store's (the
// embedded interface forwards them); AppendChainedEntry delegates the chain
// sequencing and the durable write to the real store and then keeps a pointer to
// the entry it wrote so tests can assert on what the module emitted, including
// Details/Changes values in their original Go types.
//
// No CFGMS behaviour is reimplemented here: the chain-head read, the
// SequenceNumber/PreviousChecksum assignment and the checksum callback all run in
// the real provider under test (Issue #3754).
type recordingAuditStore struct {
	business.AuditStore
	mu      sync.Mutex
	entries []*business.AuditEntry
}

func (r *recordingAuditStore) AppendChainedEntry(ctx context.Context, tenantID string, entry *business.AuditEntry, computeChecksum func(entry *business.AuditEntry) string) error {
	if err := r.AuditStore.AppendChainedEntry(ctx, tenantID, entry, computeChecksum); err != nil {
		return err
	}
	r.mu.Lock()
	r.entries = append(r.entries, entry)
	r.mu.Unlock()
	return nil
}

// captured returns a snapshot copy of all entries the real store accepted.
func (r *recordingAuditStore) captured() []*business.AuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*business.AuditEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// newRecordingAuditStore builds the real flat-file audit store the tests write
// through. The provider is resolved through pkg/storage/interfaces (central
// provider rule); providers_test.go performs the registration import.
func newRecordingAuditStore(t *testing.T) *recordingAuditStore {
	t.Helper()
	provider, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err, "flatfile storage provider must be registered")
	store, err := provider.CreateAuditStore(map[string]interface{}{"root": t.TempDir()})
	require.NoError(t, err, "creating the real audit store must not fail in test setup")
	t.Cleanup(func() { _ = store.Close() })
	return &recordingAuditStore{AuditStore: store}
}

// newRecordingAuditManager returns an audit.Manager backed by that real store.
//
// t.Cleanup registers Stop() after newRecordingAuditStore's own Close()
// cleanup, so LIFO ordering quiesces the manager's drain goroutine first, then
// closes the store, then lets t.TempDir() remove the directory — otherwise the
// drain goroutine can still be writing under the tenant directory when
// TempDir's RemoveAll walks it, which surfaces on Windows as "the directory is
// not empty" (Issue #3795).
func newRecordingAuditManager(t *testing.T) (*audit.Manager, *recordingAuditStore) {
	t.Helper()
	store := newRecordingAuditStore(t)
	mgr, err := audit.NewManager(store, "hyperv-test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })
	return mgr, store
}

// ─── recordHypervOp tests ──────────────────────────────────────────────────────

// TestAuditRecordHypervOp_NilSafe verifies that a nil audit manager does not panic.
func TestAuditRecordHypervOp_NilSafe(t *testing.T) {
	// Must not panic — nil mgr is the default for lightweight edge stewards.
	recordHypervOp(context.Background(), nil, "tenant-1", "steward-1", "host-1", "New-VM", "vm:vm1", nil, nil, nil)
}

// TestAuditRecordHypervOp_NoRawPS verifies that Details contains no raw PowerShell
// script text or argument values such as VM names, VHD paths, or switch names.
func TestAuditRecordHypervOp_NoRawPS(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	recordHypervOp(context.Background(), mgr, "tenant-1", "steward-1", "host-1", "New-VM", "vm:vm1", nil, nil, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	// None of the Detail values should contain raw PS script text fragments
	// or any other user-supplied argument value that belongs in ArgumentList.
	for k, v := range entry.Details {
		vStr, _ := v.(string)
		assert.NotContains(t, vStr, "New-VM -Name", "Details[%q] must not contain raw PS command", k)
		assert.NotContains(t, vStr, "ArgumentList", "Details[%q] must not contain ArgumentList", k)
		assert.NotContains(t, vStr, ".vhdx", "Details[%q] must not contain VHD path fragments", k)
		assert.NotContains(t, vStr, "-MemoryStartupBytes", "Details[%q] must not contain PS parameter names", k)
	}
	// Only the allowed structured keys should appear.
	for k := range entry.Details {
		assert.Contains(t, []string{"host", "steward_id"}, k,
			"unexpected Detail key %q: only 'host' and 'steward_id' are allowed", k)
	}
}

// TestAuditRecordHypervOp_ErrorPath verifies that a non-nil opErr produces a
// non-success result with an error message, and that recordHypervOp does not
// change what error the caller sees (separation of concerns).
func TestAuditRecordHypervOp_ErrorPath(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	opErr := errors.New("VM creation failed: disk quota exceeded")
	recordHypervOp(context.Background(), mgr, "tenant-1", "steward-1", "host-1", "New-VM", "vm:vm1", nil, nil, opErr)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	// Result must indicate failure (not success).
	assert.NotEqual(t, business.AuditResultSuccess, entry.Result,
		"opErr != nil must produce a non-success result")
	// Error message must carry the original message for forensics.
	assert.Contains(t, entry.ErrorMessage, "VM creation failed",
		"error message must contain the original error text")
}

// TestAuditLog_VMOperation verifies that a New-VM operation produces an audit
// entry with all required fields correctly populated and result Success.
func TestAuditLog_VMOperation(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	tenantID := "tenant-a"
	stewardID := "steward-a"
	host := "winhost.example.com"
	verb := "New-VM"
	cfgResourceID := "vm:myvm" // cfg-declared resource id

	recordHypervOp(context.Background(), mgr, tenantID, stewardID, host, verb, cfgResourceID, nil, nil, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, tenantID, entry.TenantID, "tenant_id")
	assert.Equal(t, verb, entry.Action, "action/verb")
	assert.Equal(t, "hyperv/"+verb, entry.ResourceType, "resource_type")
	assert.Equal(t, cfgResourceID, entry.ResourceID, "resource_id must be the cfg-declared id")
	assert.Equal(t, business.AuditResultSuccess, entry.Result, "result")

	hostVal, ok := entry.Details["host"].(string)
	assert.True(t, ok, "Details[host] must be a string")
	assert.Equal(t, host, hostVal, "Details[host]")

	stewardVal, ok := entry.Details["steward_id"].(string)
	assert.True(t, ok, "Details[steward_id] must be a string")
	assert.Equal(t, stewardID, stewardVal, "Details[steward_id]")
}

// ─── Resource identity tests ──────────────────────────────────────────────────

// TestAuditResourceID_UsesCfgID verifies that the audit Resource id is the
// cfg-declared id (e.g. "vm:web-01") and not a raw bare name.
func TestAuditResourceID_UsesCfgID(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	cfgID := "vm:web-01"
	recordHypervOp(context.Background(), mgr, "t", "s", "h", "Set-VMProcessor", cfgID, nil, nil, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, cfgID, entry.ResourceID,
		"ResourceID must be the cfg-declared id (vm:name), not the bare live VM name")
	// The raw bare name must not appear in ResourceID.
	assert.NotEqual(t, "web-01", entry.ResourceID,
		"ResourceID must not be a bare name without the resource type prefix")
}

// ─── Before/after change capture tests ───────────────────────────────────────

// TestAuditChanges_ResizeBeforeAfter verifies that a resize operation produces
// an audit entry with correctly populated Changes.Before, Changes.After, and
// Changes.Fields for both cpu and memory_mb.
func TestAuditChanges_ResizeBeforeAfter(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	before := map[string]interface{}{"cpu": 1, "memory_mb": int64(512)}
	after := map[string]interface{}{"cpu": 2, "memory_mb": int64(1024)}

	recordHypervOp(context.Background(), mgr, "t", "s", "h", "Set-VMProcessor", "vm:resize-vm", before, after, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	entry := entries[0]
	require.NotNil(t, entry.Changes, "Changes must be populated for a resize operation")

	assert.Equal(t, 1, entry.Changes.Before["cpu"], "Changes.Before[cpu]")
	assert.Equal(t, int64(512), entry.Changes.Before["memory_mb"], "Changes.Before[memory_mb]")
	assert.Equal(t, 2, entry.Changes.After["cpu"], "Changes.After[cpu]")
	assert.Equal(t, int64(1024), entry.Changes.After["memory_mb"], "Changes.After[memory_mb]")
	assert.ElementsMatch(t, []string{"cpu", "memory_mb"}, entry.Changes.Fields,
		"Changes.Fields must list all changed keys")
}

// TestAuditChanges_CreateEmptyBefore verifies that a create operation records
// an empty Changes.Before (new resource, no prior state).
func TestAuditChanges_CreateEmptyBefore(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	after := map[string]interface{}{"cpu": 2, "memory_mb": int64(1024), "state": "stopped"}
	recordHypervOp(context.Background(), mgr, "t", "s", "h", "New-VM", "vm:new-vm", nil, after, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entry := store.captured()[0]

	require.NotNil(t, entry.Changes, "Changes must be populated when after is non-nil")
	assert.Empty(t, entry.Changes.Before, "Changes.Before must be empty for a create op")
	assert.NotEmpty(t, entry.Changes.After, "Changes.After must carry the desired state")
	assert.Equal(t, 2, entry.Changes.After["cpu"])
}

// TestAuditChanges_DeleteEmptyAfter verifies that a delete operation records
// an empty Changes.After (resource removed, no desired state).
func TestAuditChanges_DeleteEmptyAfter(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	before := map[string]interface{}{"cpu": 4, "memory_mb": int64(2048), "state": "stopped"}
	recordHypervOp(context.Background(), mgr, "t", "s", "h", "Remove-VM", "vm:old-vm", before, nil, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entry := store.captured()[0]

	require.NotNil(t, entry.Changes, "Changes must be populated when before is non-nil")
	assert.NotEmpty(t, entry.Changes.Before, "Changes.Before must carry the prior state")
	assert.Equal(t, 4, entry.Changes.Before["cpu"])
	assert.Empty(t, entry.Changes.After, "Changes.After must be empty for a delete op")
}

// TestAuditChanges_NilBeforeAfter verifies that when both before and after are
// nil (e.g. provisioning intermediate ops), Changes is not populated.
func TestAuditChanges_NilBeforeAfter(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	recordHypervOp(context.Background(), mgr, "t", "s", "h", "Set-VMFirmware", "vm:prov-vm", nil, nil, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entry := store.captured()[0]
	assert.Nil(t, entry.Changes, "Changes must be nil when both before and after are nil")
}

// ─── Security: no live host names in audit ────────────────────────────────────

// TestAuditSecurity_NoLiveNamesInResizeEntry verifies that for a VM resize,
// the live VM name, VHD path, and any switch names from the host state do NOT
// appear in the emitted audit entry (Resource id, Details, or Changes).
func TestAuditSecurity_NoLiveNamesInResizeEntry(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	const liveVMName = "prod-vm-7f3a"
	const vhdPath = `C:\VMs\prod-vm-7f3a.vhdx`
	const switchName = "corp-network-vswitch"
	cfgID := "vm:" + liveVMName // the cfg id includes the prefix but not the bare name by itself

	before := map[string]interface{}{"cpu": 2, "memory_mb": int64(4096)}
	after := map[string]interface{}{"cpu": 4, "memory_mb": int64(8192)}

	recordHypervOp(context.Background(), mgr, "tenant", "steward", "host-a", "Set-VMProcessor", cfgID, before, after, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entry := store.captured()[0]

	// The cfg resource id uses the vm: prefix — verify it's the cfg id.
	assert.Equal(t, cfgID, entry.ResourceID, "ResourceID must be the cfg-declared id")

	// VHD path must not appear anywhere.
	assertNoString(t, entry, vhdPath, "VHD path")
	// Switch name must not appear anywhere.
	assertNoString(t, entry, switchName, "live switch name")
	// Changes must only contain non-sensitive scalar fields.
	if entry.Changes != nil {
		for k := range entry.Changes.Before {
			assert.NotContains(t, k, "vhd", "Changes.Before key must not reference VHD path")
			assert.NotContains(t, k, "switch", "Changes.Before key must not reference switch names")
		}
		for k := range entry.Changes.After {
			assert.NotContains(t, k, "vhd", "Changes.After key must not reference VHD path")
			assert.NotContains(t, k, "switch", "Changes.After key must not reference switch names")
		}
	}
}

// TestAuditSecurity_NoLiveNamesInDeleteEntry verifies that for a VM delete,
// the live VM name, VHD path, and live switch names do NOT appear in
// the emitted audit entry.
func TestAuditSecurity_NoLiveNamesInDeleteEntry(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	const liveVMName = "db-server-9a2b"
	const vhdPath = `C:\ClusterStorage\Volume1\db-server-9a2b.vhdx`
	const switchName = "storage-fabric-switch"
	cfgID := "vm:" + liveVMName

	// before carries only safe scalar fields (no VHD path, no switch names).
	before := map[string]interface{}{
		"cpu":       8,
		"memory_mb": int64(32768),
		"state":     "running",
	}

	recordHypervOp(context.Background(), mgr, "tenant", "steward", "host-b", "Remove-VM", cfgID, before, nil, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entry := store.captured()[0]

	assert.Equal(t, cfgID, entry.ResourceID, "ResourceID must be the cfg-declared id")

	// VHD path and live switch name must not appear anywhere in the entry.
	assertNoString(t, entry, vhdPath, "VHD path")
	assertNoString(t, entry, switchName, "live switch name")

	// Changes.Before carries only safe scalars.
	if entry.Changes != nil && entry.Changes.Before != nil {
		assert.NotContains(t, entry.Changes.Before, "vhd_path", "vhd_path must not appear in Changes.Before")
		assert.NotContains(t, entry.Changes.Before, "switch_name", "switch_name must not appear in Changes.Before")
	}
	// Changes.After must be nil (delete op).
	if entry.Changes != nil {
		assert.Empty(t, entry.Changes.After, "Changes.After must be empty for a delete op")
	}
}

// assertNoString checks that a string does not appear in any field of the audit
// entry (ResourceID, Details values, Changes.Before values, Changes.After values).
func assertNoString(t *testing.T, entry *business.AuditEntry, forbidden, label string) {
	t.Helper()

	assert.NotContains(t, entry.ResourceID, forbidden,
		"%s must not appear in ResourceID", label)

	for k, v := range entry.Details {
		vStr, _ := v.(string)
		assert.NotContains(t, vStr, forbidden,
			"%s must not appear in Details[%q]", label, k)
	}

	if entry.Changes == nil {
		return
	}
	for k, v := range entry.Changes.Before {
		msg := fmt.Sprintf("%v", v)
		assert.NotContains(t, msg, forbidden,
			"%s must not appear in Changes.Before[%q]", label, k)
	}
	for k, v := range entry.Changes.After {
		msg := fmt.Sprintf("%v", v)
		assert.NotContains(t, msg, forbidden,
			"%s must not appear in Changes.After[%q]", label, k)
	}
}

// ─── changedFields helper tests ───────────────────────────────────────────────

// TestChangedFields_ComputesDiff verifies that changedFields returns the sorted
// list of keys whose values differ.
func TestChangedFields_ComputesDiff(t *testing.T) {
	before := map[string]interface{}{"cpu": 1, "memory_mb": int64(512), "state": "stopped"}
	after := map[string]interface{}{"cpu": 2, "memory_mb": int64(512), "state": "stopped"}
	fields := changedFields(before, after)
	assert.Equal(t, []string{"cpu"}, fields, "only cpu changed")
}

// TestChangedFields_BothChanged verifies both fields appear when both differ.
func TestChangedFields_BothChanged(t *testing.T) {
	before := map[string]interface{}{"cpu": 1, "memory_mb": int64(512)}
	after := map[string]interface{}{"cpu": 2, "memory_mb": int64(1024)}
	fields := changedFields(before, after)
	assert.Equal(t, []string{"cpu", "memory_mb"}, fields,
		"both fields changed — sorted alphabetically")
}

// TestChangedFields_NilBeforeOrAfter verifies that keys in a nil map vs a
// present map are correctly detected as changed.
func TestChangedFields_NilBeforeOrAfter(t *testing.T) {
	after := map[string]interface{}{"cpu": 2}
	fields := changedFields(nil, after)
	assert.Equal(t, []string{"cpu"}, fields,
		"key present only in after should appear as changed")

	before := map[string]interface{}{"cpu": 2}
	fields2 := changedFields(before, nil)
	assert.Equal(t, []string{"cpu"}, fields2,
		"key present only in before should appear as changed")
}

// TestChangedFields_NoChange verifies that an empty slice is returned when
// before and after are identical.
func TestChangedFields_NoChange(t *testing.T) {
	m := map[string]interface{}{"cpu": 2, "state": "running"}
	fields := changedFields(m, m)
	assert.Empty(t, fields, "identical maps must produce no changed fields")
}

// ─── vm.go call-site audit tests ─────────────────────────────────────────────

// vmModuleWithAudit returns a hypervModule wired with both the given transport
// and an audit manager over a real audit store, for tests that need to inspect
// audit entries.
func vmModuleWithAudit(t *testing.T, transport winrmTransport, tenantID string) (*hypervModule, *recordingAuditStore) {
	t.Helper()
	store := newRecordingAuditStore(t)
	mgr, err := audit.NewManager(store, "hyperv-test-vm")
	require.NoError(t, err, "audit.NewManager must not fail in test setup")
	return &hypervModule{
		executor:  &stubHypervExecutor{},
		transport: transport,
		tenantID:  tenantID,
		auditMgr:  mgr,
		vms:       make(map[string]VMConfig),
		detector:  &fakeDetector{result: true},
	}, store
}

// TestAuditVM_ResizePopulatesBeforeAfter exercises the full setVM → applyVMState
// path for a cpu+memory resize and asserts that the audit entries for
// Set-VMProcessor and Set-VMMemory carry the correct before/after changes.
func TestAuditVM_ResizePopulatesBeforeAfter(t *testing.T) {
	const vmName = "resize-me"
	// Current host state: 2 CPUs, 4096 MB, stopped.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON(vmName, "stopped", 2, 4096)},
	}
	m, store := vmModuleWithAudit(t, transport, "t1")
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	// Desired: 4 CPUs, 8192 MB, stopped.
	cfg := &VMConfig{
		Name:       vmName,
		MemoryMB:   8192,
		CPUCount:   4,
		VHDPath:    `C:\VMs\resize-me.vhdx`,
		SwitchName: "External",
		Generation: 2,
		State:      "stopped",
	}

	err := m.Set(context.Background(), "vm:"+vmName, cfg)
	require.NoError(t, err)

	mgr := m.auditMgr
	require.NoError(t, mgr.Flush(context.Background()))

	entries := store.captured()
	require.NotEmpty(t, entries, "at least one audit entry expected for resize")

	// Find the Set-VMProcessor and Set-VMMemory entries.
	var cpuEntry, memEntry *business.AuditEntry
	for _, e := range entries {
		switch e.Action {
		case "Set-VMProcessor":
			cpuEntry = e
		case "Set-VMMemory":
			memEntry = e
		}
	}

	require.NotNil(t, cpuEntry, "Set-VMProcessor audit entry must be emitted")
	require.NotNil(t, memEntry, "Set-VMMemory audit entry must be emitted")

	// Resource IDs must be the cfg id.
	assert.Equal(t, "vm:"+vmName, cpuEntry.ResourceID, "cpu entry must use cfg resource id")
	assert.Equal(t, "vm:"+vmName, memEntry.ResourceID, "memory entry must use cfg resource id")

	// cpu entry: before={cpu:2}, after={cpu:4}
	require.NotNil(t, cpuEntry.Changes, "cpu entry must have Changes")
	assert.Equal(t, 2, cpuEntry.Changes.Before["cpu"])
	assert.Equal(t, 4, cpuEntry.Changes.After["cpu"])
	assert.Equal(t, []string{"cpu"}, cpuEntry.Changes.Fields)

	// memory entry: before={memory_mb:4096}, after={memory_mb:8192}
	require.NotNil(t, memEntry.Changes, "memory entry must have Changes")
	assert.Equal(t, int64(4096), memEntry.Changes.Before["memory_mb"])
	assert.Equal(t, int64(8192), memEntry.Changes.After["memory_mb"])
	assert.Equal(t, []string{"memory_mb"}, memEntry.Changes.Fields)

	// Neither entry should contain raw VM name (bare, without prefix) in resource id.
	assert.NotEqual(t, vmName, cpuEntry.ResourceID,
		"bare VM name must not be the resource id (must include vm: prefix)")
}

// TestAuditVM_DeleteEmptyAfter verifies that a Remove-VM audit entry has
// a populated Before and an empty After, and uses the cfg resource id.
func TestAuditVM_DeleteEmptyAfter(t *testing.T) {
	const vmName = "del-vm"
	// Transport: first call (getVM in absent path) returns current VM state;
	// second call (Remove-VM) returns empty.
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			hostVMJSON(vmName, "stopped", 2, 2048),
			"", // Remove-VM response ignored
		},
	}
	m, store := vmModuleWithAudit(t, transport, "t2")
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	err := m.Set(context.Background(), "vm:"+vmName, mapConfigState{"name": vmName, "state": "absent"})
	require.NoError(t, err)

	mgr := m.auditMgr
	require.NoError(t, mgr.Flush(context.Background()))

	entries := store.captured()
	var removeEntry *business.AuditEntry
	for _, e := range entries {
		if e.Action == "Remove-VM" {
			removeEntry = e
		}
	}
	require.NotNil(t, removeEntry, "Remove-VM audit entry must be emitted")

	assert.Equal(t, "vm:"+vmName, removeEntry.ResourceID, "delete entry must use cfg resource id")

	require.NotNil(t, removeEntry.Changes, "Changes must be populated for delete")
	assert.NotEmpty(t, removeEntry.Changes.Before, "Changes.Before must carry prior state for delete")
	assert.Empty(t, removeEntry.Changes.After, "Changes.After must be empty for delete")
}

// TestAuditVM_CreateEmptyBefore verifies that a New-VM audit entry has an
// empty Before and a populated After, and uses the cfg resource id.
func TestAuditVM_CreateEmptyBefore(t *testing.T) {
	const vmName = "new-vm"
	// Transport: first call (getVM) returns absent; second call (New-VM) succeeds.
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"found":false}`},
	}
	m, store := vmModuleWithAudit(t, transport, "t3")
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &VMConfig{
		Name:       vmName,
		MemoryMB:   2048,
		CPUCount:   2,
		VHDPath:    `C:\VMs\new-vm.vhdx`,
		SwitchName: "External",
		Generation: 2,
		State:      "stopped",
	}

	err := m.Set(context.Background(), "vm:"+vmName, cfg)
	require.NoError(t, err)

	mgr := m.auditMgr
	require.NoError(t, mgr.Flush(context.Background()))

	entries := store.captured()
	var createEntry *business.AuditEntry
	for _, e := range entries {
		if e.Action == "New-VM" {
			createEntry = e
		}
	}
	require.NotNil(t, createEntry, "New-VM audit entry must be emitted")

	assert.Equal(t, "vm:"+vmName, createEntry.ResourceID, "create entry must use cfg resource id")

	require.NotNil(t, createEntry.Changes, "Changes must be populated for create")
	assert.Empty(t, createEntry.Changes.Before, "Changes.Before must be empty for create op")
	assert.NotEmpty(t, createEntry.Changes.After, "Changes.After must carry desired state for create")
}

// TestAuditVM_SecurityNoLiveNames verifies that for a resize operation performed
// via the full setVM path, the live VM name (bare), VHD path, and live switch
// names do not appear anywhere in the emitted audit entries.
func TestAuditVM_SecurityNoLiveNames(t *testing.T) {
	const vmName = "secret-vm"
	const vhdPath = `C:\VMs\secret-vm.vhdx`
	const switchName = "corp-internal"

	// Host reports the VM with the VHD path and switch name.
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			fmt.Sprintf(`{"found":true,"Name":%q,"MemoryStartupBytes":%d,"ProcessorCount":%d,"Generation":2,"Path":%q,"SwitchName":%q,"SwitchNames":[%q],"State":"Off"}`,
				vmName, int64(4096)*1024*1024, 2, vhdPath, switchName, switchName),
		},
	}
	m, store := vmModuleWithAudit(t, transport, "t4")
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &VMConfig{
		Name:       vmName,
		MemoryMB:   8192,
		CPUCount:   4,
		VHDPath:    vhdPath,
		SwitchName: switchName,
		Generation: 2,
		State:      "stopped",
	}
	err := m.Set(context.Background(), "vm:"+vmName, cfg)
	require.NoError(t, err)

	mgr := m.auditMgr
	require.NoError(t, mgr.Flush(context.Background()))

	for _, entry := range store.captured() {
		// Live VM name (bare) must not be the resource id.
		assert.NotEqual(t, vmName, entry.ResourceID,
			"bare VM name must not appear as ResourceID (must use vm: prefix)")

		// VHD path must not appear in any entry field.
		assertNoString(t, entry, vhdPath, "VHD path")

		// Live switch name must not appear in resize audit entries.
		if entry.Action == "Set-VMProcessor" || entry.Action == "Set-VMMemory" {
			assertNoString(t, entry, switchName, "switch name in resize entry")
		}
	}
}

// TestAuditVM_PowerStateBeforeAfter verifies that Start-VM and Stop-VM audit
// entries carry the correct before/after power state.
func TestAuditVM_PowerStateBeforeAfter(t *testing.T) {
	const vmName = "power-vm"
	// VM is running; desired state is stopped.
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON(vmName, "running", 2, 4096)},
	}
	m, store := vmModuleWithAudit(t, transport, "t5")
	defer func() { _ = m.auditMgr.Stop(context.Background()) }()

	cfg := &VMConfig{
		Name:       vmName,
		MemoryMB:   4096,
		CPUCount:   2,
		VHDPath:    `C:\VMs\power-vm.vhdx`,
		SwitchName: "External",
		Generation: 2,
		State:      "stopped",
	}
	err := m.Set(context.Background(), "vm:"+vmName, cfg)
	require.NoError(t, err)

	mgr := m.auditMgr
	require.NoError(t, mgr.Flush(context.Background()))

	var stopEntry *business.AuditEntry
	for _, e := range store.captured() {
		if e.Action == "Stop-VM" {
			stopEntry = e
		}
	}
	require.NotNil(t, stopEntry, "Stop-VM audit entry must be emitted")

	assert.Equal(t, "vm:"+vmName, stopEntry.ResourceID)

	require.NotNil(t, stopEntry.Changes, "Stop-VM must have Changes")
	// getVM normalizes "Running" → "running", so current.State is "running" when passed to execStopVM.
	assert.Equal(t, "running", stopEntry.Changes.Before["state"], "before state must be running (getVM-normalized)")
	assert.Equal(t, "stopped", stopEntry.Changes.After["state"], "after state must be stopped")
}

// ─── vswitch audit tests ──────────────────────────────────────────────────────

// TestAuditVSwitch_CreateUsescfgID verifies that New-VMSwitch audit entries use
// the vswitch: prefixed cfg resource id.
func TestAuditVSwitch_CreateUsesCfgID(t *testing.T) {
	mgr, store := newRecordingAuditManager(t)
	defer func() { _ = mgr.Stop(context.Background()) }()

	const switchName = "my-internal"
	cfgID := "vswitch:" + switchName

	after := map[string]interface{}{"switch_type": "internal", "state": "present"}
	recordHypervOp(context.Background(), mgr, "t", "s", "h", "New-VMSwitch", cfgID, nil, after, nil)

	require.NoError(t, mgr.Flush(context.Background()))
	entries := store.captured()
	require.Len(t, entries, 1)

	assert.Equal(t, cfgID, entries[0].ResourceID,
		"vswitch audit entry must use vswitch:<name> cfg resource id")
	require.NotNil(t, entries[0].Changes)
	assert.Empty(t, entries[0].Changes.Before, "New-VMSwitch must have empty Before")
	assert.Equal(t, "internal", entries[0].Changes.After["switch_type"])
}
