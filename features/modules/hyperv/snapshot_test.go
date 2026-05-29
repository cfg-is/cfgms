// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
)

// snapModuleWithTransport creates a hypervModule wired with the given transport
// and tenantID for snapshot operation tests.
func snapModuleWithTransport(transport winrmTransport, tenantID string) *hypervModule {
	return &hypervModule{
		executor:  &stubHypervExecutor{},
		transport: transport,
		tenantID:  tenantID,
		vms:       make(map[string]VMConfig),
		detector:  &fakeDetector{result: true},
	}
}

// ─── snapHostName collision tests ─────────────────────────────────────────────

// TestSnapHostName_NoPrefixCollision verifies that distinct (tenantID, snapName) pairs
// always produce distinct host-side names, defeating tenant prefix forgery.
func TestSnapHostName_NoPrefixCollision(t *testing.T) {
	type pair struct {
		tenantID string
		snapName string
	}
	cases := []pair{
		{"tenant_a", "snap"},
		{"tenant", "a_snap"},
		{"tenant-a", "b"},
		{"tenant", "a-b"},
		{"root/msp-a", "snap"},
	}

	seen := make(map[string]pair)
	for _, c := range cases {
		host := snapHostName(c.tenantID, c.snapName)
		if prev, ok := seen[host]; ok {
			t.Errorf("collision: (%q, %q) and (%q, %q) both produce %q",
				prev.tenantID, prev.snapName, c.tenantID, c.snapName, host)
		}
		seen[host] = c
	}
}

// TestSnapHostName_Format verifies the returned format matches the spec.
func TestSnapHostName_Format(t *testing.T) {
	got := snapHostName("root/msp-a", "mysnap")
	assert.Equal(t, "cfgms-root-msp-a__mysnap", got)
}

// ─── SnapshotConfig.Validate tests ────────────────────────────────────────────

// TestSnapshotConfig_Validate_RejectsInjectionChars verifies that snapshot names
// containing PowerShell injection characters are rejected.
func TestSnapshotConfig_Validate_RejectsInjectionChars(t *testing.T) {
	payloads := []string{
		"'; Remove-VM -Force; '", // single-quote injection
		"$(Remove-VM)",           // subexpression
		"`Remove-VM",             // backtick escape
		"snap\x00name",           // null byte
		"__hidden",               // double-underscore separator
	}
	for _, payload := range payloads {
		cfg := &SnapshotConfig{VMName: "myvm", Name: payload}
		err := cfg.Validate()
		require.Error(t, err, "payload %q must be rejected", payload)
	}
}

// TestSnapshotConfig_Validate_RejectsDoubleUnderscore verifies that __ in snapshot
// name is rejected (tenant separator).
func TestSnapshotConfig_Validate_RejectsDoubleUnderscore(t *testing.T) {
	cfg := &SnapshotConfig{VMName: "myvm", Name: "my__snap"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSnapshotName)
}

// TestSnapshotConfig_Validate_AcceptsSpaces verifies that snapshot names with
// spaces are accepted (Hyper-V convention).
func TestSnapshotConfig_Validate_AcceptsSpaces(t *testing.T) {
	cfg := &SnapshotConfig{VMName: "myvm", Name: "Before update 2026-01-01"}
	require.NoError(t, cfg.Validate())
}

// TestSnapshotConfig_Validate_AcceptsValidConfig verifies a well-formed config passes.
func TestSnapshotConfig_Validate_AcceptsValidConfig(t *testing.T) {
	cfg := &SnapshotConfig{VMName: "prod-vm", Name: "snap-v1", State: "present"}
	require.NoError(t, cfg.Validate())
}

// TestSnapshotConfig_Validate_RejectsInvalidVMName verifies that VM names with
// injection characters are rejected.
func TestSnapshotConfig_Validate_RejectsInvalidVMName(t *testing.T) {
	cfg := &SnapshotConfig{VMName: "vm__bad", Name: "snap"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidVMName)
}

// ─── SnapshotConfig interface tests ───────────────────────────────────────────

// TestSnapshotConfig_AsMap verifies AsMap includes all fields.
func TestSnapshotConfig_AsMap(t *testing.T) {
	cfg := &SnapshotConfig{VMName: "my-vm", Name: "my-snap", State: "present"}
	m := cfg.AsMap()
	assert.Equal(t, "my-vm", m["vm_name"])
	assert.Equal(t, "my-snap", m["name"])
	assert.Equal(t, "present", m["state"])
}

// TestSnapshotConfig_YAML verifies round-trip YAML serialization.
func TestSnapshotConfig_YAML(t *testing.T) {
	original := &SnapshotConfig{VMName: "roundtrip-vm", Name: "roundtrip-snap", State: "present"}
	data, err := original.ToYAML()
	require.NoError(t, err)

	decoded := &SnapshotConfig{}
	require.NoError(t, decoded.FromYAML(data))
	assert.Equal(t, original, decoded)
}

// ─── Injection defense tests ───────────────────────────────────────────────────

// TestSnapshotInjectionDefense verifies that prefixed VM and snapshot names are
// transmitted as WinRM ArgumentList parameters, never interpolated into the
// PowerShell script text.
func TestSnapshotInjectionDefense(t *testing.T) {
	const tenantID = "acme"
	const vmName = "webserver"
	const snapName = "before-patch"

	expectedVMHost := vmHostName(tenantID, vmName)
	expectedSnapHost := snapHostName(tenantID, snapName)

	transport := &testWinRMTransport{}
	m := snapModuleWithTransport(transport, tenantID)

	cfg := &SnapshotConfig{VMName: vmName, Name: snapName, State: "present"}
	err := m.Set(context.Background(), fmt.Sprintf("snapshot:%s/%s", vmName, snapName), cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected")
	call := calls[0]

	// Both prefixed names must appear in args, not scriptBlock.
	// Keys sorted: "Name" < "VMName", so args[0]=snapHostName, args[1]=vmHostName.
	require.Len(t, call.args, 2, "Name and VMName must both be in psArgs")
	assert.Equal(t, expectedSnapHost, call.args[0], "snapshot host name must be args[0] (key 'Name')")
	assert.Equal(t, expectedVMHost, call.args[1], "VM host name must be args[1] (key 'VMName')")

	assert.NotContains(t, call.scriptBlock, expectedSnapHost,
		"snapshot host name must NOT appear in scriptBlock text")
	assert.NotContains(t, call.scriptBlock, expectedVMHost,
		"VM host name must NOT appear in scriptBlock text")
}

// ─── Restore tests ─────────────────────────────────────────────────────────────

// TestRestoreSnapshot_CallsRestoreExecutor verifies that Set(state: restored) issues
// a Restore-VMSnapshot command via the WinRM transport.
func TestRestoreSnapshot_CallsRestoreExecutor(t *testing.T) {
	transport := &testWinRMTransport{}
	m := snapModuleWithTransport(transport, "prod")

	cfg := &SnapshotConfig{VMName: "myvm", Name: "mysnap", State: "restored"}
	err := m.Set(context.Background(), "snapshot:myvm/mysnap", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1, "exactly one ExecutePS call expected for restore")
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "Restore-VMSnapshot",
		"Set with state restored must invoke Restore-VMSnapshot")
	assert.Contains(t, call.scriptBlock, "-Confirm:$false",
		"Restore-VMSnapshot must include -Confirm:$false")

	// Prefixed names must appear in args, not in the script text.
	require.Len(t, call.args, 2)
	assert.Equal(t, "cfgms-prod__mysnap", call.args[0], "snapshot host name in args[0]")
	assert.Equal(t, "cfgms-prod__myvm", call.args[1], "VM host name in args[1]")
	assert.NotContains(t, call.scriptBlock, "cfgms-prod__mysnap")
	assert.NotContains(t, call.scriptBlock, "cfgms-prod__myvm")
}

// TestRestoreReturnsPresent verifies that Get returns State="present" after a restore.
// "restored" is write-only: Hyper-V does not delete the checkpoint on restore, so
// Get always reflects the snapshot as present.
func TestRestoreReturnsPresent(t *testing.T) {
	// Transport always returns "found:true" for any ExecutePS call (restore + get).
	transport := &testWinRMTransport{output: `{"found":true}`}
	m := snapModuleWithTransport(transport, "t")

	ctx := context.Background()

	// Set restore
	err := m.Set(ctx, "snapshot:myvm/mysnap",
		&SnapshotConfig{VMName: "myvm", Name: "mysnap", State: "restored"})
	require.NoError(t, err)

	// Get must return "present", never "restored"
	state, err := m.Get(ctx, "snapshot:myvm/mysnap")
	require.NoError(t, err)
	require.NotNil(t, state)

	snap, ok := state.(*SnapshotConfig)
	require.True(t, ok, "Get must return *SnapshotConfig")
	assert.Equal(t, "present", snap.State, "Get must return state=present after restore")
	assert.NotEqual(t, "restored", snap.State, "Get must never return state=restored")
}

// TestGet_Snapshot_AfterRestore_ReturnsPresent is an alias for TestRestoreReturnsPresent
// using explicit name per the acceptance criteria.
func TestGet_Snapshot_AfterRestore_ReturnsPresent(t *testing.T) {
	transport := &testWinRMTransport{output: `{"found":true}`}
	m := snapModuleWithTransport(transport, "staging")

	ctx := context.Background()
	require.NoError(t, m.Set(ctx, "snapshot:prod-vm/before-update",
		&SnapshotConfig{VMName: "prod-vm", Name: "before-update", State: "restored"}))

	state, err := m.Get(ctx, "snapshot:prod-vm/before-update")
	require.NoError(t, err)
	snap := state.(*SnapshotConfig)
	assert.Equal(t, "present", snap.State)
	assert.NotContains(t, snap.State, "restored")
}

// ─── Not found tests ───────────────────────────────────────────────────────────

// TestGet_Snapshot_ReturnsErrSnapshotNotFound_WhenMissing verifies that Get returns
// ErrSnapshotNotFound when the host reports the snapshot does not exist.
func TestGet_Snapshot_ReturnsErrSnapshotNotFound_WhenMissing(t *testing.T) {
	transport := &testWinRMTransport{output: `{"found":false}`}
	m := snapModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "snapshot:myvm/nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSnapshotNotFound)
}

// TestGet_Snapshot_ReturnsErrSnapshotNotFound_OnTransportError verifies that transport
// errors are surfaced as ErrSnapshotNotFound.
func TestGet_Snapshot_ReturnsErrSnapshotNotFound_OnTransportError(t *testing.T) {
	transport := &testWinRMTransport{execErr: errors.New("winrm: connection refused")}
	m := snapModuleWithTransport(transport, "t")

	_, err := m.Get(context.Background(), "snapshot:myvm/unreachable")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSnapshotNotFound)
}

// TestGet_Snapshot_NoTransport verifies that Get returns ErrSnapshotNotFound when
// the module has no transport configured.
func TestGet_Snapshot_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor: &stubHypervExecutor{},
		vms:      make(map[string]VMConfig),
		detector: &fakeDetector{result: true},
	}
	_, err := m.Get(context.Background(), "snapshot:myvm/mysnap")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSnapshotNotFound)
}

// ─── Tenant boundary tests ─────────────────────────────────────────────────────

// TestSnapshotTenantBoundary verifies cross-tenant isolation: tenant A's restore
// operation uses args prefixed with "cfgms-a__"; a tenant B module instance cannot
// produce args prefixed with "cfgms-a__".
func TestSnapshotTenantBoundary(t *testing.T) {
	transportA := &testWinRMTransport{}
	transportB := &testWinRMTransport{}

	moduleA := snapModuleWithTransport(transportA, "a")
	moduleB := snapModuleWithTransport(transportB, "b")

	ctx := context.Background()

	// Both tenants restore a snapshot on a VM named "vm" with snapshot name "snap".
	cfgA := &SnapshotConfig{VMName: "vm", Name: "snap", State: "restored"}
	cfgB := &SnapshotConfig{VMName: "vm", Name: "snap", State: "restored"}

	require.NoError(t, moduleA.Set(ctx, "snapshot:vm/snap", cfgA))
	require.NoError(t, moduleB.Set(ctx, "snapshot:vm/snap", cfgB))

	transportA.mu.Lock()
	callsA := transportA.calls
	transportA.mu.Unlock()

	transportB.mu.Lock()
	callsB := transportB.calls
	transportB.mu.Unlock()

	require.Len(t, callsA, 1)
	require.Len(t, callsB, 1)

	// Tenant A: args must contain "cfgms-a__snap" and "cfgms-a__vm".
	// Keys sorted: "Name" < "VMName", so args[0]=snapHostName, args[1]=vmHostName.
	require.Len(t, callsA[0].args, 2)
	assert.Equal(t, "cfgms-a__snap", callsA[0].args[0], "tenant A: snap host name in args[0]")
	assert.Equal(t, "cfgms-a__vm", callsA[0].args[1], "tenant A: VM host name in args[1]")

	// Tenant B: args must contain "cfgms-b__snap" and "cfgms-b__vm" (not "cfgms-a__").
	require.Len(t, callsB[0].args, 2)
	assert.Equal(t, "cfgms-b__snap", callsB[0].args[0], "tenant B: snap host name in args[0]")
	assert.Equal(t, "cfgms-b__vm", callsB[0].args[1], "tenant B: VM host name in args[1]")

	// Tenant B's args must not contain any "cfgms-a__" prefix.
	for _, arg := range callsB[0].args {
		argStr := fmt.Sprint(arg)
		assert.NotContains(t, argStr, "cfgms-a__",
			"tenant B must not produce args with tenant A's prefix")
	}

	// Tenant A's args must not contain any "cfgms-b__" prefix.
	for _, arg := range callsA[0].args {
		argStr := fmt.Sprint(arg)
		assert.NotContains(t, argStr, "cfgms-b__",
			"tenant A must not produce args with tenant B's prefix")
	}
}

// ─── Set absent tests ──────────────────────────────────────────────────────────

// TestSet_SnapshotAbsent_CallsRemoveSnapshot verifies that Set with state "absent"
// invokes Remove-VMSnapshot with prefixed names in args.
func TestSet_SnapshotAbsent_CallsRemoveSnapshot(t *testing.T) {
	transport := &testWinRMTransport{}
	m := snapModuleWithTransport(transport, "ops")

	cfg := &SnapshotConfig{VMName: "myvm", Name: "mysnap", State: "absent"}
	err := m.Set(context.Background(), "snapshot:myvm/mysnap", cfg)
	require.NoError(t, err)

	transport.mu.Lock()
	calls := transport.calls
	transport.mu.Unlock()

	require.Len(t, calls, 1)
	call := calls[0]

	assert.Contains(t, call.scriptBlock, "Remove-VMSnapshot",
		"Set with state absent must invoke Remove-VMSnapshot")
	require.Len(t, call.args, 2)
	assert.Equal(t, "cfgms-ops__mysnap", call.args[0])
	assert.Equal(t, "cfgms-ops__myvm", call.args[1])
	assert.NotContains(t, call.scriptBlock, "cfgms-ops__mysnap")
	assert.NotContains(t, call.scriptBlock, "cfgms-ops__myvm")
}

// TestSet_Snapshot_NoTransport verifies that Set returns ErrNotImplemented
// when the module has no transport configured.
func TestSet_Snapshot_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor: &stubHypervExecutor{},
		vms:      make(map[string]VMConfig),
		detector: &fakeDetector{result: true},
	}
	cfg := &SnapshotConfig{VMName: "myvm", Name: "mysnap", State: "present"}
	err := m.Set(context.Background(), "snapshot:myvm/mysnap", cfg)
	assert.ErrorIs(t, err, modules.ErrNotImplemented)
}

// TestModule_Get_SnapshotPrefix_NoTransport verifies that the snapshot prefix
// routes correctly and returns ErrSnapshotNotFound when transport is absent.
func TestModule_Get_SnapshotPrefix_NoTransport(t *testing.T) {
	m := &hypervModule{
		executor: &stubHypervExecutor{},
		vms:      make(map[string]VMConfig),
		detector: &fakeDetector{result: true},
	}
	_, err := m.Get(context.Background(), "snapshot:vm/snap")
	assert.ErrorIs(t, err, ErrSnapshotNotFound)
}

// ─── Set path injection rejection tests ───────────────────────────────────────

// TestSet_Snapshot_RejectsInjectionPayloads verifies that injection payloads in
// the vmName or snapName portion of the resource ID are rejected by setSnapshot
// before any WinRM transport call is made.
func TestSet_Snapshot_RejectsInjectionPayloads(t *testing.T) {
	type testCase struct {
		resourceID string
		desc       string
	}
	cases := []testCase{
		{"snapshot:'; Remove-VM -Force; '/safe", "single-quote injection in vmName"},
		{"snapshot:myvm/'; Remove-VM -Force; '", "single-quote injection in snapName"},
		{"snapshot:$(Remove-VM)/safe", "subexpression injection in vmName"},
		{"snapshot:myvm/$(Remove-VM)", "subexpression injection in snapName"},
		{"snapshot:myvm/snap__evil", "double-underscore in snapName"},
		{"snapshot:vm__evil/snap", "double-underscore in vmName"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			// transport must not receive any call when validation rejects the input
			transport := &testWinRMTransport{}
			m := snapModuleWithTransport(transport, "t")

			cfg := &SnapshotConfig{State: "present"}
			err := m.Set(context.Background(), tc.resourceID, cfg)
			require.Error(t, err, "injection payload %q must be rejected", tc.resourceID)

			transport.mu.Lock()
			calls := transport.calls
			transport.mu.Unlock()
			assert.Empty(t, calls, "transport must not be called when validation rejects the input")
		})
	}
}
