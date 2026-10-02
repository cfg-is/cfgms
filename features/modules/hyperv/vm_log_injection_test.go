// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package hyperv

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ─── Issue #4341: log-injection coverage for vm.go's error-value log sites ─────
//
// CLAUDE.md's sanitization rule ("error", logging.SanitizeLogValue(err.Error()),
// never "error", err) applies to error values just as much as to any other
// externally-influenced string — a WMI/transport/store error can carry
// attacker-controlled content (host names, VM names) back out inside its
// message text. Each test below forces a CR/LF-laden error through one of
// vm.go's Warn call sites and asserts the field reaching the captured log
// record contains no raw \r or \n.

// setFailProvisionStore wraps a real ProvisionStore and forces every
// SetProvision call to fail with err, delegating every other method to the
// wrapped store unchanged. Used because errProvisionStore (vm_provision_csv_test.go)
// fails GetProvision too, which short-circuits renameProvisionRecord and the
// completion reconciler's sweep before they ever reach the SetProvision-failure
// Warn call this file targets.
type setFailProvisionStore struct {
	ProvisionStore
	err error
}

func (s *setFailProvisionStore) SetProvision(context.Context, *ProvisionRecord) error {
	return s.err
}

// injectedLogError is a CR/LF-laden error message standing in for a tainted
// value (host/VM/cluster name, transport response text) that a compromised or
// malicious host could return.
const injectedLogError = "boom\r\nINJECTED forged-log-line: evil=1\r\nmore"

// TestRenameProvisionRecord_SetProvisionFailure_LogsSanitizedError covers
// vm.go's renameProvisionRecord Warn call ("hyperv: rename provisioning record
// failed"), which previously logged the raw error via err.Error() instead of
// logging.SanitizeLogValue(err.Error()).
func TestRenameProvisionRecord_SetProvisionFailure_LogsSanitizedError(t *testing.T) {
	const oldName = "cfgms-ci-lin-01"
	const newName = "lab-lin-01"
	ctx := context.Background()

	m := vmModuleWithTransport(&testWinRMTransport{}, "t-logsan-rename")
	capLog := logging.NewCapturingLogger()
	require.NoError(t, m.SetLogger(capLog))

	base := m.storeFor(&VMConfig{})
	require.NoError(t, base.SetProvision(ctx, &ProvisionRecord{VMName: oldName, State: ProvisionStateReady}))
	m.provisionStore = &setFailProvisionStore{ProvisionStore: base, err: errors.New(injectedLogError)}

	cfg := &VMConfig{Name: newName, OldName: oldName}
	m.renameProvisionRecord(ctx, cfg, oldName, newName)

	entry, found := capLog.FindWarn("hyperv: rename provisioning record failed")
	require.True(t, found, "a SetProvision failure during rename migration must be logged")

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error must not carry a raw LF")
}

// TestGetVM_CheckpointProbeFailure_LogsSanitizedError covers vm.go's
// checkpointsComply-probe Warn call ("hyperv: checkpoint compliance probe
// failed; reporting as drift this cycle"), which previously logged the raw
// error via cErr.Error() instead of logging.SanitizeLogValue(cErr.Error()).
func TestGetVM_CheckpointProbeFailure_LogsSanitizedError(t *testing.T) {
	desired := map[string]interface{}{"policy": "retain", "max_age": "100000h"}
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSONWithCheckpoints("cp-vm", 1), ``},
		perCallErrors:  []error{nil, errors.New(injectedLogError)},
	}
	m := vmModuleWithTransport(transport, "t-logsan-checkpoint")
	capLog := logging.NewCapturingLogger()
	require.NoError(t, m.SetLogger(capLog))
	m.checkpointDesired["cp-vm"] = desired

	_, err := m.getVM(context.Background(), "cp-vm")
	require.NoError(t, err, "a checkpoint-compliance probe failure must not fail the VM read")

	entry, found := capLog.FindWarn("hyperv: checkpoint compliance probe failed; reporting as drift this cycle")
	require.True(t, found)

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error must not carry a raw LF")
}

// TestGetVM_ClusterRoleProbeFailure_LogsSanitizedError covers vm.go's
// probeClusterRoleMembership Warn call ("hyperv: cluster-role membership probe
// failed; reporting no HA role this cycle"), which previously logged the raw
// error via roErr.Error() instead of logging.SanitizeLogValue(roErr.Error()).
func TestGetVM_ClusterRoleProbeFailure_LogsSanitizedError(t *testing.T) {
	const vmName = "degraded-vm"
	transport := &testWinRMTransport{
		perCallOutputs: []string{hostVMJSON(vmName, "running", 2, 4096), ``},
		perCallErrors:  []error{nil, errors.New(injectedLogError)},
	}
	m := vmModuleWithTransport(transport, "t-logsan-role-probe")
	m.clusterName = "lab-hv"
	capLog := logging.NewCapturingLogger()
	require.NoError(t, m.SetLogger(capLog))

	_, err := m.getVM(context.Background(), vmName)
	require.NoError(t, err, "a probe failure must not fail the VM read")

	entry, found := capLog.FindWarn("hyperv: cluster-role membership probe failed; reporting no HA role this cycle")
	require.True(t, found)

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error must not carry a raw LF")
}

// TestApplyVMState_OwnerProbeFailure_LogsSanitizedError covers vm.go's
// applyVMState ha_role owner-probe Warn call ("hyperv: ha_role owner probe
// failed; skipping lifecycle convergence this cycle"), which previously logged
// the raw error via roErr.Error() instead of
// logging.SanitizeLogValue(roErr.Error()).
func TestApplyVMState_OwnerProbeFailure_LogsSanitizedError(t *testing.T) {
	const vmName = "ha-probe-flaky-vm"
	const cluster = "lab-hv"

	transport := &testWinRMTransport{
		perCallOutputs: []string{``},
		perCallErrors:  []error{errors.New(injectedLogError)},
	}
	m := vmModuleWithTransport(transport, "t-logsan-owner-probe")
	m.nodeHostname = "NODE1"
	capLog := logging.NewCapturingLogger()
	require.NoError(t, m.SetLogger(capLog))

	desired := &VMConfig{
		Name:     vmName,
		CPUCount: 4,
		MemoryMB: 8192,
		HARole:   &HARoleConfig{ClusterName: cluster},
	}
	current := &VMConfig{Name: vmName, CPUCount: 2, MemoryMB: 4096, State: "stopped"}

	require.NoError(t, m.applyVMState(context.Background(), vmName, vmName, desired, current, "running"),
		"a transient ownership-probe error must not surface as a steward error")

	entry, found := capLog.FindWarn("hyperv: ha_role owner probe failed; skipping lifecycle convergence this cycle")
	require.True(t, found)

	errVal, ok := entry["error"].(string)
	require.True(t, ok, "error field must be a sanitized string, not a raw error value")
	assert.NotContains(t, errVal, "\r", "sanitized error must not carry a raw CR")
	assert.NotContains(t, errVal, "\n", "sanitized error must not carry a raw LF")
}
