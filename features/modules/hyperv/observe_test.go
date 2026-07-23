// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/conformance"
)

// ── observeLocalCluster tests ──────────────────────────────────────────────────

// TestObserveLocalCluster_NonCNONode verifies that a non-CNO cluster member
// (NODE2) reports full cluster membership via observeLocalCluster — the
// whole-domain observe path — without requiring a declared hyperv.cluster
// resource. This is the motivating AC2 scenario from issue #2891.
func TestObserveLocalCluster_NonCNONode(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			// psGetClusterSelf: self-discovery, no -Name parameter
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			// clusterOwnershipHelper → readCNOOwner (psGetClusterOwnerNode)
			`{"owner":"NODE1"}`,
			// clusterOwnershipHelper → readResourceOwners (psGetClusterResourceOwner)
			`{"owners":{"web-01":"NODE1"}}`,
			// readCNOOwner again (non-owner path in observeLocalCluster)
			`{"owner":"NODE1"}`,
			// probeClusterAccess (psGetClusterAccessSelf)
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"
	// No m.clusterName — no declared hyperv.cluster resource.

	status, err := m.observeLocalCluster(context.Background())
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.True(t, status.Found, "cluster must be found on a cluster member")
	assert.Equal(t, "cfg-lab", status.Name)
	assert.ElementsMatch(t, []string{"NODE1", "NODE2"}, status.MemberNodes)
	assert.Equal(t, "NODE1", status.CNOOwnerNode, "CNO owner must be NODE1")
	assert.True(t, status.ClusterAccessOK)
	assert.Equal(t, map[string]string{"web-01": "NODE1"}, status.RoleOwners)
}

// TestObserveLocalCluster_CNOOwner verifies that the CNO-owning node populates
// its own hostname as CNOOwnerNode.
func TestObserveLocalCluster_CNOOwner(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			// clusterOwnershipHelper: NODE1 is the CNO owner
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			// probeClusterAccess
			`{"account":"LAB\\NODE1$","access_ok":true,"remediation":""}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE1"

	status, err := m.observeLocalCluster(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "NODE1", status.CNOOwnerNode)
	assert.True(t, status.ClusterAccessOK)
}

// TestObserveLocalCluster_Standalone verifies that a standalone (non-clustered)
// host returns Found=false with no error.
func TestObserveLocalCluster_Standalone(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":false}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "STANDALONE"

	status, err := m.observeLocalCluster(context.Background())
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Found, "standalone host must not report a cluster")
	assert.True(t, status.ClusterAccessOK, "standalone host access is always ok")
}

// TestObserveLocalCluster_NoTransport verifies that observeLocalCluster returns
// ErrTransportNotConfigured when no transport is wired, matching the contract
// used by existing declared-resource paths.
func TestObserveLocalCluster_NoTransport(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	// m.transport deliberately left nil

	_, err := m.observeLocalCluster(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTransportNotConfigured)
}

// TestObserveLocalCluster_ScopeCapNotRequired verifies that observeLocalCluster
// works even when m.clusterName is empty (no declared hyperv.cluster resource),
// which is the primary non-CNO-node use case.
func TestObserveLocalCluster_ScopeCapNotRequired(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"owner":"NODE1"}`,
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"
	// m.clusterName == "" — no scope cap — must still work.

	status, err := m.observeLocalCluster(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cfg-lab", status.Name)
}

// ── AC3: Read-only conformance ─────────────────────────────────────────────────

// TestObserveLocalCluster_ReadOnly is the AC3 acceptance test. It verifies that
// observeLocalCluster only executes read-only PowerShell scripts (Get-* cmdlets)
// and never issues any write-mutating command.
func TestObserveLocalCluster_ReadOnly(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"owner":"NODE1"}`,
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"

	_, err := m.observeLocalCluster(context.Background())
	require.NoError(t, err)

	transport.mu.Lock()
	calls := make([]winRMCall, len(transport.calls))
	copy(calls, transport.calls)
	transport.mu.Unlock()

	// AC3: only these read-only scripts are allowed in the observe path.
	allowedScripts := map[string]bool{
		psGetClusterSelf:          true,
		psGetClusterOwnerNode:     true,
		psGetClusterResourceOwner: true,
		psGetClusterAccessSelf:    true,
	}
	for _, call := range calls {
		if !allowedScripts[call.scriptBlock] {
			t.Errorf("observe path used unexpected (non-read-only) script:\n%s", call.scriptBlock)
		}
	}
}

// TestObserveDomain_ReadOnly extends AC3 to the full domain summary path —
// GetDomain and getDomainSummary must only issue read-only PS scripts.
func TestObserveDomain_ReadOnly(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			// observeLocalCluster
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"owner":"NODE1"}`,
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
			// enumerateVMNames
			`{"vms":["web-01"]}`,
			// observeVSwitchDomain
			`{"switches":[{"Name":"External","SwitchType":"External"}]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"

	_, err := m.getDomainSummary(context.Background())
	require.NoError(t, err)

	transport.mu.Lock()
	calls := make([]winRMCall, len(transport.calls))
	copy(calls, transport.calls)
	transport.mu.Unlock()

	allowedScripts := map[string]bool{
		psGetClusterSelf:          true,
		psGetClusterOwnerNode:     true,
		psGetClusterResourceOwner: true,
		psGetClusterAccessSelf:    true,
		psEnumerateVMs:            true,
		psEnumerateVSwitches:      true,
	}
	for _, call := range calls {
		if !allowedScripts[call.scriptBlock] {
			t.Errorf("domain observe path used unexpected (non-read-only) script:\n%s", call.scriptBlock)
		}
	}

	// Belt-and-suspenders: also scan for write verb patterns in the scripts.
	assertNoWriteCmdlets(t, calls)
}

// assertNoWriteCmdlets scans all recorded PS calls and fails if any script
// contains a known write-mutating cmdlet name as a standalone invocation token.
// It complements the allowlist check in the AC3/AC3-domain tests.
//
// Note: psGetClusterAccessSelf contains "Grant-ClusterAccess" as a STRING VALUE
// in its remediation output — it is not an actual cmdlet call in that script.
// The allowlist-based check in TestObserve*_ReadOnly already guards this; this
// helper focuses on patterns that appear only as true cmdlet invocations.
func assertNoWriteCmdlets(t *testing.T, calls []winRMCall) {
	t.Helper()
	writePatterns := []string{
		"New-VM", "Remove-VM", "Rename-VM", "Move-VMStorage",
		"New-VMSwitch", "Remove-VMSwitch",
		"Add-VMNetworkAdapter", "Remove-VMNetworkAdapter",
		"Set-VM ", "Set-VMProcessor", "Set-VMMemory",
		"Start-VM", "Stop-VM",
		"Add-ClusterVirtualMachineRole", "Remove-ClusterGroup",
		"Set-ClusterOwnerNode", "Set-ClusterGroup",
	}
	for _, call := range calls {
		for _, pattern := range writePatterns {
			if strings.Contains(call.scriptBlock, pattern) {
				t.Errorf("observe path used write-mutating cmdlet %q in script:\n%s",
					pattern, call.scriptBlock)
			}
		}
	}
}

// ── enumerateVMNames tests ─────────────────────────────────────────────────────

func TestEnumerateVMNames_ReturnsNames(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"vms":["web-01","db-01","jump-01"]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport

	names, err := m.enumerateVMNames(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"web-01", "db-01", "jump-01"}, names)
}

func TestEnumerateVMNames_EmptyHost(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"vms":[]}`},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport

	names, err := m.enumerateVMNames(context.Background())
	require.NoError(t, err)
	assert.Empty(t, names)
}

func TestEnumerateVMNames_NoTransport(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	// transport deliberately nil

	names, err := m.enumerateVMNames(context.Background())
	require.NoError(t, err)
	assert.Nil(t, names)
}

// ── observeVSwitchDomain tests ─────────────────────────────────────────────────

func TestObserveVSwitchDomain_ReturnsAllSwitches(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"switches":[{"Name":"External","SwitchType":"External"},{"Name":"Mgmt","SwitchType":"Internal"}]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport

	switches, err := m.observeVSwitchDomain(context.Background())
	require.NoError(t, err)
	require.Len(t, switches, 2)
	assert.Equal(t, "External", switches[0].Name)
	assert.Equal(t, "external", switches[0].SwitchType)
	assert.Equal(t, "present", switches[0].State)
	assert.Equal(t, "Mgmt", switches[1].Name)
	assert.Equal(t, "internal", switches[1].SwitchType)
}

func TestObserveVSwitchDomain_NoSwitches(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{`{"switches":[]}`},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport

	switches, err := m.observeVSwitchDomain(context.Background())
	require.NoError(t, err)
	assert.Empty(t, switches)
}

func TestObserveVSwitchDomain_NoTransport(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	// transport deliberately nil

	switches, err := m.observeVSwitchDomain(context.Background())
	require.NoError(t, err)
	assert.Nil(t, switches)
}

// ── getDomainSummary tests ─────────────────────────────────────────────────────

func TestGetDomainSummary_ClusterMember(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"owner":"NODE1"}`,
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
			`{"vms":["web-01","db-01"]}`,
			`{"switches":[{"Name":"External","SwitchType":"External"}]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"

	obs, err := m.getDomainSummary(context.Background())
	require.NoError(t, err)
	require.NotNil(t, obs)

	assert.True(t, obs.ClusterFound)
	assert.Equal(t, "cfg-lab", obs.ClusterName)
	assert.Equal(t, []string{"db-01", "web-01"}, obs.VMNames, "VM names must be sorted")
	assert.Equal(t, []string{"External"}, obs.VSwitchNames)
}

func TestGetDomainSummary_Standalone(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":false}`,
			`{"vms":[]}`,
			`{"switches":[]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport

	obs, err := m.getDomainSummary(context.Background())
	require.NoError(t, err)
	assert.False(t, obs.ClusterFound)
	assert.Empty(t, obs.ClusterName)
	assert.Empty(t, obs.VMNames)
	assert.Empty(t, obs.VSwitchNames)
}

// ── AC4: Regression — convergence call counts unchanged ───────────────────────

// TestObserveDomain_NoSetCalls is the AC4 regression guard: calling
// getDomainSummary must never issue any PS write-mutating command, confirming
// that the domain observe path does not change existing convergence behaviour.
func TestObserveDomain_NoSetCalls(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"owner":"NODE1"}`,
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
			`{"vms":[]}`,
			`{"switches":[]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"

	_, err := m.getDomainSummary(context.Background())
	require.NoError(t, err)

	transport.mu.Lock()
	calls := make([]winRMCall, len(transport.calls))
	copy(calls, transport.calls)
	transport.mu.Unlock()

	assertNoWriteCmdlets(t, calls)
}

// ── AC6: Conformance — determinism + no ephemeral fields ──────────────────────

// buildDomainTestTransport builds a testWinRMTransport pre-loaded with enough
// outputs for two successive calls to Get("domain:hyperv") — each call issues
// the same sequence of PS reads, so outputs repeat twice for determinism testing.
func buildDomainTestTransport() *testWinRMTransport {
	oneCycle := []string{
		`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
		`{"owner":"NODE1"}`,
		`{"owners":{}}`,
		`{"owner":"NODE1"}`,
		`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
		`{"vms":["web-01"]}`,
		`{"switches":[{"Name":"External","SwitchType":"External"}]}`,
	}
	return &testWinRMTransport{
		perCallOutputs: append(append([]string{}, oneCycle...), oneCycle...),
	}
}

// TestGetDomain_Deterministic is the AC6 determinism assertion. It uses
// conformance.AssertDeterministicGet, which calls Get("domain:hyperv") twice
// and verifies that AsMap() produces byte-for-byte identical JSON both times.
func TestGetDomain_Deterministic(t *testing.T) {
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = buildDomainTestTransport()
	m.nodeHostname = "NODE2"

	conformance.AssertDeterministicGet(t, m, "domain:hyperv")
}

// TestGetDomain_NoEphemeralFields is the AC6 ephemeral-field assertion. It uses
// conformance.AssertNoEphemeralFields to confirm DomainObservation.AsMap()
// contains no banned runtime values (ADR-016 §4).
func TestGetDomain_NoEphemeralFields(t *testing.T) {
	transport := &testWinRMTransport{
		perCallOutputs: []string{
			`{"found":true,"Name":"cfg-lab","MemberNodes":["NODE1","NODE2"],"CsvPaths":[]}`,
			`{"owner":"NODE1"}`,
			`{"owners":{}}`,
			`{"owner":"NODE1"}`,
			`{"account":"LAB\\NODE2$","access_ok":true,"remediation":""}`,
			`{"vms":["web-01"]}`,
			`{"switches":[{"Name":"External","SwitchType":"External"}]}`,
		},
	}
	m := newModuleWithDetector(nil, &fakeDetector{result: true})
	m.transport = transport
	m.nodeHostname = "NODE2"

	state, err := m.Get(context.Background(), "domain:hyperv")
	require.NoError(t, err)
	conformance.AssertNoEphemeralFields(t, state, conformance.DefaultBannedEphemeralFields)
}

// TestGetDomain_AsMapKeys verifies DomainObservation.AsMap() returns all
// expected keys, including the newly added vm_count and vswitch_count.
func TestGetDomain_AsMapKeys(t *testing.T) {
	obs := &DomainObservation{
		ClusterName:  "cfg-lab",
		ClusterFound: true,
		VMNames:      []string{"db-01", "web-01"},
		VSwitchNames: []string{"External"},
	}
	m := obs.AsMap()

	assert.Equal(t, "cfg-lab", m["cluster_name"])
	assert.Equal(t, true, m["cluster_found"])
	assert.Equal(t, 2, m["vm_count"])
	assert.Equal(t, 1, m["vswitch_count"])
	vmNames, ok := m["vm_names"].([]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"db-01", "web-01"}, vmNames)
}
