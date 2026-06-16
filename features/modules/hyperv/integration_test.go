// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build integration

package hyperv

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// integrationModule configures a hypervModule using env-var credentials.
// Returns nil and skips the test if CFGMS_HYPERV_HOST is not set.
func integrationModule(t *testing.T) *hypervModule {
	t.Helper()

	host := os.Getenv("CFGMS_HYPERV_HOST")
	if host == "" {
		t.Skip("CFGMS_HYPERV_HOST not set — Hyper-V host required for integration tests")
	}

	user := os.Getenv("CFGMS_HYPERV_USER")
	pass := os.Getenv("CFGMS_HYPERV_PASS")

	store := newInlineStore("user-key", user, "pass-key", pass)
	m := newModuleWithDetector(store, &fakeDetector{result: true})

	require.NoError(t, m.Configure(mapConfigState{
		"winrm_host":        host,
		"winrm_user_secret": "user-key",
		"winrm_pass_secret": "pass-key",
	}))

	return m
}

// TestHypervIntegration_VMLifecycle exercises the full VM lifecycle against a real
// Hyper-V host: create → start → stop → snapshot → restore → remove.
//
// Run via:
//
//	go test -tags=integration -run TestHypervIntegration ./features/modules/hyperv/...
//
// Excluded from make test-complete because it requires an external Hyper-V host.
func TestHypervIntegration_VMLifecycle(t *testing.T) {
	m := integrationModule(t)
	ctx := context.Background()

	vmName := "cfgms-test__lifecycle-vm"
	snapName := "cfgms-integration-snap"

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = m.transport.ExecutePS(bg,
			"Get-VMSnapshot -VMName $VMName -Name $SnapName -ErrorAction SilentlyContinue | Remove-VMSnapshot -Confirm:$false",
			map[string]string{"VMName": vmName, "SnapName": snapName})
		_, _ = m.transport.ExecutePS(bg,
			"$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue; if ($vm) { Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue; Remove-VM -Name $VMName -Force }",
			map[string]string{"VMName": vmName})
	})

	// Create VM (Generation 2, no VHD, 512 MB — minimal for smoke test)
	_, err := m.transport.ExecutePS(ctx,
		"New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -NoVHD",
		map[string]string{"VMName": vmName})
	require.NoError(t, err, "create VM")

	// Start VM
	_, err = m.transport.ExecutePS(ctx,
		"Start-VM -Name $VMName",
		map[string]string{"VMName": vmName})
	require.NoError(t, err, "start VM")

	// Stop VM
	_, err = m.transport.ExecutePS(ctx,
		"Stop-VM -Name $VMName -Force",
		map[string]string{"VMName": vmName})
	require.NoError(t, err, "stop VM")

	// Create snapshot (checkpoint)
	_, err = m.transport.ExecutePS(ctx,
		"Checkpoint-VM -Name $VMName -SnapshotName $SnapName",
		map[string]string{"VMName": vmName, "SnapName": snapName})
	require.NoError(t, err, "create snapshot")

	// Restore snapshot
	_, err = m.transport.ExecutePS(ctx,
		"Get-VMSnapshot -VMName $VMName -Name $SnapName | Restore-VMSnapshot -Confirm:$false",
		map[string]string{"VMName": vmName, "SnapName": snapName})
	require.NoError(t, err, "restore snapshot")

	// Remove snapshot
	_, err = m.transport.ExecutePS(ctx,
		"Get-VMSnapshot -VMName $VMName -Name $SnapName | Remove-VMSnapshot -Confirm:$false",
		map[string]string{"VMName": vmName, "SnapName": snapName})
	require.NoError(t, err, "remove snapshot")

	// Remove VM
	_, err = m.transport.ExecutePS(ctx,
		"Remove-VM -Name $VMName -Force",
		map[string]string{"VMName": vmName})
	require.NoError(t, err, "remove VM")
}

// TestHypervIntegration_VSwitch exercises the external vswitch lifecycle against a
// real Hyper-V host: create external switch → attach adapter → detach → remove.
//
// The test queries the first UP physical adapter on the host; it skips if none is
// found so it can run on hosts with only virtual adapters.
func TestHypervIntegration_VSwitch(t *testing.T) {
	m := integrationModule(t)
	ctx := context.Background()

	switchName := "cfgms-test__integration-vswitch"
	vmName := "cfgms-test__vswitch-vm"
	adapterName := "cfgms-integration-adapter"

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = m.transport.ExecutePS(bg,
			"$vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue; if ($vm) { Remove-VMNetworkAdapter -VMName $VMName -Name $AdapterName -ErrorAction SilentlyContinue; Remove-VM -Name $VMName -Force }",
			map[string]string{"VMName": vmName, "AdapterName": adapterName})
		_, _ = m.transport.ExecutePS(bg,
			"$sw = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue; if ($sw) { Remove-VMSwitch -Name $SwitchName -Force }",
			map[string]string{"SwitchName": switchName})
	})

	// Query the first UP physical adapter to use for the external switch.
	adapterOut, err := m.transport.ExecutePS(ctx,
		"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1 -ExpandProperty Name",
		nil)
	require.NoError(t, err, "query network adapters")
	physicalAdapter := strings.TrimSpace(adapterOut)
	if physicalAdapter == "" {
		t.Skip("no UP network adapter found on Hyper-V host — cannot create external switch")
	}

	// Create external switch
	_, err = m.transport.ExecutePS(ctx,
		"New-VMSwitch -Name $SwitchName -SwitchType External -NetAdapterName $PhysAdapter",
		map[string]string{"SwitchName": switchName, "PhysAdapter": physicalAdapter})
	require.NoError(t, err, "create external vswitch")

	// Create a VM to attach the adapter to
	_, err = m.transport.ExecutePS(ctx,
		"New-VM -Name $VMName -MemoryStartupBytes 512MB -Generation 2 -NoVHD",
		map[string]string{"VMName": vmName})
	require.NoError(t, err, "create VM for vswitch test")

	// Attach adapter
	_, err = m.transport.ExecutePS(ctx,
		"Add-VMNetworkAdapter -VMName $VMName -Name $AdapterName -SwitchName $SwitchName",
		map[string]string{"VMName": vmName, "AdapterName": adapterName, "SwitchName": switchName})
	require.NoError(t, err, "attach adapter to vswitch")

	// Detach adapter
	_, err = m.transport.ExecutePS(ctx,
		"Remove-VMNetworkAdapter -VMName $VMName -Name $AdapterName",
		map[string]string{"VMName": vmName, "AdapterName": adapterName})
	require.NoError(t, err, "detach adapter from vswitch")

	// Remove VM
	_, err = m.transport.ExecutePS(ctx,
		"Remove-VM -Name $VMName -Force",
		map[string]string{"VMName": vmName})
	require.NoError(t, err, "remove VM")

	// Remove external switch
	_, err = m.transport.ExecutePS(ctx,
		"Remove-VMSwitch -Name $SwitchName -Force",
		map[string]string{"SwitchName": switchName})
	require.NoError(t, err, "remove vswitch")
}
