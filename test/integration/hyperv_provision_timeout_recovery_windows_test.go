// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
//go:build windows

// Issue #3804 (Epic #3799): the Windows-only half of the timeout-repair-visibility
// regression. hyperv_provision_timeout_recovery_test.go proves the cross-component
// composition (commands.Handler deadline decoupling + retry-exhausted visibility)
// by driving the real module against a scripted host injected at its exported
// hyperv.HostCommandTransport boundary. This file proves the piece a scripted host
// cannot reach: that a deadline-killed seed-mount operation against the REAL
// pstransport_windows.go transport (features/modules/hyperv's default "ps-host"
// transport) does not leave a seed VHD wedged on the host, and that a subsequent
// convergence pass genuinely repairs the VM rather than failing again with a
// "still attached" / sharing-violation error.
//
// # Why this drives the real hyperv module instead of a fake transport
//
// hypervModule, psHostTransport, runFresh, dismountAfterKill, and the Cfgms-* seed
// helper functions baked into pstransport_preamble_windows.go are ALL unexported —
// features/modules/hyperv's own test suite (pstransport_windows_test.go,
// vm_reconcile_integration_test.go) already covers them at the package-internal
// level, with real fake transports for the reconcile logic and a real (non-Hyper-V)
// Start-Sleep for the raw kill/cleanup mechanism — see pstransport_windows_test.go's
// own TestDismountAfterKill_UsesFreshContext, which is deliberately "asserted
// structurally... because the cleanup path shells out and cannot run in a unit test
// on a non-Hyper-V host." None of that surface is reachable from test/integration.
//
// The only way to exercise the real Cfgms-MountSeedVHD / Cfgms-DismountAndVerify
// PowerShell functions from outside the hyperv package is through the module's
// public surface: hyperv.New + hyperv.WithProvisionStore (both exported), driving a
// real modules.Module.Set() call against a real Windows host with Hyper-V actually
// enabled. That is what this file does — no fake transport, no reimplemented
// PowerShell, no mocks.
//
// # Scope and honesty about local validation
//
// This test requires a real, administratively-accessible Hyper-V host: it gates on
// hyperv.NewDefaultDetector().IsHypervHost, the SAME production detector the module
// itself uses, which returns (false, nil) — not an error — on a non-elevated host
// (features/modules/hyperv/detection_windows.go's isSoftError treats "access is
// denied" as "not a Hyper-V host"). It could not be live-executed in the environment
// this test was authored in (no administrative Hyper-V access), so its first real
// execution is CI's self-hosted Windows runner. It has been checked for gofmt,
// go vet, and (cross-compiled) go build correctness, and every field/type/behavior
// it depends on was verified by reading the actual hyperv package source — but the
// PowerShell call sequence itself has not been observed to run.
package integration

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/features/steward/execution"
)

// requireRealHypervHostOrSkip gates the test on the SAME production detector
// hypervModule itself uses (hyperv.NewDefaultDetector). On a non-elevated host, the
// underlying Get-VMHost probe fails with "access is denied", which
// features/modules/hyperv/detection_windows.go's isSoftError classifies as "not a
// Hyper-V host" (ok=false, err=nil) rather than an error — exactly the case this
// test was authored against and could not execute past locally.
func requireRealHypervHostOrSkip(t *testing.T) {
	t.Helper()
	ok, err := hyperv.NewDefaultDetector().IsHypervHost(context.Background())
	if err != nil || !ok {
		t.Skipf("skipping: this host is not an administratively-accessible Hyper-V host (IsHypervHost ok=%v err=%v); "+
			"validated for real on CI's self-hosted Windows Hyper-V runner", ok, err)
	}
}

// buildSeedPhaseFailedFixtureRealHost builds the "already failed during the seed
// phase, attemptCount attempts made" starting fixture by driving the REAL
// module — real transport, real Hyper-V host — through its own createVM ->
// provisionVM -> failProvision code path attemptCount times, then reading the
// resulting record back from the real hyperv.ProvisionStore — never a
// hand-built ProvisionRecord literal that could silently drift from what
// production actually writes (Issue #3804 AC2). This is the real-host
// counterpart of the scripted-host fixture builder of the same name in the
// untagged sibling file (hyperv_provision_timeout_recovery_test.go); it
// cannot reuse that one directly because there is no scripted transport to
// inject here.
//
// The technique: configure the module with a deliberately invalid seed_dir (a
// UNC path). createVM never reads seed_dir, so it still runs for real against
// the live host on the first (VM-absent) pass — a genuine New-VM. But
// provisionVM's real validateSeedPath check rejects a UNC seed path before any
// PowerShell is spawned for the seed itself (vm_provision.go), so every pass
// fails deterministically and instantly: no dependency on real host timing, no
// risk of a wedged VHD, and no PowerShell error string to guess at. Each call
// still goes through the real loadOrInitProvision -> advanceProvision(creating)
// -> validateSeedPath -> failProvision chain, so the resulting record is
// exactly what production writes for an N-times-failed seed build. The VM
// itself, and RetryCount, accumulate across passes the same way a real
// steward's repeated convergence attempts would.
//
// The caller must build a FRESH module (hyperv.New + Configure with a valid,
// unset seed_dir) over the returned store before driving the scenario it
// actually wants to observe — this function's module used a poisoned seed_dir
// on purpose and must not be reused.
func buildSeedPhaseFailedFixtureRealHost(t *testing.T, vmName, vhdPath, isoPath string, attemptCount int) hyperv.ProvisionStore {
	t.Helper()
	require.Positive(t, attemptCount, "fixture requires at least one real failed attempt")

	store := hyperv.NewMemProvisionStore()
	m := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(store))

	injectable, ok := m.(modules.SecretStoreInjectable)
	require.True(t, ok, "hyperv module must implement modules.SecretStoreInjectable")
	require.NoError(t, injectable.SetSecretStore(newTestSecretStore()))

	configurable, ok := m.(modules.Configurable)
	require.True(t, ok, "hyperv module must implement modules.Configurable")
	require.NoError(t, configurable.Configure(execution.NewConfigState(map[string]interface{}{
		"tenant_id": "cfgms-it-3804",
		// Deliberately invalid (UNC): rejected by the real validateSeedPath
		// before any PowerShell runs for the seed step. createVM never reads
		// seed_dir, so it is unaffected.
		"seed_dir": `\\cfgms-it-3804-invalid-seed-host\seed`,
	})))

	desired := execution.NewConfigState(map[string]interface{}{
		"name":        vmName,
		"memory_mb":   512,
		"cpu_count":   1,
		"vhd_path":    vhdPath,
		"generation":  2,
		"state":       "running",
		"switch_name": []interface{}{},
		"source": map[string]interface{}{
			"iso":       isoPath,
			"os_family": "linux",
			"completion": map[string]interface{}{
				"mode":    "steward-registration",
				"timeout": "60m",
			},
			"on_existing": "never",
			// A budget comfortably larger than attemptCount so these
			// fixture-building passes never themselves trip retry-exhaustion,
			// which would stop short of attemptCount real failures.
			"retry_max": attemptCount + 5,
		},
	})

	for i := 0; i < attemptCount; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := m.Set(ctx, "vm:"+vmName, desired)
		cancel()
		require.Errorf(t, err, "attempt %d: an invalid seed_dir must deterministically fail the seed/create phase", i+1)
		require.ErrorIsf(t, err, hyperv.ErrInvalidSeedPath, "attempt %d", i+1)
	}

	record, err := store.GetProvision(context.Background(), vmName)
	require.NoError(t, err)
	require.Equal(t, hyperv.ProvisionStateFailed, record.State,
		"fixture-building must leave the record failed")
	require.Equal(t, hyperv.ProvisionStateCreating, record.FailedFrom,
		"fixture-building must fail during the seed/create phase")
	require.Equal(t, attemptCount, record.RetryCount,
		"fixture-building must consume exactly attemptCount real attempts")

	return store
}

// TestHypervVMSeedRepair_Windows_DeadlineKilledMountRecoversOnRetry drives the REAL
// features/modules/hyperv module against a real Hyper-V host: a VM whose seed-phase
// previously failed (RetryCount within budget) is retried under a deadline short
// enough to kill the seed-mount PowerShell process mid-operation, exercising the
// real pstransport_windows.go runFresh/dismountAfterKill cleanup path (Issue #3798)
// instead of a fake transport. A second, generously-timed Set() then proves the
// cleanup left nothing wedged: the retry converges rather than failing with a
// "seed VHD still attached" / 0x80070020 sharing-violation error, which is exactly
// the failure mode #3798/#3802 exist to prevent.
func TestHypervVMSeedRepair_Windows_DeadlineKilledMountRecoversOnRetry(t *testing.T) {
	requireRealHypervHostOrSkip(t)

	const vmName = "cfgms-it-3804-seed-repair"
	tempDir := t.TempDir()
	vhdPath := filepath.Join(tempDir, "boot.vhdx")
	isoPath := filepath.Join(tempDir, "fake-install.iso")

	// A placeholder install ISO — never booted (the seed-phase retry this test
	// drives fails/succeeds long before the guest OS would run), but Add-VMDvdDrive
	// requires the path to exist.
	require.NoError(t, os.WriteFile(isoPath, []byte("cfgms-3804-placeholder-iso"), 0o644))

	t.Cleanup(func() {
		_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`Stop-VM -Name '`+vmName+`' -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -Name '`+vmName+`' -Force -ErrorAction SilentlyContinue`).Run()
	})

	// One prior failed attempt, built via the real module's own
	// createVM/provisionVM/failProvision path (Issue #3804 AC2) — see
	// buildSeedPhaseFailedFixtureRealHost. This is also what puts the real VM on the
	// host (createVM), so no separate raw-PowerShell VM-shell fixture is
	// needed. Well within the default retry budget of 3.
	store := buildSeedPhaseFailedFixtureRealHost(t, vmName, vhdPath, isoPath, 1)

	m := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(store))

	injectable, ok := m.(modules.SecretStoreInjectable)
	require.True(t, ok, "hyperv module must implement modules.SecretStoreInjectable")
	require.NoError(t, injectable.SetSecretStore(newTestSecretStore()))

	configurable, ok := m.(modules.Configurable)
	require.True(t, ok, "hyperv module must implement modules.Configurable")
	require.NoError(t, configurable.Configure(execution.NewConfigState(map[string]interface{}{
		"tenant_id": "cfgms-it-3804",
	})))

	desired := execution.NewConfigState(map[string]interface{}{
		"name":        vmName,
		"memory_mb":   512,
		"cpu_count":   1,
		"vhd_path":    vhdPath,
		"generation":  2,
		"state":       "running",
		"switch_name": []interface{}{},
		"source": map[string]interface{}{
			"iso":       isoPath,
			"os_family": "linux",
			"completion": map[string]interface{}{
				"mode":    "steward-registration",
				"timeout": "60m",
			},
			"on_existing": "never",
		},
	})

	// First attempt: a deadline short enough to virtually guarantee the seed-build
	// PowerShell process (New-VHD -> Mount-VHD/Initialize-Disk/Format-Volume ->
	// Copy -> Add-VMHardDiskDrive, each a freshly-spawned powershell.exe per
	// runFresh) is killed mid-operation rather than completing cleanly. The exact
	// step killed is inherently timing-dependent — this mirrors the same
	// short-deadline-against-real-work approach as
	// pstransport_windows_test.go's own TestRunFresh_DeadlineKillProducesDistinguishableError,
	// adapted here because the real seed cmdlets (unlike a synthetic Start-Sleep)
	// cannot be made deterministically slow from outside the hyperv package.
	killCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	killErr := m.Set(killCtx, "vm:"+vmName, desired)
	cancel()
	require.Error(t, killErr, "a 2s deadline against real seed-build PowerShell work must not silently succeed")

	// Second attempt: a generous deadline. If the killed attempt above left the
	// seed VHD wedged (Cfgms-DismountAndVerify not reached because the whole
	// powershell.exe process was killed before its try/finally could run — the
	// exact leak #3798's dismountAfterKill exists to close on the OS-process
	// level), this retry fails with a 0x80070020 sharing-violation instead of
	// converging.
	repairCtx, repairCancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer repairCancel()
	repairErr := m.Set(repairCtx, "vm:"+vmName, desired)
	assert.NoError(t, repairErr,
		"a subsequent convergence pass must repair the seed-phase failure, not fail again due to a VHD left attached by the killed attempt")

	rec, err := store.GetProvision(context.Background(), vmName)
	require.NoError(t, err)
	assert.NotEqual(t, hyperv.ProvisionStateFailed, rec.State,
		"a successful repair must advance the provisioning record off Failed")
}

// TestHypervVMSeedRepair_Windows_RetryBudgetExhausted_NeverAttemptsHostWork proves
// the complementary real-host guard: once the retry budget is already exhausted,
// the module must not spend any more real host mutation attempting a doomed
// repair — it surfaces retry-exhaustion immediately (proven at the cross-component
// ConfigStatusReport level by the untagged sibling test) without ever calling
// New-VHD again.
func TestHypervVMSeedRepair_Windows_RetryBudgetExhausted_NeverAttemptsHostWork(t *testing.T) {
	requireRealHypervHostOrSkip(t)

	const vmName = "cfgms-it-3804-seed-exhausted"
	tempDir := t.TempDir()
	vhdPath := filepath.Join(tempDir, "boot.vhdx")
	isoPath := filepath.Join(tempDir, "fake-install.iso")
	require.NoError(t, os.WriteFile(isoPath, []byte("cfgms-3804-placeholder-iso"), 0o644))

	t.Cleanup(func() {
		_ = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
			`Stop-VM -Name '`+vmName+`' -TurnOff -Force -ErrorAction SilentlyContinue; Remove-VM -Name '`+vmName+`' -Force -ErrorAction SilentlyContinue`).Run()
	})

	// Exhaustion is expressed through authored config, not a copy of the
	// module's built-in default: the desired state below declares
	// source.retry_max: 2 and the record already carries 2 real attempts,
	// built via the real module's own createVM/provisionVM/failProvision path
	// (Issue #3804 AC2, buildSeedPhaseFailedFixtureRealHost), so the module derives
	// "exhausted" from the budget the operator declared.
	const declaredRetryMax = 2

	store := buildSeedPhaseFailedFixtureRealHost(t, vmName, vhdPath, isoPath, declaredRetryMax)

	m := hyperv.New(hyperv.NewDefaultDetector(), hyperv.WithProvisionStore(store))
	injectable, ok := m.(modules.SecretStoreInjectable)
	require.True(t, ok)
	require.NoError(t, injectable.SetSecretStore(newTestSecretStore()))
	configurable, ok := m.(modules.Configurable)
	require.True(t, ok)
	require.NoError(t, configurable.Configure(execution.NewConfigState(map[string]interface{}{
		"tenant_id": "cfgms-it-3804",
	})))

	desired := execution.NewConfigState(map[string]interface{}{
		"name":        vmName,
		"memory_mb":   512,
		"cpu_count":   1,
		"vhd_path":    vhdPath,
		"generation":  2,
		"state":       "running",
		"switch_name": []interface{}{},
		"source": map[string]interface{}{
			"iso":         isoPath,
			"os_family":   "linux",
			"completion":  map[string]interface{}{"mode": "steward-registration", "timeout": "60m"},
			"on_existing": "never",
			"retry_max":   declaredRetryMax,
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := m.Set(ctx, "vm:"+vmName, desired)

	var retryExhausted *modules.RetryExhaustedError
	require.True(t, errors.As(err, &retryExhausted),
		"a VM already at the retry budget must return *modules.RetryExhaustedError, not attempt another real seed rebuild")

	rec, getErr := store.GetProvision(context.Background(), vmName)
	require.NoError(t, getErr)
	assert.Equal(t, declaredRetryMax, rec.RetryCount,
		"RetryCount must not increment past the budget — no further real host attempt was made")
}
