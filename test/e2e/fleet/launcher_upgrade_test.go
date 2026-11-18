// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Launcher-supervised upgrade E2E tests: validate the auto-apply chain
// (staged binary → self-exit → launcher re-exec → reconnect on new version)
// under a launcher-managed steward, plus the broken-binary startup-window
// auto-rollback variant. (Issue #2005)
package fleet

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/test/e2e/fleet/fleetkit"
)

// TestFleetLauncherManagedUpgradeHappyPath runs a steward under cfgms-steward-launcher
// and proves the full auto-apply chain end to end:
//   - push a real signed binary at a strictly higher version
//   - steward stages it, self-exits after the grace delay (launcher-managed)
//   - launcher re-execs the new binary
//   - steward reconnects with the same identity (cert/registration unchanged)
//   - AC3: upgrade command is not redelivered — no self-exit loop observed for 45 s
//
// Uses a 90 s poll window for the upgrade status (vs 35 s for fake-payload tests)
// because the real binary is ~30 MB. (Issue #2005)
func TestFleetLauncherManagedUpgradeHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping launcher upgrade test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	stewardID := suite.StewardIDs[fleetkit.LauncherTestContainer]
	require.NotEmpty(t, stewardID, "%s must have a registered steward ID", fleetkit.LauncherTestContainer)

	// ── Step 1: Transition from bare steward to launcher-supervised steward ───────
	// Register cleanup before any destructive action so the container is restored
	// even if the test fails mid-way.
	t.Cleanup(func() { suite.RestoreBareSteward(t, fleetkit.LauncherTestContainer, stewardID) })

	// The controller keeps the killed process's connection_state=connected until it
	// notices the drop, so convergence alone would let the upgrade be sent to the
	// dead stream. Wait for the launcher-supervised steward's own new session first
	// (Issue #4671).
	sessionsBefore := suite.StewardLogCount(t, fleetkit.LauncherTestContainer, fleetkit.StewardSessionMarkers...)
	fleetkit.KillBareSteward(t, fleetkit.LauncherTestContainer)
	fleetkit.InstallLauncherLayout(t, fleetkit.LauncherTestContainer, fleetkit.LauncherInitialVersion)
	fleetkit.StartLauncherSupervised(t, fleetkit.LauncherTestContainer, fleetkit.LauncherRegistrationToken)
	suite.RequireLauncherSession(t, fleetkit.LauncherTestContainer, stewardID, sessionsBefore)

	// The launcher sets CFGMS_STEWARD_LAUNCHER_MANAGED=1 on its child automatically
	// (see lifecycle.go:execOnce); we just wait for the steward to reconnect.
	suite.RequireStewardConnected(t, fleetkit.LauncherTestContainer, stewardID, 60*time.Second,
		"launcher-supervised steward (bare-to-launcher swap)")
	fleetkit.RequireNoBareSteward(t, fleetkit.LauncherTestContainer)
	t.Logf("Launcher-supervised steward connected (steward_id=%s)", stewardID)

	// ── Step 2: Publish the real steward binary as a higher version ───────────────
	// Extract /app/steward (the running binary) and publish it as fleetkit.LauncherHappyVersion.
	// Using the real executable so the launcher can actually exec it after re-spawn
	// and the new process passes its startup window. (Issue #2005)
	binaryContent := extractBinaryFromContainer(t, fleetkit.LauncherTestContainer, "/app/steward")
	code := fleetkit.PublishStewardBin(t, client, fleetkit.LauncherHappyVersion, binaryContent, true)
	require.Equal(t, http.StatusOK, code, "publish %s must return 200", fleetkit.LauncherHappyVersion)
	t.Logf("Published %s (%d bytes)", fleetkit.LauncherHappyVersion, len(binaryContent))

	// ── Step 3: Dispatch upgrade and wait for committed ───────────────────────────
	sessionsBeforeUpgrade := suite.StewardLogCount(t, fleetkit.LauncherTestContainer, fleetkit.StewardSessionMarkers...)
	upgradeID := fleetkit.DispatchUpgrade(t, client, stewardID, fleetkit.LauncherHappyVersion)
	t.Logf("Launcher-managed upgrade dispatched: upgrade_id=%s steward_id=%s", upgradeID, stewardID)

	// EventCommandCompleted is emitted by the steward after the launcher swap
	// succeeds and before the graceful self-exit fires — so 'committed' appears
	// in the status endpoint before the steward process actually exits.
	status := fleetkit.FetchUpgradeStatus(t, client, upgradeID, fleetkit.LauncherUpgradeWindow)
	require.Equal(t, "committed", status,
		"upgrade status must reach 'committed' within %v (got %q)", fleetkit.LauncherUpgradeWindow, status)
	t.Logf("Upgrade status: committed (upgrade_id=%s)", upgradeID)

	// ── Step 4: Verify the launcher swapped to the new version ───────────────────
	// state.json must point at fleetkit.LauncherHappyVersion: proof that the swap ran and
	// the launcher will re-exec the new binary after the steward self-exits.
	if !fleetkit.WaitForLauncherCurrentVersion(t, fleetkit.LauncherTestContainer, fleetkit.LauncherHappyVersion, 30*time.Second) {
		t.Fatalf("launcher state.json must point at %s after committed\n%s",
			fleetkit.LauncherHappyVersion, suite.LauncherDiagnostics(t, fleetkit.LauncherTestContainer))
	}

	// The swap alone rewrites state.json, so it does not prove the re-exec: the
	// steward must exit and the launcher must start the new binary, which opens a
	// new control session (Issue #4680).
	if !suite.WaitForNewStewardLogEntry(t, fleetkit.LauncherTestContainer, sessionsBeforeUpgrade, 90*time.Second, fleetkit.StewardSessionMarkers...) {
		t.Fatalf("launcher must re-exec the steward (a new control session) after the swap\n%s",
			suite.LauncherDiagnostics(t, fleetkit.LauncherTestContainer))
	}

	// ── Step 5: Verify the steward reconnects on the new binary ──────────────────
	// The steward self-exits after the grace delay; the launcher re-execs the new
	// binary from /opt/cfgms/versions/<LauncherHappyVersion>/cfgms-steward.
	// We verify reconnect with the SAME steward ID (cert/registration unchanged).
	// (Issue #2005 AC1)
	suite.RequireStewardConnected(t, fleetkit.LauncherTestContainer, stewardID, 90*time.Second,
		"steward after launcher re-exec")
	t.Logf("Steward reconnected after launcher re-exec (steward_id=%s)", stewardID)

	// ── Step 6 (AC3): Assert no re-dispatch loop after reconnect ─────────────────
	// Wait 45 s and verify the upgrade record stays 'committed' (not re-triggered)
	// and the steward remains connected (no repeated self-exit cycle). (Issue #2005 AC3)
	t.Logf("AC3: waiting 45 s to assert no re-dispatch loop after reconnect...")
	time.Sleep(45 * time.Second)

	finalStatus := fleetkit.FetchUpgradeStatus(t, client, upgradeID, 5*time.Second)
	require.Equal(t, "committed", finalStatus,
		"upgrade status must remain 'committed' 45 s after reconnect (got %q); redelivery loop suspected", finalStatus)

	state, err := suite.GetStewardConnectionState(t, stewardID)
	require.NoError(t, err, "steward must be reachable 45 s after reconnect")
	require.Equal(t, "connected", state,
		"steward must remain connected 45 s after reconnect (no re-exit loop)")
	t.Logf("AC3: no re-dispatch loop detected; steward stable on %s", fleetkit.LauncherHappyVersion)
}

// TestFleetLauncherManagedUpgradeBrokenBinaryRollback runs a steward under
// cfgms-steward-launcher and proves the startup-window auto-rollback:
//   - push a binary that passes all steward-side checks (valid signature, SHA-256)
//     but fails to run past the launcher's startup window (exits immediately)
//   - launcher auto-rolls back to the previous version
//   - steward reconnects on the restored version with the same identity
//
// The broken binary is a shell script (#!/bin/sh; exit 1) that is a valid
// executable on the container (Debian bookworm-slim ships /bin/sh=dash),
// passes mTLS download and signature verification, but exits in <1 s when
// the launcher execs it — well inside the 30 s startup window. (Issue #2005 AC2)
func TestFleetLauncherManagedUpgradeBrokenBinaryRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping launcher rollback test — requires Docker fleet infrastructure")
	}

	suite := newFleetScenarioSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	stewardID := suite.StewardIDs[fleetkit.LauncherTestContainer]
	require.NotEmpty(t, stewardID, "%s must have a registered steward ID", fleetkit.LauncherTestContainer)

	// ── Step 1: Transition to launcher-supervised steward ────────────────────────
	t.Cleanup(func() { suite.RestoreBareSteward(t, fleetkit.LauncherTestContainer, stewardID) })

	// The controller keeps the killed process's connection_state=connected until it
	// notices the drop, so convergence alone would let the upgrade be sent to the
	// dead stream. Wait for the launcher-supervised steward's own new session first
	// (Issue #4671).
	sessionsBefore := suite.StewardLogCount(t, fleetkit.LauncherTestContainer, fleetkit.StewardSessionMarkers...)
	fleetkit.KillBareSteward(t, fleetkit.LauncherTestContainer)
	fleetkit.InstallLauncherLayout(t, fleetkit.LauncherTestContainer, fleetkit.LauncherInitialVersion)
	fleetkit.StartLauncherSupervised(t, fleetkit.LauncherTestContainer, fleetkit.LauncherRegistrationToken)
	suite.RequireLauncherSession(t, fleetkit.LauncherTestContainer, stewardID, sessionsBefore)

	suite.RequireStewardConnected(t, fleetkit.LauncherTestContainer, stewardID, 60*time.Second,
		"launcher-supervised steward (bare-to-launcher swap)")
	fleetkit.RequireNoBareSteward(t, fleetkit.LauncherTestContainer)
	t.Logf("Launcher-supervised steward connected (steward_id=%s)", stewardID)

	// ── Step 2: Publish a broken binary ──────────────────────────────────────────
	// A shell script that exits immediately with code 1. It passes:
	//   • SHA-256 check (computed from the actual content)
	//   • Ed25519 signature check (signed with the zero-seed test key)
	//   • Version monotonicity (0.6.1 > 0.5.0)
	//   • launcher swap (copies bytes to /opt/cfgms/versions/… with mode 0755)
	// But when the launcher execs it, /bin/sh runs the script → exit 1 in <1 s
	// → ranFor < StartupWindow (30 s) → auto-rollback fires. (Issue #2005 AC2)
	brokenBinary := []byte("#!/bin/sh\nexit 1\n")
	code := fleetkit.PublishStewardBin(t, client, fleetkit.LauncherBrokenVersion, brokenBinary, true)
	require.Equal(t, http.StatusOK, code, "publish %s must return 200", fleetkit.LauncherBrokenVersion)
	t.Logf("Published broken binary %s (%d bytes)", fleetkit.LauncherBrokenVersion, len(brokenBinary))

	// ── Step 3: Dispatch upgrade ─────────────────────────────────────────────────
	upgradeID := fleetkit.DispatchUpgrade(t, client, stewardID, fleetkit.LauncherBrokenVersion)
	t.Logf("Broken-binary upgrade dispatched: upgrade_id=%s", upgradeID)

	// The swap itself succeeds (binary passes all steward-side checks), so the
	// controller marks the record 'committed' when EventCommandCompleted arrives.
	// The launcher's startup-window auto-rollback is transparent to the upgrade
	// record; the record stays 'committed'. (Issue #2005 AC2)
	status := fleetkit.FetchUpgradeStatus(t, client, upgradeID, fleetkit.LauncherUpgradeWindow)
	require.Equal(t, "committed", status,
		"upgrade status must reach 'committed' within %v (got %q) — swap succeeded even for broken binary",
		fleetkit.LauncherUpgradeWindow, status)
	t.Logf("Upgrade status: committed (swap succeeded; launcher rollback in progress)")

	// ── Step 4: Verify the launcher rolled back to the initial version ────────────
	// After the broken binary exits within the startup window, the launcher
	// auto-rolls back. state.json current must return to fleetkit.LauncherInitialVersion.
	if !fleetkit.WaitForLauncherCurrentVersion(t, fleetkit.LauncherTestContainer, fleetkit.LauncherInitialVersion, 30*time.Second) {
		t.Fatalf("launcher state.json must roll back to %s after broken binary exits within startup window\n%s",
			fleetkit.LauncherInitialVersion, suite.LauncherDiagnostics(t, fleetkit.LauncherTestContainer))
	}
	t.Logf("Launcher rolled back to %s", fleetkit.LauncherInitialVersion)

	// ── Step 5: Verify the steward reconnects on the restored version ─────────────
	// The launcher re-execs fleetkit.LauncherInitialVersion (the real steward binary) after
	// rollback. The steward reconnects with the same identity. (Issue #2005 AC2)
	suite.RequireStewardConnected(t, fleetkit.LauncherTestContainer, stewardID, 60*time.Second,
		"steward on the restored version after launcher rollback")

	state, err := suite.GetStewardConnectionState(t, stewardID)
	require.NoError(t, err, "steward must be reachable after launcher rollback")
	require.Equal(t, "connected", state,
		"steward must be connected on restored version after launcher rollback")
	t.Logf("Steward reconnected on restored version (steward_id=%s)", stewardID)
}
