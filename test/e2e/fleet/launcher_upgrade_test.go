// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Launcher-supervised upgrade E2E tests: validate the auto-apply chain
// (staged binary → self-exit → launcher re-exec → reconnect on new version)
// under a launcher-managed steward, plus the broken-binary startup-window
// auto-rollback variant. (Issue #2005)
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	// launcherRoot is the on-disk install root the launcher manages in fleet containers.
	launcherRoot = "/opt/cfgms"

	// launcherBin is the compiled launcher binary path inside the fleet steward images.
	launcherBin = "/usr/local/bin/cfgms-launcher"

	// launcherInitialVersion is the version label assigned to /app/steward when
	// staging the launcher layout. Matches the compile-time version.Version default.
	launcherInitialVersion = "v0.5.0-dev"

	// launcherHappyVersion is the version label published for the happy-path upgrade.
	// Must be strictly higher than launcherInitialVersion (0.6 > 0.5).
	launcherHappyVersion = "v0.6.0-launchtest"

	// launcherBrokenVersion is the version label for the broken-binary rollback test.
	// Must be strictly higher than launcherInitialVersion (0.6.1 > 0.5).
	launcherBrokenVersion = "v0.6.1-launchtest-broken"

	// launcherRegistrationToken is the token for fleet-steward-1 (from docker-compose).
	launcherRegistrationToken = "dockertest_fleet_child_a"

	// launcherTestContainer is the fleet container that gets reconfigured to use the
	// launcher. fleet-steward-1 is used because it belongs to fleet-child-a, whose
	// tenant scoping matches upgradeAPIKey.
	launcherTestContainer = "fleet-steward-1"

	// launcherUpgradeWindow is the poll window for launcher-managed upgrade status.
	// The real steward binary is ~30 MB; in-container download takes longer than the
	// 35 s used for fake-payload bare-steward tests. (Issue #2005 AC4)
	launcherUpgradeWindow = 90 * time.Second
)

// killBareStewdAndWrapper kills the bare steward process and its docker-compose
// restart wrapper in container. Errors are logged but not fatal: pkill -f with a
// pattern that appears in the sh -c cmdline will send SIGKILL to the executing
// shell as well as the targets (exit 137). The targets (steward + wrapper) have
// lower PIDs and are killed first, so the operation is effective. The exit-137
// from the sh process itself is expected and does not indicate a real failure.
func killBareStewdAndWrapper(t *testing.T, container string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", "--user", "root", container,
		"sh", "-c",
		"pkill -9 -f './steward' 2>/dev/null; pkill -9 -f '/app/steward' 2>/dev/null; pkill -9 -f 'while true' 2>/dev/null; sleep 0.5; true",
	).CombinedOutput()
	if err != nil {
		t.Logf("killBareStewdAndWrapper in %s: %v (output: %s)", container, err, string(out))
	}
}

// installLauncherLayout creates the launcher's versioned binary tree under
// launcherRoot in container for initialVersion and writes the initial state.json.
//
//	/opt/cfgms/versions/<initialVersion>/cfgms-steward  ← copy of /app/steward
//	/opt/cfgms/state.json                              ← {"current":"<initialVersion>"}
//
// The entire versions tree is chowned to cfgms so the launcher (running as cfgms)
// can create sub-directories when staging subsequent upgrade versions.
func installLauncherLayout(t *testing.T, container, initialVersion string) {
	t.Helper()
	versionDir := launcherRoot + "/versions/" + initialVersion
	stewardPath := versionDir + "/cfgms-steward"
	stateJSON := fmt.Sprintf(`{"current":%q}`, initialVersion)
	script := strings.Join([]string{
		"mkdir -p " + versionDir,
		"cp /app/steward " + stewardPath,
		"chmod 755 " + stewardPath,
		"chown -R cfgms:cfgms " + launcherRoot + "/versions",
		fmt.Sprintf("echo '%s' > %s/state.json", stateJSON, launcherRoot),
		"chown cfgms:cfgms " + launcherRoot + "/state.json",
	}, " && ")
	dockerExecRoot(t, container, "sh", "-c", script)
}

// startLauncherSupervised starts cfgms-steward-launcher run in detached (-d) mode
// inside container as the cfgms user. The launcher supervises from launcherRoot
// and forwards --child-args to the supervised steward.
func startLauncherSupervised(t *testing.T, container, regtoken string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec",
		"-d", "--user", "cfgms",
		container,
		launcherBin, "run",
		"--root", launcherRoot,
		"--child-args", "--regtoken "+regtoken,
	).CombinedOutput()
	require.NoError(t, err, "start launcher in %s failed: %s", container, string(out))
	t.Logf("Launcher started in %s (detached)", container)
}

// getLauncherCurrentVersion reads the launcher's state.json and returns the
// current version field. Returns "" on any error (file missing, invalid JSON).
func getLauncherCurrentVersion(t *testing.T, container string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", container,
		"cat", launcherRoot+"/state.json").CombinedOutput()
	if err != nil {
		return ""
	}
	var ps struct {
		Current string `json:"current"`
	}
	if jerr := json.Unmarshal(out, &ps); jerr != nil {
		return ""
	}
	return ps.Current
}

// waitForLauncherCurrentVersion polls state.json until its current field equals
// wantVersion or the timeout expires.
func waitForLauncherCurrentVersion(t *testing.T, container, wantVersion string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := getLauncherCurrentVersion(t, container); got == wantVersion {
			t.Logf("Launcher state: current=%q confirmed in %s", wantVersion, container)
			return true
		}
		time.Sleep(3 * time.Second)
	}
	t.Logf("Launcher state: current never reached %q in %s within %v",
		wantVersion, container, timeout)
	return false
}

// restoreBareStewdInContainer kills the launcher and its supervised steward, then
// starts the original bare-steward retry wrapper. Used in t.Cleanup to return
// fleet-steward-1 to its docker-compose baseline state so subsequent tests are
// not affected. All docker exec errors are logged (not silently swallowed) so
// any cleanup failure is visible in test output.
func restoreBareStewdInContainer(t *testing.T, container string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", "--user", "root", container,
		"sh", "-c",
		"pkill -9 -f 'cfgms-steward-launcher' 2>/dev/null; "+
			"pkill -9 -f 'cfgms-launcher' 2>/dev/null; "+
			"pkill -9 -f 'cfgms-steward' 2>/dev/null; "+
			"true",
	).CombinedOutput()
	if err != nil {
		t.Logf("cleanup: kill launcher/steward in %s failed: %v (output: %s)", container, err, string(out))
	}
	time.Sleep(400 * time.Millisecond)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	out2, err2 := exec.CommandContext(ctx2, "docker", "exec",
		"-d", "--user", "cfgms",
		container,
		"sh", "-c",
		"mkdir -p /tmp/cfgms && while true; do /app/steward --regtoken dockertest_fleet_child_a && break; echo 'steward exited, retrying in 5s...'; sleep 5; done",
	).CombinedOutput()
	if err2 != nil {
		t.Logf("cleanup: restart bare steward in %s failed: %v (output: %s)", container, err2, string(out2))
	} else {
		t.Logf("Restored bare steward in %s", container)
	}
}

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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	stewardID := suite.stewardIDs[launcherTestContainer]
	require.NotEmpty(t, stewardID, "%s must have a registered steward ID", launcherTestContainer)

	// ── Step 1: Transition from bare steward to launcher-supervised steward ───────
	// Register cleanup before any destructive action so the container is restored
	// even if the test fails mid-way.
	t.Cleanup(func() { restoreBareStewdInContainer(t, launcherTestContainer) })

	killBareStewdAndWrapper(t, launcherTestContainer)
	installLauncherLayout(t, launcherTestContainer, launcherInitialVersion)
	startLauncherSupervised(t, launcherTestContainer, launcherRegistrationToken)

	// The launcher sets CFGMS_STEWARD_LAUNCHER_MANAGED=1 on its child automatically
	// (see lifecycle.go:execOnce); we just wait for the steward to reconnect.
	require.True(t, suite.waitForConvergence(t, stewardID, 60*time.Second),
		"launcher-supervised steward must reconnect within 60 s using same identity")
	t.Logf("Launcher-supervised steward connected (steward_id=%s)", stewardID)

	// ── Step 2: Publish the real steward binary as a higher version ───────────────
	// Extract /app/steward (the running binary) and publish it as launcherHappyVersion.
	// Using the real executable so the launcher can actually exec it after re-spawn
	// and the new process passes its startup window. (Issue #2005)
	binaryContent := extractBinaryFromContainer(t, launcherTestContainer, "/app/steward")
	code := publishStewardBin(t, client, launcherHappyVersion, binaryContent, true)
	require.Equal(t, http.StatusOK, code, "publish %s must return 200", launcherHappyVersion)
	t.Logf("Published %s (%d bytes)", launcherHappyVersion, len(binaryContent))

	// ── Step 3: Dispatch upgrade and wait for committed ───────────────────────────
	upgradeID := dispatchUpgrade(t, client, stewardID, launcherHappyVersion)
	t.Logf("Launcher-managed upgrade dispatched: upgrade_id=%s steward_id=%s", upgradeID, stewardID)

	// EventCommandCompleted is emitted by the steward after the launcher swap
	// succeeds and before the graceful self-exit fires — so 'committed' appears
	// in the status endpoint before the steward process actually exits.
	status := fetchUpgradeStatus(t, client, upgradeID, launcherUpgradeWindow)
	require.Equal(t, "committed", status,
		"upgrade status must reach 'committed' within %v (got %q)", launcherUpgradeWindow, status)
	t.Logf("Upgrade status: committed (upgrade_id=%s)", upgradeID)

	// ── Step 4: Verify the launcher swapped to the new version ───────────────────
	// state.json must point at launcherHappyVersion: proof that the swap ran and
	// the launcher will re-exec the new binary after the steward self-exits.
	require.True(t, waitForLauncherCurrentVersion(t, launcherTestContainer, launcherHappyVersion, 30*time.Second),
		"launcher state.json must point at %s after committed", launcherHappyVersion)

	// ── Step 5: Verify the steward reconnects on the new binary ──────────────────
	// The steward self-exits after the grace delay; the launcher re-execs the new
	// binary from /opt/cfgms/versions/launcherHappyVersion/cfgms-steward.
	// We verify reconnect with the SAME steward ID (cert/registration unchanged).
	// (Issue #2005 AC1)
	require.True(t, suite.waitForConvergence(t, stewardID, 90*time.Second),
		"steward must reconnect after launcher re-exec with same identity within 90 s")
	t.Logf("Steward reconnected after launcher re-exec (steward_id=%s)", stewardID)

	// ── Step 6 (AC3): Assert no re-dispatch loop after reconnect ─────────────────
	// Wait 45 s and verify the upgrade record stays 'committed' (not re-triggered)
	// and the steward remains connected (no repeated self-exit cycle). (Issue #2005 AC3)
	t.Logf("AC3: waiting 45 s to assert no re-dispatch loop after reconnect...")
	time.Sleep(45 * time.Second)

	finalStatus := fetchUpgradeStatus(t, client, upgradeID, 5*time.Second)
	require.Equal(t, "committed", finalStatus,
		"upgrade status must remain 'committed' 45 s after reconnect (got %q); redelivery loop suspected", finalStatus)

	state, err := suite.getStewardConnectionState(t, stewardID)
	require.NoError(t, err, "steward must be reachable 45 s after reconnect")
	require.Equal(t, "connected", state,
		"steward must remain connected 45 s after reconnect (no re-exit loop)")
	t.Logf("AC3: no re-dispatch loop detected; steward stable on %s", launcherHappyVersion)
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

	suite := setupFleetSuite(t)
	client := insecureHTTPClient()
	waitForControllerAPI(t, client)

	stewardID := suite.stewardIDs[launcherTestContainer]
	require.NotEmpty(t, stewardID, "%s must have a registered steward ID", launcherTestContainer)

	// ── Step 1: Transition to launcher-supervised steward ────────────────────────
	t.Cleanup(func() { restoreBareStewdInContainer(t, launcherTestContainer) })

	killBareStewdAndWrapper(t, launcherTestContainer)
	installLauncherLayout(t, launcherTestContainer, launcherInitialVersion)
	startLauncherSupervised(t, launcherTestContainer, launcherRegistrationToken)

	require.True(t, suite.waitForConvergence(t, stewardID, 60*time.Second),
		"launcher-supervised steward must connect within 60 s")
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
	code := publishStewardBin(t, client, launcherBrokenVersion, brokenBinary, true)
	require.Equal(t, http.StatusOK, code, "publish %s must return 200", launcherBrokenVersion)
	t.Logf("Published broken binary %s (%d bytes)", launcherBrokenVersion, len(brokenBinary))

	// ── Step 3: Dispatch upgrade ─────────────────────────────────────────────────
	upgradeID := dispatchUpgrade(t, client, stewardID, launcherBrokenVersion)
	t.Logf("Broken-binary upgrade dispatched: upgrade_id=%s", upgradeID)

	// The swap itself succeeds (binary passes all steward-side checks), so the
	// controller marks the record 'committed' when EventCommandCompleted arrives.
	// The launcher's startup-window auto-rollback is transparent to the upgrade
	// record; the record stays 'committed'. (Issue #2005 AC2)
	status := fetchUpgradeStatus(t, client, upgradeID, launcherUpgradeWindow)
	require.Equal(t, "committed", status,
		"upgrade status must reach 'committed' within %v (got %q) — swap succeeded even for broken binary",
		launcherUpgradeWindow, status)
	t.Logf("Upgrade status: committed (swap succeeded; launcher rollback in progress)")

	// ── Step 4: Verify the launcher rolled back to the initial version ────────────
	// After the broken binary exits within the startup window, the launcher
	// auto-rolls back. state.json current must return to launcherInitialVersion.
	require.True(t, waitForLauncherCurrentVersion(t, launcherTestContainer, launcherInitialVersion, 30*time.Second),
		"launcher state.json must roll back to %s after broken binary exits within startup window",
		launcherInitialVersion)
	t.Logf("Launcher rolled back to %s", launcherInitialVersion)

	// ── Step 5: Verify the steward reconnects on the restored version ─────────────
	// The launcher re-execs launcherInitialVersion (the real steward binary) after
	// rollback. The steward reconnects with the same identity. (Issue #2005 AC2)
	require.True(t, suite.waitForConvergence(t, stewardID, 60*time.Second),
		"steward must reconnect on restored version within 60 s")

	state, err := suite.getStewardConnectionState(t, stewardID)
	require.NoError(t, err, "steward must be reachable after launcher rollback")
	require.Equal(t, "connected", state,
		"steward must be connected on restored version after launcher rollback")
	t.Logf("Steward reconnected on restored version (steward_id=%s)", stewardID)
}
