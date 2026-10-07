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

// bareHoldFile pauses the container's bare-steward wrapper (docker-compose.test.yml)
// while it exists. The wrapper is the container's PID 1, which the kernel protects
// from a SIGKILL sent inside the container, so killing it is not an option: before
// the hold existed it restarted a bare steward 5 s after every kill, leaving two
// stewards with one identity beside the launcher's (Issue #4680).
const bareHoldFile = "/tmp/cfgms-bare-hold"

// launcherLogPath receives the launcher's stdout and stderr, including its
// supervision and rollback decisions.
const launcherLogPath = "/tmp/cfgms/launcher.log"

// containerShell runs script in container as root and returns its combined output.
// Process patterns inside script must not match the script's own command line
// (use pkill -x, or the [c]haracter-class idiom with -f): pkill -f with a plain
// pattern kills the shell running the script and silently skips everything after.
func containerShell(container, script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", "--user", "root", container,
		"sh", "-c", script).CombinedOutput()
	return string(out), err
}

// killBareSteward holds the container's bare-steward wrapper and kills the bare
// steward, then requires that no bare steward is left running. A steward the
// wrapper was just starting when the hold appeared is caught by the retry.
func killBareSteward(t *testing.T, container string) {
	t.Helper()
	script := "touch " + bareHoldFile + "; " +
		"for i in $(seq 1 20); do " +
		"pkill -9 -x steward; sleep 0.5; " +
		"if ! pgrep -x steward >/dev/null; then sleep 1; pgrep -x steward >/dev/null || exit 0; fi; " +
		"done; exit 1"
	out, err := containerShell(container, script, 30*time.Second)
	require.NoError(t, err, "bare steward in %s must stay stopped once held: %s", container, out)
}

// requireNoBareSteward fails the test if a bare (non-launcher) steward is running
// in container, so a command can only reach the launcher-supervised steward.
func requireNoBareSteward(t *testing.T, container string) {
	t.Helper()
	out, err := containerShell(container, "pgrep -a -x steward; true", 10*time.Second)
	require.NoError(t, err)
	require.Empty(t, strings.TrimSpace(out), "no bare steward may run beside the launcher's in %s", container)
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
		"cp --remove-destination /app/steward " + stewardPath,
		"chmod 755 " + stewardPath,
		"chown -R cfgms:cfgms " + launcherRoot + "/versions",
		fmt.Sprintf("echo '%s' > %s/state.json", stateJSON, launcherRoot),
		"chown cfgms:cfgms " + launcherRoot + "/state.json",
	}, " && ")
	dockerExecRoot(t, container, "sh", "-c", script)
}

// startLauncherSupervised starts cfgms-steward-launcher run in the background
// inside container as the cfgms user, with its output in launcherLogPath. The
// launcher supervises from launcherRoot and forwards --child-args to the
// supervised steward.
func startLauncherSupervised(t *testing.T, container, regtoken string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := fmt.Sprintf("exec %s run --root %s --child-args '--regtoken %s' >>%s 2>&1",
		launcherBin, launcherRoot, regtoken, launcherLogPath)
	out, err := exec.CommandContext(ctx, "docker", "exec",
		"-d", "--user", "cfgms",
		container,
		"sh", "-c", cmd,
	).CombinedOutput()
	require.NoError(t, err, "start launcher in %s failed: %s", container, string(out))
	t.Logf("Launcher started in %s (detached, log %s)", container, launcherLogPath)
}

// launcherDiagnostics returns the launcher's log tail, the steward's log tail and
// the container's steward processes, for a failed launcher assertion.
func (s *FleetTestSuite) launcherDiagnostics(t *testing.T, container string) string {
	t.Helper()
	launcherLog, _ := containerShell(container, "tail -n 60 "+launcherLogPath+" 2>&1", 10*time.Second)
	procs, _ := containerShell(container, "pgrep -a -f '[s]teward'; true", 10*time.Second)
	stewardLog, _ := s.readStewardLog(t, container)
	return fmt.Sprintf("launcher log tail:\n%s\nsteward processes:\n%s\nsteward log tail:\n%s",
		launcherLog, procs, lastLines(stewardLog, 60))
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

// restoreBareStewdInContainer returns container to its docker-compose baseline:
// it kills the launcher and its supervised steward, empties launcherRoot (the
// image ships it empty, and a later test must not inherit launcher version state),
// and releases the hold so the PID 1 wrapper restarts the one bare steward. Used
// in t.Cleanup; failures are logged so a broken cleanup is visible.
func restoreBareStewdInContainer(t *testing.T, container string) {
	t.Helper()
	script := "pkill -9 -f '[c]fgms-launcher'; pkill -9 -f '[c]fgms-steward'; " +
		"for i in $(seq 1 20); do pgrep -f '[c]fgms-launcher|[c]fgms-steward' >/dev/null || break; sleep 0.5; done; " +
		"find " + launcherRoot + " -mindepth 1 -delete; " +
		"rm -f " + bareHoldFile + "; " +
		"for i in $(seq 1 30); do pgrep -x steward >/dev/null && exit 0; sleep 0.5; done; exit 1"
	if out, err := containerShell(container, script, 30*time.Second); err != nil {
		t.Logf("cleanup: restore bare steward in %s failed: %v (output: %s)", container, err, out)
		return
	}
	t.Logf("Restored bare steward in %s", container)
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

	// The controller keeps the killed process's connection_state=connected until it
	// notices the drop, so convergence alone would let the upgrade be sent to the
	// dead stream. Wait for the launcher-supervised steward's own new session first
	// (Issue #4671).
	sessionsBefore := suite.stewardLogCount(t, launcherTestContainer, stewardSessionMarkers...)
	killBareSteward(t, launcherTestContainer)
	installLauncherLayout(t, launcherTestContainer, launcherInitialVersion)
	startLauncherSupervised(t, launcherTestContainer, launcherRegistrationToken)
	require.True(t, suite.waitForNewStewardLogEntry(t, launcherTestContainer, sessionsBefore, 60*time.Second, stewardSessionMarkers...),
		"launcher-supervised steward must open a new control session within 60 s")

	// The launcher sets CFGMS_STEWARD_LAUNCHER_MANAGED=1 on its child automatically
	// (see lifecycle.go:execOnce); we just wait for the steward to reconnect.
	require.True(t, suite.waitForConvergence(t, stewardID, 60*time.Second),
		"launcher-supervised steward must reconnect within 60 s using same identity")
	requireNoBareSteward(t, launcherTestContainer)
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
	sessionsBeforeUpgrade := suite.stewardLogCount(t, launcherTestContainer, stewardSessionMarkers...)
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
	if !waitForLauncherCurrentVersion(t, launcherTestContainer, launcherHappyVersion, 30*time.Second) {
		t.Fatalf("launcher state.json must point at %s after committed\n%s",
			launcherHappyVersion, suite.launcherDiagnostics(t, launcherTestContainer))
	}

	// The swap alone rewrites state.json, so it does not prove the re-exec: the
	// steward must exit and the launcher must start the new binary, which opens a
	// new control session (Issue #4680).
	if !suite.waitForNewStewardLogEntry(t, launcherTestContainer, sessionsBeforeUpgrade, 90*time.Second, stewardSessionMarkers...) {
		t.Fatalf("launcher must re-exec the steward (a new control session) after the swap\n%s",
			suite.launcherDiagnostics(t, launcherTestContainer))
	}

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

	// The controller keeps the killed process's connection_state=connected until it
	// notices the drop, so convergence alone would let the upgrade be sent to the
	// dead stream. Wait for the launcher-supervised steward's own new session first
	// (Issue #4671).
	sessionsBefore := suite.stewardLogCount(t, launcherTestContainer, stewardSessionMarkers...)
	killBareSteward(t, launcherTestContainer)
	installLauncherLayout(t, launcherTestContainer, launcherInitialVersion)
	startLauncherSupervised(t, launcherTestContainer, launcherRegistrationToken)
	require.True(t, suite.waitForNewStewardLogEntry(t, launcherTestContainer, sessionsBefore, 60*time.Second, stewardSessionMarkers...),
		"launcher-supervised steward must open a new control session within 60 s")

	require.True(t, suite.waitForConvergence(t, stewardID, 60*time.Second),
		"launcher-supervised steward must connect within 60 s")
	requireNoBareSteward(t, launcherTestContainer)
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
	if !waitForLauncherCurrentVersion(t, launcherTestContainer, launcherInitialVersion, 30*time.Second) {
		t.Fatalf("launcher state.json must roll back to %s after broken binary exits within startup window\n%s",
			launcherInitialVersion, suite.launcherDiagnostics(t, launcherTestContainer))
	}
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
