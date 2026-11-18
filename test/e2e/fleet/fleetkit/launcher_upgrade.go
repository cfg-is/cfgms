// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Launcher-supervised upgrade E2E tests: validate the auto-apply chain
// (staged binary → self-exit → launcher re-exec → reconnect on new version)
// under a launcher-managed steward, plus the broken-binary startup-window
// auto-rollback variant. (Issue #2005)
package fleetkit

import (
	"context"
	"encoding/json"
	"fmt"
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

	// LauncherInitialVersion is the version label assigned to /app/steward when
	// staging the launcher layout. Matches the compile-time version.Version default.
	LauncherInitialVersion = "v0.5.0-dev"

	// LauncherHappyVersion is the version label published for the happy-path upgrade.
	// Must be strictly higher than LauncherInitialVersion (0.6 > 0.5).
	LauncherHappyVersion = "v0.6.0-launchtest"

	// LauncherBrokenVersion is the version label for the broken-binary rollback test.
	// Must be strictly higher than LauncherInitialVersion (0.6.1 > 0.5).
	LauncherBrokenVersion = "v0.6.1-launchtest-broken"

	// LauncherRegistrationToken is the token for fleet-steward-1 (from docker-compose).
	LauncherRegistrationToken = "dockertest_fleet_child_a"

	// LauncherTestContainer is the fleet container that gets reconfigured to use the
	// launcher. fleet-steward-1 is used because it belongs to fleet-child-a, whose
	// tenant scoping matches UpgradeAPIKey.
	LauncherTestContainer = "fleet-steward-1"

	// LauncherUpgradeWindow is the poll window for launcher-managed upgrade status.
	// The real steward binary is ~30 MB; in-container download takes longer than the
	// 35 s used for fake-payload bare-steward tests. (Issue #2005 AC4)
	LauncherUpgradeWindow = 90 * time.Second
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

// ContainerShell runs script in container as root and returns its combined output.
// Process patterns inside script must not match the script's own command line
// (use pkill -x, or the [c]haracter-class idiom with -f): pkill -f with a plain
// pattern kills the shell running the script and silently skips everything after.
func ContainerShell(container, script string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- docker/tar are fixed binaries; arguments are test-controlled fleet container names and paths, never external input
	out, err := exec.CommandContext(ctx, "docker", "exec", "--user", "root", container,
		"sh", "-c", script).CombinedOutput()
	return string(out), err
}

// KillBareSteward holds the container's bare-steward wrapper and kills the bare
// steward, then requires that no bare steward is left running. A steward the
// wrapper was just starting when the hold appeared is caught by the retry.
func KillBareSteward(t *testing.T, container string) {
	t.Helper()
	script := "touch " + bareHoldFile + "; " +
		"for i in $(seq 1 20); do " +
		"pkill -9 -x steward; sleep 0.5; " +
		"if ! pgrep -x steward >/dev/null; then sleep 1; pgrep -x steward >/dev/null || exit 0; fi; " +
		"done; exit 1"
	out, err := ContainerShell(container, script, 30*time.Second)
	require.NoError(t, err, "bare steward in %s must stay stopped once held: %s", container, out)
}

// RequireNoBareSteward fails the test if a bare (non-launcher) steward is running
// in container, so a command can only reach the launcher-supervised steward.
func RequireNoBareSteward(t *testing.T, container string) {
	t.Helper()
	out, err := ContainerShell(container, "pgrep -a -x steward; true", 10*time.Second)
	require.NoError(t, err)
	require.Empty(t, strings.TrimSpace(out), "no bare steward may run beside the launcher's in %s", container)
}

// InstallLauncherLayout creates the launcher's versioned binary tree under
// launcherRoot in container for initialVersion and writes the initial state.json.
//
//	/opt/cfgms/versions/<initialVersion>/cfgms-steward  ← copy of /app/steward
//	/opt/cfgms/state.json                              ← {"current":"<initialVersion>"}
//
// The entire versions tree is chowned to cfgms so the launcher (running as cfgms)
// can create sub-directories when staging subsequent upgrade versions.
func InstallLauncherLayout(t *testing.T, container, initialVersion string) {
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
	DockerExecRoot(t, container, "sh", "-c", script)
}

// StartLauncherSupervised starts cfgms-steward-launcher run in the background
// inside container as the cfgms user, with its output in launcherLogPath. The
// launcher supervises from launcherRoot and forwards --child-args to the
// supervised steward.
func StartLauncherSupervised(t *testing.T, container, regtoken string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// The token goes into a 0600 file owned by the user that runs the steward;
	// the launcher forwards only the file path.
	const tokenFile = "/tmp/regtoken"
	cmd := fmt.Sprintf("umask 077; printf %%s '%s' > %s && exec %s run --root %s --child-args '--regtoken-file %s' >>%s 2>&1",
		regtoken, tokenFile, launcherBin, launcherRoot, tokenFile, launcherLogPath)
	// #nosec G204 -- docker/tar are fixed binaries; arguments are test-controlled fleet container names and paths, never external input
	out, err := exec.CommandContext(ctx, "docker", "exec",
		"-d", "--user", "cfgms",
		container,
		"sh", "-c", cmd,
	).CombinedOutput()
	require.NoError(t, err, "start launcher in %s failed: %s", container, string(out))
	t.Logf("Launcher started in %s (detached, log %s)", container, launcherLogPath)
}

// LauncherDiagnostics returns the launcher's log tail, the steward's log tail and
// the container's steward processes, for a failed launcher assertion.
func (s *FleetTestSuite) LauncherDiagnostics(t *testing.T, container string) string {
	t.Helper()
	launcherLog, _ := ContainerShell(container, "tail -n 60 "+launcherLogPath+" 2>&1", 10*time.Second)
	procs, _ := ContainerShell(container, "pgrep -a -f '[s]teward'; true", 10*time.Second)
	stewardLog, _ := s.ReadStewardLog(t, container)
	return fmt.Sprintf("launcher log tail:\n%s\nsteward processes:\n%s\nsteward log tail:\n%s",
		launcherLog, procs, LastLines(stewardLog, 60))
}

// GetLauncherCurrentVersion reads the launcher's state.json and returns the
// current version field. Returns "" on any error (file missing, invalid JSON).
func GetLauncherCurrentVersion(t *testing.T, container string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 -- docker/tar are fixed binaries; arguments are test-controlled fleet container names and paths, never external input
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

// WaitForLauncherCurrentVersion polls state.json until its current field equals
// wantVersion or the timeout expires.
func WaitForLauncherCurrentVersion(t *testing.T, container, wantVersion string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if got := GetLauncherCurrentVersion(t, container); got == wantVersion {
			t.Logf("Launcher state: current=%q confirmed in %s", wantVersion, container)
			return true
		}
		time.Sleep(3 * time.Second)
	}
	t.Logf("Launcher state: current never reached %q in %s within %v",
		wantVersion, container, timeout)
	return false
}

// RestoreBareStewdInContainer returns container to its docker-compose baseline:
// it kills the launcher and its supervised steward, empties launcherRoot (the
// image ships it empty, and a later test must not inherit launcher version state),
// and releases the hold so the PID 1 wrapper restarts the one bare steward. It
// returns an error when the baseline was not restored.
func RestoreBareStewdInContainer(t *testing.T, container string) error {
	t.Helper()
	script := "pkill -9 -f '[c]fgms-launcher'; pkill -9 -f '[c]fgms-steward'; " +
		"for i in $(seq 1 20); do pgrep -f '[c]fgms-launcher|[c]fgms-steward' >/dev/null || break; sleep 0.5; done; " +
		"find " + launcherRoot + " -mindepth 1 -delete; " +
		"rm -f " + bareHoldFile + "; " +
		"for i in $(seq 1 30); do pgrep -x steward >/dev/null && exit 0; sleep 0.5; done; exit 1"
	if out, err := ContainerShell(container, script, 30*time.Second); err != nil {
		return fmt.Errorf("restore bare steward in %s: %w (output: %s)", container, err, out)
	}
	t.Logf("Restored bare steward in %s", container)
	return nil
}

// Waits that prove the restored bare steward is back on the controller. They are
// the cleanup's own bounds, so a launcher test that left the fleet without a
// working steward session fails here, at its own cleanup.
const (
	restoredSessionWindow = 60 * time.Second
	restoredConnectWindow = 30 * time.Second
)

// RestoreBareSteward returns container to the compose baseline (see
// RestoreBareStewdInContainer) and then requires the restored bare steward to
// open a new control session and the controller to report stewardID connected.
// A launcher test's cleanup used to return as soon as the bare steward process
// existed, so a steward the controller never saw reconnect was inherited by the
// next test and surfaced there as an unrelated timeout. A failure here is
// reported as a test error with the controller's view of the session.
func (s *FleetTestSuite) RestoreBareSteward(t *testing.T, container, stewardID string) {
	t.Helper()
	sessionsBefore := s.StewardLogCount(t, container, StewardSessionMarkers...)
	if err := RestoreBareStewdInContainer(t, container); err != nil {
		t.Errorf("cleanup: %v\n%s", err, s.LauncherDiagnostics(t, container))
		return
	}
	if !s.WaitForNewStewardLogEntry(t, container, sessionsBefore, restoredSessionWindow, StewardSessionMarkers...) {
		t.Errorf("cleanup: restored bare steward in %s did not open a new control session within %v\n%s\n%s",
			container, restoredSessionWindow, s.ControllerStallDiagnostics(stewardID), s.LauncherDiagnostics(t, container))
		return
	}
	if !s.WaitForConvergence(t, stewardID, restoredConnectWindow) {
		t.Errorf("cleanup: controller did not report restored bare steward %s in %s connected within %v\n%s\n%s",
			stewardID, container, restoredConnectWindow, s.ControllerStallDiagnostics(stewardID), s.LauncherDiagnostics(t, container))
	}
}

// RequireLauncherSession fails the calling test when the launcher-supervised
// steward in container does not log a new control session (marker count above
// before) within 60 s of the swap, with the launcher, steward and controller
// state that explains it.
func (s *FleetTestSuite) RequireLauncherSession(t *testing.T, container, stewardID string, before int) {
	t.Helper()
	const window = 60 * time.Second
	if s.WaitForNewStewardLogEntry(t, container, before, window, StewardSessionMarkers...) {
		return
	}
	t.Fatalf("launcher-supervised steward in %s must open a new control session within %v\n%s\n%s",
		container, window, s.LauncherDiagnostics(t, container), s.ControllerStallDiagnostics(stewardID))
}
