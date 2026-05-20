// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestDriftAutoCorrection verifies that apply mode (the fleet default) auto-corrects drift.
//
// Flow:
//  1. Set up the suite and upload fleet-config.yaml to fleet-steward-1.
//  2. Wait until managed-file is present (config applied).
//  3. Corrupt managed-file via docker exec.
//  4. Wait up to 90 seconds for the steward to detect and correct the drift.
//  5. Verify the file content is restored to "fleet-managed-content\n" (final_state).
//  6. Assert the steward's convergence report records the drift event
//     (drift_detected), apply mode (drift_setting), and the correction
//     (convergence_result).
func TestDriftAutoCorrection(t *testing.T) {
	if os.Getenv("CFGMS_FLEET_TEST") != "1" {
		t.Skip("Fleet E2E tests require CFGMS_FLEET_TEST=1 (run via: make test-e2e-fleet)")
	}

	suite := setupFleetSuite(t)
	container := "fleet-steward-1"
	stewardID := suite.stewardIDs[container]

	if !suite.waitForConvergence(t, stewardID, 60*time.Second) {
		t.Fatalf("steward %s not connected before drift test", stewardID)
	}

	// Upload config so the managed-file resource is declared.
	if err := suite.uploadConfig(t, stewardID, "configs/fleet-config.yaml"); err != nil {
		t.Fatalf("upload config before drift test: %v", err)
	}

	// Wait for the file to appear (steward applies the config).
	if !suite.waitForManagedFile(t, container, 60*time.Second) {
		t.Fatalf("managed-file did not appear within 60s after config upload")
	}

	// Snapshot how many drift-detected entries the steward log already has for
	// managed-file (the initial config apply logs one). The post-correction count
	// must exceed this baseline, proving the *injected* drift was detected — not
	// just the initial resource creation.
	baselineLog, err := suite.readStewardLog(t, container)
	if err != nil {
		t.Fatalf("read steward log baseline: %v", err)
	}
	driftBaseline := countLogLinesWith(baselineLog, "drift detected", "managed-file")

	// Inject drift by overwriting the file with unexpected content.
	if _, err := suite.dockerExec(t, container, "sh", "-c",
		`echo "drift-injected-content" > /test-workspace/managed-file`); err != nil {
		t.Fatalf("inject drift: %v", err)
	}
	t.Log("Drift injected: managed-file overwritten with unexpected content")

	// Confirm the write was visible (fail fast if docker exec itself errored).
	got, err := suite.dockerExec(t, container, "cat", "/test-workspace/managed-file")
	if err != nil {
		t.Fatalf("verify drift injection: %v", err)
	}
	// The apply-mode convergence loop may correct drift quickly; log what we observe.
	t.Logf("File content immediately after drift injection: %q", strings.TrimSpace(got))

	// Wait for apply-mode convergence loop to detect and correct the drift.
	corrected := false
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		content, err := suite.dockerExec(t, container, "cat", "/test-workspace/managed-file")
		if err == nil && content == "fleet-managed-content\n" {
			corrected = true
			t.Log("Drift corrected: managed-file restored to expected content")
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !corrected {
		finalContent, _ := suite.dockerExec(t, container, "cat", "/test-workspace/managed-file")
		t.Errorf("Drift not corrected within 90s; file content: %q", finalContent)
	}

	// Assert the steward's own convergence report records the drift cycle.
	// The steward exposes no HTTP status endpoint, so its structured log file
	// is the authoritative upstream report — the same convergence outcome is
	// published to the controller as an EventConfigApplied event.
	logContent, err := suite.readStewardLog(t, container)
	if err != nil {
		t.Fatalf("read steward log for drift report: %v", err)
	}
	assertDriftReport(t, logContent, driftBaseline)
}

// assertDriftReport verifies the steward convergence log records the facts
// AC8 requires for a drift cycle:
//   - drift_detected: a NEW drift event (beyond driftBaseline) was logged for
//     the managed-file resource — i.e. the injected drift, not the initial apply.
//   - drift_setting: apply mode is in effect (no monitor-mode skip was logged).
//   - convergence_result: the drift was corrected by re-applying the resource.
//
// final_state is asserted separately above via the restored file content.
func assertDriftReport(t *testing.T, log string, driftBaseline int) {
	t.Helper()

	// drift_detected — the Compare step logged a drift event for managed-file
	// after the injection (count must exceed the pre-injection baseline).
	driftCount := countLogLinesWith(log, "drift detected", "managed-file")
	if driftCount <= driftBaseline {
		t.Errorf("drift report: no new drift-detected entry for managed-file (count %d, baseline %d)",
			driftCount, driftBaseline)
	}

	// drift_setting — apply mode auto-corrects; it must NOT log the monitor-mode
	// skip. Its presence would mean the steward was running drift_setting=monitor.
	if strings.Contains(strings.ToLower(log), "monitor mode: drift detected, skipping set") {
		t.Errorf("drift report: steward logged a monitor-mode skip; expected drift_setting=apply")
	}

	// convergence_result — the drifted resource was successfully re-applied.
	if countLogLinesWith(log, "applied successfully", "managed-file") == 0 {
		t.Errorf("drift report: no successful re-apply entry for managed-file in steward log")
	}
}

// countLogLinesWith returns the number of log lines that contain every
// case-insensitive substring in substrs.
func countLogLinesWith(log string, substrs ...string) int {
	count := 0
	for _, line := range strings.Split(log, "\n") {
		lower := strings.ToLower(line)
		matched := true
		for _, sub := range substrs {
			if !strings.Contains(lower, strings.ToLower(sub)) {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}
	return count
}
