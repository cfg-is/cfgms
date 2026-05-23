// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"strings"
	"testing"
	"time"
)

// testDriftAutoCorrection verifies that apply mode (the fleet default) auto-corrects drift.
//
// It runs as the final TestFleetWalkthrough scenario — a standalone top-level
// test would execute before the walkthrough (source-file order) and leave
// managed resources behind, breaking the walkthrough's VanillaState assertion.
//
// Flow:
//  1. Upload fleet-config.yaml to fleet-steward-1 and wait until managed-file is present.
//  2. Corrupt managed-file via docker exec.
//  3. Wait up to 90 seconds for the steward to detect and correct the drift.
//  4. Verify the file content is restored to "fleet-managed-content\n" (final_state).
//  5. Assert the steward's convergence report records the drift event
//     (drift_detected), apply mode (drift_setting), and the correction
//     (convergence_result).
func (s *FleetTestSuite) testDriftAutoCorrection(t *testing.T, configPath string) {
	t.Helper()

	container := "fleet-steward-1"
	stewardID := s.stewardIDs[container]

	if !s.waitForConvergence(t, stewardID, 60*time.Second) {
		t.Fatalf("steward %s not connected before drift test", stewardID)
	}

	// Upload config so the managed-file resource is declared.
	if err := s.uploadConfig(t, stewardID, configPath); err != nil {
		t.Fatalf("upload config before drift test: %v", err)
	}

	// Wait for the file to appear (steward applies the config).
	if !s.waitForManagedFile(t, container, 60*time.Second) {
		t.Fatalf("managed-file did not appear within 60s after config upload")
	}

	// Snapshot how many drift-detected entries the steward log already has for
	// managed-file (the initial config apply logs one). The post-correction count
	// must exceed this baseline, proving the *injected* drift was detected — not
	// just the initial resource creation.
	baselineLog, err := s.readStewardLog(t, container)
	if err != nil {
		t.Fatalf("read steward log baseline: %v", err)
	}
	driftBaseline := countLogLinesWith(baselineLog, "drift detected", "managed-file")

	// Inject drift by overwriting the file with unexpected content.
	if _, err := s.dockerExec(t, container, "sh", "-c",
		`echo "drift-injected-content" > /test-workspace/managed-file`); err != nil {
		t.Fatalf("inject drift: %v", err)
	}
	t.Log("Drift injected: managed-file overwritten with unexpected content")

	// Confirm the write was visible (fail fast if docker exec itself errored).
	got, err := s.dockerExec(t, container, "cat", "/test-workspace/managed-file")
	if err != nil {
		t.Fatalf("verify drift injection: %v", err)
	}
	// The apply-mode convergence loop may correct drift quickly; log what we observe.
	t.Logf("File content immediately after drift injection: %q", strings.TrimSpace(got))

	// Wait for apply-mode convergence loop to detect and correct the drift.
	corrected := false
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		content, err := s.dockerExec(t, container, "cat", "/test-workspace/managed-file")
		if err == nil && content == "fleet-managed-content\n" {
			corrected = true
			t.Log("Drift corrected: managed-file restored to expected content")
			break
		}
		time.Sleep(2 * time.Second)
	}

	if !corrected {
		finalContent, _ := s.dockerExec(t, container, "cat", "/test-workspace/managed-file")
		t.Errorf("Drift not corrected within 90s; file content: %q", finalContent)
	}

	// Assert the steward's own convergence report records the drift cycle.
	// The steward exposes no HTTP status endpoint, so its structured log file
	// is the authoritative upstream report — the same convergence outcome is
	// published to the controller as an EventConfigApplied event.
	//
	// Poll for up to 15 s while the buffered file logger flushes the
	// drift-correction entries. The steward's file logger flushes every 5 s,
	// so a convergence run that completes just after a flush will not be
	// observable on disk until the next flush tick.
	var logContent string
	flushDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(flushDeadline) {
		var readErr error
		logContent, readErr = s.readStewardLog(t, container)
		if readErr == nil &&
			countLogLinesWith(logContent, "drift detected", "managed-file") > driftBaseline {
			break
		}
		time.Sleep(1 * time.Second)
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
