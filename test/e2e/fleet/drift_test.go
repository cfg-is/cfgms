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
//  5. Verify the file content is restored to "fleet-managed-content\n".
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
}
