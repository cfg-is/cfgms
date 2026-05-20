// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package fleet

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// testVanillaState verifies both stewards are connected before any config is applied.
// The /test-workspace tmpfs is empty at container start, so managed resources should not exist.
func (s *FleetTestSuite) testVanillaState(t *testing.T) {
	t.Helper()

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Errorf("steward %s (%s) not connected in vanilla state", container, stewardID)
		}
	}
	t.Log("VanillaState: both stewards connected, baseline established")
}

// testConfigUploadAndConvergence uploads fleet-config.yaml to both stewards and verifies
// all three module resources (file, directory, script) are applied within 60 seconds.
func (s *FleetTestSuite) testConfigUploadAndConvergence(t *testing.T, configPath string) {
	t.Helper()

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if err := s.uploadConfig(t, stewardID, configPath); err != nil {
			t.Fatalf("upload config to %s: %v", container, err)
		}
	}

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]

		if !s.waitForConvergence(t, stewardID, 60*time.Second) {
			t.Errorf("steward %s (%s) did not converge after config upload", container, stewardID)
			continue
		}

		// Poll until all resources appear (controller→steward push may take a few seconds).
		if !s.waitForManagedFile(t, container, 60*time.Second) {
			t.Errorf("%s: managed-file did not appear within 60s", container)
		} else {
			s.verifyManagedFile(t, container)
		}

		s.verifyManagedDir(t, container)
		s.verifyScriptOutput(t, container)
	}
}

// testIdempotentReUpload re-uploads the same config and verifies resources remain correct.
func (s *FleetTestSuite) testIdempotentReUpload(t *testing.T, configPath string) {
	t.Helper()

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if err := s.uploadConfig(t, stewardID, configPath); err != nil {
			t.Fatalf("re-upload config to %s: %v", container, err)
		}
	}

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Errorf("steward %s (%s) disconnected after idempotent re-upload", container, stewardID)
			continue
		}
		s.verifyManagedFile(t, container)
		s.verifyManagedDir(t, container)
	}
	t.Log("IdempotentReUpload: resources unchanged after second upload")
}

// testPerModuleConvergence verifies each module type individually on fleet-steward-1.
func (s *FleetTestSuite) testPerModuleConvergence(t *testing.T) {
	t.Helper()

	container := "fleet-steward-1"
	t.Run("FileModule", func(t *testing.T) { s.verifyManagedFile(t, container) })
	t.Run("DirectoryModule", func(t *testing.T) { s.verifyManagedDir(t, container) })
	t.Run("ScriptModule", func(t *testing.T) { s.verifyScriptOutput(t, container) })
}

// testControllerRestart restarts fleet-controller, waits for stewards to reconnect,
// re-uploads configs (controller loses in-memory state on restart), and verifies convergence.
func (s *FleetTestSuite) testControllerRestart(t *testing.T, configPath string) {
	t.Helper()

	s.containerRestart(t, "fleet-controller", 60*time.Second)

	// Rebuild HTTP clients — the admin bundle is regenerated on every controller init.
	if err := s.rebuildClients(t); err != nil {
		t.Fatalf("rebuild clients after controller restart: %v", err)
	}

	// Re-upload configs; the controller does not persist config across restarts
	// (fleet-controller has no data volume in docker-compose.test.yml).
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if err := s.uploadConfig(t, stewardID, configPath); err != nil {
			t.Fatalf("re-upload config to %s after controller restart: %v", container, err)
		}
	}

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 90*time.Second) {
			t.Errorf("steward %s (%s) did not reconnect after controller restart", container, stewardID)
			continue
		}
		s.verifyManagedFile(t, container)
		s.verifyManagedDir(t, container)
	}
	t.Log("ControllerRestart: both stewards reconnected and converged")
}

// testStewardRestart restarts fleet-steward-1, discovers its (possibly new) steward ID,
// re-uploads config, and verifies the apply-mode steward re-applies resources on reconnect.
func (s *FleetTestSuite) testStewardRestart(t *testing.T, configPath string) {
	t.Helper()

	container := "fleet-steward-1"
	oldID := s.stewardIDs[container]

	s.containerRestart(t, container, 60*time.Second)

	// The steward may re-register with a new ID after restart.
	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("steward ID not found after %s restart: %v", container, err)
	}
	s.stewardIDs[container] = newID
	if newID != oldID {
		t.Logf("Steward re-registered: %s → %s", oldID, newID)
	}

	if err := s.uploadConfig(t, newID, configPath); err != nil {
		t.Fatalf("upload config to %s after restart: %v", container, err)
	}

	if !s.waitForConvergence(t, newID, 90*time.Second) {
		t.Fatalf("steward %s (%s) did not reconnect after restart", container, newID)
	}

	if !s.waitForManagedFile(t, container, 60*time.Second) {
		t.Errorf("%s: managed-file did not appear after restart", container)
	} else {
		s.verifyManagedFile(t, container)
	}
	s.verifyManagedDir(t, container)
	t.Logf("StewardRestart: %s reconnected and converged (steward ID: %s)", container, newID)
}

// testDeferredConfig uploads a config for fleet-steward-2 and verifies the controller
// stores it and the steward applies it — confirming config delivery works end-to-end
// for a steward that may have just become available.
func (s *FleetTestSuite) testDeferredConfig(t *testing.T, configPath string) {
	t.Helper()

	container := "fleet-steward-2"
	stewardID := s.stewardIDs[container]

	if err := s.uploadConfig(t, stewardID, configPath); err != nil {
		t.Fatalf("deferred config upload to %s: %v", container, err)
	}

	if !s.waitForConvergence(t, stewardID, 60*time.Second) {
		t.Errorf("steward %s (%s) did not converge after deferred config", container, stewardID)
		return
	}

	s.verifyManagedFile(t, container)
	s.verifyManagedDir(t, container)
	t.Logf("DeferredConfig: %s applied config (steward ID: %s)", container, stewardID)
}

// --- shared resource verification helpers ---

// waitForManagedFile polls until /test-workspace/managed-file exists or timeout expires.
func (s *FleetTestSuite) waitForManagedFile(t *testing.T, container string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := s.dockerExec(t, container, "test", "-f", "/test-workspace/managed-file"); err == nil {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// verifyManagedFile checks /test-workspace/managed-file content and permissions.
func (s *FleetTestSuite) verifyManagedFile(t *testing.T, container string) {
	t.Helper()

	content, err := s.dockerExec(t, container, "cat", "/test-workspace/managed-file")
	if err != nil {
		t.Errorf("%s: managed-file not readable: %v", container, err)
		return
	}
	if content != "fleet-managed-content\n" {
		t.Errorf("%s: managed-file content = %q, want %q", container, content, "fleet-managed-content\n")
	}

	perms, err := s.dockerExec(t, container, "stat", "-c", "%a", "/test-workspace/managed-file")
	if err != nil {
		t.Errorf("%s: stat managed-file: %v", container, err)
		return
	}
	if got := strings.TrimSpace(perms); got != "644" {
		t.Errorf("%s: managed-file perms = %s, want 644", container, got)
	}
	t.Logf("%s: managed-file verified (content: %d bytes, perms: %s)", container, len(content), strings.TrimSpace(perms))
}

// verifyManagedDir checks /test-workspace/managed-dir existence and permissions.
func (s *FleetTestSuite) verifyManagedDir(t *testing.T, container string) {
	t.Helper()

	if _, err := s.dockerExec(t, container, "test", "-d", "/test-workspace/managed-dir"); err != nil {
		t.Errorf("%s: managed-dir does not exist: %v", container, err)
		return
	}

	perms, err := s.dockerExec(t, container, "stat", "-c", "%a", "/test-workspace/managed-dir")
	if err != nil {
		t.Errorf("%s: stat managed-dir: %v", container, err)
		return
	}
	if got := strings.TrimSpace(perms); got != "755" {
		t.Errorf("%s: managed-dir perms = %s, want 755", container, got)
	}
	t.Logf("%s: managed-dir verified (perms: %s)", container, strings.TrimSpace(perms))
}

// verifyScriptOutput checks that the script module wrote /test-workspace/script-output.txt.
func (s *FleetTestSuite) verifyScriptOutput(t *testing.T, container string) {
	t.Helper()

	content, err := s.dockerExec(t, container, "cat", "/test-workspace/script-output.txt")
	if err != nil {
		t.Errorf("%s: script-output.txt not found: %v", container, err)
		return
	}
	if !strings.Contains(content, "fleet-script-executed") {
		t.Errorf("%s: script-output.txt = %q, want to contain %q", container, content, "fleet-script-executed")
	}
	t.Logf("%s: script-output.txt verified: %s", container, fmt.Sprintf("%q", strings.TrimSpace(content)))
}
