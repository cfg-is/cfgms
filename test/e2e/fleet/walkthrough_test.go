// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// testVanillaState verifies both stewards are connected before any config is applied
// and asserts that no managed resources exist yet — the /test-workspace tmpfs is
// empty at container start, so managed-file, managed-dir, and script-output.txt
// must all be absent until a config is uploaded.
func (s *FleetTestSuite) testVanillaState(t *testing.T) {
	t.Helper()

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Errorf("steward %s (%s) not connected in vanilla state", container, stewardID)
		}
		s.assertNoManagedResources(t, container)
	}
	t.Log("VanillaState: both stewards connected with no managed resources")
}

// assertNoManagedResources fails if any managed resource path exists in the container.
func (s *FleetTestSuite) assertNoManagedResources(t *testing.T, container string) {
	t.Helper()
	for _, path := range []string{
		"/test-workspace/managed-file",
		"/test-workspace/managed-dir",
		"/test-workspace/script-output.txt",
	} {
		// `test -e` exits non-zero (dockerExec returns an error) when the path
		// is absent — which is the expected vanilla state.
		if _, err := s.dockerExec(t, container, "test", "-e", path); err == nil {
			t.Errorf("%s: %s exists before config upload — expected vanilla state with no managed resources", container, path)
		}
	}
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

// testPerModuleConvergence verifies each module type individually on both stewards.
func (s *FleetTestSuite) testPerModuleConvergence(t *testing.T) {
	t.Helper()

	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		container := container
		t.Run(container, func(t *testing.T) {
			t.Run("FileModule", func(t *testing.T) { s.verifyManagedFile(t, container) })
			t.Run("DirectoryModule", func(t *testing.T) { s.verifyManagedDir(t, container) })
			t.Run("ScriptModule", func(t *testing.T) { s.verifyScriptOutput(t, container) })
		})
	}
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

	// AC6: the steward must reuse its stored cert and reconnect with the SAME ID.
	// A docker restart preserves the container's writable layer (where the cert
	// lives), so re-registration with a new ID indicates the stored-cert reuse
	// path is broken.
	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("steward ID not found after %s restart: %v", container, err)
	}
	if newID != oldID {
		t.Errorf("steward %s re-registered after restart: %s → %s; expected stored-cert reuse (no re-registration)",
			container, oldID, newID)
	}
	s.stewardIDs[container] = newID

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

// testDeferredConfig stops fleet-steward-2, uploads a config while it is offline,
// then restarts it and verifies the controller-stored config is delivered and
// applied on reconnect. The config upload cannot reach the steward live — it must
// be deferred by the controller until the steward comes back online.
func (s *FleetTestSuite) testDeferredConfig(t *testing.T, configPath string) {
	t.Helper()

	container := "fleet-steward-2"
	stewardID := s.stewardIDs[container]

	// Take steward-2 offline before uploading so the config cannot be delivered live.
	s.containerStop(t, container)

	// Upload while steward-2 is offline — the controller must store the config and
	// hold it for delivery when the steward reconnects.
	if err := s.uploadConfig(t, stewardID, configPath); err != nil {
		// Restart before failing so later scenarios are not left with a dead container.
		s.containerStart(t, container, 90*time.Second)
		t.Fatalf("deferred config upload to %s while offline: %v", container, err)
	}
	t.Logf("DeferredConfig: config uploaded for %s while it was offline", container)

	// Bring steward-2 back online. Its /test-workspace tmpfs is recreated empty,
	// so any managed resources that appear are proof the deferred config was applied.
	s.containerStart(t, container, 90*time.Second)

	// The stored cert survives docker stop/start, so the ID must be unchanged.
	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("steward ID not found after %s restart: %v", container, err)
	}
	if newID != stewardID {
		t.Errorf("steward %s re-registered after restart: %s → %s; expected stored-cert reuse",
			container, stewardID, newID)
	}
	s.stewardIDs[container] = newID

	if !s.waitForConvergence(t, newID, 90*time.Second) {
		t.Fatalf("steward %s (%s) did not reconnect after coming back online", container, newID)
	}

	// The deferred config must now be applied even though it was uploaded offline.
	if !s.waitForManagedFile(t, container, 60*time.Second) {
		t.Errorf("%s: deferred config not applied — managed-file absent after restart", container)
	} else {
		s.verifyManagedFile(t, container)
	}
	s.verifyManagedDir(t, container)
	t.Logf("DeferredConfig: %s applied config uploaded while offline (steward ID: %s)", container, newID)
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
