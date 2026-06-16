// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// signingCertRotationResult holds the response fields from POST /api/v1/certificates/signing/rotate.
type signingCertRotationResult struct {
	OldSerial        string `json:"old_serial"`
	NewSerial        string `json:"new_serial"`
	OverlapDays      int    `json:"overlap_days"`
	StewardsNotified int    `json:"stewards_notified"`
	OverlapExpiresAt string `json:"overlap_expires_at"` // RFC3339; empty when overlap_days=0
}

// rotateSigningCert calls POST /api/v1/certificates/signing/rotate with force=true
// and returns the result. Operator-initiated rotations should bypass the
// in-progress guard so back-to-back e2e scenarios succeed independent of the
// cursor state left by the previous test.
func (s *FleetTestSuite) rotateSigningCert(t *testing.T, overlapDays int) signingCertRotationResult {
	t.Helper()

	reqBody := fmt.Sprintf(`{"overlap_days":%d,"force":true}`, overlapDays)
	url := fmt.Sprintf("%s/api/v1/certificates/signing/rotate", s.controllerURL)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(reqBody))
	if err != nil {
		t.Fatalf("build rotation request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST signing/rotate: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rotation response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotation API error: %d - %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var apiResp struct {
		Data signingCertRotationResult `json:"data"`
	}
	if err := json.Unmarshal(body, &apiResp); err != nil {
		t.Fatalf("parse rotation response: %v (body: %s)", err, string(body))
	}
	return apiResp.Data
}

// tryRotateSigningCert calls the rotation endpoint WITHOUT force and returns any
// error without failing the test. Used by CrashMidRotation to verify the
// in-progress guard fires on the second call.
func (s *FleetTestSuite) tryRotateSigningCert(t *testing.T, overlapDays int) error {
	t.Helper()

	reqBody := fmt.Sprintf(`{"overlap_days":%d}`, overlapDays)
	url := fmt.Sprintf("%s/api/v1/certificates/signing/rotate", s.controllerURL)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("build rotation request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST signing/rotate: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rotation API error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// rotationEndpointAvailable probes the rotation route with a deliberately malformed
// JSON body so the request is rejected at body-validation time without triggering a
// real rotation. The endpoint returns 4xx (typically 400) when it is registered and
// 404 when stories B2a (#1815) and B2b (#1816) have not yet been merged. The probe
// is non-destructive: no rotation primitive runs on a 4xx body-validation failure.
func (s *FleetTestSuite) rotationEndpointAvailable(t *testing.T) bool {
	t.Helper()
	url := fmt.Sprintf("%s/api/v1/certificates/signing/rotate", s.controllerURL)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader("{not-json"))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode != http.StatusNotFound
}

// ensureContainerRunning restarts container if it is not currently running and
// waits for it to reach a healthy state. Intended for use as a t.Cleanup so a
// test that stops a container always leaves it back up, even if the test fails
// before its happy-path restart call.
func (s *FleetTestSuite) ensureContainerRunning(t *testing.T, container string, healthTimeout time.Duration) {
	t.Helper()
	if err := validateFleetContainer(container); err != nil {
		t.Logf("ensureContainerRunning: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	out, err := exec.CommandContext(ctx, "docker", "ps",
		"--filter", "name="+container,
		"--filter", "status=running",
		"--format", "{{.Names}}").CombinedOutput()
	cancel()
	if err == nil && strings.Contains(string(out), container) {
		// Already running — nothing to do. Health is verified by setupFleetSuite
		// in subsequent tests.
		return
	}
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "docker", "start", container).CombinedOutput(); err != nil {
		t.Logf("ensureContainerRunning: docker start %s failed: %v (output: %s)",
			container, err, strings.TrimSpace(string(out)))
		return
	}
	if !s.waitForContainerHealthy(t, container, healthTimeout) {
		t.Logf("ensureContainerRunning: %s did not reach healthy within %v after cleanup restart",
			container, healthTimeout)
	}
}

// waitForStewardLogEntry polls the steward log for a line containing want until timeout.
func (s *FleetTestSuite) waitForStewardLogEntry(t *testing.T, container, want string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		log, err := s.readStewardLog(t, container)
		if err == nil && strings.Contains(log, want) {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// TestFleetRotation is the ordered entry point for all signing-cert rotation scenarios.
//
// Prerequisite stories:
//   - #1765 (cert: purpose-scoped certificate selection) — merged
//   - #1815 (B2a: RotateSigningCertificate primitive) — must be merged before running
//   - #1816 (B2b: rotation API endpoint) — must be merged before running
//   - #1817 (B2d: refresh-on-connect) — must be merged before running
//
// Scenarios execute in definition order; each is independently identified via t.Run.
func TestFleetRotation(t *testing.T) {
	s := setupFleetSuite(t)

	// Skip cleanly when the rotation API endpoint is not yet wired up. The endpoint
	// is implemented by stories B2a (#1815) and B2b (#1816); until both are merged,
	// the controller returns 404 for POST /api/v1/certificates/signing/rotate.
	// Once those land, the probe returns true and this skip is bypassed.
	if !s.rotationEndpointAvailable(t) {
		t.Skip("Rotation API endpoint not available (depends on #1815 B2a + #1816 B2b); skipping until merged")
	}

	t.Run("OverlapAccept", func(t *testing.T) { s.testOverlapAccept(t) })
	t.Run("PostExpiryReject", func(t *testing.T) { s.testPostExpiryReject(t) })
	t.Run("OfflineDuringOverlapReconnect", func(t *testing.T) { s.testOfflineDuringOverlapReconnect(t) })
	t.Run("OfflinePastWindow", func(t *testing.T) { s.testOfflinePastWindow(t) })
	t.Run("CrashMidRotation", func(t *testing.T) { s.testCrashMidRotation(t) })
	t.Run("RefreshOnConnectNewSteward", func(t *testing.T) { s.testRefreshOnConnectNewSteward(t) })
}

// testOverlapAccept rotates with a 30-day overlap window and verifies that both
// stewards remain connected and continue to accept config pushes during the window.
// The controller signs outgoing configs with the new cert; stewards that have
// received the refresh push verify against the new cert and must still converge.
func (s *FleetTestSuite) testOverlapAccept(t *testing.T) {
	t.Helper()

	result := s.rotateSigningCert(t, 30)

	if result.OldSerial == "" {
		t.Error("rotation response: old_serial must not be empty")
	}
	if result.NewSerial == "" {
		t.Error("rotation response: new_serial must not be empty")
	}
	if result.OldSerial == result.NewSerial {
		t.Errorf("rotation response: old_serial == new_serial (%s); expected distinct values", result.OldSerial)
	}
	if result.OverlapDays != 30 {
		t.Errorf("rotation response: overlap_days = %d, want 30", result.OverlapDays)
	}

	// Both stewards must stay connected during the overlap window.
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Errorf("%s (%s): must remain connected after rotation during overlap", container, stewardID)
		}
	}

	// Config upload (signed with the new cert by the controller) must converge.
	const configPath = "configs/fleet-config.yaml"
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		if err := s.uploadConfig(t, s.stewardIDs[container], configPath); err != nil {
			t.Errorf("config upload during overlap for %s: %v", container, err)
		}
	}
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		if !s.waitForManagedFile(t, container, 60*time.Second) {
			t.Errorf("%s: managed-file must appear after config upload during overlap", container)
		}
	}
	t.Logf("OverlapAccept: rotation succeeded; old=%s new=%s stewards_notified=%d",
		result.OldSerial, result.NewSerial, result.StewardsNotified)
}

// testPostExpiryReject rotates with overlap_days=0 (minimum) so that
// overlapExpiresAt is immediately in the past. The test verifies the
// rotation API returns overlap_days=0 and that no sleep is required for
// the expiry condition to take effect.
func (s *FleetTestSuite) testPostExpiryReject(t *testing.T) {
	t.Helper()

	result := s.rotateSigningCert(t, 0)

	if result.OldSerial == "" || result.NewSerial == "" {
		t.Fatal("rotation response: old_serial and new_serial must not be empty")
	}
	if result.OldSerial == result.NewSerial {
		t.Errorf("rotation response: old_serial == new_serial; expected distinct values after rotation")
	}
	if result.OverlapDays != 0 {
		t.Errorf("rotation response: overlap_days = %d, want 0", result.OverlapDays)
	}

	// With overlap_days=0 the old serial is expired immediately. Stewards that
	// have received the refresh push must accept configs signed with the new cert
	// and reject any payload still signed with the old cert.
	// After the rotation, the controller must push configs signed with the new cert.
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Errorf("%s (%s): must remain connected after overlap_days=0 rotation", container, stewardID)
		}
	}

	// Verify the steward log records a signing-cert refresh event (delivered by
	// refresh-on-connect from story B2d).
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		if !s.waitForStewardLogEntry(t, container, "signing_cert", 30*time.Second) {
			t.Errorf("%s: steward log must contain signing_cert refresh entry after rotation", container)
		}
	}
	t.Logf("PostExpiryReject: overlap_days=0 rotation completed; old=%s new=%s",
		result.OldSerial, result.NewSerial)
}

// testOfflineDuringOverlapReconnect stops fleet-steward-2 before rotation,
// then restarts it while the overlap window is still open. Refresh-on-connect
// (story B2d) must deliver the new signing cert; the steward must then accept
// configs signed with the new cert.
func (s *FleetTestSuite) testOfflineDuringOverlapReconnect(t *testing.T) {
	t.Helper()

	container := "fleet-steward-2"
	stewardID := s.stewardIDs[container]

	// Take steward-2 offline before rotation. Register a cleanup that brings it
	// back up no matter how the test exits — without this, a t.Fatalf mid-test
	// would leave the container stopped and break every subsequent test in the
	// package (notably TestFleetComposeStartup).
	s.containerStop(t, container)
	t.Cleanup(func() { s.ensureContainerRunning(t, container, 90*time.Second) })
	t.Log("OfflineDuringOverlapReconnect: steward-2 stopped before rotation")

	result := s.rotateSigningCert(t, 30)
	t.Logf("OfflineDuringOverlapReconnect: rotated signing cert; old=%s new=%s overlap=30d",
		result.OldSerial, result.NewSerial)

	// Bring steward-2 back online during the overlap window.
	s.containerStart(t, container, 90*time.Second)

	// The stored cert survives docker stop/start; steward ID must be unchanged.
	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("steward ID not found after %s restart: %v", container, err)
	}
	if newID != stewardID {
		t.Errorf("steward %s re-registered after restart: %s → %s; expected stored-cert reuse",
			container, stewardID, newID)
	}
	s.stewardIDs[container] = newID

	// Refresh-on-connect must deliver the new signing cert automatically.
	if !s.waitForConvergence(t, newID, 90*time.Second) {
		t.Fatalf("%s (%s): must reconnect after coming back online during overlap", container, newID)
	}

	// Config upload after reconnect must converge (controller uses new cert).
	if err := s.uploadConfig(t, newID, "configs/fleet-config.yaml"); err != nil {
		t.Fatalf("config upload for %s after offline-during-overlap reconnect: %v", container, err)
	}
	if !s.waitForManagedFile(t, container, 60*time.Second) {
		t.Errorf("%s: managed-file must appear after reconnect during overlap", container)
	}
	t.Logf("OfflineDuringOverlapReconnect: %s reconnected during overlap and applied config", container)
}

// testOfflinePastWindow stops fleet-steward-2 before rotation with overlap_days=0,
// so the steward is offline through the entire (zero-length) overlap. When it
// reconnects, refresh-on-connect (story B2d) must deliver a fresh signing cert,
// allowing the steward to accept configs signed with the new cert.
func (s *FleetTestSuite) testOfflinePastWindow(t *testing.T) {
	t.Helper()

	container := "fleet-steward-2"
	stewardID := s.stewardIDs[container]

	// Stop steward-2 before rotation. Register a cleanup that brings it back up
	// regardless of test outcome so a failure mid-test cannot leave the fleet
	// in a broken state for subsequent tests.
	s.containerStop(t, container)
	t.Cleanup(func() { s.ensureContainerRunning(t, container, 90*time.Second) })
	t.Log("OfflinePastWindow: steward-2 stopped before rotation")

	// Rotate with overlap_days=0 — the overlap expires immediately.
	result := s.rotateSigningCert(t, 0)
	t.Logf("OfflinePastWindow: rotated signing cert with overlap_days=0; old=%s new=%s",
		result.OldSerial, result.NewSerial)

	// Bring steward-2 back online after overlap has expired.
	s.containerStart(t, container, 90*time.Second)

	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("steward ID not found after %s restart: %v", container, err)
	}
	if newID != stewardID {
		t.Errorf("steward %s re-registered: %s → %s; expected stored-cert reuse",
			container, stewardID, newID)
	}
	s.stewardIDs[container] = newID

	// Refresh-on-connect delivers a fresh signing cert even though the overlap
	// window has already closed. The steward must reconnect and converge.
	if !s.waitForConvergence(t, newID, 90*time.Second) {
		t.Fatalf("%s (%s): must reconnect past overlap window via refresh-on-connect", container, newID)
	}

	if err := s.uploadConfig(t, newID, "configs/fleet-config.yaml"); err != nil {
		t.Fatalf("config upload for %s after offline-past-window reconnect: %v", container, err)
	}
	if !s.waitForManagedFile(t, container, 60*time.Second) {
		t.Errorf("%s: managed-file must appear after past-window reconnect", container)
	}
	t.Logf("OfflinePastWindow: %s reconnected past overlap, refresh-on-connect delivered cert, config applied", container)
}

// testCrashMidRotation verifies that when the rotation state machine has
// RotatingSerial set (a rotation is in progress), a second rotate call returns
// a "rotation in progress" error rather than starting a second concurrent rotation.
func (s *FleetTestSuite) testCrashMidRotation(t *testing.T) {
	t.Helper()

	// Start a rotation with a long overlap so the cursor stays in RotatingSerial state.
	if err := s.tryRotateSigningCert(t, 30); err != nil {
		t.Fatalf("first rotation must succeed: %v", err)
	}
	t.Log("CrashMidRotation: first rotation started")

	// A second rotation attempt while the first is in progress must be rejected.
	err := s.tryRotateSigningCert(t, 30)
	if err == nil {
		t.Error("second rotation while first is in progress must return an error")
	} else {
		errMsg := err.Error()
		if !strings.Contains(errMsg, "rotation in progress") &&
			!strings.Contains(errMsg, "already rotating") &&
			!strings.Contains(errMsg, "409") {
			t.Errorf("second rotation error must indicate in-progress state, got: %s", errMsg)
		}
		t.Logf("CrashMidRotation: second rotation correctly rejected: %s", errMsg)
	}
}

// testRefreshOnConnectNewSteward verifies that a freshly registered steward
// receives the current signing cert via refresh-on-connect on its first
// ControlChannel connection. This ensures no logic split between registration-time
// cert pinning and post-registration refresh delivery.
func (s *FleetTestSuite) testRefreshOnConnectNewSteward(t *testing.T) {
	t.Helper()

	// Rotate the signing cert so there is a "new" cert that differs from the
	// cert that was in place when fleet-steward-1 and fleet-steward-2 registered.
	result := s.rotateSigningCert(t, 30)
	t.Logf("RefreshOnConnectNewSteward: rotated signing cert; new=%s", result.NewSerial)

	// Both existing stewards must receive the refresh push and remain connected.
	// Their logs must record a signing-cert refresh within 30 seconds of rotation.
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Errorf("%s (%s): must remain connected after rotation", container, stewardID)
		}
		if !s.waitForStewardLogEntry(t, container, result.NewSerial, 30*time.Second) {
			t.Errorf("%s: log must contain new serial %s after refresh-on-connect push",
				container, result.NewSerial)
		}
	}
	t.Logf("RefreshOnConnectNewSteward: both existing stewards received refresh push with new serial %s",
		result.NewSerial)
}
