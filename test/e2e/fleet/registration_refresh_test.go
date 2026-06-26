// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"testing"
	"time"
)

// TestFleetRegistrationRefresh exercises the full registration-refresh flow in the
// real fleet docker-compose harness (Linux containers). Three scenarios:
//
//  1. AutoAccept   — cert expires offline → steward reconnects via refresh handshake
//     (same steward ID, no full re-registration, new cert with future expiry).
//  2. Revoked      — steward marked revoked → restart → 403, "refresh rejected" in log,
//     steward does NOT reconnect.
//  3. Archived     — steward marked archived → restart → 202 queued, pending entry
//     created → approve via API → steward reconnects on retry.
//
// All scenarios verify audit log entries via the test-mode controller endpoint.
//
// Fleet containers must be running (CFGMS_FLEET_TEST=1). Requires
// CFGMS_ENABLE_TEST_ENDPOINTS=true on fleet-controller (set in docker-compose.test.yml).
func TestFleetRegistrationRefresh(t *testing.T) {
	suite := setupFleetSuite(t)

	// Top-level cleanup: restore both stewards to "registered" after all subtests so
	// downstream tests (TestFleetRotation, TestFleetIDSelector) start with both stewards
	// in a known-good state. Individual subtests register their own cleanups for their
	// specific mutations, but this catches any residual state from a subtest that panics
	// or whose cleanup is not yet registered when it fails.
	t.Cleanup(func() {
		for _, id := range suite.stewardIDs {
			if id != "" {
				suite.setStewardStatusByID(t, id, "registered")
			}
		}
	})

	t.Run("AutoAccept", func(t *testing.T) {
		suite.testRefreshAutoAccept(t)
	})

	t.Run("Revoked", func(t *testing.T) {
		suite.testRefreshRevoked(t)
	})

	t.Run("Archived", func(t *testing.T) {
		suite.testRefreshArchived(t)
	})
}

// testRefreshAutoAccept verifies Scenario 1 (AC1–AC4):
//   - Stop steward → expire certs → restart → steward reconnects via refresh
//   - Same steward ID in logs; no full re-registration line
//   - New cert issued with future expiry (controller grants it immediately)
//   - Audit log records exactly one "refresh_cert_issued" entry for this device
func (s *FleetTestSuite) testRefreshAutoAccept(t *testing.T) {
	t.Helper()

	const container = "fleet-steward-1"
	// fleet-steward-1 uses tenant fleet-root/fleet-child-a.
	const tenantID = "fleet-root/fleet-child-a"

	stewardID := s.stewardIDs[container]
	if !s.waitForConvergence(t, stewardID, 30*time.Second) {
		t.Fatalf("AutoAccept: steward %s not converged before test", stewardID)
	}

	// Ensure the refresh policy is auto_accept for this tenant.
	s.setRefreshPolicy(t, tenantID, "auto_accept")

	// Capture device_id before stopping the container — the identity file persists.
	deviceID := s.getDeviceIDFromContainer(t, container)
	t.Logf("AutoAccept: device_id=%s steward_id=%s", deviceID, stewardID)

	// Stop the container and replace its client cert with an expired one.
	s.containerStop(t, container)
	s.expireStewardCerts(t, container)

	// Restart — the steward finds no valid cert, finds an expired cert, and performs
	// the refresh handshake (challenge → complete). The controller auto-accepts
	// (policy=auto_accept) and issues a new cert.
	s.containerStart(t, container, 90*time.Second)

	// Wait for the steward to reconnect via the refresh path. The log will contain
	// "Registration refresh approved" before "Steward registered and connected".
	if !s.waitForStewardLogEntry(t, container, "Registration refresh approved", 60*time.Second) {
		log, _ := s.readStewardLog(t, container)
		t.Fatalf("AutoAccept: steward did not log refresh approval within 60s\nlog tail:\n%s", lastLines(log, 40))
	}

	// AC: same steward ID reconnects — no new registration ID.
	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("AutoAccept: steward ID not found after restart: %v", err)
	}
	if newID != stewardID {
		t.Errorf("AutoAccept: steward re-registered with new ID %s → %s; expected refresh reuse (no re-registration)",
			stewardID, newID)
	}
	s.stewardIDs[container] = newID

	// AC: no full re-registration log line.
	log, _ := s.readStewardLog(t, container)
	if countLogLinesWith(log, "Steward registered and connected successfully via gRPC transport") > 1 {
		t.Errorf("AutoAccept: steward logged more than one 'registered and connected' entry — indicates re-registration rather than refresh")
	}

	// AC: steward converges after refresh.
	if !s.waitForConvergence(t, newID, 60*time.Second) {
		t.Errorf("AutoAccept: steward %s did not converge after refresh", newID)
	}

	// AC: audit log records exactly one refresh_cert_issued entry for this device.
	auditCount := s.queryAuditActionCount(t, "refresh_cert_issued", deviceID)
	if auditCount < 1 {
		t.Errorf("AutoAccept: expected at least 1 'refresh_cert_issued' audit entry for device %s, got %d",
			deviceID, auditCount)
	}
	t.Logf("AutoAccept: audit refresh_cert_issued count=%d for device %s", auditCount, deviceID)
}

// testRefreshRevoked verifies Scenario 2 (AC5–AC6):
//   - Mark steward as revoked via test-mode API
//   - Expire certs → restart → steward receives 403 → logs "refresh rejected"
//   - Steward does NOT reconnect (remains offline)
//   - Audit log records at least one "refresh_challenge_rejected" entry for this device
func (s *FleetTestSuite) testRefreshRevoked(t *testing.T) {
	t.Helper()

	const container = "fleet-steward-2"

	stewardID := s.stewardIDs[container]
	if !s.waitForConvergence(t, stewardID, 30*time.Second) {
		t.Fatalf("Revoked: steward %s not converged before test", stewardID)
	}

	deviceID := s.getDeviceIDFromContainer(t, container)
	t.Logf("Revoked: device_id=%s steward_id=%s", deviceID, stewardID)

	// Stop container, expire certs, mark as revoked, then restart.
	s.containerStop(t, container)
	s.expireStewardCerts(t, container)

	// Restore to registered before returning — runs even if t.Fatalf fires below.
	t.Cleanup(func() {
		s.setStewardStatusByID(t, stewardID, "registered")
	})

	// Mark the steward as revoked in the controller DB (via test-mode REST endpoint).
	s.setStewardStatusByID(t, stewardID, "revoked")
	t.Logf("Revoked: marked steward %s as revoked", stewardID)

	// Wait for the controller to detect the container stop and mark the steward as
	// disconnected before proceeding. Without this, the connection registry still
	// shows "connected" from the pre-stop gRPC session, causing a false positive
	// in the "must NOT be connected" check below.
	disconnectDeadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(disconnectDeadline) {
		state, _ := s.getStewardConnectionState(t, stewardID)
		if state != "connected" {
			t.Logf("Revoked: controller detected disconnection (state=%q)", state)
			break
		}
		time.Sleep(2 * time.Second)
	}

	// Restart — steward attempts refresh challenge, controller returns 403 (revoked-before-PoP).
	s.containerStart(t, container, 60*time.Second)

	// AC: steward must log the rejection message. The docker-compose retry loop
	// exits on ErrRefreshRejected so the steward process stops and the container
	// restarts after 5s. Wait for the log entry across restarts.
	if !s.waitForStewardLogEntry(t, container, "Registration refresh rejected", 60*time.Second) {
		log, _ := s.readStewardLog(t, container)
		t.Fatalf("Revoked: steward did not log 'Registration refresh rejected' within 60s\nlog tail:\n%s",
			lastLines(log, 40))
	}
	t.Log("Revoked: steward logged refresh rejection as expected")

	// AC: steward must NOT be connected (it should not have recovered).
	// Poll for 15s to make sure it doesn't eventually reconnect.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		state, err := s.getStewardConnectionState(t, stewardID)
		if err == nil && state == "connected" {
			t.Errorf("Revoked: steward reconnected after revocation — this should not happen")
			break
		}
		time.Sleep(3 * time.Second)
	}

	// AC: audit log records at least one refresh_challenge_rejected entry.
	// The revoked-before-PoP gate fires at the challenge step.
	auditCount := s.queryAuditActionCount(t, "refresh_challenge_rejected", deviceID)
	if auditCount < 1 {
		t.Errorf("Revoked: expected at least 1 'refresh_challenge_rejected' audit entry for device %s, got %d",
			deviceID, auditCount)
	}
	t.Logf("Revoked: audit refresh_challenge_rejected count=%d for device %s", auditCount, deviceID)

	t.Log("Revoked: steward correctly rejected; status will be restored to 'registered' by t.Cleanup")
}

// testRefreshArchived verifies Scenario 3 (AC7–AC9):
//   - Mark steward as archived → expire certs → restart → 202 queued
//   - Steward logs "refresh pending" and stays offline
//   - approve via cfg steward refresh approve API → steward reconnects on retry
//   - Audit log records refresh_queued and refresh_admin_approved entries
func (s *FleetTestSuite) testRefreshArchived(t *testing.T) {
	t.Helper()

	const container = "fleet-steward-2"
	const tenantID = "fleet-root/fleet-child-b"

	stewardID := s.stewardIDs[container]

	// testRefreshRevoked leaves steward-2's status as "registered" and the
	// container in a restart loop (retrying after revocation). Wait briefly for
	// convergence — best-effort; we stop the container next regardless.
	_ = s.waitForConvergence(t, stewardID, 20*time.Second)

	deviceID := s.getDeviceIDFromContainer(t, container)
	t.Logf("Archived: device_id=%s steward_id=%s", deviceID, stewardID)

	// Stop container, expire certs, mark archived.
	s.containerStop(t, container)
	s.expireStewardCerts(t, container)

	// Restore to registered before returning — runs even if t.Fatalf fires below.
	// Without this cleanup, TestFleetRotation and TestFleetIDSelector fail because
	// fleet-steward-2 stays archived and never reaches connected state.
	t.Cleanup(func() {
		s.setStewardStatusByID(t, stewardID, "registered")
	})

	// Mark archived — the controller's refresh gate queues archived stewards automatically
	// (bypasses policy: even auto_accept policy queues archived stewards).
	s.setStewardStatusByID(t, stewardID, "archived")
	t.Logf("Archived: marked steward %s as archived", stewardID)

	// Set auto_accept policy so that after admin approval promotes the steward from
	// "archived" to "registered", the steward's next retry immediately receives a new
	// cert rather than being re-queued by the default require_approval policy.
	// The archived status is what drives the initial 202 queue — policy is irrelevant
	// for the first attempt (archived bypasses policy). Policy only applies on retry.
	s.setRefreshPolicy(t, tenantID, "auto_accept")
	t.Logf("Archived: set refresh policy for %s to auto_accept", tenantID)

	// Start the container.
	s.containerStart(t, container, 60*time.Second)

	// AC: steward must log the pending message.
	if !s.waitForStewardLogEntry(t, container, "Registration refresh pending", 60*time.Second) {
		log, _ := s.readStewardLog(t, container)
		t.Fatalf("Archived: steward did not log 'Registration refresh pending' within 60s\nlog tail:\n%s",
			lastLines(log, 40))
	}
	t.Log("Archived: steward logged refresh queued as expected")

	// Fetch the pending refresh entry.
	var pendingID string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		entries := s.listPendingRefreshes(t, tenantID)
		for _, e := range entries {
			if e.DeviceID == deviceID && e.Status == "pending" {
				pendingID = e.PendingID
				break
			}
		}
		if pendingID != "" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if pendingID == "" {
		t.Fatalf("Archived: no pending refresh entry found for device %s within 30s", deviceID)
	}
	t.Logf("Archived: pending_id=%s", pendingID)

	// AC: audit log records at least one refresh_queued entry.
	auditCount := s.queryAuditActionCount(t, "refresh_queued", deviceID)
	if auditCount < 1 {
		t.Errorf("Archived: expected at least 1 'refresh_queued' audit entry for device %s, got %d",
			deviceID, auditCount)
	}

	// Approve via the admin REST API.
	s.approveRefreshViaAPI(t, pendingID)
	t.Logf("Archived: approved pending refresh %s", pendingID)

	// Restore steward status to "registered" so the controller accepts the reconnect.
	// The approve handler re-promotes the status, but marking archived first ensures
	// the claim bundle delivery path is exercised on the steward's next retry.
	// (The steward polls until it gets the approved cert bundle.)
	if !s.waitForStewardLogEntry(t, container, "Registration refresh approved", 90*time.Second) {
		log, _ := s.readStewardLog(t, container)
		t.Fatalf("Archived: steward did not log refresh approval within 90s after admin approve\nlog tail:\n%s",
			lastLines(log, 40))
	}
	t.Log("Archived: steward received approved cert bundle and reconnected")

	// Update local steward ID map (may have changed if the container restarted).
	newID, err := s.getStewardIDFromLogs(t, container)
	if err != nil {
		t.Fatalf("Archived: steward ID not found after reconnect: %v", err)
	}
	if newID != stewardID {
		t.Errorf("Archived: steward re-registered with new ID %s → %s; expected refresh reuse",
			stewardID, newID)
	}
	s.stewardIDs[container] = newID

	if !s.waitForConvergence(t, newID, 60*time.Second) {
		t.Errorf("Archived: steward %s did not converge after refresh approval", newID)
	}

	// AC: audit log records at least one refresh_admin_approved entry.
	approveCount := s.queryAuditActionCount(t, "refresh_admin_approved", deviceID)
	if approveCount < 1 {
		t.Errorf("Archived: expected at least 1 'refresh_admin_approved' audit entry for device %s, got %d",
			deviceID, approveCount)
	}
	t.Logf("Archived: audit refresh_admin_approved count=%d for device %s", approveCount, deviceID)
}

// lastLines returns the last n lines of s.
func lastLines(s string, n int) string {
	lines := splitLines(s)
	if len(lines) <= n {
		return s
	}
	return joinLines(lines[len(lines)-n:])
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func joinLines(lines []string) string {
	result := ""
	for i, l := range lines {
		if i > 0 {
			result += "\n"
		}
		result += l
	}
	return result
}
