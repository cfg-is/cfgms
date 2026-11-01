// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package fleet

import (
	"strings"
	"testing"
	"time"
)

// testConfigCascade proves multi-tenant config cascade end-to-end (Issue #1723).
//
// Setup (seeded at controller startup by seedFleetCascadeTestData):
//   - fleet-steward-1 → tenant fleet-root/fleet-child-a
//   - fleet-steward-2 → tenant fleet-root/fleet-child-b
//   - Parent policy stored at fleet-root / msp-policies / global:
//     cascade-policy (parent content) + cascade-parent-only
//
// Cascade assertions (AC coverage):
//  1. Before child upload: both stewards have cascade-policy (parent content)
//     and cascade-parent-only — proving the MSP-level policy cascades to both
//     child tenants automatically.
//  2. After uploading cascade-child.cfg to fleet-steward-1:
//     - cascade-policy on steward-1 shows child-override-content (child wins).
//     - cascade-parent-only is still present on steward-1 even though it is absent
//     from the child device config — proving the parent resource cascades through.
//     - cascade-child-only appears on steward-1 (new child-only resource).
//  3. fleet-steward-2 is unaffected: cascade-policy still parent content,
//     cascade-parent-only still present, cascade-child-only absent.
func (s *FleetTestSuite) testConfigCascade(t *testing.T) {
	t.Helper()

	// ── Step 1: verify both stewards already have the parent policy resources ──
	// The controller seeds the MSP-level policy at startup; stewards receive it
	// on first config request after registration (before this scenario runs).
	for _, container := range []string{"fleet-steward-1", "fleet-steward-2"} {
		stewardID := s.stewardIDs[container]
		if !s.waitForConvergence(t, stewardID, 30*time.Second) {
			t.Fatalf("cascade pre-check: steward %s (%s) not connected", container, stewardID)
		}

		if !s.waitForFileContent(t, container, "/test-workspace/cascade-policy", "parent-policy-content\n", 60*time.Second) {
			t.Errorf("cascade pre-check: %s: cascade-policy missing or wrong content (parent policy not cascaded)", container)
		}

		if !s.waitForFileContent(t, container, "/test-workspace/cascade-parent-only", "parent-only-content\n", 30*time.Second) {
			t.Errorf("cascade pre-check: %s: cascade-parent-only not delivered by parent cascade", container)
		}

		t.Logf("cascade pre-check: %s has parent policy resources (cascade active)", container)
	}

	// ── Step 2: upload child override to fleet-steward-1 ──
	// cascade-child.cfg overrides cascade-policy and adds cascade-child-only.
	// cascade-parent-only is NOT in the child config; it must arrive via cascade.
	steward1ID := s.stewardIDs["fleet-steward-1"]
	if err := s.uploadConfig(t, steward1ID, "configs/cascade-child.cfg"); err != nil {
		t.Fatalf("cascade: upload child config to fleet-steward-1: %v", err)
	}
	t.Log("cascade: child config uploaded to fleet-steward-1")

	// ── Step 3: assert fleet-steward-1 shows the merged cascade result ──
	// child wins for cascade-policy; parent still delivers cascade-parent-only.

	if !s.waitForFileContent(t, "fleet-steward-1", "/test-workspace/cascade-policy", "child-override-content\n", 60*time.Second) {
		got, _ := s.dockerExec(t, "fleet-steward-1", "cat", "/test-workspace/cascade-policy")
		t.Errorf("cascade: fleet-steward-1: cascade-policy = %q, want child-override-content (child override not applied)", strings.TrimSpace(got))
	}

	if !s.waitForFileContent(t, "fleet-steward-1", "/test-workspace/cascade-parent-only", "parent-only-content\n", 30*time.Second) {
		t.Errorf("cascade: fleet-steward-1: cascade-parent-only absent — parent cascade not delivered despite child device config lacking it")
	}

	if !s.waitForFileContent(t, "fleet-steward-1", "/test-workspace/cascade-child-only", "child-only-content\n", 30*time.Second) {
		t.Errorf("cascade: fleet-steward-1: cascade-child-only absent — child-only resource not applied")
	}

	t.Log("cascade: fleet-steward-1 shows merged result (parent cascade + child override)")

	// ── Step 4: assert fleet-steward-2 is unaffected ──
	// Uploading a child config to steward-1's tenant must not change steward-2.
	steward2ID := s.stewardIDs["fleet-steward-2"]
	if !s.waitForConvergence(t, steward2ID, 10*time.Second) {
		t.Errorf("cascade post-check: fleet-steward-2 disconnected after steward-1 child upload")
	}

	if !s.waitForFileContent(t, "fleet-steward-2", "/test-workspace/cascade-policy", "parent-policy-content\n", 30*time.Second) {
		got, _ := s.dockerExec(t, "fleet-steward-2", "cat", "/test-workspace/cascade-policy")
		t.Errorf("cascade post-check: fleet-steward-2: cascade-policy = %q, want parent-policy-content (sibling upload must not affect steward-2)", strings.TrimSpace(got))
	}

	if _, err := s.dockerExec(t, "fleet-steward-2", "test", "-f", "/test-workspace/cascade-child-only"); err == nil {
		t.Errorf("cascade post-check: fleet-steward-2: cascade-child-only exists — child resource must not leak to sibling tenant")
	}

	t.Log("cascade: fleet-steward-2 unaffected by sibling child upload (tenant isolation verified)")
}

// waitForFileContent polls until the file at path in container has exactly wantContent,
// or until timeout expires. Returns true when content matches.
func (s *FleetTestSuite) waitForFileContent(t *testing.T, container, path, wantContent string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got, err := s.dockerExec(t, container, "cat", path)
		if err == nil && got == wantContent {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
