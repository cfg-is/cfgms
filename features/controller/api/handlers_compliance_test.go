// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	reportsprovider "github.com/cfgis/cfgms/features/reports/provider"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// setupComplianceTestServer creates a test server with a real DataProvider
// backed by a t.TempDir()-isolated SQLite DNA storage manager, following the
// real-component TDD mandate (no mocks). Returns the server and the underlying
// storage manager so individual tests can store fixture DNA snapshots.
func setupComplianceTestServer(t *testing.T) (*Server, *fleetStorage.Manager) {
	t.Helper()
	server := setupTestServer(t)

	cfg := fleetStorage.DefaultConfig()
	cfg.DataDir = t.TempDir()
	storageManager, err := fleetStorage.NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err, "failed to create fleet storage manager")
	t.Cleanup(func() {
		if err := storageManager.Close(); err != nil {
			t.Logf("fleet storage manager Close() failed: %v", err)
		}
	})

	detector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logging.NewNoopLogger())
	require.NoError(t, err, "failed to create drift detector")
	t.Cleanup(func() {
		if err := detector.Close(); err != nil {
			t.Logf("drift detector Close() failed: %v", err)
		}
	})

	dp := reportsprovider.New(storageManager, detector, logging.NewNoopLogger())
	server.SetDataProvider(dp)
	return server, storageManager
}

// buildComplianceDNA constructs a commonpb.DNA for deviceID from a
// fragment-id → state map. Each fragment's canonical_bytes is the state text;
// fragment_hash is SHA-256, matching the ADR-017 fragment contract the drift
// detector diffs. Fragments are emitted in sorted order for determinism.
func buildComplianceDNA(deviceID string, state map[string]string) *commonpb.DNA {
	ids := make([]string, 0, len(state))
	for id := range state {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	fragments := make([]*commonpb.Fragment, 0, len(ids))
	for _, id := range ids {
		canonical := []byte(state[id])
		sum := sha256.Sum256(canonical)
		fragments = append(fragments, &commonpb.Fragment{
			FragmentId:     id,
			Authority:      "osquery",
			CanonicalBytes: canonical,
			FragmentHash:   hex.EncodeToString(sum[:]),
		})
	}

	return &commonpb.DNA{
		Id:          deviceID,
		Fragments:   fragments,
		LastUpdated: timestamppb.Now(),
	}
}

// storeDNAPair stores two consecutive DNA snapshots for deviceID, changing the
// named attribute from prevVal to currVal. Uses storageManager.Store which
// timestamps each record at time.Now(), so both records fall within the
// compliance handler's 24h look-back window.
func storeDNAPair(t *testing.T, sm *fleetStorage.Manager, deviceID, fragmentID, prevVal, currVal string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t,
		sm.Store(ctx, deviceID, buildComplianceDNA(deviceID, map[string]string{fragmentID: prevVal}), nil),
		"failed to store first DNA snapshot")
	require.NoError(t,
		sm.Store(ctx, deviceID, buildComplianceDNA(deviceID, map[string]string{fragmentID: currVal}), nil),
		"failed to store second DNA snapshot")
}

// ── handleGetStewardCompliance ────────────────────────────────────────────────

func TestHandleGetStewardCompliance(t *testing.T) {
	t.Run("503 when data provider unavailable", func(t *testing.T) {
		// No data provider wired — all compliance handlers must return 503.
		server := setupTestServer(t)
		require.NoError(t, server.controllerService.RegisterSteward("s1", "test-tenant", "addr-1", "online"))
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		req := httptest.NewRequest("GET", "/api/v1/stewards/s1/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("steward not found returns 404", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	// [REQUIRED AC TEST] A steward with real detected drift (fixture DNA history
	// showing a genuine attribute change) reports non-compliant status even though
	// its connection status is "online."
	t.Run("drift detected reports non-compliant even when online", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		// Register the steward as "online" — liveness says it is healthy.
		require.NoError(t, server.controllerService.RegisterSteward("drifted-steward", "test-tenant", "addr-1", "online"))

		// Store two DNA snapshots with a changed network fragment. A hostname change
		// produces SeverityWarning; combined with 3 pairs we need ≥3 warning events to
		// lower ComplianceScore below 0.8 (medium risk). Simpler: a security:firewall
		// attribute triggers SeverityCritical → RiskLevelCritical immediately.
		storeDNAPair(t, sm, "drifted-steward", "security:firewall_rules", "allow-all", "deny-all")

		req := httptest.NewRequest("GET", "/api/v1/stewards/drifted-steward/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// Compliance must reflect the drift signal, not liveness.
		assert.NotEqual(t, "compliant", resp.Status, "drifted-steward should not report compliant")
		// Liveness must remain available separately.
		assert.Equal(t, "online", resp.ConnectionStatus, "connection_status must reflect the actual liveness")
	})

	// [REQUIRED AC TEST] A steward with no drift and no history reports compliant
	// regardless of connection status (matches calculateComplianceScore's "no events
	// = 1.0" default → RiskLevelLow → compliant).
	t.Run("no history reports compliant regardless of connection status", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		// Register as "offline" — liveness says it is down. No DNA records exist.
		require.NoError(t, server.controllerService.RegisterSteward("offline-no-drift", "test-tenant", "addr-2", "offline"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/offline-no-drift/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// No drift events → score=1.0 → RiskLevelLow → compliant.
		assert.Equal(t, "compliant", resp.Status)
		// Connection status is still visible separately.
		assert.Equal(t, "offline", resp.ConnectionStatus)
	})

	// [REQUIRED AC TEST] A steward with one fixture critical-severity drift event
	// but an otherwise-high aggregate ComplianceScore still reports critical — proves
	// the handler reads RiskLevel's critical-event override, not a re-derived score
	// threshold that would drop it.
	//
	// One critical-severity event (security:firewall change) produces a ComplianceScore
	// of 0.8 (1.0 - 1.0/5.0). Score 0.8 alone maps to RiskLevelLow (< 0.8 threshold)
	// — a handler re-deriving from ComplianceScore without the override would report
	// "compliant". calculateRiskLevel's "criticalCount > 0" override forces
	// RiskLevelCritical regardless; reading RiskLevel directly preserves it.
	t.Run("single critical drift event overrides high aggregate score to report critical", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("high-score-critical", "test-tenant", "addr-3", "online"))

		// Exactly 2 snapshots → 1 drift event pair → SeverityCritical for security:firewall.
		// ComplianceScore = 1.0 - (1.0/1.0)/5.0 = 0.8.
		// Without the criticalCount override, score=0.8 → RiskLevelLow → "compliant" (wrong).
		// With the override: criticalCount=1 > 0 → RiskLevelCritical → "critical" (correct).
		storeDNAPair(t, sm, "high-score-critical", "security:firewall_rules", "allow-all", "deny-all")

		req := httptest.NewRequest("GET", "/api/v1/stewards/high-score-critical/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		assert.Equal(t, "critical", resp.Status,
			"single critical event must force critical even when aggregate score is 0.8")
		assert.Equal(t, "critical", resp.AlertLevel)
	})

	// Storage-failure path: the DNA storage manager backing the real DataProvider
	// is closed before the request, so every GetHistory read fails. The provider
	// logs and skips the device, returning a stats map with no entry for it — the
	// handler must surface that as 500 rather than publishing the zero-value
	// DeviceStats (whose empty RiskLevel would render as a "critical" verdict).
	t.Run("storage failure returns 500", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("storage-down", "test-tenant", "addr-5", "online"))

		// Close the SQLite-backed manager; the t.Cleanup close is idempotent.
		require.NoError(t, sm.Close(), "closing the storage manager must succeed")

		req := httptest.NewRequest("GET", "/api/v1/stewards/storage-down/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"a storage failure must not be reported as a compliance verdict")
		assert.NotContains(t, rec.Body.String(), "critical",
			"the response must not fabricate a compliance status from missing stats")
	})

	t.Run("last_checked falls back to heartbeat when no DNA records", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("s-heartbeat", "test-tenant", "addr-4", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/s-heartbeat/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceStatusResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.NotEmpty(t, resp.LastChecked)
	})
}

func TestHandleGetStewardCompliance_TenantIsolation(t *testing.T) {
	t.Run("tenant-A caller gets 404 for tenant-B steward", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-compliance"}, "tenant-a", 5*time.Minute)

		require.NoError(t, server.controllerService.RegisterSteward("steward-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-b/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("tenant-A caller can see own steward", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-compliance"}, "tenant-a", 5*time.Minute)

		require.NoError(t, server.controllerService.RegisterSteward("steward-a", "tenant-a", "addr-a", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-a/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("tenant-A caller can see descendant-tenant steward", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-compliance"}, "tenant-a", 5*time.Minute)

		require.NoError(t, server.controllerService.RegisterSteward("steward-child", "tenant-a/child", "addr-c", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-child/compliance", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped context blocks cross-tenant access", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("steward-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-b/compliance", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "steward-b"})
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetStewardCompliance(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

// ── handleGetStewardComplianceReport ─────────────────────────────────────────

func TestHandleGetStewardComplianceReport(t *testing.T) {
	t.Run("503 when data provider unavailable", func(t *testing.T) {
		server := setupTestServer(t)
		require.NoError(t, server.controllerService.RegisterSteward("s1", "test-tenant", "addr-1", "online"))
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		req := httptest.NewRequest("GET", "/api/v1/stewards/s1/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("steward not found returns 404", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("no history reports compliant in report", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("clean-steward", "test-tenant", "addr-1", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/clean-steward/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "clean-steward", resp.DeviceID)
		assert.Equal(t, "compliant", resp.Status)
		assert.NotEmpty(t, resp.ReportGeneratedAt)
	})

	t.Run("drift detected steward reports critical in report", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("drifted-report", "test-tenant", "addr-2", "online"))
		storeDNAPair(t, sm, "drifted-report", "security:firewall_rules", "allow-all", "deny-all")

		req := httptest.NewRequest("GET", "/api/v1/stewards/drifted-report/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "critical", resp.Status)
		// Liveness is present separately; drift drove the status, not the connection.
		assert.Equal(t, "online", resp.ConnectionStatus)
	})

	// Storage-failure path for the report handler: same mechanism as
	// TestHandleGetStewardCompliance/"storage failure returns 500".
	t.Run("storage failure returns 500", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("report-storage-down", "test-tenant", "addr-4", "online"))
		require.NoError(t, sm.Close(), "closing the storage manager must succeed")

		req := httptest.NewRequest("GET", "/api/v1/stewards/report-storage-down/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"a storage failure must not be reported as a compliance verdict")
		assert.NotContains(t, rec.Body.String(), "critical",
			"the response must not fabricate a compliance status from missing stats")
	})

	t.Run("report includes connection_status distinct from status", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-compliance"})

		require.NoError(t, server.controllerService.RegisterSteward("s-offline", "test-tenant", "addr-3", "offline"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/s-offline/compliance/report", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceReportResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		// No DNA history → compliant, even though offline.
		assert.Equal(t, "compliant", resp.Status)
		// Connection status is the real liveness — not mislabeled as compliance.
		assert.Equal(t, "offline", resp.ConnectionStatus)
	})
}

func TestHandleGetStewardComplianceReport_TenantIsolation(t *testing.T) {
	t.Run("tenant-A caller gets 404 for tenant-B steward report", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("steward-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-b/compliance/report", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "steward-b"})
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetStewardComplianceReport(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("tenant-A caller can see own steward report", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("steward-a", "tenant-a", "addr-a", "online"))

		req := httptest.NewRequest("GET", "/api/v1/stewards/steward-a/compliance/report", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "steward-a"})
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetStewardComplianceReport(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// ── handleGetComplianceSummary ────────────────────────────────────────────────

func TestHandleGetComplianceSummary(t *testing.T) {
	t.Run("503 when data provider unavailable", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	})

	t.Run("no stewards returns zero counts", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 0, resp.TotalDevices)
		assert.Equal(t, 0, resp.CompliantDevices)
		assert.Empty(t, resp.ByTenant)
	})

	// Root/unscoped callers see all tenants' stewards; compliance buckets derive
	// from drift signal, not liveness. Calling the handler directly to inject an
	// empty-tenant context (root/admin — no TenantID in context).
	t.Run("root caller sees drift-based compliance counts", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s2", "tenant-1", "addr-2", "offline"))
		require.NoError(t, server.controllerService.RegisterSteward("s3", "tenant-2", "addr-3", "online"))

		// s1 has critical drift; s2 and s3 have no DNA history → compliant.
		storeDNAPair(t, sm, "s1", "security:firewall_rules", "allow-all", "deny-all")

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 3, resp.TotalDevices)
		// s1 has drift → critical; s2 and s3 have no history → compliant.
		// Offline s2 must NOT be counted as critical (liveness ≠ compliance).
		assert.Equal(t, 2, resp.CompliantDevices, "offline steward with no drift must be compliant")
		assert.Equal(t, 1, resp.CriticalDevices, "only the drifted steward is critical")
		assert.Len(t, resp.ByTenant, 2)
	})

	// Storage-failure path for the summary handler. Unlike the per-steward
	// handlers this is only reachable once at least one steward ID is collected,
	// so a steward is registered before the storage manager is closed.
	t.Run("storage failure returns 500", func(t *testing.T) {
		server, sm := setupComplianceTestServer(t)
		apiKey := NewTestKey(t, server, []string{"compliance:read-summary"})

		require.NoError(t, server.controllerService.RegisterSteward("summary-storage-down", "test-tenant", "addr-1", "online"))
		require.NoError(t, sm.Close(), "closing the storage manager must succeed")

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code,
			"a storage failure must not be published as aggregate compliance counts")
		assert.NotContains(t, rec.Body.String(), "total_devices",
			"no summary body may be emitted when the device stats are incomplete")
	})

	t.Run("root caller tenant filter returns matching stewards only", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s2", "tenant-2", "addr-2", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=tenant-1", nil)
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 1, resp.TotalDevices)
		assert.Equal(t, 1, resp.CompliantDevices)
		assert.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-1", resp.ByTenant[0].TenantID)
	})

	t.Run("root caller tenant filter with no match returns zero counts", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s1", "tenant-1", "addr-1", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=nonexistent", nil)
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, 0, resp.TotalDevices)
		assert.Empty(t, resp.ByTenant)
	})
}

func TestHandleGetComplianceSummary_TenantIsolation(t *testing.T) {
	// [REQUIRED TEST]: a tenant-A caller hitting /api/v1/compliance/summary never
	// sees tenant-B's by_tenant entry, even when no tenant_id param is supplied.
	t.Run("tenant-A caller never sees tenant-B data in by_tenant", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s-a", "tenant-a", "addr-a", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		assert.Equal(t, 1, resp.TotalDevices)
		require.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-a", resp.ByTenant[0].TenantID)
	})

	t.Run("tenant-A caller with tenant_id=tenant-B param still only sees tenant-A data", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s-a", "tenant-a", "addr-a", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary?tenant_id=tenant-b", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// Query param must be ignored; caller's own tenant scoping is enforced.
		assert.Equal(t, 1, resp.TotalDevices)
		require.Len(t, resp.ByTenant, 1)
		assert.Equal(t, "tenant-a", resp.ByTenant[0].TenantID)
	})

	t.Run("tenant-A caller sees descendant tenant stewards", func(t *testing.T) {
		server, _ := setupComplianceTestServer(t)

		require.NoError(t, server.controllerService.RegisterSteward("s-a", "tenant-a", "addr-a", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-child", "tenant-a/child", "addr-c", "online"))
		require.NoError(t, server.controllerService.RegisterSteward("s-b", "tenant-b", "addr-b", "online"))

		req := httptest.NewRequest("GET", "/api/v1/compliance/summary", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		server.handleGetComplianceSummary(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp ComplianceSummaryResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

		// tenant-a and tenant-a/child are visible; tenant-b is not.
		assert.Equal(t, 2, resp.TotalDevices)
		assert.Len(t, resp.ByTenant, 2)
		tenantIDs := make(map[string]bool)
		for _, bt := range resp.ByTenant {
			tenantIDs[bt.TenantID] = true
		}
		assert.True(t, tenantIDs["tenant-a"], "tenant-a should be in by_tenant")
		assert.True(t, tenantIDs["tenant-a/child"], "tenant-a/child should be in by_tenant")
		assert.False(t, tenantIDs["tenant-b"], "tenant-b must not appear")
	})
}
