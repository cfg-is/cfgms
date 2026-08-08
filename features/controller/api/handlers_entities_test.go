// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// newTestEntityGraphProvider returns a file-backed SQLite entity graph provider
// rooted in a temporary directory. The provider is closed automatically when the
// test ends. Imports go through providers_test.go's allowlisted import path.
func newTestEntityGraphProvider(t *testing.T) *sqlite.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := sqlite.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err, "creating SQLite entity graph provider")
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// newEntityTestServer wires the given provider into a standard test server.
func newEntityTestServer(t *testing.T, p egReadProvider) *Server {
	t.Helper()
	srv := setupTestServer(t)
	srv.SetEntityGraphProvider(p)
	return srv
}

// reportEntity is a test helper that injects an entity into the provider.
func reportEntity(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, eid string, tenant string, kind string) {
	t.Helper()
	now := time.Now().UTC()
	err := p.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:reporter",
		Observations: []egtypes.Observation{
			{
				Source:     "test:reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid,
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind":   kind,
					"owning_tenant": tenant,
					"hostname":      eid,
				},
			},
		},
	})
	require.NoError(t, err, "reportEntity: %s", eid)
}

// ---- /api/v1/entities (QueryEntities) ----

func TestHandleQueryEntities_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleQueryEntities_EmptyResult(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "empty query must return 200: %s", rec.Body.String())
	var page eginterfaces.EntityPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	assert.Empty(t, page.Entities)
}

func TestHandleQueryEntities_KindFilter(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	reportEntity(t, p, "host:qent-host1", "test-tenant", "host")
	reportEntity(t, p, "host:qent-user1", "test-tenant", "user")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities?kind=host", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "kind filter: %s", rec.Body.String())
	var page eginterfaces.EntityPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	assert.Len(t, page.Entities, 1)
	assert.Equal(t, "host", page.Entities[0].Entity.Kind)
}

func TestHandleQueryEntities_RequiresAuth(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleQueryEntities_InvalidPageSize(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities?page_size=bad", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---- /api/v1/entities/{eid} (GetEntity) ----

func TestHandleGetEntity_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:notfound", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetEntity_NotFound_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nope", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "missing entity must return 404")
}

func TestHandleGetEntity_Found_Returns200(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	reportEntity(t, p, "host:ent-test1", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ent-test1", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "found entity must return 200: %s", rec.Body.String())
	var view egtypes.EntityView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.Equal(t, "host", view.Entity.Kind)
}

func TestHandleGetEntity_InvalidEID_Returns400(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	// "badeid" has no colon separator — not a valid EID.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/badeid", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleGetEntity_CrossTenantReturns404 is the required AC-5 test:
// a request scoped to tenant-a for an entity owned by tenant-b must return 404,
// not 403 (ADR-022 §7 non-disclosure requirement).
func TestHandleGetEntity_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	// Create entity owned by "tenant-b".
	reportEntity(t, p, "host:xt-secret1", "tenant-b", "host")

	// Authenticate as "tenant-a" (different tenant subtree).
	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:read"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:xt-secret1", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	// Must be 404, not 403 — existence of tenant-b's entity must not be disclosed.
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant entity read must return 404, not 403 (ADR-022 §7): got %d", rec.Code)
}

// ---- /api/v1/entities/{eid}/edges (GetEdges) ----

func TestHandleGetEdges_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:e1/edges", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetEdges_ReturnsEmpty(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	reportEntity(t, p, "host:edge-src1", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:edge-src1/edges", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "no-edges must return 200: %s", rec.Body.String())
	var edges []*eginterfaces.EdgeView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &edges))
	assert.Empty(t, edges)
}

// ---- /api/v1/entities/{eid}/neighborhood (GetNeighborhood) ----

func TestHandleGetNeighborhood_InvalidDepth(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nh1/neighborhood?depth=99", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "depth>3 must be rejected")
}

func TestHandleGetNeighborhood_InvalidDirection(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nh1/neighborhood?direction=sideways", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid direction must be rejected")
}

// ---- /api/v1/entities/{eid}/history (GetHistory) ----

func TestHandleGetHistory_MissingTimeRange(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:hist1/history", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "missing time range must be rejected")
}

func TestHandleGetHistory_InvalidFromTime(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:hist1/history?from=not-a-time&to=2026-01-01T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid from time must be rejected")
}

func TestHandleGetHistory_ToBeforeFrom(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:hist1/history?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "to before from must be rejected")
}

func TestHandleGetHistory_ValidRange_ReturnsEmpty(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	reportEntity(t, p, "host:hist2", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:hist2/history?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "valid range: %s", rec.Body.String())
	var records []*eginterfaces.ObservationRecord
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &records))
	assert.Empty(t, records, "no observations in the requested historical range")
}

func TestHandleGetHistory_EntityNotFound_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:hist-nope/history?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "history for non-existent entity must return 404")
}

func TestHandleGetHistory_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:hist-secret", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:read"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:hist-secret/history?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant history read must return 404, not 403 (ADR-022 §7)")
}

// ---- /api/v1/entities/{eid}/neighborhood (GetNeighborhood, additional) ----

func TestHandleGetNeighborhood_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nh503/neighborhood", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetNeighborhood_EntityNotFound_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nh-nope/neighborhood", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "neighborhood for non-existent entity must return 404")
}

func TestHandleGetNeighborhood_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:nh-secret", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:read"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nh-secret/neighborhood", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant neighborhood read must return 404, not 403 (ADR-022 §7)")
}

// ---- /api/v1/entities/{eid}/diff (Diff) ----

func TestHandleDiff_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:diff503/diff?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleDiff_MissingTimeRange(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:diff1/diff", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleDiff_EntityNotFound_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:diff-nope/diff?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "diff for non-existent entity must return 404")
}

func TestHandleDiff_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:diff-secret", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:read"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:diff-secret/diff?from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant diff read must return 404, not 403 (ADR-022 §7)")
}

// ---- /api/v1/entities/timeline (GetTimeline) ----

func TestHandleGetTimeline_MissingEID(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/timeline?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "missing eid must be rejected")
}

func TestHandleGetTimeline_InvalidEID(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/timeline?eid=badeid&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid EID in timeline must be rejected")
}

func TestHandleGetTimeline_ValidRequest(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	// Entity must exist for the pre-check to pass (access verified via GetEntity).
	reportEntity(t, p, "host:tl1", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/timeline?eid=host:tl1&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "valid timeline request: %s", rec.Body.String())
	var events []*eginterfaces.TimelineEvent
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &events))
}

func TestHandleGetTimeline_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:tl-secret", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:list"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/timeline?eid=host:tl-secret&from=2020-01-01T00:00:00Z&to=2020-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant timeline read must return 404, not 403 (ADR-022 §7)")
}

// TestHandleGetTimeline_MixedTenantEIDsReturns404 covers the attack shape that
// makes the timeline endpoint the most exposed of the temporal reads: the eid
// query parameter is repeatable and attacker-chosen, so a caller can smuggle a
// foreign EID alongside one it legitimately owns. Every EID must be verified,
// and a single unauthorized EID must fail the whole request without emitting any
// events for the authorized ones.
func TestHandleGetTimeline_MixedTenantEIDsReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:tl-mine", "tenant-a", "host")
	reportEntity(t, p, "host:tl-theirs", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:list"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/timeline?eid=host:tl-mine&eid=host:tl-theirs"+
			"&from=2020-01-01T00:00:00Z&to=2030-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code,
		"timeline containing a foreign EID must return 404 for the whole request: %s", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "tl-theirs",
		"404 body must not disclose the foreign EID")
	assert.NotContains(t, rec.Body.String(), "tl-mine",
		"a rejected request must not emit events for the authorized EIDs")
}

// TestHandleGetTimeline_MultipleOwnedEIDsSucceeds proves the per-EID access check
// does not break the legitimate multi-EID case it guards.
func TestHandleGetTimeline_MultipleOwnedEIDsSucceeds(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:tl-own1", "tenant-a", "host")
	reportEntity(t, p, "host:tl-own2", "tenant-a/child", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:list"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/timeline?eid=host:tl-own1&eid=host:tl-own2"+
			"&from=2020-01-01T00:00:00Z&to=2030-01-02T00:00:00Z", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"own-tenant and descendant-tenant EIDs must be readable: %s", rec.Body.String())
	var events []*eginterfaces.TimelineEvent
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &events))
	assert.NotEmpty(t, events, "state observations must produce timeline events")
}

// ---- /api/v1/entities/{eid}/drift (GetDriftState) ----

func TestHandleGetDriftState_EntityNotFound_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nodrift1/drift", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "drift for non-existent entity must return 404")
}

func TestHandleGetDriftState_NoDriftRecord_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	// Entity exists but has no drift record.
	reportEntity(t, p, "host:nodrift2", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:nodrift2/drift", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "entity with no drift record must return 404")
}

func TestHandleGetDriftState_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:drift503/drift", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetDriftState_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	reportEntity(t, p, "host:drift-secret", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:read"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:drift-secret/drift", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant drift read must return 404, not 403 (ADR-022 §7)")
}

// ---- /api/v1/entities/drifted (ListDrifted) ----

func TestHandleListDrifted_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/drifted", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleListDrifted_EmptyResult(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/drifted", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "empty drifted list: %s", rec.Body.String())
	var states []*eginterfaces.DriftState
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &states))
	assert.Empty(t, states)
}

func TestHandleListDrifted_InvalidLifecycleStatus(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/drifted?lifecycle_status=unknown", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid lifecycle_status must be rejected")
}

// ---- tenant-subtree filtering (collection endpoint) ----

// TestHandleQueryEntities_TenantFiltering verifies that a scoped caller only sees
// entities in their own tenant subtree (ADR-022 §7).
func TestHandleQueryEntities_TenantFiltering(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	// Two entities in different tenants.
	reportEntity(t, p, "host:qf-visible", "tenant-a", "host")
	reportEntity(t, p, "host:qf-hidden", "tenant-b", "host")

	// Authenticate as tenant-a.
	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:list"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "filtered list: %s", rec.Body.String())
	var page eginterfaces.EntityPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Entities, 1, "tenant-a must only see its own entity")
	assert.Equal(t, "tenant-a", page.Entities[0].Entity.OwningTenant)
}
