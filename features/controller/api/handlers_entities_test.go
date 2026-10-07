// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	assert.Equal(t, "host:ent-test1", view.Entity.EID.String(),
		"entity EID must round-trip through the JSON response, not decode to a zero value")
}

// TestHandleGetEntity_ResponseBody_EncodesEIDAsString guards against the entity
// identifier silently degrading to an opaque "{}" in the wire format: EID has
// only unexported fields, so without types.EID's MarshalJSON, encoding/json
// would serialize it as an empty object and callers could never learn which
// entity a response describes.
func TestHandleGetEntity_ResponseBody_EncodesEIDAsString(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	reportEntity(t, p, "host:ent-wire1", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ent-wire1", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "found entity must return 200: %s", rec.Body.String())

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	entity, ok := raw["Entity"].(map[string]interface{})
	require.True(t, ok, "response must have an Entity object: %s", rec.Body.String())
	assert.Equal(t, "host:ent-wire1", entity["EID"],
		"EID must be encoded as its canonical string, not an object: %s", rec.Body.String())
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

// ---- /api/v1/entities/edges (POST — handleAssertEdge) ----

// newEntityRWTestServer wires the given provider into a standard test server for
// both read and write entity graph access (Issue #3374).
func newEntityRWTestServer(t *testing.T, p *sqlite.SQLiteEntityGraphProvider) *Server {
	t.Helper()
	srv := setupTestServer(t)
	srv.SetEntityGraphProvider(p)
	srv.SetEntityGraphWriteProvider(p)
	return srv
}

// assertEdgeBody builds a JSON body for POST /api/v1/entities/edges.
func assertEdgeBody(t *testing.T, edgeType, fromEID, toEID string) *bytes.Buffer {
	t.Helper()
	body, err := json.Marshal(assertEdgeRequest{
		EdgeType: edgeType,
		FromEID:  fromEID,
		ToEID:    toEID,
	})
	require.NoError(t, err)
	return bytes.NewBuffer(body)
}

// assertEdgeBodyWithAttrs builds a JSON body for POST /api/v1/entities/edges
// carrying caller-supplied attributes.
func assertEdgeBodyWithAttrs(t *testing.T, edgeType, fromEID, toEID string, attrs map[string]interface{}) *bytes.Buffer {
	t.Helper()
	body, err := json.Marshal(assertEdgeRequest{
		EdgeType:   edgeType,
		FromEID:    fromEID,
		ToEID:      toEID,
		Attributes: attrs,
	})
	require.NoError(t, err)
	return bytes.NewBuffer(body)
}

// postAssertEdge issues an authenticated POST /api/v1/entities/edges and returns
// the recorder.
func postAssertEdge(t *testing.T, srv *Server, apiKey string, body *bytes.Buffer) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges", body)
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	return rec
}

// requireNoEntityRecord asserts that no entity record exists for subject — used to
// prove a rejected assertion wrote nothing to the entity projection.
func requireNoEntityRecord(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, subject string) {
	t.Helper()
	eid, err := egtypes.ParseEID(subject)
	require.NoError(t, err, "test subject must parse as an EID: %s", subject)
	view, err := p.GetEntity(context.Background(), eid, eginterfaces.GetEntityOpts{})
	if err == nil {
		require.Nil(t, view, "no entity record may exist for %s", subject)
		return
	}
	require.ErrorIs(t, err, eginterfaces.ErrNotFound, "unexpected error for %s", subject)
}

func TestHandleAssertEdge_NoWriteProvider_Returns503(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p) // write provider NOT set
	apiKey := NewTestKey(t, srv, []string{"entity:write"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges",
		assertEdgeBody(t, "depends-on", "host:ae-from1", "host:ae-to1"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleAssertEdge_HappyPath verifies that a valid POST asserts the edge and
// makes it readable via GetEdges (AC-1).
func TestHandleAssertEdge_HappyPath(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write", "entity:read"})

	reportEntity(t, p, "host:ae-happy-from", "test-tenant", "host")
	reportEntity(t, p, "host:ae-happy-to", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges",
		assertEdgeBody(t, "depends-on", "host:ae-happy-from", "host:ae-happy-to"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, "valid assertion must return 201: %s", rec.Body.String())

	// Verify the edge is readable via the existing GET /entities/{eid}/edges path.
	getReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/entities/host:ae-happy-from/edges?edge_type=depends-on", nil)
	getReq.Header.Set("X-API-Key", apiKey)
	getRec := httptest.NewRecorder()
	srv.router.ServeHTTP(getRec, getReq)

	require.Equal(t, http.StatusOK, getRec.Code, "GetEdges after assertion: %s", getRec.Body.String())
	var edges []*eginterfaces.EdgeView
	require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &edges))
	require.Len(t, edges, 1, "asserted edge must appear in GetEdges result")
	assert.Equal(t, "depends-on", edges[0].Edge.Type)
	// The source class is the segment before the first ':', so the prefix must be
	// the declared operator-assertion class (ADR-022 §4) — a bare "operator:"
	// prefix is not a class constant and silently resolves to observer, storing
	// untrusted manual input at machine-observation precedence.
	assert.True(t, strings.HasPrefix(edges[0].Edge.Sources[0].Source,
		string(egtypes.SourceClassOperatorAssertion)+":"),
		"edge source must carry the operator-assertion class prefix, got %q",
		edges[0].Edge.Sources[0].Source)
}

// TestHandleAssertEdge_RejectsDelimiterInEdgeType verifies that an edge_type
// carrying the subject delimiter is rejected: the providers recover the subject
// fields with a three-way split on '|', so an unconstrained edge_type shifts the
// field boundaries and names an endpoint subject that never passed the tenant
// check.
func TestHandleAssertEdge_RejectsDelimiterInEdgeType(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write", "entity:read"})

	reportEntity(t, p, "host:ae-inj-from", "test-tenant", "host")
	reportEntity(t, p, "host:ae-inj-to", "test-tenant", "host")

	rec := postAssertEdge(t, srv, apiKey,
		assertEdgeBody(t, "contains|host:ae-victim", "host:ae-inj-from", "host:ae-inj-to"))

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"edge_type containing '|' must be rejected: %s", rec.Body.String())

	// Nothing was written: no forged endpoint node and no edge on the real one.
	requireNoEntityRecord(t, p, "host:ae-victim")
	fromEID, err := egtypes.ParseEID("host:ae-inj-from")
	require.NoError(t, err)
	edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &fromEID})
	require.NoError(t, err)
	assert.Empty(t, edges, "rejected assertion must write no edge")
}

// TestHandleAssertEdge_RejectsUnknownEdgeType verifies that an edge_type outside
// the taxonomy is rejected. An entity-shaped edge_type would make the whole
// subject parse as an EID, routing the observation to the entity projection where
// the caller's payload becomes an entity index row.
func TestHandleAssertEdge_RejectsUnknownEdgeType(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write", "entity:read"})

	reportEntity(t, p, "host:ae-unk-from", "test-tenant", "host")
	reportEntity(t, p, "host:ae-unk-to", "test-tenant", "host")

	for _, edgeType := range []string{"host:ae-forged", "not-a-real-edge-type"} {
		rec := postAssertEdge(t, srv, apiKey,
			assertEdgeBody(t, edgeType, "host:ae-unk-from", "host:ae-unk-to"))
		require.Equal(t, http.StatusBadRequest, rec.Code,
			"edge_type %q must be rejected: %s", edgeType, rec.Body.String())
	}

	fromEID, err := egtypes.ParseEID("host:ae-unk-from")
	require.NoError(t, err)
	edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &fromEID})
	require.NoError(t, err)
	assert.Empty(t, edges, "rejected assertion must write no edge")
}

// TestHandleAssertEdge_AcceptsRelatedEscapeEdgeType verifies the open-subtype
// escape of ADR-022 §2 still works through the taxonomy check.
func TestHandleAssertEdge_AcceptsRelatedEscapeEdgeType(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write", "entity:read"})

	reportEntity(t, p, "host:ae-rel-from", "test-tenant", "host")
	reportEntity(t, p, "host:ae-rel-to", "test-tenant", "host")

	rec := postAssertEdge(t, srv, apiKey,
		assertEdgeBody(t, "related:backup-target", "host:ae-rel-from", "host:ae-rel-to"))

	require.Equal(t, http.StatusCreated, rec.Code,
		"related: escape edge type must be accepted: %s", rec.Body.String())
}

// TestHandleAssertEdge_RejectsDelimiterInEID verifies that an endpoint EID
// carrying the subject delimiter is rejected. ParseEID permits '|' inside an
// authority name, so parsing alone does not make an EID safe to join into a
// pipe-delimited subject.
func TestHandleAssertEdge_RejectsDelimiterInEID(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write", "entity:read"})

	reportEntity(t, p, "host:ae-pipe-ok", "test-tenant", "host")

	rec := postAssertEdge(t, srv, apiKey,
		assertEdgeBody(t, "depends-on", "host:ae-pipe|host:ae-other", "host:ae-pipe-ok"))
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"from_eid containing '|' must be rejected: %s", rec.Body.String())

	rec = postAssertEdge(t, srv, apiKey,
		assertEdgeBody(t, "depends-on", "host:ae-pipe-ok", "host:ae-pipe2|host:ae-other"))
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"to_eid containing '|' must be rejected: %s", rec.Body.String())

	okEID, err := egtypes.ParseEID("host:ae-pipe-ok")
	require.NoError(t, err)
	edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &okEID})
	require.NoError(t, err)
	assert.Empty(t, edges, "rejected assertion must write no edge")
}

// TestHandleAssertEdge_RejectsReservedAttributes verifies that operator-supplied
// attributes cannot carry the provider's trusted ingest metadata keys — tenant
// provenance and the identity keys that drive entity collapse.
func TestHandleAssertEdge_RejectsReservedAttributes(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:write", "entity:read"}, "tenant-a", 5*time.Minute)

	reportEntity(t, p, "host:ae-attr-from", "tenant-a", "host")
	reportEntity(t, p, "host:ae-attr-to", "tenant-a", "host")

	reserved := []string{
		"tenant_path", "owning_tenant", "entity_kind", "hostname", "mac_addrs",
		"machine_sid", "dir_object_guid", "serial_number", "cloud_object_id",
	}
	for _, key := range reserved {
		rec := postAssertEdge(t, srv, apiKey, assertEdgeBodyWithAttrs(t,
			"depends-on", "host:ae-attr-from", "host:ae-attr-to",
			map[string]interface{}{key: "tenant-b"}))
		require.Equal(t, http.StatusBadRequest, rec.Code,
			"reserved attribute %q must be rejected: %s", key, rec.Body.String())
	}

	fromEID, err := egtypes.ParseEID("host:ae-attr-from")
	require.NoError(t, err)
	edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &fromEID})
	require.NoError(t, err)
	assert.Empty(t, edges, "rejected assertion must write no edge")
}

// TestHandleAssertEdge_AcceptsNonReservedAttributes verifies that ordinary edge
// attributes still round-trip through the assertion path.
func TestHandleAssertEdge_AcceptsNonReservedAttributes(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write", "entity:read"})

	reportEntity(t, p, "host:ae-attr2-from", "test-tenant", "host")
	reportEntity(t, p, "host:ae-attr2-to", "test-tenant", "host")

	rec := postAssertEdge(t, srv, apiKey, assertEdgeBodyWithAttrs(t,
		"depends-on", "host:ae-attr2-from", "host:ae-attr2-to",
		map[string]interface{}{"note": "manual failover dependency"}))
	require.Equal(t, http.StatusCreated, rec.Code,
		"non-reserved attributes must be accepted: %s", rec.Body.String())

	fromEID, err := egtypes.ParseEID("host:ae-attr2-from")
	require.NoError(t, err)
	edges, err := p.GetEdges(context.Background(), eginterfaces.EdgeFilter{FromEID: &fromEID})
	require.NoError(t, err)
	require.Len(t, edges, 1)
	assert.Equal(t, "manual failover dependency", edges[0].Edge.Attributes["note"])
}

// TestHandleAssertEdge_InvalidFromEID returns 400 with no partial write (AC-2).
func TestHandleAssertEdge_InvalidFromEID_Returns400(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write"})

	body, _ := json.Marshal(map[string]string{
		"edge_type": "depends-on",
		"from_eid":  "not-a-valid-eid",
		"to_eid":    "host:ae-to-inv",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges", bytes.NewBuffer(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid from_eid must return 400")
}

// TestHandleAssertEdge_InvalidToEID returns 400 with no partial write (AC-2).
func TestHandleAssertEdge_InvalidToEID_Returns400(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:write"})

	reportEntity(t, p, "host:ae-from-inv2", "test-tenant", "host")

	body, _ := json.Marshal(map[string]string{
		"edge_type": "depends-on",
		"from_eid":  "host:ae-from-inv2",
		"to_eid":    "not-a-valid-eid",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges", bytes.NewBuffer(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "invalid to_eid must return 400")
}

// TestHandleAssertEdge_FromEIDCrossTenantReturns404 verifies AC-3: cross-tenant
// from_eid returns 404, not 403 (ADR-022 §7 non-disclosure requirement).
func TestHandleAssertEdge_FromEIDCrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)

	// from_eid owned by tenant-b; to_eid owned by tenant-a.
	reportEntity(t, p, "host:ae-xt-from", "tenant-b", "host")
	reportEntity(t, p, "host:ae-xt-to1", "tenant-a", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:write"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges",
		assertEdgeBody(t, "depends-on", "host:ae-xt-from", "host:ae-xt-to1"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant from_eid must return 404, not 403 (ADR-022 §7): got %d", rec.Code)
}

// TestHandleAssertEdge_ToEIDCrossTenantReturns404 verifies AC-3: cross-tenant
// to_eid returns 404, not 403 (ADR-022 §7 non-disclosure requirement).
func TestHandleAssertEdge_ToEIDCrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)

	// from_eid owned by tenant-a; to_eid owned by tenant-b.
	reportEntity(t, p, "host:ae-xt-from2", "tenant-a", "host")
	reportEntity(t, p, "host:ae-xt-to2", "tenant-b", "host")

	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:write"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges",
		assertEdgeBody(t, "depends-on", "host:ae-xt-from2", "host:ae-xt-to2"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant to_eid must return 404, not 403 (ADR-022 §7): got %d", rec.Code)
}

// TestHandleAssertEdge_RequiresPermission verifies AC-4: a key without entity:write
// is rejected (AC-4).
func TestHandleAssertEdge_RequiresPermission(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)

	reportEntity(t, p, "host:ae-perm-from", "test-tenant", "host")
	reportEntity(t, p, "host:ae-perm-to", "test-tenant", "host")

	// entity:read does not include write permission.
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges",
		assertEdgeBody(t, "depends-on", "host:ae-perm-from", "host:ae-perm-to"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"insufficient permission must return 403: got %d", rec.Code)
}

// TestHandleAssertEdge_RequiresAuth verifies that an unauthenticated request is rejected.
func TestHandleAssertEdge_RequiresAuth(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities/edges",
		assertEdgeBody(t, "depends-on", "host:ae-noauth-from", "host:ae-noauth-to"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleCreateAPIKey_AcceptsEntityWrite verifies that entity:write — the
// permission gating POST /api/v1/entities/edges — is grantable through the real
// key-minting path and that the resulting least-privilege key reaches the route.
//
// The other tests in this file mint keys via NewTestKey/NewEphemeralTestKey, which
// call generateEphemeralKey directly and bypass isKnownPermission. That path cannot
// detect a permission that is enforced on a route but missing from the
// knownPermissions allow-list. With such a gap handleCreateAPIKey (and the web-account
// handlers) reject the permission with 400 INVALID_PERMISSION, leaving an unscoped
// principal (Permissions == nil, which hasPermission blanket-allows) as the only one
// able to reach the mutating route — the privilege inflation fixed for tenant:create
// (Issue #3195) and cluster:drain-node et al. (Issue #3303). This test goes through
// handleCreateAPIKey so that gap fails the suite.
func TestHandleCreateAPIKey_AcceptsEntityWrite(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityRWTestServer(t, p)

	const tenantID = "test-tenant"
	reportEntity(t, p, "host:ae-grant-from", tenantID, "host")
	reportEntity(t, p, "host:ae-grant-to", tenantID, "host")

	createBody := []byte(`{"name":"entity-write-key","tenant_id":"` + tenantID +
		`","permissions":["entity:write","entity:read"]}`)
	createRec := callHandleCreateAPIKey(srv, createBody, tenantID)
	require.Equal(t, http.StatusCreated, createRec.Code,
		"entity:write must be a known permission and grantable to a scoped API key: %s",
		createRec.Body.String())

	var created struct {
		Data struct {
			Key         string   `json:"key"`
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEmpty(t, created.Data.Key, "plaintext key must be returned on creation")
	assert.ElementsMatch(t, []string{"entity:write", "entity:read"}, created.Data.Permissions,
		"created key must carry exactly the requested entity permissions")

	// The scoped key really is scoped: it must not inherit blanket authority.
	srv.mu.RLock()
	stored := srv.apiKeys[created.Data.Key]
	srv.mu.RUnlock()
	require.NotNil(t, stored, "created key must be registered for authentication")
	require.NotNil(t, stored.Permissions,
		"created key must carry an explicit permission set, not the blanket-allow nil set")

	// And it reaches the route it was minted for.
	rec := postAssertEdge(t, srv, created.Data.Key,
		assertEdgeBody(t, "depends-on", "host:ae-grant-from", "host:ae-grant-to"))
	require.Equal(t, http.StatusCreated, rec.Code,
		"scoped entity:write key must be authorised for POST /entities/edges: %s", rec.Body.String())
}

// TestEntityPermissions_EnforcedOnRoutesAreGrantable verifies that every permission
// enforced by requirePermission on an /api/v1/entities route is present in the
// knownPermissions allow-list. A permission enforced on a route but absent from the
// allow-list is unusable: enforced but ungrantable, so only unscoped principals reach
// the route.
func TestEntityPermissions_EnforcedOnRoutesAreGrantable(t *testing.T) {
	for _, permID := range []string{"entity:list", "entity:read", "entity:write"} {
		assert.True(t, isKnownPermission(permID),
			"%s is enforced by requirePermission on an /entities route but absent from "+
				"knownPermissions, so no scoped API key or web account can ever hold it", permID)
	}
}

// ---- /api/v1/entities/{eid}/desired-state (GetDesiredState) ----

// reportDesiredState injects a desired-state observation for the given entity.
func reportDesiredState(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, eid string, state map[string]interface{}) {
	t.Helper()
	now := time.Now().UTC()
	payload := make(map[string]interface{}, len(state)+1)
	for k, v := range state {
		payload[k] = v
	}
	payload["config_revision"] = "rev-test-1"
	err := p.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:desired-state-reporter",
		Observations: []egtypes.Observation{
			{
				Source:     "test:desired-state-reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid,
				Kind:       egtypes.ObservationKindDesiredState,
				Confidence: egtypes.ConfidenceHigh,
				Payload:    payload,
			},
		},
	})
	require.NoError(t, err, "reportDesiredState: %s", eid)
}

func TestHandleGetDesiredState_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ds503/desired-state", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetDesiredState_EntityNotFound_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ds-nope/desired-state", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "desired-state for non-existent entity must return 404")
}

func TestHandleGetDesiredState_NoDesiredStateRecord_Returns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	// Entity exists but has no desired-state observation.
	reportEntity(t, p, "host:ds-norecord", "test-tenant", "host")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ds-norecord/desired-state", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "entity with no desired-state record must return 404")
}

// TestHandleGetDesiredState_CrossTenantReturns404 is the required AC test:
// a request scoped to tenant-a for an entity owned by tenant-b must return 404,
// not 403 (ADR-022 §7 non-disclosure requirement).
func TestHandleGetDesiredState_CrossTenantReturns404(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)

	// Create entity owned by "tenant-b".
	reportEntity(t, p, "host:ds-secret", "tenant-b", "host")
	reportDesiredState(t, p, "host:ds-secret", map[string]interface{}{"mode": "managed"})

	// Authenticate as "tenant-a" (different tenant subtree).
	apiKey := NewEphemeralTestKey(t, srv, []string{"entity:read"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ds-secret/desired-state", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	// Must be 404, not 403 — existence of tenant-b's entity must not be disclosed.
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"cross-tenant desired-state read must return 404, not 403 (ADR-022 §7): got %d", rec.Code)
}

func TestHandleGetDesiredState_HappyPath_Returns200(t *testing.T) {
	p := newTestEntityGraphProvider(t)
	srv := newEntityTestServer(t, p)
	apiKey := NewTestKey(t, srv, []string{"entity:read"})

	reportEntity(t, p, "host:ds-happy", "test-tenant", "host")
	reportDesiredState(t, p, "host:ds-happy", map[string]interface{}{"mode": "managed"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/host:ds-happy/desired-state", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "desired-state for existing entity must return 200: %s", rec.Body.String())
	var view egtypes.DesiredStateView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &view))
	assert.Equal(t, "rev-test-1", view.ConfigRevision)
}
