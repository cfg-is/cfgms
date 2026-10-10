// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

const rgMSP = "msp-graph"

// rgFixture is a server with an entity graph holding one root-owned and one
// client-tenant entity (joined by an edge), plus a drift record on each.
type rgFixture struct {
	server *Server
	prov   *sqlite.SQLiteEntityGraphProvider
}

const (
	rgRootEID   = "host:rg-root-host"
	rgClientEID = "host:rg-client-host"
)

func newRGFixture(t *testing.T) *rgFixture {
	t.Helper()
	server := seedRootTenant(t, wireCrossingStore(t, setupTestServer(t)))
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: rgMSP, ParentID: testRootTenantID})
	require.NoError(t, err)
	prov := newTestEntityGraphProvider(t)
	server.SetEntityGraphProvider(prov)

	reportEntity(t, prov, rgRootEID, testRootTenantID, "host")
	reportEntity(t, prov, rgClientEID, rgMSP, "host")
	now := time.Now().UTC()
	for _, subject := range []string{rgRootEID, rgClientEID} {
		require.NoError(t, prov.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
			Source: "test:reporter",
			Observations: []egtypes.Observation{{
				Source: "test:reporter", ObservedAt: now, RecordedAt: now, Subject: subject,
				Kind: egtypes.ObservationKindDriftDiff, Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"fields": []map[string]interface{}{{"attribute": "a", "desired": "x", "actual": "y", "matching": false}},
				},
			}},
		}))
	}
	require.NoError(t, prov.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:reporter",
		Observations: []egtypes.Observation{{
			Source: "test:reporter", ObservedAt: now, RecordedAt: now,
			Subject: "runs-on|" + rgRootEID + "|" + rgClientEID,
			Kind:    egtypes.ObservationKindState, Confidence: egtypes.ConfidenceHigh,
			Payload: map[string]interface{}{},
		}},
	}))
	return &rgFixture{server: server, prov: prov}
}

func (f *rgFixture) get(t *testing.T, h http.HandlerFunc, path string, op *Principal, vars map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, asRootOperator(httptest.NewRequest(http.MethodGet, path, nil), op, vars))
	return rec
}

func rgEntityEIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var page eginterfaces.EntityPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	var out []string
	for _, e := range page.Entities {
		out = append(out, e.Entity.EID.String())
	}
	return out
}

func rgDriftEIDs(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var states []*eginterfaces.DriftState
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &states))
	out := []string{}
	for _, s := range states {
		out = append(out, s.EID.String())
	}
	return out
}

// TestRootEntityListReads_CrossingBoundary: list-shaped entity-graph reads return
// only root-owned entities to a boundary-subject root caller, then the client's
// too after a crossing.
func TestRootEntityListReads_CrossingBoundary(t *testing.T) {
	f := newRGFixture(t)
	op := boundRootOperator("rg-list-op")

	t.Run("no crossing", func(t *testing.T) {
		assert.ElementsMatch(t, []string{rgRootEID}, rgEntityEIDs(t, f.get(t, f.server.handleQueryEntities, "/api/v1/entities", op, nil)))
		assert.ElementsMatch(t, []string{rgRootEID}, rgDriftEIDs(t, f.get(t, f.server.handleListDrifted, "/api/v1/entities/drifted", op, nil)))

		q := url.Values{"eid": {rgRootEID, rgClientEID}, "from": {time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)}, "to": {time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}
		rec := f.get(t, f.server.handleGetTimeline, "/api/v1/entities/timeline?"+q.Encode(), op, nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var events []*eginterfaces.TimelineEvent
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &events))
		for _, ev := range events {
			assert.NotEqual(t, rgClientEID, ev.Subject.String())
		}
	})

	t.Run("active crossing", func(t *testing.T) {
		grantCrossing(t, f.server, op.ID, rgMSP)
		assert.ElementsMatch(t, []string{rgRootEID, rgClientEID}, rgEntityEIDs(t, f.get(t, f.server.handleQueryEntities, "/api/v1/entities", op, nil)))
		assert.ElementsMatch(t, []string{rgRootEID, rgClientEID}, rgDriftEIDs(t, f.get(t, f.server.handleListDrifted, "/api/v1/entities/drifted", op, nil)))
	})
}

// TestRootEntityKeyedReads_CrossingBoundary: every entity-keyed read of a client
// entity is challenged without a crossing and served with one.
func TestRootEntityKeyedReads_CrossingBoundary(t *testing.T) {
	f := newRGFixture(t)
	window := "from=" + url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)) +
		"&to=" + url.QueryEscape(time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	routes := []struct {
		name   string
		h      http.HandlerFunc
		suffix string
	}{
		{"entity", f.server.handleGetEntity, ""},
		{"edges", f.server.handleGetEdges, "/edges"},
		{"neighborhood", f.server.handleGetNeighborhood, "/neighborhood"},
		{"history", f.server.handleGetHistory, "/history?" + window},
		{"diff", f.server.handleDiff, "/diff?" + window},
		{"drift", f.server.handleGetDriftState, "/drift"},
		{"desired-state", f.server.handleGetDesiredState, "/desired-state"},
	}
	for i, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			vars := map[string]string{"eid": rgClientEID}
			path := "/api/v1/entities/" + rgClientEID + rt.suffix

			noCrossing := boundRootOperator("rg-keyed-no-" + string(rune('a'+i)))
			assertCrossingChallenge(t, f.get(t, rt.h, path, noCrossing, vars), rgMSP)

			// A root-owned entity is still served without a crossing.
			rec := f.get(t, rt.h, "/api/v1/entities/"+rgRootEID+rt.suffix, noCrossing, map[string]string{"eid": rgRootEID})
			assert.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

			withCrossing := boundRootOperator("rg-keyed-yes-" + string(rune('a'+i)))
			grantCrossing(t, f.server, withCrossing.ID, rgMSP)
			rec = f.get(t, rt.h, path, withCrossing, vars)
			assert.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
			assert.NotEqual(t, http.StatusInternalServerError, rec.Code, rec.Body.String())
		})
	}
}

// TestRootEntityEdges_DropClientEndpoint: an edge from a root entity to a client
// entity is not returned to a root caller without a crossing.
func TestRootEntityEdges_DropClientEndpoint(t *testing.T) {
	f := newRGFixture(t)
	vars := map[string]string{"eid": rgRootEID}
	path := "/api/v1/entities/" + rgRootEID + "/edges"

	rec := f.get(t, f.server.handleGetEdges, path, boundRootOperator("rg-edge-no"), vars)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var edges []*eginterfaces.EdgeView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &edges))
	assert.Empty(t, edges)

	with := boundRootOperator("rg-edge-yes")
	grantCrossing(t, f.server, with.ID, rgMSP)
	rec = f.get(t, f.server.handleGetEdges, path, with, vars)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	edges = nil
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &edges))
	assert.Len(t, edges, 1)
}

// TestFilterReadableNeighborhood drops a client-tenant neighbor and the edges that
// touch it, whatever the provider returned.
func TestFilterReadableNeighborhood(t *testing.T) {
	f := newRGFixture(t)
	rootEID, err := egtypes.ParseEID(rgRootEID)
	require.NoError(t, err)
	clientEID, err := egtypes.ParseEID(rgClientEID)
	require.NoError(t, err)
	n := &egtypes.Neighborhood{
		Root: rootEID,
		Nodes: []*egtypes.Entity{
			{EID: rootEID, OwningTenant: testRootTenantID},
			{EID: clientEID, OwningTenant: rgMSP},
		},
		Edges: []*egtypes.Edge{{Type: "runs-on", From: rootEID, To: clientEID}},
	}
	req := asRootOperator(httptest.NewRequest(http.MethodGet, "/x", nil), boundRootOperator("rg-nbr"), nil)
	scope := f.server.tenantReadScope(req, "TEST")
	got := filterReadableNeighborhood(scope, n)
	require.Len(t, got.Nodes, 1)
	assert.Equal(t, rgRootEID, got.Nodes[0].EID.String())
	assert.Empty(t, got.Edges)
}

// TestRootClusterReads_CrossingBoundary: clusters are built from readable
// stewards; a client cluster is challenged without a crossing and served with one.
func TestRootClusterReads_CrossingBoundary(t *testing.T) {
	server := seedRootTenant(t, wireCrossingStore(t, setupTestServer(t)))
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: rgMSP, ParentID: testRootTenantID})
	require.NoError(t, err)
	seedClusterSteward(t, server, "rg-root-s", testRootTenantID, nil, clusterFragment(t, "rg-root-cluster", map[string]string{"csv": "N1"}))
	seedClusterSteward(t, server, "rg-client-s", rgMSP, nil, clusterFragment(t, "rg-client-cluster", map[string]string{"csv": "N2"}))

	call := func(h http.HandlerFunc, path, name string, op *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, asRootOperator(httptest.NewRequest(http.MethodGet, path, nil), op, map[string]string{"name": name}))
		return rec
	}
	names := func(rec *httptest.ResponseRecorder) []string {
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var resp struct {
			Data []ClusterInfo `json:"data"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		out := []string{}
		for _, c := range resp.Data {
			out = append(out, c.Name)
		}
		return out
	}

	no := boundRootOperator("rg-cl-no")
	assert.Equal(t, []string{"rg-root-cluster"}, names(call(server.handleListClusters, "/api/v1/clusters", "", no)))
	assertCrossingChallenge(t, call(server.handleGetCluster, "/api/v1/clusters/rg-client-cluster", "rg-client-cluster", no), rgMSP)
	assertCrossingChallenge(t, call(server.handleClusterReconciliation, "/api/v1/clusters/rg-client-cluster/reconciliation", "rg-client-cluster", no), rgMSP)
	assert.Equal(t, http.StatusOK, call(server.handleGetCluster, "/api/v1/clusters/rg-root-cluster", "rg-root-cluster", no).Code)
	assert.Equal(t, http.StatusNotFound, call(server.handleGetCluster, "/api/v1/clusters/none", "none", no).Code)

	yes := boundRootOperator("rg-cl-yes")
	grantCrossing(t, server, yes.ID, rgMSP)
	assert.ElementsMatch(t, []string{"rg-root-cluster", "rg-client-cluster"}, names(call(server.handleListClusters, "/api/v1/clusters", "", yes)))
	assert.Equal(t, http.StatusOK, call(server.handleGetCluster, "/api/v1/clusters/rg-client-cluster", "rg-client-cluster", yes).Code)
	assert.Equal(t, http.StatusOK, call(server.handleClusterReconciliation, "/api/v1/clusters/rg-client-cluster/reconciliation", "rg-client-cluster", yes).Code)
}

// TestTenantAndCertAdminGraphReads_Unchanged: a tenant-scoped caller keeps its
// subtree (and a 404, never a challenge, outside it); an unrestricted certificate
// admin keeps root breadth.
func TestTenantAndCertAdminGraphReads_Unchanged(t *testing.T) {
	f := newRGFixture(t)

	t.Run("tenant-scoped MSP admin", func(t *testing.T) {
		call := func(h http.HandlerFunc, path string, vars map[string]string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			req := withClusterTenant(httptest.NewRequest(http.MethodGet, path, nil), rgMSP)
			h(rec, mux_SetVars(req, vars))
			return rec
		}
		assert.ElementsMatch(t, []string{rgClientEID}, rgEntityEIDs(t, call(f.server.handleQueryEntities, "/api/v1/entities", nil)))
		assert.Equal(t, http.StatusOK, call(f.server.handleGetEntity, "/x", map[string]string{"eid": rgClientEID}).Code)
		assert.Equal(t, http.StatusNotFound, call(f.server.handleGetEntity, "/x", map[string]string{"eid": rgRootEID}).Code)
	})

	t.Run("unrestricted certificate admin", func(t *testing.T) {
		call := func(h http.HandlerFunc, path string, vars map[string]string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			req := withClusterTenant(httptest.NewRequest(http.MethodGet, path, nil), "")
			h(rec, mux_SetVars(req, vars))
			return rec
		}
		assert.ElementsMatch(t, []string{rgRootEID, rgClientEID}, rgEntityEIDs(t, call(f.server.handleQueryEntities, "/api/v1/entities", nil)))
		assert.Equal(t, http.StatusOK, call(f.server.handleGetEntity, "/x", map[string]string{"eid": rgClientEID}).Code)
		assert.ElementsMatch(t, []string{rgRootEID, rgClientEID}, rgDriftEIDs(t, call(f.server.handleListDrifted, "/x", nil)))
	})
}

// TestIntakeAssist_DropsClientEntityWithoutCrossing: intake candidates that live
// in a client tenant are silently dropped for a boundary-subject root caller.
func TestIntakeAssist_DropsClientEntityWithoutCrossing(t *testing.T) {
	f := newRGFixture(t)
	reportEntityWithClaims(t, f.prov, "host:rg-intake-client", rgMSP, "rg-intake-client", "")
	claims := `{"hostname":"rg-intake-client"}`
	run := func(op *Principal) []eginterfaces.EIDRef {
		rec := httptest.NewRecorder()
		req := asRootOperator(httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist", stringsReader(claims)), op, nil)
		f.server.handleCasesIntakeAssist(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var out []eginterfaces.EIDRef
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
		return out
	}
	assert.Empty(t, run(boundRootOperator("rg-intake-no")))
	with := boundRootOperator("rg-intake-yes")
	grantCrossing(t, f.server, with.ID, rgMSP)
	assert.Len(t, run(with), 1)
}

func mux_SetVars(r *http.Request, vars map[string]string) *http.Request {
	if vars == nil {
		return r
	}
	return mux.SetURLVars(r, vars)
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

// TestCockpitWatch_RootCrossingBoundary: a root caller is challenged, before the
// WebSocket upgrade, for the watch of a client-tenant case and gets past the
// authorization step once it holds a crossing.
func TestCockpitWatch_RootCrossingBoundary(t *testing.T) {
	server := seedRootTenant(t, wireCrossingStore(t, setupCockpitWatchServer(t, newWatchProbe(t))))
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: rgMSP, ParentID: testRootTenantID})
	require.NoError(t, err)
	c := seedWatchCaseNoPins(t, server.casesStore, rgMSP)

	watch := func(op *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		server.handleCockpitWatch(rec, asRootOperator(
			httptest.NewRequest(http.MethodGet, "/api/v1/cases/"+c.ID+"/watch", nil), op, map[string]string{"id": c.ID}))
		return rec
	}
	assertCrossingChallenge(t, watch(boundRootOperator("rg-watch-no")), rgMSP)

	with := boundRootOperator("rg-watch-yes")
	grantCrossing(t, server, with.ID, rgMSP)
	// Past authorization the handler tries the WebSocket upgrade, which a plain
	// recorder request cannot complete: any answer but the challenge or 404 proves it.
	rec := watch(with)
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
	assert.NotEqual(t, http.StatusNotFound, rec.Code)
}
