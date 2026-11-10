// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/features/controller/health"
)

// osquerySignalsServer returns a test server with a real health collector, the
// given dispatcher and a fleet of the given steward IDs.
func osquerySignalsServer(t *testing.T, disp stewardOsqueryDispatcher, withCollector bool, ids ...string) (*Server, *health.Collector) {
	t.Helper()
	server := setupTestServer(t)
	var collector *health.Collector
	if withCollector {
		collector = health.NewCollector(nil, nil, nil, nil)
		server.healthCollector = collector
	}
	server.SetOsqueryDispatcher(disp)
	server.fleetQuery = fleetWithStewardIDs(ids...)
	return server, collector
}

func postOsqueryQuery(t *testing.T, server *Server, body osqueryQueryRequest) *httptest.ResponseRecorder {
	t.Helper()
	req := makeOsqueryRequest(t, server, body, osqueryStrongPrincipal())
	rec := httptest.NewRecorder()
	server.requirePermission("osquery", "execute")(http.HandlerFunc(server.handleOsqueryQuery)).ServeHTTP(rec, req)
	return rec
}

func osquerySignalText(t *testing.T, collector *health.Collector) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, collector.Signals().WriteText(&sb))
	return sb.String()
}

func TestOsqueryQuerySignalsOk(t *testing.T) {
	disp := &stubOsqueryDispatcher{rows: []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}}}
	server, collector := osquerySignalsServer(t, disp, true, "steward-1", "steward-2")

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	text := osquerySignalText(t, collector)
	assert.Contains(t, text, `cfgms_osquery_queries_total{outcome="ok"} 1`)
	assert.NotContains(t, text, `outcome="partial"`)
	assert.NotContains(t, text, `outcome="failed"`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_ok"} 2`)
	assert.NotContains(t, text, `steward_failed"}`)
	assert.Contains(t, text, "cfgms_osquery_query_duration_seconds_count 1")
	assert.Contains(t, text, "cfgms_osquery_query_duration_seconds_bucket{le=\"+Inf\"} 1")

	for _, forbidden := range []string{"host_info", "steward-1", "steward-2", "SELECT"} {
		assert.NotContains(t, text, forbidden, "no catalog ID, query text or steward ID in the exposition")
	}
}

func TestOsqueryQuerySignalsPartial(t *testing.T) {
	disp := &partialOsqueryDispatcher{
		failSteward: "steward-2",
		failErr:     errors.New("steward not connected to osquery stream"),
		rows:        []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}},
	}
	server, collector := osquerySignalsServer(t, disp, true, "steward-1", "steward-2", "steward-3")

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	text := osquerySignalText(t, collector)
	assert.Contains(t, text, `cfgms_osquery_queries_total{outcome="partial"} 1`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_failed"} 1`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_ok"} 2`)
	assert.Contains(t, text, "cfgms_osquery_query_duration_seconds_count 1")
	assert.NotContains(t, text, "steward-2")
}

func TestOsqueryQuerySignalsFailed(t *testing.T) {
	disp := &stubOsqueryDispatcher{err: errors.New("steward not connected")}
	server, collector := osquerySignalsServer(t, disp, true, "steward-1", "steward-2")

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	text := osquerySignalText(t, collector)
	assert.Contains(t, text, `cfgms_osquery_queries_total{outcome="failed"} 1`)
	assert.Contains(t, text, `cfgms_osquery_steward_results_total{result="steward_failed"} 2`)
	assert.NotContains(t, text, `result="steward_ok"`)
	assert.Contains(t, text, "cfgms_osquery_query_duration_seconds_count 1")

	// A request rejected before dispatch records nothing further.
	rec = postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "no_such_catalog_id", Selector: "all"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	rec = postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info"})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	text = osquerySignalText(t, collector)
	assert.Contains(t, text, `cfgms_osquery_queries_total{outcome="failed"} 1`)
	assert.Contains(t, text, "cfgms_osquery_query_duration_seconds_count 1")
}

func TestOsqueryQuerySignalsNilCollector(t *testing.T) {
	disp := &stubOsqueryDispatcher{rows: []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}}}
	server, _ := osquerySignalsServer(t, disp, false, "steward-1")
	require.Nil(t, server.healthCollector)

	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code, "a nil health collector must not affect the request")
	assert.Len(t, disp.calls, 1)
}
