// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// docSignalRow returns the cells of the row of the signal document's table whose
// first cell is the backticked metric name.
func docSignalRow(t *testing.T, doc, name string) []string {
	t.Helper()
	prefix := "| `" + name + "` |"
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		require.Len(t, cells, 5, "%s: the row must have metric, type, labels, buckets and meaning", name)
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		return cells
	}
	require.Failf(t, "signal row missing", "%s has no row in %s", name, signalDocPath)
	return nil
}

// TestOsqueryQuerySignalsMatchDoc drives a real live-query fan-out, so the lazily
// registered osquery instruments exist, and compares each one's type, labels,
// buckets and help text with its row in the signal document. The server package's
// doc test cannot reach this endpoint (it needs a strong-assurance principal), so
// this test owns the check for these three signals.
func TestOsqueryQuerySignalsMatchDoc(t *testing.T) {
	disp := &partialOsqueryDispatcher{
		failSteward: "steward-2",
		failErr:     errors.New("steward not connected to osquery stream"),
		rows:        []*transportpb.OsqueryRow{{Columns: map[string]string{"hostname": "h"}}},
	}
	server, collector := osquerySignalsServer(t, disp, true, "steward-1", "steward-2")
	rec := postOsqueryQuery(t, server, osqueryQueryRequest{CatalogID: "host_info", Selector: "all"})
	require.Equal(t, http.StatusOK, rec.Code)

	text := osquerySignalText(t, collector)
	b, err := os.ReadFile(filepath.FromSlash(signalDocPath))
	require.NoError(t, err, "the signal document must exist")
	doc := string(b)

	labelName := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="`)
	leValue := regexp.MustCompile(`le="([^"]+)"`)

	for _, name := range []string{
		"cfgms_osquery_query_duration_seconds",
		"cfgms_osquery_queries_total",
		"cfgms_osquery_steward_results_total",
	} {
		var kind, help string
		labels := map[string]bool{}
		var buckets []string
		for _, line := range strings.Split(text, "\n") {
			switch {
			case strings.HasPrefix(line, "# HELP "+name+" "):
				help = strings.TrimPrefix(line, "# HELP "+name+" ")
			case strings.HasPrefix(line, "# TYPE "+name+" "):
				kind = strings.TrimPrefix(line, "# TYPE "+name+" ")
			case strings.HasPrefix(line, name+"{") || strings.HasPrefix(line, name+"_bucket{"):
				pairs := line[strings.Index(line, "{"):strings.Index(line, "}")]
				for _, m := range labelName.FindAllStringSubmatch(pairs, -1) {
					if m[1] != "le" {
						labels[m[1]] = true
					}
				}
				if le := leValue.FindStringSubmatch(pairs); le != nil && le[1] != "+Inf" {
					buckets = append(buckets, le[1])
				}
			}
		}
		require.NotEmpty(t, kind, "%s must be registered once a fan-out ran", name)

		wantLabels := make([]string, 0, len(labels))
		for l := range labels {
			wantLabels = append(wantLabels, l)
		}
		sort.Strings(wantLabels)

		cells := docSignalRow(t, doc, name)
		var docLabels, docBuckets []string
		for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(cells[2], -1) {
			docLabels = append(docLabels, m[1])
		}
		sort.Strings(docLabels)
		if cells[3] != "—" {
			for _, v := range strings.Split(cells[3], ",") {
				docBuckets = append(docBuckets, strings.TrimSpace(v))
			}
		}

		assert.Equal(t, kind, cells[1], "%s: type", name)
		assert.Equal(t, help, cells[4], "%s: meaning must be the registry's help text", name)
		assert.Equal(t, wantLabels, append([]string{}, docLabels...), "%s: labels", name)
		assert.Equal(t, buckets, docBuckets, "%s: buckets", name)
	}

	// Both result and outcome values the fan-out produced are listed with their metric.
	for _, v := range []string{"steward_ok", "steward_failed", "partial"} {
		assert.Contains(t, text, v)
		assert.Contains(t, doc, "`"+v+"`", "label value %s must be documented", v)
	}
}
