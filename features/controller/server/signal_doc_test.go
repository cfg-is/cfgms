// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

const (
	signalDocPath  = "../../../docs/operations/service-level-signals.md"
	monitoringDoc  = "../../../docs/monitoring.md"
	operationsDoc  = "../../../docs/operations/README.md"
	containerDoc   = "../../../docs/deployment/container/README.md"
	docNoneMarker  = "—"
	signalsHeading = "## Signals"
)

// docSignal is one row of the signal table in the signal document.
type docSignal struct {
	kind    string
	labels  []string
	buckets []string
	help    string
}

// scrapedSignal is one metric family as the controller's registry renders it.
type scrapedSignal struct {
	kind        string
	help        string
	labelNames  map[string]bool
	labelValues map[string]map[string]bool
	buckets     []string
	hasSeries   bool
}

func readDoc(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.FromSlash(path))
	require.NoError(t, err, "document %s must exist", path)
	return string(b)
}

// tableRows returns the cells of every row in the first markdown table that
// follows heading, up to the next heading. The header and separator rows are
// dropped.
func tableRows(t *testing.T, doc, heading string) [][]string {
	t.Helper()
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == heading {
			start = i + 1
			break
		}
	}
	require.NotEqual(t, -1, start, "heading %q not found", heading)

	var rows [][]string
	for _, l := range lines[start:] {
		if strings.HasPrefix(l, "#") {
			break
		}
		if !strings.HasPrefix(l, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(strings.TrimSpace(l), "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, cells)
	}
	require.GreaterOrEqual(t, len(rows), 2, "table under %q is missing", heading)
	return rows[2:]
}

// backtickItems returns the backticked items of a table cell, or nil for the
// none marker.
func backtickItems(cell string) []string {
	if cell == docNoneMarker {
		return nil
	}
	var items []string
	for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(cell, -1) {
		items = append(items, m[1])
	}
	return items
}

func parseSignalDoc(t *testing.T, doc string) map[string]docSignal {
	t.Helper()
	out := map[string]docSignal{}
	for _, cells := range tableRows(t, doc, signalsHeading) {
		require.Len(t, cells, 5, "signal row must have metric, type, labels, buckets and meaning: %v", cells)
		names := backtickItems(cells[0])
		require.Len(t, names, 1, "metric cell must hold exactly one name: %q", cells[0])
		require.NotContains(t, out, names[0], "metric %s is listed twice", names[0])

		var buckets []string
		if cells[3] != docNoneMarker {
			for _, b := range strings.Split(cells[3], ",") {
				buckets = append(buckets, strings.TrimSpace(b))
			}
		}
		labels := backtickItems(cells[2])
		sort.Strings(labels)
		out[names[0]] = docSignal{kind: cells[1], labels: labels, buckets: buckets, help: cells[4]}
	}
	return out
}

var (
	seriesLinePattern = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? `)
	labelPairPattern  = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)
)

// parseScrape reads the registry's text exposition into metric families.
func parseScrape(t *testing.T, text string) map[string]*scrapedSignal {
	t.Helper()
	families := map[string]*scrapedSignal{}
	family := func(name string) *scrapedSignal {
		if f, ok := families[name]; ok {
			return f
		}
		f := &scrapedSignal{labelNames: map[string]bool{}, labelValues: map[string]map[string]bool{}}
		families[name] = f
		return f
	}

	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name, help, _ := strings.Cut(strings.TrimPrefix(line, "# HELP "), " ")
			family(name).help = help
		case strings.HasPrefix(line, "# TYPE "):
			name, kind, _ := strings.Cut(strings.TrimPrefix(line, "# TYPE "), " ")
			family(name).kind = kind
		case line == "" || strings.HasPrefix(line, "#"):
		default:
			m := seriesLinePattern.FindStringSubmatch(line)
			require.NotNil(t, m, "unparseable series line %q", line)
			name := m[1]
			isBucket := false
			if _, ok := families[name]; !ok {
				for _, suffix := range []string{"_bucket", "_sum", "_count"} {
					if base := strings.TrimSuffix(name, suffix); base != name && families[base] != nil {
						name, isBucket = base, suffix == "_bucket"
						break
					}
				}
			}
			f := family(name)
			f.hasSeries = true
			for _, p := range labelPairPattern.FindAllStringSubmatch(m[2], -1) {
				if p[1] == "le" {
					if isBucket && p[2] != "+Inf" && !contains(f.buckets, p[2]) {
						f.buckets = append(f.buckets, p[2])
					}
					continue
				}
				f.labelNames[p[1]] = true
				if f.labelValues[p[1]] == nil {
					f.labelValues[p[1]] = map[string]bool{}
				}
				f.labelValues[p[1]][p[2]] = true
			}
		}
	}
	return families
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// newSignalDocServer builds a real controller server and attaches the
// components that are optional in a minimal configuration (heartbeat service,
// control plane transport, command publisher), so every signal source
// registers.
func newSignalDocServer(t *testing.T) *Server {
	t.Helper()
	t.Setenv("CFGMS_SECRETS_REPO_PATH", t.TempDir())
	srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())

	cp := &statsControlPlane{}
	svc, err := heartbeat.New(&heartbeat.Config{
		ControlPlane:          cp,
		StewardOfflineTimeout: time.Minute,
		Logger:                logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	srv.heartbeatService = svc
	srv.controlPlane = cp
	srv.commandPublisher = newCommandSignalTestPublisher(t)
	return srv
}

// TestSignalDocMatchesRegistry builds a real server, runs the signal sources
// and compares the registry's metrics with the signal document in both
// directions: every registered metric is documented, every documented metric is
// registered, and the type, labels, buckets and meaning agree.
func TestSignalDocMatchesRegistry(t *testing.T) {
	srv := newSignalDocServer(t)

	srv.startHealthServices()
	t.Cleanup(srv.stopHealthServices)

	// Drive one completed and one failed send so the labeled command series exist.
	ctx := context.Background()
	id, err := srv.commandPublisher.PublishCommandWithCallback(ctx, "steward-1", types.CommandSyncConfig, nil, 60*time.Second, nil, nil)
	require.NoError(t, err)
	require.NoError(t, srv.commandPublisher.HandleEventUpdate(ctx, &types.Event{
		Type: types.EventCommandCompleted, StewardID: "steward-1", CommandID: id,
	}))
	require.Error(t, srv.commandPublisher.PublishCommandWithID(ctx, "cmd-doc-2", "steward-gone", types.CommandSyncDNA, nil))

	// The API request signals register on the first request through the real API
	// handler, so send one before scraping. /api/v1/health needs no credential.
	apiSrv := srv.GetAPIServer()
	require.NotNil(t, apiSrv, "the server must have built its API handler")
	rec := httptest.NewRecorder()
	apiSrv.GetRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	require.Equal(t, http.StatusOK, rec.Code, "the seed request must be served")

	// The first collector tick samples the storage probe and heartbeat gauge.
	var scraped map[string]*scrapedSignal
	require.Eventually(t, func() bool {
		var sb strings.Builder
		if err := srv.healthCollector.Signals().WriteText(&sb); err != nil {
			return false
		}
		scraped = parseScrape(t, sb.String())
		storage, ok := scraped["cfgms_storage_probe_duration_seconds"]
		return ok && storage.hasSeries
	}, 10*time.Second, 10*time.Millisecond, "the storage probe must run on the first collector tick")

	doc := readDoc(t, signalDocPath)
	documented := parseSignalDoc(t, doc)

	assert.Equal(t, sortedNames(scraped), sortedNames(documented),
		"the registered metric names and the documented metric names must match both ways")

	for name, want := range documented {
		got, ok := scraped[name]
		if !ok {
			continue
		}
		assert.Equal(t, got.kind, want.kind, "%s: type", name)
		assert.Equal(t, got.help, want.help, "%s: meaning must be the registry's help text", name)

		if got.hasSeries {
			gotLabels := sortedNames(got.labelNames)
			assert.Equal(t, gotLabels, orEmpty(want.labels), "%s: labels", name)
		} else {
			assert.Empty(t, want.labels, "%s: a labeled metric must be exercised so its labels are checked", name)
		}
		if got.kind == "histogram" {
			assert.Equal(t, expectedBuckets(t, name, got), want.buckets, "%s: buckets", name)
		} else {
			assert.Empty(t, want.buckets, "%s: only a histogram has buckets", name)
		}
	}

	// Every observed value of a closed label set is listed in the label tables.
	for _, name := range []string{
		"cfgms_command_send_total", "cfgms_command_completion_seconds",
		"cfgms_api_requests_total", "cfgms_api_request_duration_seconds",
	} {
		require.NotNil(t, scraped[name], "%s must be registered once an API request has been served", name)
		require.True(t, scraped[name].hasSeries, "%s must have a series from the seed request", name)
		for label, values := range scraped[name].labelValues {
			for v := range values {
				assert.Contains(t, doc, "`"+v+"`", "%s: %s value %q is not documented", name, label, v)
			}
		}
	}
	require.True(t, scraped["cfgms_command_send_total"].labelValues["outcome"]["sent"])
	require.True(t, scraped["cfgms_command_send_total"].labelValues["outcome"]["send_failed"])
	require.True(t, scraped["cfgms_api_requests_total"].labelValues["route_class"]["health"])
	require.True(t, scraped["cfgms_api_requests_total"].labelValues["status_class"]["2xx"])

	// The built-in collector series must not be listed as registered signals.
	for _, cells := range tableRows(t, doc, "### Built-in collector series") {
		names := backtickItems(cells[0])
		require.Len(t, names, 1)
		assert.NotContains(t, documented, names[0], "a built-in series is not a registered signal")
	}
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// expectedBuckets returns the bucket bounds a histogram renders: the scraped
// ones, or for the convergence histogram (which has no series until a push
// completes) the bounds the observer is registered with.
func expectedBuckets(t *testing.T, name string, got *scrapedSignal) []string {
	t.Helper()
	if len(got.buckets) > 0 {
		return got.buckets
	}
	require.Equal(t, convergenceSecondsMetric, name, "histogram %s has no series to read its buckets from", name)
	out := make([]string, len(convergenceBuckets))
	for i, b := range convergenceBuckets {
		out[i] = strconv.FormatFloat(b, 'g', -1, 64)
	}
	return out
}

// TestSignalDocStatesLimits checks that the signal document keeps stating the
// limits the registry cannot express, and that the monitoring guide documents
// the signal and marker routes.
func TestSignalDocStatesLimits(t *testing.T) {
	doc := readDoc(t, signalDocPath)
	for _, phrase := range []string{
		"Per controller node",
		"summed",
		"30 seconds",
		"command-completed event",
		"on-connect and periodic applies",
		"dedupe is durable",
		"Tenant-scoped rollouts are not markers",
	} {
		assert.Contains(t, strings.ToLower(doc), strings.ToLower(phrase), "limit not stated: %s", phrase)
	}

	monitoring := readDoc(t, monitoringDoc)
	for _, route := range []string{
		"/api/v1/health/metrics/prometheus",
		"/api/v1/monitoring/markers",
		"operations/service-level-signals.md",
	} {
		assert.Contains(t, monitoring, route, "docs/monitoring.md must mention %s", route)
	}
	assert.Contains(t, readDoc(t, operationsDoc), "service-level-signals.md")
	assert.Contains(t, readDoc(t, containerDoc), "service-level-signals.md")
}
