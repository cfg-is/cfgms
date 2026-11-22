// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOsqueryCatalogCommand(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/osquery/catalog", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": []map[string]interface{}{
				{"id": "host_info", "params": []interface{}{}},
				{"id": "listening_ports", "params": []map[string]interface{}{
					{"name": "proto", "type": "enum", "allowed_values": []string{"tcp", "udp"}},
				}},
				{"id": "file_info", "params": []map[string]interface{}{{"name": "path", "type": "charset"}}},
			},
		})
	}))
	defer srv.Close()

	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")
	origURL, origInsecure, origBundle, origNoBundle := osqueryURL, osqueryTLSInsecure, bundlePath, noBundle
	osqueryURL, osqueryTLSInsecure, bundlePath, noBundle = srv.URL, true, bundleFilePath, false
	defer func() {
		osqueryURL, osqueryTLSInsecure, bundlePath, noBundle = origURL, origInsecure, origBundle, origNoBundle
	}()

	var out bytes.Buffer
	osqueryCatalogCmd.SetOut(&out)
	require.NoError(t, runOsqueryCatalog(osqueryCatalogCmd, nil))

	assert.Contains(t, out.String(), "host_info")
	assert.Contains(t, out.String(), "proto (enum: tcp|udp)")
	assert.Contains(t, out.String(), "path (charset)")
}

// setupOsqueryQueryTest points the osquery flags at srv with a test bundle and
// resets the query flags the command reads.
func setupOsqueryQueryTest(t *testing.T, srvURL string) *bytes.Buffer {
	t.Helper()
	bundleFilePath := filepath.Join(t.TempDir(), "admin.bundle.yaml")
	generateTestBundleFile(t, bundleFilePath, "https://placeholder.local:9443")
	origURL, origInsecure, origBundle, origNoBundle := osqueryURL, osqueryTLSInsecure, bundlePath, noBundle
	origSel, origParams := osquerySelector, osqueryParams
	osqueryURL, osqueryTLSInsecure, bundlePath, noBundle = srvURL, true, bundleFilePath, false
	t.Cleanup(func() {
		osqueryURL, osqueryTLSInsecure, bundlePath, noBundle = origURL, origInsecure, origBundle, origNoBundle
		osquerySelector, osqueryParams = origSel, origParams
	})
	var out bytes.Buffer
	osqueryQueryCmd.SetOut(&out)
	return &out
}

func TestOsqueryQueryCommand_SendsBodyAndRelaysPresence(t *testing.T) {
	const presenceToken = "presence-token-5454"
	var retried int
	var gotBody map[string]interface{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/osquery/query", r.URL.Path)
		if r.Header.Get("X-Presence-Token") != presenceToken {
			w.Header().Set("WWW-Authenticate", `CFGMS-StepUp realm="cfgms", required="strong", presence="required", permission="osquery:execute"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		retried++
		raw, _ := io.ReadAll(r.Body)
		require.NoError(t, json.Unmarshal(raw, &gotBody))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"results": []map[string]interface{}{
				{"steward_id": "stw-1", "rows": []map[string]string{{"port": "22", "proto": "tcp"}}},
			}},
		})
	}))
	defer srv.Close()

	out := setupOsqueryQueryTest(t, srv.URL)
	origTerminal, origFlow := isTerminalFn, presenceBrowserFlowFn
	t.Cleanup(func() { isTerminalFn, presenceBrowserFlowFn = origTerminal, origFlow })
	isTerminalFn = func() bool { return true }
	var relayed string
	presenceBrowserFlowFn = func(_ *APIClient, _, _ string, _ []byte, permission string) (string, error) {
		relayed = permission
		return presenceToken, nil
	}

	osquerySelector = "tenant:acme"
	osqueryParams = []string{"proto=tcp", "empty="}
	require.NoError(t, runOsqueryQuery(osqueryQueryCmd, []string{"listening_ports"}))

	assert.Equal(t, "osquery:execute", relayed)
	assert.Equal(t, 1, retried)
	assert.Equal(t, "listening_ports", gotBody["catalog_id"])
	assert.Equal(t, "tenant:acme", gotBody["selector"])
	assert.Equal(t, map[string]interface{}{"proto": "tcp", "empty": ""}, gotBody["params"])
	assert.Contains(t, out.String(), "stw-1")
	assert.Contains(t, out.String(), "22")
	assert.Contains(t, out.String(), "tcp")
}

func TestOsqueryQueryCommand_RequiresSelector(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()
	setupOsqueryQueryTest(t, srv.URL)

	osquerySelector = "  "
	err := runOsqueryQuery(osqueryQueryCmd, []string{"host_info"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--selector")
	assert.Equal(t, 0, hits, "no request may be made with an empty selector")
}

func TestOsqueryQueryCommand_ParamErrors(t *testing.T) {
	setupOsqueryQueryTest(t, "http://127.0.0.1:1")
	osquerySelector = "all"

	osqueryParams = []string{"k=1", "k=2"}
	err := runOsqueryQuery(osqueryQueryCmd, []string{"x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parameter k given twice")

	osqueryParams = []string{"novalue"}
	err = runOsqueryQuery(osqueryQueryCmd, []string{"x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "k=v")
}

func TestOsqueryQueryCommand_ShowsPerStewardErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"results": []map[string]interface{}{
				{"steward_id": "stw-ok", "rows": []map[string]string{}},
				{"steward_id": "stw-bad", "rows": []map[string]string{}, "error": "osquery not installed"},
			}},
		})
	}))
	defer srv.Close()
	out := setupOsqueryQueryTest(t, srv.URL)

	osquerySelector = "all"
	require.NoError(t, runOsqueryQuery(osqueryQueryCmd, []string{"host_info"}))

	s := out.String()
	assert.Contains(t, s, "stw-bad")
	assert.Contains(t, s, "error: osquery not installed")
	assert.Contains(t, s, "stw-ok")
	assert.Contains(t, s, "(no rows)")
	assert.NotContains(t, s, "stw-ok: error")
}

func TestOsqueryQueryCommand_EscapesControlCharacters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{"results": []map[string]interface{}{
				{"steward_id": "stw\x1b]0;x\x07", "rows": []map[string]string{}, "error": "bad\x1b[2Jerr\r"},
				{"steward_id": "stw-2", "rows": []map[string]string{{"c\x1b[1m": "v\x1b[31mal\u009b\u202e"}}},
			}},
		})
	}))
	defer srv.Close()
	out := setupOsqueryQueryTest(t, srv.URL)

	osquerySelector = "all"
	require.NoError(t, runOsqueryQuery(osqueryQueryCmd, []string{"host_info"}))

	s := out.String()
	assert.NotContains(t, s, "\x1b")
	assert.NotContains(t, s, "\x07")
	assert.NotContains(t, s, "\r")
	assert.NotContains(t, s, "\u009b")
	assert.NotContains(t, s, "\u202e")
	assert.Contains(t, s, `bad\x1b[2Jerr\x0d`)
	assert.Contains(t, s, `v\x1b[31mal\x9b`)
}

// serveOsqueryQuery returns a test server that answers the query route with body.
func serveOsqueryQuery(t *testing.T, body map[string]interface{}) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/osquery/query", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runOsqueryQueryAgainst runs the query command against body and returns the output.
func runOsqueryQueryAgainst(t *testing.T, body map[string]interface{}) string {
	t.Helper()
	srv := serveOsqueryQuery(t, body)
	out := setupOsqueryQueryTest(t, srv.URL)
	osquerySelector = "all"
	require.NoError(t, runOsqueryQuery(osqueryQueryCmd, []string{"host_info"}))
	return out.String()
}

// requireOrdered asserts each needle occurs in s, each after the previous one.
func requireOrdered(t *testing.T, s string, needles ...string) {
	t.Helper()
	prev, prevNeedle := -1, ""
	for _, n := range needles {
		idx := strings.Index(s, n)
		require.GreaterOrEqual(t, idx, 0, "missing %q in output:\n%s", n, s)
		require.Greater(t, idx, prev, "%q must come after %q in output:\n%s", n, prevNeedle, s)
		prev, prevNeedle = idx, n
	}
}

func TestOsqueryQueryCommand_GroupsByOutcomeInOrder(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{
		"data": map[string]interface{}{
			"summary": map[string]interface{}{
				"matched": 5, "answered": 2, "not_connected": 2, "failed": 1,
				"queried_at": "2026-11-22T14:03:05.123Z",
			},
			"results": []map[string]interface{}{
				{"steward_id": "s-fail", "error": "osquery execution failed", "outcome": "failed"},
				{"steward_id": "s-ans1", "rows": []map[string]string{{"hostname": "host-one"}}, "outcome": "answered"},
				{"steward_id": "s-nr-seen", "error": "osquery: steward not connected to osquery stream", "outcome": "not_connected", "last_seen": "2026-11-22T13:40:00Z"},
				{"steward_id": "s-ans2", "outcome": "answered"},
				{"steward_id": "s-nr-never", "error": "osquery: steward not connected to osquery stream", "outcome": "not_connected"},
			},
		},
		"timestamp": "2026-11-22T14:03:06Z",
	})
	t.Logf("output:\n%s", s)

	firstLine, _, _ := strings.Cut(s, "\n")
	assert.Equal(t, "5 matched: 2 answered, 2 not reached, 1 failed. Queried at 2026-11-22T14:03:05Z.", firstLine)

	requireOrdered(t, s,
		firstLine,
		"ANSWERED (2)",
		"STEWARD s-ans1", "host-one",
		"STEWARD s-ans2", "(no rows)",
		"NOT REACHED (2)",
		"  s-nr-seen", "last seen 2026-11-22T13:40:00Z (23m before the query)",
		"  s-nr-never", "no check-in recorded",
		"FAILED (1)",
		"  s-fail", "error: osquery execution failed",
	)
	assert.Contains(t, s, "hostname")
	assert.NotContains(t, s, "steward not connected to osquery stream",
		"the not-reached group must not show the error text")
	neverLine := osqueryOutputLine(t, s, "s-nr-never")
	assert.Contains(t, neverLine, "no check-in recorded")
	assert.NotContains(t, neverLine, "last seen")
}

// osqueryOutputLine returns the single output line containing needle.
func osqueryOutputLine(t *testing.T, s, needle string) string {
	t.Helper()
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	require.Failf(t, "line not found", "no line contains %q in output:\n%s", needle, s)
	return ""
}

func TestOsqueryQueryCommand_ZeroMatched(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{
		"data": map[string]interface{}{
			"summary": map[string]interface{}{
				"matched": 0, "answered": 0, "not_connected": 0, "failed": 0,
				"queried_at": "2026-11-22T14:03:05Z",
			},
			"results": []map[string]interface{}{},
		},
	})
	assert.Equal(t,
		"0 matched: 0 answered, 0 not reached, 0 failed. Queried at 2026-11-22T14:03:05Z.\n"+
			"No stewards matched the selector.\n", s)
}

func TestOsqueryQueryCommand_EmptyGroupsNotPrinted(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{
		"data": map[string]interface{}{
			"summary": map[string]interface{}{
				"matched": 1, "answered": 1, "not_connected": 0, "failed": 0,
				"queried_at": "2026-11-22T14:03:05Z",
			},
			"results": []map[string]interface{}{
				{"steward_id": "s-1", "rows": []map[string]string{{"hostname": "h"}}, "outcome": "answered"},
			},
		},
	})
	assert.True(t, strings.HasPrefix(s, "1 matched: 1 answered, 0 not reached, 0 failed. Queried at 2026-11-22T14:03:05Z.\n"), s)
	assert.Contains(t, s, "ANSWERED (1)")
	assert.NotContains(t, s, "NOT REACHED")
	assert.NotContains(t, s, "FAILED")
}

func TestOsqueryQueryCommand_OlderControllerDerivesOutcome(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{
		"data": map[string]interface{}{"results": []map[string]interface{}{
			{"steward_id": "s-1", "rows": []map[string]string{{"hostname": "h"}}},
			{"steward_id": "s-2", "error": "osquery not installed"},
			{"steward_id": "s-3", "rows": []map[string]string{}},
			{"steward_id": "s-4", "outcome": "bogus"},
		}},
	})
	firstLine, _, _ := strings.Cut(s, "\n")
	assert.Equal(t, "4 matched: 3 answered, 0 not reached, 1 failed.", firstLine)
	assert.NotContains(t, s, "Queried at")
	assert.NotContains(t, s, "NOT REACHED")
	requireOrdered(t, s, "ANSWERED (3)", "STEWARD s-1", "STEWARD s-3", "STEWARD s-4",
		"FAILED (1)", "  s-2", "error: osquery not installed")
}

func TestOsqueryQueryCommand_EscapesControlCharactersInGroups(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{
		"data": map[string]interface{}{
			"summary": map[string]interface{}{
				"matched": 2, "answered": 0, "not_connected": 1, "failed": 1,
				"queried_at": "2026-11-22T14:03:05Z",
			},
			"results": []map[string]interface{}{
				{"steward_id": "nr\x1b]0;x\x07\t", "outcome": "not_connected", "error": "e"},
				{"steward_id": "f\u202e", "outcome": "failed", "error": "bad\x1b[2Jerr\r\n"},
			},
		},
	})
	for _, raw := range []string{"\x1b", "\x07", "\r", "\t", "\u202e"} {
		assert.NotContains(t, s, raw)
	}
	assert.Contains(t, s, `nr\x1b]0;x\x07\x09`)
	assert.Contains(t, s, `f\u202e`)
	assert.Contains(t, s, `error: bad\x1b[2Jerr\x0d\x0a`)
}

func TestOsqueryQueryCommand_HelpDescribesOutcomes(t *testing.T) {
	long := osqueryQueryCmd.Long
	for _, want := range []string{"summary", "matched", "answered", "not reached", "failed", "last seen", "presence", "controller node", "no check-in recorded"} {
		assert.Contains(t, long, want)
	}
	assert.NotContains(t, strings.ToLower(long), "planned")
	assert.NotContains(t, strings.ToLower(long), "not yet")
}

func TestOsqueryAge(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{59600 * time.Millisecond, "59s"},
		{60 * time.Second, "1m"},
		{23 * time.Minute, "23m"},
		{59*time.Minute + 59*time.Second, "59m"},
		{time.Hour, "1h"},
		{23*time.Hour + 59*time.Minute, "23h"},
		{24 * time.Hour, "1d"},
		{49 * time.Hour, "2d"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, osqueryAge(tc.d), "osqueryAge(%s)", tc.d)
	}
}

func TestOsqueryQueryCommand_SummaryAndLastSeenEdges(t *testing.T) {
	const queriedAt = "2026-11-22T14:03:05Z"
	notReached := func(lastSeen string) map[string]interface{} {
		r := map[string]interface{}{"steward_id": "s-nr", "outcome": "not_connected", "error": "e"}
		if lastSeen != "" {
			r["last_seen"] = lastSeen
		}
		return r
	}
	summary := func(q string) map[string]interface{} {
		s := map[string]interface{}{"matched": 1, "answered": 0, "not_connected": 1, "failed": 0}
		if q != "" {
			s["queried_at"] = q
		}
		return s
	}
	cases := []struct {
		name      string
		body      map[string]interface{}
		firstLine string
		lineWith  string
		lineHas   string
		lineLacks string
	}{
		{
			name: "server counts are printed, not recounted",
			body: map[string]interface{}{"data": map[string]interface{}{
				"summary": map[string]interface{}{"matched": 9, "answered": 4, "not_connected": 3, "failed": 2, "queried_at": queriedAt},
				"results": []map[string]interface{}{
					{"steward_id": "s-a", "outcome": "answered"},
					notReached(""),
					{"steward_id": "s-f", "outcome": "failed", "error": "x"},
				},
			}},
			firstLine: "9 matched: 4 answered, 3 not reached, 2 failed. Queried at " + queriedAt + ".",
		},
		{
			name: "summary without queried_at",
			body: map[string]interface{}{"data": map[string]interface{}{
				"summary": summary(""), "results": []map[string]interface{}{notReached("2026-11-22T13:40:00Z")},
			}},
			firstLine: "1 matched: 0 answered, 1 not reached, 0 failed.",
			lineWith:  "s-nr", lineHas: "last seen 2026-11-22T13:40:00Z", lineLacks: "(",
		},
		{
			name: "last_seen after queried_at",
			body: map[string]interface{}{"data": map[string]interface{}{
				"summary": summary(queriedAt), "results": []map[string]interface{}{notReached("2026-11-22T14:10:00Z")},
			}},
			lineWith: "s-nr", lineHas: "last seen 2026-11-22T14:10:00Z", lineLacks: "(",
		},
		{
			name: "zero last_seen is no check-in",
			body: map[string]interface{}{"data": map[string]interface{}{
				"summary": summary(queriedAt), "results": []map[string]interface{}{notReached("0001-01-01T00:00:00Z")},
			}},
			lineWith: "s-nr", lineHas: "no check-in recorded", lineLacks: "last seen",
		},
		{
			name: "top-level results without data envelope",
			body: map[string]interface{}{"results": []map[string]interface{}{
				{"steward_id": "s-top", "rows": []map[string]string{{"hostname": "h-top"}}},
			}},
			firstLine: "1 matched: 1 answered, 0 not reached, 0 failed.",
			lineWith:  "h-top", lineHas: "h-top",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := runOsqueryQueryAgainst(t, tc.body)
			if tc.firstLine != "" {
				firstLine, _, _ := strings.Cut(s, "\n")
				assert.Equal(t, tc.firstLine, firstLine)
			}
			if tc.lineWith == "" {
				return
			}
			line := osqueryOutputLine(t, s, tc.lineWith)
			assert.Contains(t, line, tc.lineHas)
			if tc.lineLacks != "" {
				assert.NotContains(t, line, tc.lineLacks)
			}
		})
	}
}

func TestOsqueryQueryCommand_AnsweredWithErrorInFailedGroup(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{"data": map[string]interface{}{
		"results": []map[string]interface{}{{"steward_id": "s-x", "outcome": "answered", "error": "boom"}},
	}})
	requireOrdered(t, s, "1 matched: 0 answered, 0 not reached, 1 failed.", "FAILED (1)", "  s-x", "error: boom")
	assert.NotContains(t, s, "ANSWERED")
}

func TestOsqueryQueryCommand_NullResultsInData(t *testing.T) {
	s := runOsqueryQueryAgainst(t, map[string]interface{}{"data": map[string]interface{}{
		"summary": map[string]interface{}{"matched": 0, "answered": 0, "not_connected": 0, "failed": 0},
		"results": nil,
	}})
	assert.Equal(t, "0 matched: 0 answered, 0 not reached, 0 failed.\nNo stewards matched the selector.\n", s)
}
