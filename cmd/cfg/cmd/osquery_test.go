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
	"testing"

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
