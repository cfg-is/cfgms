// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type reportCapture struct {
	mu     sync.Mutex
	method string
	uri    string
	path   string
	body   map[string]interface{}
	calls  int
}

func (c *reportCapture) snapshot() (string, string, string, map[string]interface{}, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.method, c.path, c.uri, c.body, c.calls
}

// setupReportTest starts a real HTTP server, points the report verbs at it and
// restores every flag variable afterwards.
func setupReportTest(t *testing.T, status int, resp string, hdr map[string]string) *reportCapture {
	t.Helper()
	rc := &reportCapture{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		rc.mu.Lock()
		rc.method, rc.path, rc.uri = r.Method, r.URL.Path, r.URL.RequestURI()
		rc.calls++
		rc.body = nil
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &rc.body)
		}
		rc.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(resp))
	}))
	t.Cleanup(ts.Close)

	origs := []interface{}{reportURL, reportTLSInsecure, reportFile, reportYes, reportShareWith,
		reportSharePerms, reportShareExpiry, reportStreamToken, reportPage, reportPageSize, output}
	t.Cleanup(func() {
		reportURL, reportTLSInsecure, reportFile, reportYes = origs[0].(string), origs[1].(bool), origs[2].(string), origs[3].(bool)
		reportShareWith, reportSharePerms, reportShareExpiry = origs[4].([]string), origs[5].([]string), origs[6].(string)
		reportStreamToken, reportPage, reportPageSize, output = origs[7].(string), origs[8].(int), origs[9].(int), origs[10].(string)
	})
	reportURL = ts.URL
	reportTLSInsecure = true
	output = "text"
	return rc
}

func writeReportDef(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

const reportTemplateListResp = `{"templates":[{"id":"t-1","name":"Fleet Health","tenant_id":"acme-corp","is_shared":true,"usage_count":3,"updated_at":"2026-10-01T00:00:00Z"}],"count":1}`

func TestReportTemplateList(t *testing.T) {
	rc := setupReportTest(t, 200, reportTemplateListResp, nil)
	out := captureStdout(t, func() { require.NoError(t, runReportTemplateList(reportTemplateListCmd, nil)) })
	m, p, _, _, _ := rc.snapshot()
	assert.Equal(t, http.MethodGet, m)
	assert.Equal(t, "/api/v1/reports/custom-templates", p)
	assert.Contains(t, out, "ID")
	assert.Contains(t, out, "t-1")
	assert.Contains(t, out, "Fleet Health")

	output = "json"
	out = captureStdout(t, func() { require.NoError(t, runReportTemplateList(reportTemplateListCmd, nil)) })
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &parsed))
	assert.EqualValues(t, 1, parsed["count"])
}

func TestReportTemplateShow(t *testing.T) {
	rc := setupReportTest(t, 200, `{"id":"t-1","name":"Fleet Health","query":{"data_sources":["dna"]}}`, nil)
	out := captureStdout(t, func() { require.NoError(t, runReportTemplateShow(reportTemplateShowCmd, []string{"t-1"})) })
	m, p, _, _, _ := rc.snapshot()
	assert.Equal(t, http.MethodGet, m)
	assert.Equal(t, "/api/v1/reports/custom-templates/t-1", p)
	assert.Contains(t, out, "Fleet Health")
	assert.Contains(t, out, "dna")
}

func TestReportTemplateCreate(t *testing.T) {
	rc := setupReportTest(t, 201, `{"id":"t-9","name":"New"}`, nil)
	reportFile = writeReportDef(t, "t.yaml", "name: New\nquery:\n  data_sources: [dna]\n")
	out := captureStdout(t, func() { require.NoError(t, runReportTemplateCreate(reportTemplateCreateCmd, nil)) })
	m, p, _, body, _ := rc.snapshot()
	assert.Equal(t, http.MethodPost, m)
	assert.Equal(t, "/api/v1/reports/custom-templates", p)
	assert.Equal(t, "New", body["name"])
	assert.NotContains(t, body, "tenant_id")
	assert.NotContains(t, body, "created_by")
	assert.Contains(t, out, "t-9")
}

func TestReportTemplateDelete(t *testing.T) {
	rc := setupReportTest(t, 204, ``, nil)
	reportYes = true
	captureStdout(t, func() { require.NoError(t, runReportTemplateDelete(reportTemplateDeleteCmd, []string{"t-1"})) })
	m, p, _, body, _ := rc.snapshot()
	assert.Equal(t, http.MethodDelete, m)
	assert.Equal(t, "/api/v1/reports/custom-templates/t-1", p)
	assert.Nil(t, body)
}

func TestReportTemplateDelete_NoYesNoTerminalMakesNoRequest(t *testing.T) {
	rc := setupReportTest(t, 204, ``, nil)
	err := runReportTemplateDelete(reportTemplateDeleteCmd, []string{"t-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--yes")
	_, _, _, _, calls := rc.snapshot()
	assert.Zero(t, calls)
}

func TestReportTemplateShare(t *testing.T) {
	rc := setupReportTest(t, 200, `{"status":"shared"}`, nil)
	reportShareWith = []string{"acme-corp", "beta-inc"}
	reportSharePerms = []string{"read", "execute"}
	reportShareExpiry = "72h"
	captureStdout(t, func() { require.NoError(t, runReportTemplateShare(reportTemplateShareCmd, []string{"t-1"})) })
	m, p, _, body, _ := rc.snapshot()
	assert.Equal(t, http.MethodPost, m)
	assert.Equal(t, "/api/v1/reports/custom-templates/t-1/share", p)
	assert.Equal(t, []interface{}{"acme-corp", "beta-inc"}, body["shared_with_tenants"])
	assert.Equal(t, []interface{}{"read", "execute"}, body["permissions"])
	assert.NotEmpty(t, body["expires_at"])
	assert.NotContains(t, body, "tenant_id")
	assert.NotContains(t, body, "shared_by")
}

func TestReportTemplateShare_InvalidInputMakesNoRequest(t *testing.T) {
	rc := setupReportTest(t, 200, `{}`, nil)
	reportShareWith = []string{"acme-corp"}
	reportSharePerms = []string{"admin"}
	require.Error(t, runReportTemplateShare(reportTemplateShareCmd, []string{"t-1"}))
	reportSharePerms = []string{"read"}
	reportShareExpiry = "soon"
	require.Error(t, runReportTemplateShare(reportTemplateShareCmd, []string{"t-1"}))
	_, _, _, _, calls := rc.snapshot()
	assert.Zero(t, calls)
}

func TestReportCustomRun(t *testing.T) {
	rc := setupReportTest(t, 200, `{"id":"r-1","name":"Run","data_points":5,"is_streamed":true,"stream_token":"tok","total_pages":2}`, nil)
	reportFile = writeReportDef(t, "r.json", `{"name":"Run","query":{"data_sources":["dna"]},"format":"json"}`)
	out := captureStdout(t, func() { require.NoError(t, runReportCustomRun(reportCustomRunCmd, nil)) })
	m, p, _, body, _ := rc.snapshot()
	assert.Equal(t, http.MethodPost, m)
	assert.Equal(t, "/api/v1/reports/custom/generate", p)
	assert.Equal(t, "Run", body["name"])
	assert.NotContains(t, body, "tenant_id")
	assert.NotContains(t, body, "created_by")
	assert.Contains(t, out, "tok")
}

func TestReportCustomPage(t *testing.T) {
	const page = `[{"host":"a","score":1},{"host":"b","score":2}]`
	rc := setupReportTest(t, 200, page, map[string]string{"X-Has-More": "true"})
	reportStreamToken = "tok"
	reportPage = 2
	reportPageSize = 50
	out := captureStdout(t, func() { require.NoError(t, runReportCustomPage(reportCustomPageCmd, nil)) })
	m, p, uri, body, _ := rc.snapshot()
	assert.Equal(t, http.MethodGet, m)
	assert.Equal(t, "/api/v1/reports/custom/data", p)
	assert.Contains(t, uri, "stream_token=tok")
	assert.Contains(t, uri, "page=2")
	assert.Contains(t, uri, "page_size=50")
	assert.Nil(t, body)
	assert.Contains(t, out, "HOST")
	assert.Contains(t, out, "SCORE")

	output = "json"
	out = captureStdout(t, func() { require.NoError(t, runReportCustomPage(reportCustomPageCmd, nil)) })
	var rows []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(out), &rows))
	assert.Len(t, rows, 2)
}

func TestReportDefinitionRejectsDerivedKeys(t *testing.T) {
	for _, key := range []string{"tenant_id", "created_by"} {
		rc := setupReportTest(t, 201, `{}`, nil)
		reportFile = writeReportDef(t, "bad.yaml", "name: X\n"+key+": someone\n")
		for _, run := range []func() error{
			func() error { return runReportTemplateCreate(reportTemplateCreateCmd, nil) },
			func() error { return runReportCustomRun(reportCustomRunCmd, nil) },
		} {
			err := run()
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
			assert.Contains(t, err.Error(), "controller derives")
		}
		_, _, _, _, calls := rc.snapshot()
		assert.Zero(t, calls)
	}
}

func TestReportNotFound(t *testing.T) {
	setupReportTest(t, 404, `{"error":"template not found","status":404}`, nil)
	err := runReportTemplateShow(reportTemplateShowCmd, []string{"missing"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template not found")
	assert.Contains(t, err.Error(), "404")
}

func TestReportCommandRegistered(t *testing.T) {
	found, _, err := rootCmd.Find([]string{"report", "custom", "page"})
	require.NoError(t, err)
	assert.Equal(t, "page", found.Name())
	found, _, err = rootCmd.Find([]string{"report", "template", "share"})
	require.NoError(t, err)
	assert.Equal(t, "share", found.Name())
}
