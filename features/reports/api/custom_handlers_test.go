// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	reportsengine "github.com/cfgis/cfgms/features/reports/engine"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const customTestRoot = "root"

// recordingProvider is a real DataProvider that serves DNA rows per tenant and records
// every query it receives.
type recordingProvider struct {
	mu   sync.Mutex
	rows map[string][]storage.DNARecord
	qs   []interfaces.DataQuery
}

func (p *recordingProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.qs)
}

func (p *recordingProvider) queries() []interfaces.DataQuery {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]interfaces.DataQuery(nil), p.qs...)
}

func (p *recordingProvider) record(q interfaces.DataQuery) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.qs = append(p.qs, q)
}

func (p *recordingProvider) GetDNAData(_ context.Context, q interfaces.DataQuery) ([]storage.DNARecord, error) {
	p.record(q)
	var out []storage.DNARecord
	for _, t := range q.TenantIDs {
		out = append(out, p.rows[t]...)
	}
	return out, nil
}

func (p *recordingProvider) GetDriftEvents(_ context.Context, q interfaces.DataQuery) ([]drift.DriftEvent, error) {
	p.record(q)
	return nil, nil
}

func (p *recordingProvider) GetDeviceStats(context.Context, []string, interfaces.TimeRange) (map[string]interfaces.DeviceStats, error) {
	p.record(interfaces.DataQuery{})
	return map[string]interfaces.DeviceStats{}, nil
}

func (p *recordingProvider) GetTrendData(_ context.Context, _ string, q interfaces.DataQuery) ([]interfaces.TrendPoint, error) {
	p.record(q)
	return nil, nil
}

// countingTemplates wraps the real manager and counts calls so a test can prove a refused
// request never reached it.
type countingTemplates struct {
	interfaces.CustomTemplateManager
	mu sync.Mutex
	n  int
}

func (c *countingTemplates) hit() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}
func (c *countingTemplates) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
func (c *countingTemplates) SaveTemplate(ctx context.Context, t *interfaces.CustomReportTemplate) (*interfaces.CustomReportTemplate, error) {
	c.hit()
	return c.CustomTemplateManager.SaveTemplate(ctx, t)
}
func (c *countingTemplates) GetTemplate(ctx context.Context, id, tenant string) (*interfaces.CustomReportTemplate, error) {
	c.hit()
	return c.CustomTemplateManager.GetTemplate(ctx, id, tenant)
}
func (c *countingTemplates) GetAccessibleTemplates(ctx context.Context, tenant string) ([]*interfaces.CustomReportTemplate, error) {
	c.hit()
	return c.CustomTemplateManager.GetAccessibleTemplates(ctx, tenant)
}
func (c *countingTemplates) ShareTemplate(ctx context.Context, r interfaces.ShareTemplateRequest) error {
	c.hit()
	return c.CustomTemplateManager.ShareTemplate(ctx, r)
}
func (c *countingTemplates) DeleteTemplate(ctx context.Context, id, tenant string) error {
	c.hit()
	return c.CustomTemplateManager.DeleteTemplate(ctx, id, tenant)
}

type customStack struct {
	router    *mux.Router
	provider  *recordingProvider
	templates *countingTemplates
}

// callerCtx describes the authenticated context a request carries.
type callerCtx struct {
	tenant string // restricted tenant; "" with root=false means no tenant in context
	root   bool
	user   string
}

func newCustomStack(t *testing.T) *customStack {
	t.Helper()
	provider := &recordingProvider{rows: map[string][]storage.DNARecord{}}
	for i := 0; i < 5; i++ {
		provider.rows["tenant-a"] = append(provider.rows["tenant-a"], storage.DNARecord{DeviceID: "a-dev", TenantID: "tenant-a"})
	}
	provider.rows["tenant-b"] = []storage.DNARecord{{DeviceID: "b-dev", TenantID: "tenant-b"}}

	store := pkgtesting.SetupTestStorage(t).GetReportTemplateStore()
	require.NotNil(t, store)
	paths := map[string][]string{
		"tenant-a": {customTestRoot, "msp-1", "tenant-a"},
		"tenant-b": {customTestRoot, "msp-1", "tenant-b"},
	}
	scope := func(_ context.Context, owner, target string) (bool, error) {
		o, t := paths[owner], paths[target]
		return len(o) > 1 && len(t) > 1 && owner != target && o[1] == t[1], nil
	}
	mgr, err := reportsengine.NewCustomTemplateManager(store, time.Now, scope)
	require.NoError(t, err)
	templates := &countingTemplates{CustomTemplateManager: mgr}

	cfg := interfaces.DefaultCustomReportConfig()
	cfg.StreamThreshold = 2
	cfg.DefaultPageSize = 2
	pages := cache.NewCache(cache.CacheConfig{Name: "test-pages", MaxRuntimeItems: 100, DefaultTTL: time.Hour})
	t.Cleanup(pages.Close)
	builder, err := reportsengine.NewCustomReportBuilder(provider, cfg, pages, nil, nil, customTestRoot)
	require.NoError(t, err)

	h := New(nil, nil, nil, nil, logging.NewNoopLogger())
	h.SetCustomReports(templates, builder)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	return &customStack{router: router, provider: provider, templates: templates}
}

func (s *customStack) do(c callerCtx, method, path string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	ctx := req.Context()
	switch {
	case c.root:
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
		ctx = context.WithValue(ctx, ctxkeys.TenantID, customTestRoot)
	case c.tenant != "":
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(c.tenant))
		ctx = context.WithValue(ctx, ctxkeys.TenantID, c.tenant)
	}
	if c.user != "" {
		ctx = context.WithValue(ctx, ctxkeys.UserIDKey, c.user)
	}
	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, req.WithContext(ctx))
	return rec
}

var (
	callerA = callerCtx{tenant: "tenant-a", user: "alice"}
	callerB = callerCtx{tenant: "tenant-b", user: "bob"}
)

func sampleTemplate() map[string]interface{} {
	return map[string]interface{}{
		"name":  "inventory",
		"query": map[string]interface{}{"data_sources": []string{"dna"}, "filters": map[string]interface{}{}},
		// Body fields that must be ignored.
		"tenant_id":  "tenant-b",
		"created_by": "mallory",
	}
}

func (s *customStack) createTemplate(t *testing.T, c callerCtx) interfaces.CustomReportTemplate {
	t.Helper()
	rec := s.do(c, http.MethodPost, "/custom-templates", sampleTemplate())
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var tmpl interfaces.CustomReportTemplate
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tmpl))
	return tmpl
}

func TestCustomTemplates_TenantIsolationAndBodyTenantIgnored(t *testing.T) {
	s := newCustomStack(t)
	tmpl := s.createTemplate(t, callerA)
	assert.Equal(t, "tenant-a", tmpl.TenantID, "body tenant_id must be overwritten from the session")
	assert.Equal(t, "alice", tmpl.CreatedBy, "body created_by must be overwritten from the session")

	assert.Equal(t, http.StatusOK, s.do(callerA, http.MethodGet, "/custom-templates/"+tmpl.ID, nil).Code)

	// Tenant B: get, share and delete are 404, list does not show it.
	assert.Equal(t, http.StatusNotFound, s.do(callerB, http.MethodGet, "/custom-templates/"+tmpl.ID, nil).Code)
	share := map[string]interface{}{
		"shared_with_tenants": []string{"tenant-b"}, "permissions": []string{"read"},
		"tenant_id": "tenant-a", "template_id": "other", "shared_by": "mallory",
	}
	assert.Equal(t, http.StatusNotFound, s.do(callerB, http.MethodPost, "/custom-templates/"+tmpl.ID+"/share", share).Code)
	assert.Equal(t, http.StatusNotFound, s.do(callerB, http.MethodDelete, "/custom-templates/"+tmpl.ID, nil).Code)

	rec := s.do(callerB, http.MethodGet, "/custom-templates", nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var list struct {
		Templates []interfaces.CustomReportTemplate `json:"templates"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	assert.Empty(t, list.Templates)

	// A missing template is indistinguishable from a foreign one.
	missing := s.do(callerB, http.MethodGet, "/custom-templates/does-not-exist", nil)
	foreign := s.do(callerB, http.MethodGet, "/custom-templates/"+tmpl.ID, nil)
	assert.Equal(t, missing.Body.String(), foreign.Body.String())

	// The owner still has it, then can share it within its MSP, and delete it.
	assert.Equal(t, http.StatusOK, s.do(callerA, http.MethodPost, "/custom-templates/"+tmpl.ID+"/share",
		map[string]interface{}{"shared_with_tenants": []string{"tenant-b"}, "permissions": []string{"read"}}).Code)
	assert.Equal(t, http.StatusOK, s.do(callerB, http.MethodGet, "/custom-templates/"+tmpl.ID, nil).Code)
	assert.Equal(t, http.StatusNoContent, s.do(callerA, http.MethodDelete, "/custom-templates/"+tmpl.ID, nil).Code)
}

func TestCustomTemplates_ShareErrors(t *testing.T) {
	s := newCustomStack(t)
	tmpl := s.createTemplate(t, callerA)
	path := "/custom-templates/" + tmpl.ID + "/share"

	rec := s.do(callerA, http.MethodPost, path, map[string]interface{}{"shared_with_tenants": []string{"nowhere"}, "permissions": []string{"read"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), "nowhere", "the refused target must not be echoed")
	assert.Equal(t, http.StatusBadRequest, s.do(callerA, http.MethodPost, path, map[string]interface{}{"shared_with_tenants": []string{"tenant-b"}, "permissions": []string{"root"}}).Code)
	assert.Equal(t, http.StatusBadRequest, s.do(callerA, http.MethodPost, path, map[string]interface{}{"permissions": []string{"read"}}).Code)
	assert.Equal(t, http.StatusBadRequest, s.do(callerA, http.MethodPost, "/custom-templates", map[string]interface{}{"name": ""}).Code)
}

func TestCustomRoutes_Unavailable503(t *testing.T) {
	h := New(nil, nil, nil, nil, logging.NewNoopLogger())
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	for _, rt := range []struct{ method, path string }{
		{"POST", "/custom/generate"}, {"GET", "/custom/data"}, {"GET", "/custom-templates"},
		{"POST", "/custom-templates"}, {"GET", "/custom-templates/x"}, {"DELETE", "/custom-templates/x"}, {"POST", "/custom-templates/x/share"},
	} {
		req := httptest.NewRequest(rt.method, rt.path, nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "tenant-a"))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rt.method+" "+rt.path)
		assert.Contains(t, rec.Body.String(), "custom reports not available")
	}
}

func TestCustomRoutes_NoTenantInContextRefused(t *testing.T) {
	s := newCustomStack(t)
	none := callerCtx{}
	for _, rt := range []struct{ method, path string }{
		{"POST", "/custom/generate"}, {"GET", "/custom/data?stream_token=x"}, {"GET", "/custom-templates"},
		{"POST", "/custom-templates"}, {"GET", "/custom-templates/x"}, {"DELETE", "/custom-templates/x"}, {"POST", "/custom-templates/x/share"},
	} {
		rec := s.do(none, rt.method, rt.path, sampleTemplate())
		assert.Equal(t, http.StatusForbidden, rec.Code, rt.method+" "+rt.path)
	}
	assert.Zero(t, s.templates.count(), "manager must not be reached")
	assert.Zero(t, s.provider.calls(), "builder must not be reached")
}

func TestCustomReports_RootCallerRefused(t *testing.T) {
	s := newCustomStack(t)
	root := callerCtx{root: true, user: "admin"}
	body := map[string]interface{}{"name": "r", "format": "json", "query": map[string]interface{}{"data_sources": []string{"dna"}, "filters": map[string]interface{}{}}}

	rec := s.do(root, http.MethodPost, "/custom/generate", body)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.NotContains(t, rec.Body.String(), customTestRoot, "403 body is generic")
	assert.Equal(t, http.StatusForbidden, s.do(root, http.MethodGet, "/custom/data?stream_token=abc", nil).Code)
	assert.Zero(t, s.provider.calls(), "a root caller must never reach the builder")

	// A restricted MSP-level caller succeeds.
	assert.Equal(t, http.StatusOK, s.do(callerA, http.MethodPost, "/custom/generate", body).Code)

	// A root caller may still manage its own templates.
	assert.Equal(t, http.StatusOK, s.do(root, http.MethodGet, "/custom-templates", nil).Code)
}

func TestCustomReports_GenerateScopedAndStreamed(t *testing.T) {
	s := newCustomStack(t)
	body := map[string]interface{}{
		"name": "r", "format": "json", "tenant_id": "tenant-b", "created_by": "mallory",
		"query": map[string]interface{}{"data_sources": []string{"dna"}, "filters": map[string]interface{}{}},
	}
	rec := s.do(callerA, http.MethodPost, "/custom/generate", body)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var report interfaces.CustomReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &report))
	assert.Equal(t, "tenant-a", report.TenantID)
	assert.Equal(t, "alice", report.CreatedBy)

	qs := s.provider.queries()
	require.NotEmpty(t, qs)
	for _, q := range qs {
		assert.Equal(t, []string{"tenant-a"}, q.TenantIDs, "every query carries the caller's tenant only")
	}

	require.True(t, report.IsStreamed, "5 rows exceed the test threshold of 2")
	require.NotEmpty(t, report.StreamToken)

	page := s.do(callerA, http.MethodGet, "/custom/data?page=1&page_size=2&stream_token="+report.StreamToken, nil)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	assert.Equal(t, "true", page.Header().Get("X-Has-More"))
	assert.Equal(t, "no-store", page.Header().Get("Cache-Control"))

	// Another tenant's token use is refused, indistinguishably from an unknown token.
	other := s.do(callerB, http.MethodGet, "/custom/data?page=1&stream_token="+report.StreamToken, nil)
	assert.Equal(t, http.StatusNotFound, other.Code)
	assert.NotContains(t, other.Body.String(), report.StreamToken)
	assert.Equal(t, http.StatusNotFound, s.do(callerA, http.MethodGet, "/custom/data?stream_token=nope", nil).Code)
	assert.Equal(t, http.StatusBadRequest, s.do(callerA, http.MethodGet, "/custom/data?page=abc&stream_token="+report.StreamToken, nil).Code)
}

func TestCustomReports_InvalidQueryIs400(t *testing.T) {
	s := newCustomStack(t)
	rec := s.do(callerA, http.MethodPost, "/custom/generate", map[string]interface{}{"name": "r", "format": "json", "query": map[string]interface{}{"data_sources": []string{}}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, http.StatusBadRequest, s.do(callerA, http.MethodPost, "/custom/generate", "not an object").Code)
}
