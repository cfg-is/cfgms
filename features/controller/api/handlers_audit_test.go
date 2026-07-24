// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// auditResp mirrors the envelope returned by handleListAuditEntries.
type auditResp struct {
	Data struct {
		Entries []*business.AuditEntry `json:"entries"`
		HasMore bool                   `json:"has_more"`
	} `json:"data"`
}

// getAuditEntries performs GET /api/v1/audit/entries with the given tenant and optional query params.
func getAuditEntries(server *Server, tenantID, query string) *httptest.ResponseRecorder {
	url := "/api/v1/audit/entries"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if tenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	}
	rec := httptest.NewRecorder()
	server.handleListAuditEntries(rec, req)
	return rec
}

// recordAndFlush records an audit event and flushes the manager so the entry reaches the store.
func recordAndFlush(t *testing.T, mgr *audit.Manager, event *audit.AuditEventBuilder) {
	t.Helper()
	require.NoError(t, mgr.RecordEvent(context.Background(), event))
	require.NoError(t, mgr.Flush(context.Background()))
}

func TestHandleListAuditEntries_HappyPath(t *testing.T) {
	server := setupTestServer(t)

	recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
		Tenant("tenant-a").
		Type(business.AuditEventConfiguration).
		Action("update").
		User("user-1", business.AuditUserTypeHuman).
		Resource("config/dns", "res-1", "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityLow),
	)

	rec := getAuditEntries(server, "tenant-a", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Data.Entries, "expected at least one audit entry")
	for _, e := range resp.Data.Entries {
		assert.Equal(t, "tenant-a", e.TenantID, "all entries must belong to tenant-a")
	}
}

func TestHandleListAuditEntries_EmptyResult(t *testing.T) {
	server := setupTestServer(t)

	rec := getAuditEntries(server, "tenant-no-data", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	// Empty slice or nil both satisfy: no entries for an unknown tenant.
	assert.Empty(t, resp.Data.Entries)
	assert.False(t, resp.Data.HasMore)
}

func TestHandleListAuditEntries_ModulePrefixFilter(t *testing.T) {
	server := setupTestServer(t)

	// Seed two entries: one with hyperv/ prefix, one without.
	recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
		Tenant("tenant-b").
		Type(business.AuditEventConfiguration).
		Action("New-VM").
		User("system", business.AuditUserTypeSystem).
		Resource("hyperv/New-VM", "vm-001", "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityLow),
	)
	recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
		Tenant("tenant-b").
		Type(business.AuditEventConfiguration).
		Action("set").
		User("system", business.AuditUserTypeSystem).
		Resource("config", "cfg-001", "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityLow),
	)

	rec := getAuditEntries(server, "tenant-b", "module=hyperv")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data.Entries, 1, "only the hyperv/ entry must be returned")
	assert.Equal(t, "hyperv/New-VM", resp.Data.Entries[0].ResourceType)
}

func TestHandleListAuditEntries_AuditManagerNil_Returns503(t *testing.T) {
	server := setupTestServer(t)
	server.auditManager = nil

	rec := getAuditEntries(server, "tenant-a", "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "AUDIT_NOT_AVAILABLE", resp.Error.Code)
}

// TestHandleListAuditEntries_CrossTenantIsolation is the REQUIRED cross-tenant isolation test.
// It stores entries under two different tenants and asserts that a request authenticated as
// tenant A only returns tenant A's entries — no tenant B entries appear.
func TestHandleListAuditEntries_CrossTenantIsolation(t *testing.T) {
	server := setupTestServer(t)

	// Seed entries for both tenants.
	recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
		Tenant("tenant-a").
		Type(business.AuditEventConfiguration).
		Action("create").
		User("user-a", business.AuditUserTypeHuman).
		Resource("config/a", "a-1", "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityLow),
	)
	recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
		Tenant("tenant-b").
		Type(business.AuditEventConfiguration).
		Action("delete").
		User("user-b", business.AuditUserTypeHuman).
		Resource("config/b", "b-1", "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityLow),
	)

	// Request as tenant-a — must only see tenant-a's entries.
	rec := getAuditEntries(server, "tenant-a", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	for _, e := range resp.Data.Entries {
		assert.Equal(t, "tenant-a", e.TenantID,
			"tenant-a request must not expose tenant-b entry: %s", e.ID)
	}

	// Confirm at least one tenant-a entry is present.
	found := false
	for _, e := range resp.Data.Entries {
		if e.TenantID == "tenant-a" {
			found = true
			break
		}
	}
	assert.True(t, found, "tenant-a entry must be present in the response")
}

func TestHandleListAuditEntries_InvalidQueryParamsIgnored(t *testing.T) {
	server := setupTestServer(t)

	// Non-numeric limit and offset should be silently ignored (defaults used).
	rec := getAuditEntries(server, "tenant-a", "limit=notanumber&offset=bad")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleListAuditEntries_LimitClamped(t *testing.T) {
	server := setupTestServer(t)

	// limit > 500 should be silently clamped to 500; request must succeed.
	rec := getAuditEntries(server, "tenant-a", "limit=9999")
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHandleListAuditEntries_OffsetAndLimitForwarded(t *testing.T) {
	server := setupTestServer(t)

	// With no data, just verify the request parses fine and returns 200.
	rec := getAuditEntries(server, "tenant-a", "offset=10&limit=5")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleListAuditEntries_EmptyResult_NeverNull verifies that when the underlying
// storage returns a nil slice (as FlatFileAuditStore does for an unknown tenant), the
// API handler serializes "entries" as [] rather than null. A nil slice marshals as JSON null,
// which crashes client-side .map() calls. The fix is a nil-guard in handlers_audit.go
// immediately before writeSuccessResponse, mirroring the existing pattern in handlers_configs.go.
func TestHandleListAuditEntries_EmptyResult_NeverNull(t *testing.T) {
	server := setupTestServer(t)

	rec := getAuditEntries(server, "tenant-no-data-null-guard", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))

	var dataObj struct {
		Entries json.RawMessage `json:"entries"`
		HasMore bool            `json:"has_more"`
	}
	require.NoError(t, json.Unmarshal(raw["data"], &dataObj))
	assert.Equal(t, json.RawMessage("[]"), dataObj.Entries,
		"empty entries must serialize as [] not null")
	assert.False(t, dataObj.HasMore)
}

// TestHandleListAuditEntries_HasMore_True verifies that has_more is true when the
// underlying store contains more rows than the requested limit (limit+1 technique).
func TestHandleListAuditEntries_HasMore_True(t *testing.T) {
	server := setupTestServer(t)

	// Seed 3 entries; request limit=2 — the handler fetches 3 (limit+1), sees all
	// 3, trims to 2, and sets has_more=true.
	for i := range 3 {
		recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
			Tenant("tenant-hasmore").
			Type(business.AuditEventConfiguration).
			Action("op").
			User("sys", business.AuditUserTypeSystem).
			Resource("config", string(rune('a'+i)), "").
			Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityLow),
		)
	}

	rec := getAuditEntries(server, "tenant-hasmore", "limit=2")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(t, resp.Data.Entries, 2, "response must be trimmed to requested limit")
	assert.True(t, resp.Data.HasMore, "has_more must be true when more rows exist")
}

// TestHandleListAuditEntries_HasMore_False_ExactPageBoundary verifies that has_more
// is false when the result set ends exactly on a page boundary (no false positive).
// This is the bug the limit+1 technique fixes: the old heuristic
// (entries.length >= PAGE_SIZE) returned true here incorrectly.
func TestHandleListAuditEntries_HasMore_False_ExactPageBoundary(t *testing.T) {
	server := setupTestServer(t)

	// Seed exactly 2 entries; request limit=2 — the handler fetches 3 (limit+1),
	// gets back 2 (storage has no more), and sets has_more=false.
	for i := range 2 {
		recordAndFlush(t, server.auditManager, audit.NewEventBuilder().
			Tenant("tenant-exactpage").
			Type(business.AuditEventConfiguration).
			Action("op").
			User("sys", business.AuditUserTypeSystem).
			Resource("config", string(rune('a'+i)), "").
			Result(business.AuditResultSuccess).
			Severity(business.AuditSeverityLow),
		)
	}

	rec := getAuditEntries(server, "tenant-exactpage", "limit=2")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Len(t, resp.Data.Entries, 2, "all rows must be returned")
	assert.False(t, resp.Data.HasMore, "has_more must be false when result ends exactly on page boundary")
}
