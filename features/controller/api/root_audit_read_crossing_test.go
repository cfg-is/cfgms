// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	raMSP    = "msp-audit"
	raClient = "msp-audit-client"
)

type raFixture struct {
	server *Server
	op     *Principal
}

func newRAFixture(t *testing.T) *raFixture {
	t.Helper()
	server := seedRootTenant(t, wireCrossingStore(t, setupTestServer(t)))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: raMSP, ParentID: testRootTenantID})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: raClient, ParentID: raMSP})
	require.NoError(t, err)
	return &raFixture{server: server, op: boundRootOperator("ra-op")}
}

// record writes and flushes one audit entry.
func (f *raFixture) record(t *testing.T, tenantID string, et business.AuditEventType, action string, result business.AuditResult) {
	t.Helper()
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(et).
		Action(action).
		User("someone", business.AuditUserTypeHuman).
		Resource("secret-resource", "secret-id", "secret-name").
		Result(result).
		Severity(business.AuditSeverityMedium).
		Request("req", "POST", "/secret/path", "203.0.113.9", "agent").
		Detail("business_note", "client-name-leak")
	require.NoError(t, f.server.auditManager.RecordEvent(context.Background(), b))
	require.NoError(t, f.server.auditManager.Flush(context.Background()))
}

func (f *raFixture) list(t *testing.T, query string) (*httptest.ResponseRecorder, auditResp) {
	t.Helper()
	path := "/api/v1/audit/entries"
	if query != "" {
		path += "?" + query
	}
	rec := httptest.NewRecorder()
	f.server.handleListAuditEntries(rec, asRootOperator(httptest.NewRequest(http.MethodGet, path, nil), f.op, nil))
	var resp auditResp
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}
	return rec, resp
}

func raKey(e *business.AuditEntry) string { return e.TenantID + "|" + e.Action }

func raKeys(resp auditResp) []string {
	out := []string{}
	for _, e := range resp.Data.Entries {
		out = append(out, raKey(e))
	}
	return out
}

func TestRootAuditEntries_NoCrossing_RootScopeOnly(t *testing.T) {
	f := newRAFixture(t)
	f.record(t, testRootTenantID, business.AuditEventConfiguration, "root.config", business.AuditResultSuccess)
	f.record(t, testRootTenantID, business.AuditEventSystemAccess, "tenant.crossing_grant_created", business.AuditResultSuccess)
	f.record(t, raMSP, business.AuditEventConfiguration, "msp.config_change", business.AuditResultSuccess)
	f.record(t, raClient, business.AuditEventConfiguration, "client.created", business.AuditResultSuccess)

	rec, resp := f.list(t, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	keys := raKeys(resp)
	assert.ElementsMatch(t, []string{
		testRootTenantID + "|root.config",
		testRootTenantID + "|tenant.crossing_grant_created",
	}, keys)
	for _, e := range resp.Data.Entries {
		if e.TenantID == testRootTenantID && e.Action == "root.config" {
			assert.Equal(t, "client-name-leak", e.Details["business_note"], "root's own entries are returned in full")
		}
	}
}

func TestRootAuditEntries_NoCrossing_CarveOutReducedAndDepthLimited(t *testing.T) {
	f := newRAFixture(t)
	f.record(t, raMSP, business.AuditEventAuthentication, "web.passkey.login.failure", business.AuditResultFailure)
	f.record(t, raMSP, business.AuditEventAuthentication, "web.passkey.login.success", business.AuditResultSuccess)
	f.record(t, raMSP, business.AuditEventSystemAccess, "tenant.crossing_grant_used", business.AuditResultSuccess)
	f.record(t, raMSP, business.AuditEventSystemEvent, "refresh_error", business.AuditResultError)
	f.record(t, raMSP, business.AuditEventConfiguration, "msp.config_change", business.AuditResultSuccess)
	// Below an MSP: even carve-out categories are omitted.
	f.record(t, raClient, business.AuditEventAuthentication, "web.passkey.login.failure", business.AuditResultFailure)
	f.record(t, raClient, business.AuditEventSystemAccess, "tenant.crossing_grant_used", business.AuditResultSuccess)

	rec, resp := f.list(t, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.ElementsMatch(t, []string{
		raMSP + "|web.passkey.login.failure",
		raMSP + "|tenant.crossing_grant_used",
		raMSP + "|refresh_error",
	}, raKeys(resp))
	for _, e := range resp.Data.Entries {
		assert.NotContains(t, e.Details, "business_note")
		assert.Empty(t, e.ResourceID)
		assert.Empty(t, e.ResourceType)
		assert.Empty(t, e.Path)
		assert.Nil(t, e.Changes)
		assert.Equal(t, e.Action, e.Details["action"])
		assert.Equal(t, "203.0.113.9", e.Details["source_address"])
		assert.ElementsMatch(t, []string{"actor", "action", "result", "time", "source_address"}, mapKeys(e.Details))
	}
}

func mapKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestRootAuditEntries_Crossing_SubtreeInFullThenGoneAfterRevoke(t *testing.T) {
	f := newRAFixture(t)
	f.record(t, raMSP, business.AuditEventConfiguration, "msp.config_change", business.AuditResultSuccess)
	f.record(t, raClient, business.AuditEventConfiguration, "client.created", business.AuditResultSuccess)

	_, resp := f.list(t, "")
	assert.Empty(t, raKeys(resp))

	grantCrossing(t, f.server, f.op.ID, raMSP)
	_, resp = f.list(t, "")
	assert.ElementsMatch(t, []string{raMSP + "|msp.config_change", raClient + "|client.created"}, raKeys(resp))
	for _, e := range resp.Data.Entries {
		assert.Equal(t, "client-name-leak", e.Details["business_note"])
	}

	require.NoError(t, f.server.tenantCrossingStore.RevokeTenantCrossing(context.Background(), "crossing-"+f.op.ID+"-"+raMSP))
	_, resp = f.list(t, "")
	assert.Empty(t, raKeys(resp))
}

func TestRootAuditEntries_MergedOrderAndPagination(t *testing.T) {
	f := newRAFixture(t)
	// Interleave two sources: root scope and a carve-out MSP source.
	var want []string
	for i := 0; i < 3; i++ {
		f.record(t, testRootTenantID, business.AuditEventConfiguration, "root."+strconv.Itoa(i), business.AuditResultSuccess)
		want = append(want, testRootTenantID+"|root."+strconv.Itoa(i))
		time.Sleep(5 * time.Millisecond)
		f.record(t, raMSP, business.AuditEventSystemEvent, "evt."+strconv.Itoa(i), business.AuditResultError)
		want = append(want, raMSP+"|evt."+strconv.Itoa(i))
		time.Sleep(5 * time.Millisecond)
	}
	// Newest first.
	for i, j := 0, len(want)-1; i < j; i, j = i+1, j-1 {
		want[i], want[j] = want[j], want[i]
	}

	_, all := f.list(t, "limit=500")
	assert.Equal(t, want, raKeys(all))
	assert.False(t, all.Data.HasMore)

	_, p1 := f.list(t, "limit=2&offset=0")
	assert.Equal(t, want[0:2], raKeys(p1))
	assert.True(t, p1.Data.HasMore)
	_, p2 := f.list(t, "limit=2&offset=2")
	assert.Equal(t, want[2:4], raKeys(p2))
	assert.True(t, p2.Data.HasMore)
	_, p3 := f.list(t, "limit=2&offset=4")
	assert.Equal(t, want[4:6], raKeys(p3))
	assert.False(t, p3.Data.HasMore)
	_, p4 := f.list(t, "limit=4&offset=1")
	assert.Equal(t, want[1:5], raKeys(p4))
	assert.True(t, p4.Data.HasMore)
}

func TestRootAuditEntries_OffsetCap(t *testing.T) {
	f := newRAFixture(t)
	rec, _ := f.list(t, "offset="+strconv.Itoa(rootAuditMaxOffset+1))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec, _ = f.list(t, "offset="+strconv.Itoa(rootAuditMaxOffset))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRootAuditEntries_UserFiltersApplyToCarveOut(t *testing.T) {
	f := newRAFixture(t)
	f.record(t, raMSP, business.AuditEventAuthentication, "web.passkey.login.failure", business.AuditResultFailure)
	f.record(t, raMSP, business.AuditEventSystemEvent, "refresh_error", business.AuditResultError)

	_, resp := f.list(t, "event_type="+url.QueryEscape("system_event"))
	assert.Equal(t, []string{raMSP + "|refresh_error"}, raKeys(resp))
	_, resp = f.list(t, "action=business.thing")
	assert.Empty(t, raKeys(resp))
}

// TestRootAuditCarveOut_Pinned fails when the founder-owned carve-out changes
// without this test being updated (ADR-025 Decision 4, Amendment 8).
func TestRootAuditCarveOut_Pinned(t *testing.T) {
	assert.Equal(t, []rootAuditCarveOutRule{
		{
			Category:  "msp-admin-authentication-failure",
			EventType: business.AuditEventAuthentication,
			Actions:   []string{"web.passkey.login.failure"},
			Results:   []business.AuditResult{business.AuditResultFailure},
		},
		{
			Category:     "crossing-meta-log",
			EventType:    business.AuditEventSystemAccess,
			ActionPrefix: "tenant.crossing_",
		},
		{
			Category:  "platform-event",
			EventType: business.AuditEventSystemEvent,
		},
	}, rootAuditCarveOut)
	assert.Equal(t, []string{"actor", "action", "result", "time", "source_address"}, rootAuditCarveOutDetailKeys)
}

func TestAuditEntries_TenantScopedUnchanged(t *testing.T) {
	f := newRAFixture(t)
	f.record(t, raMSP, business.AuditEventConfiguration, "msp.config_change", business.AuditResultSuccess)
	f.record(t, raClient, business.AuditEventConfiguration, "client.created", business.AuditResultSuccess)
	rec := getAuditEntries(f.server, raMSP, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp auditResp
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, []string{raMSP + "|msp.config_change"}, raKeys(resp))
}
