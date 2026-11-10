// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const markersPath = "/api/v1/monitoring/markers"

type markerRecord struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Revision  string    `json:"revision"`
	Principal string    `json:"principal"`
	Resource  string    `json:"resource"`
	Note      string    `json:"note"`
}

type markerFixture struct {
	srv      *Server
	writeKey string
	readKey  string
}

func newMarkerFixture(t *testing.T) *markerFixture {
	t.Helper()
	srv := setupTestServer(t)
	return &markerFixture{
		srv:      srv,
		writeKey: NewTestKey(t, srv, []string{"monitoring:write-markers"}),
		readKey:  NewTestKey(t, srv, []string{"monitoring:read-markers"}),
	}
}

// do sends a request through the private metrics router, where the marker
// routes live.
func (f *markerFixture) do(method, path, key string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	rec := httptest.NewRecorder()
	f.srv.metricsRouter.ServeHTTP(rec, req)
	return rec
}

func (f *markerFixture) post(t *testing.T, key string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	return f.do(http.MethodPost, markersPath, key, raw)
}

// list flushes the batched audit writes, then GETs the marker list.
func (f *markerFixture) list(t *testing.T, query string) (int, []markerRecord) {
	t.Helper()
	require.NoError(t, f.srv.auditManager.Flush(context.Background()))
	path := markersPath
	if query != "" {
		path += "?" + query
	}
	rec := f.do(http.MethodGet, path, f.readKey, nil)
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	var resp struct {
		Data struct {
			Markers []markerRecord `json:"markers"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp), rec.Body.String())
	return rec.Code, resp.Data.Markers
}

func (f *markerFixture) record(t *testing.T, ev *audit.AuditEventBuilder) {
	t.Helper()
	require.NoError(t, f.srv.auditManager.RecordEvent(context.Background(), ev))
	require.NoError(t, f.srv.auditManager.Flush(context.Background()))
}

func TestMarkerRecordAndList(t *testing.T) {
	f := newMarkerFixture(t)

	rec := f.post(t, f.writeKey, map[string]any{"kind": "deploy", "revision": "a1b2c3d4e5f6", "note": "release train 12"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var created struct {
		Data markerRecord `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))
	assert.NotEmpty(t, created.Data.ID)
	assert.Equal(t, "deploy", created.Data.Kind)
	assert.Equal(t, "a1b2c3d4e5f6", created.Data.Revision)

	rec = f.post(t, f.writeKey, map[string]any{"kind": "rollback", "revision": "v1.2.3-rc.1"})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// The writes are audit rows under the system tenant.
	require.NoError(t, f.srv.auditManager.Flush(context.Background()))
	rows, err := f.srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		TenantID: audit.SystemTenantID,
		Actions:  []string{"marker_deploy"},
	})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "a1b2c3d4e5f6", rows[0].Details["revision"])
	assert.Equal(t, "release train 12", rows[0].Details["note"])
	assert.NotEmpty(t, rows[0].Details["principal"])

	code, markers := f.list(t, "")
	require.Equal(t, http.StatusOK, code)
	require.Len(t, markers, 2)
	assert.Equal(t, "deploy", markers[0].Kind)
	assert.Equal(t, "rollback", markers[1].Kind)
	assert.Equal(t, "v1.2.3-rc.1", markers[1].Revision)
	assert.False(t, markers[1].Time.Before(markers[0].Time), "time ordered, oldest first")
	for _, m := range markers {
		assert.NotEmpty(t, m.Principal)
		assert.NotEmpty(t, m.Resource)
		assert.NotContains(t, m.Resource, "/", "resource is an id, never a tenant path")
	}
	assert.Equal(t, created.Data.ID, markers[0].Resource)

	_, deploys := f.list(t, "kind=deploy")
	require.Len(t, deploys, 1)
	assert.Equal(t, "deploy", deploys[0].Kind)
}

func TestMarkerValidation(t *testing.T) {
	f := newMarkerFixture(t)

	post := []struct {
		name string
		body string
	}{
		{"unknown kind", `{"kind":"restart","revision":"a1b2c3d"}`},
		{"empty kind", `{"kind":"","revision":"a1b2c3d"}`},
		{"missing kind", `{"revision":"a1b2c3d"}`},
		{"missing revision", `{"kind":"deploy"}`},
		{"non-hex revision", `{"kind":"deploy","revision":"zzzzzzzz"}`},
		{"short hex revision", `{"kind":"deploy","revision":"abc"}`},
		{"overlong hex revision", `{"kind":"deploy","revision":"` + strings.Repeat("a", 65) + `"}`},
		{"revision with whitespace", `{"kind":"deploy","revision":"a1b2c3d e"}`},
		{"revision with newline", "{\"kind\":\"deploy\",\"revision\":\"a1b2c3d\\nx\"}"},
		{"non-semver revision", `{"kind":"deploy","revision":"v1.2"}`},
		{"overlong note", `{"kind":"deploy","revision":"a1b2c3d","note":"` + strings.Repeat("n", markerMaxNoteLen+1) + `"}`},
		{"control character in note", "{\"kind\":\"deploy\",\"revision\":\"a1b2c3d\",\"note\":\"a\\u0007b\"}"},
		{"unknown field", `{"kind":"deploy","revision":"a1b2c3d","tenant":"x"}`},
		{"trailing data", `{"kind":"deploy","revision":"a1b2c3d"}{}`},
		{"not json", `kind=deploy`},
		{"empty body", ``},
	}
	for _, tc := range post {
		t.Run("post "+tc.name, func(t *testing.T) {
			rec := f.do(http.MethodPost, markersPath, f.writeKey, []byte(tc.body))
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		})
	}

	for _, q := range []string{
		"kind=Deploy!",
		"kind=" + strings.Repeat("a", 40),
		"since=yesterday",
		"until=2026-13-45",
		"since=2026-02-01T00:00:00Z&until=2026-01-01T00:00:00Z",
	} {
		t.Run("get "+q, func(t *testing.T) {
			rec := f.do(http.MethodGet, markersPath+"?"+q, f.readKey, nil)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		})
	}

	// Nothing invalid was recorded.
	_, markers := f.list(t, "")
	assert.Empty(t, markers)

	// Every accepted kind and a semantic-version revision is recorded.
	for _, kind := range []string{"deploy", "rollback", "chaos_start", "chaos_end"} {
		rec := f.post(t, f.writeKey, map[string]any{"kind": kind, "revision": "1.4.0"})
		assert.Equal(t, http.StatusCreated, rec.Code, "%s: %s", kind, rec.Body.String())
	}
	_, markers = f.list(t, "")
	assert.Len(t, markers, 4)
}

func TestMarkerAuthAndPermission(t *testing.T) {
	f := newMarkerFixture(t)
	body := []byte(`{"kind":"deploy","revision":"a1b2c3d"}`)

	assert.Equal(t, http.StatusUnauthorized, f.do(http.MethodPost, markersPath, "", body).Code, "POST without credential")
	assert.Equal(t, http.StatusUnauthorized, f.do(http.MethodGet, markersPath, "", nil).Code, "GET without credential")

	// A credential holding the other marker permission, or an unrelated one, is refused.
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodPost, markersPath, f.readKey, body).Code, "POST with read-markers only")
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodGet, markersPath, f.writeKey, nil).Code, "GET with write-markers only")
	other := NewTestKey(t, f.srv, []string{"monitoring:read-metrics"})
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodPost, markersPath, other, body).Code)
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodGet, markersPath, other, nil).Code)

	// The write floor is Strong with machine principals allowed and no presence tap; the
	// read permission has no floor.
	req, ok := permissionAssurance["monitoring:write-markers"]
	require.True(t, ok)
	assert.Equal(t, Requirement{Min: session.AssuranceStrong, AllowMachine: true}, req)
	_, ok = permissionAssurance["monitoring:read-markers"]
	assert.False(t, ok, "reads carry no assurance floor")
	assert.True(t, isKnownPermission("monitoring:write-markers"))
	assert.True(t, isKnownPermission("monitoring:read-markers"))

	// The API key that holds the write permission succeeds without a presence token.
	assert.Equal(t, http.StatusCreated, f.do(http.MethodPost, markersPath, f.writeKey, body).Code)
}

func TestMarkerListsMarkerRowsAndControllerStart(t *testing.T) {
	f := newMarkerFixture(t)

	f.record(t, audit.SystemEvent(audit.SystemTenantID, "controller_start", "Controller server started on :8443").
		Detail("revision", "0123456789ab"))
	f.record(t, audit.SystemEvent(audit.SystemTenantID, "marker_rollout_start", "rollout started").
		Resource("rollout", "rollout-7", "").
		Detail("revision", "0123456789ab").
		Detail("principal", "deploy-agent"))
	// System-tenant rows that are not markers are never listed.
	f.record(t, audit.SystemEvent(audit.SystemTenantID, "controller_stop", "Controller stopped"))
	f.record(t, audit.SystemEvent(audit.SystemTenantID, "markers_lookalike", "not a marker"))
	// A controller_start row written before the revision detail existed has no revision.
	f.record(t, audit.SystemEvent(audit.SystemTenantID, "controller_start", "old start"))

	code, markers := f.list(t, "")
	require.Equal(t, http.StatusOK, code)
	require.Len(t, markers, 3)

	assert.Equal(t, "controller_start", markers[0].Kind)
	assert.Equal(t, "0123456789ab", markers[0].Revision)
	assert.Equal(t, "rollout_start", markers[1].Kind)
	assert.Equal(t, "rollout-7", markers[1].Resource)
	assert.Equal(t, "deploy-agent", markers[1].Principal)
	assert.Equal(t, "0123456789ab", markers[1].Revision)
	assert.Equal(t, "controller_start", markers[2].Kind)
	assert.Empty(t, markers[2].Revision)
	for i := 1; i < len(markers); i++ {
		assert.False(t, markers[i].Time.Before(markers[i-1].Time), "time ordered")
	}

	_, starts := f.list(t, "kind=controller_start")
	assert.Len(t, starts, 2)
	_, rollouts := f.list(t, "kind=rollout_start")
	require.Len(t, rollouts, 1)
	assert.Equal(t, "rollout-7", rollouts[0].Resource)
	_, none := f.list(t, "kind=chaos_end")
	assert.Empty(t, none)

	// since and until bound the window on the row time.
	cut := markers[1].Time
	_, after := f.list(t, "since="+cut.Format(time.RFC3339Nano))
	require.Len(t, after, 2)
	assert.Equal(t, "rollout_start", after[0].Kind)
	_, before := f.list(t, "until="+cut.Format(time.RFC3339Nano))
	require.Len(t, before, 2)
	assert.Equal(t, "rollout_start", before[1].Kind)
}

func TestMarkerExcludesTenantScopedRolloutAudit(t *testing.T) {
	f := newMarkerFixture(t)

	// Tenant-scoped rows are never listed, even with a marker action name.
	f.record(t, audit.NewEventBuilder().
		Tenant("tenant-a").
		Type(business.AuditEventSystemEvent).
		Action("marker_rollout_start").
		User("user-1", business.AuditUserTypeHuman).
		Resource("rollout", "tenants/tenant-a/rollout-1", "").
		Detail("revision", "0123456789ab"))
	f.record(t, audit.NewEventBuilder().
		Tenant("tenant-a").
		Type(business.AuditEventSystemEvent).
		Action("controller_start").
		User("user-1", business.AuditUserTypeHuman).
		Resource("system", "controller", ""))
	// An existing rollout audit row (no revision, not a marker action) under the system
	// tenant is not a marker either.
	f.record(t, audit.SystemEvent(audit.SystemTenantID, "rollout_start", "rollout started").
		Resource("rollout", "rollout-1", ""))

	code, markers := f.list(t, "")
	require.Equal(t, http.StatusOK, code)
	assert.Empty(t, markers)

	f.record(t, audit.SystemEvent(audit.SystemTenantID, "marker_deploy", "deploy").
		Resource("marker", "m-1", "").
		Detail("revision", "0123456789ab"))
	_, markers = f.list(t, "")
	require.Len(t, markers, 1)
	assert.Equal(t, "m-1", markers[0].Resource)
}

func TestMarkerRoutesNotOnPublicRouter(t *testing.T) {
	f := newMarkerFixture(t)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		key := f.readKey
		var body []byte
		if method == http.MethodPost {
			key = f.writeKey
			body = []byte(`{"kind":"deploy","revision":"a1b2c3d"}`)
		}
		req := httptest.NewRequest(method, markersPath, bytes.NewReader(body))
		req.Header.Set("X-API-Key", key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		f.srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code, "%s on the public router", method)
	}

	// Nothing was written by the refused public calls.
	_, markers := f.list(t, "")
	assert.Empty(t, markers)
}

func TestMarkerRefusesGrantPrincipal(t *testing.T) {
	r := newRunFixture(t)

	for _, tc := range []struct {
		method string
		body   string
	}{
		{http.MethodPost, `{"kind":"deploy","revision":"a1b2c3d"}`},
		{http.MethodGet, ""},
	} {
		req := httptest.NewRequest(tc.method, markersPath, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+r.cred)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.srv.metricsRouter.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", tc.method, rec.Body.String())
		assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec), tc.method)
	}
	assert.False(t, automationRouteAllowed(http.MethodPost, markersPath))
	assert.False(t, automationRouteAllowed(http.MethodGet, markersPath))
}

func TestMarkerBodyLimit(t *testing.T) {
	f := newMarkerFixture(t)

	// Well-formed JSON, larger than the handler's body limit but under the router-wide
	// structured-body limit, so the handler's own bound is what answers.
	big, err := json.Marshal(map[string]any{
		"kind": "deploy", "revision": "a1b2c3d", "note": strings.Repeat("n", markerMaxBodyBytes*2),
	})
	require.NoError(t, err)
	require.Less(t, int64(len(big)), maxStructuredRequestBodyBytes)
	rec := f.do(http.MethodPost, markersPath, f.writeKey, big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, rec.Body.String())

	// Over the router-wide limit the shared body-limit middleware answers 413 too.
	huge := bytes.Repeat([]byte("a"), int(maxStructuredRequestBodyBytes)+1)
	rec = f.do(http.MethodPost, markersPath, f.writeKey, huge)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)

	_, markers := f.list(t, "")
	assert.Empty(t, markers)
}
