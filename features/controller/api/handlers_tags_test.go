// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// setupTagServer creates a test server wired with a tag store and a pre-registered steward.
func setupTagServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	dsn := filepath.Join(t.TempDir(), "tags.db")
	ts, err := tagstore.NewFromDSN(dsn, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, ts.Initialize(context.Background()))
	t.Cleanup(func() { _ = ts.Close() })
	server.SetTagStore(ts)
	return server
}

// addTagTestSteward registers a steward with the given ID and tenantID in the controller service.
func addTagTestSteward(t *testing.T, server *Server, stewardID, tenantID string) {
	t.Helper()
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "addr", "active"))
}

// doTagRequest sends an HTTP request to the server router and returns the recorder.
func doTagRequest(server *Server, method, path string, apiKey string, body interface{}) *httptest.ResponseRecorder {
	var bodyReader *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// ---- handleListStewardTags ----

func TestHandleListStewardTags_HappyPath(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:read"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-list-ok", "test-tenant")

	// Pre-populate tags.
	ts := server.tagStore
	require.NoError(t, ts.Set(context.Background(), "s-list-ok", []string{"prod", "web"}))

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-list-ok/tags", apiKey, nil)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	tags, _ := data["tags"].([]interface{})
	assert.Len(t, tags, 2)
}

func TestHandleListStewardTags_EmptyList(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:read"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-empty", "test-tenant")

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-empty/tags", apiKey, nil)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	tags, _ := data["tags"].([]interface{})
	assert.Empty(t, tags)
}

func TestHandleListStewardTags_UnknownSteward(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:read"}, "test-tenant", 5*time.Minute)

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/no-such-steward/tags", apiKey, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleListStewardTags_Unauthenticated(t *testing.T) {
	server := setupTagServer(t)
	addTagTestSteward(t, server, "s-unauth", "test-tenant")

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-unauth/tags", "", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleListStewardTags_CrossTenant(t *testing.T) {
	server := setupTagServer(t)
	// API key scoped to "other-tenant" tries to access a steward in "test-tenant".
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:read"}, "other-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-cross-read", "test-tenant")

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-cross-read/tags", apiKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---- handleAddStewardTags ----

func TestHandleAddStewardTags_HappyPath(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-add-ok", "test-tenant")

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-add-ok/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod", "web"}})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	tags, _ := data["tags"].([]interface{})
	assert.Len(t, tags, 2)
}

func TestHandleAddStewardTags_Idempotent(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-idem", "test-tenant")

	// Add prod first.
	rec1 := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-idem/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	require.Equal(t, http.StatusOK, rec1.Code)

	// Add prod again + web → should have prod + web (no duplicate).
	rec2 := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-idem/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod", "web"}})
	require.Equal(t, http.StatusOK, rec2.Code, "body: %s", rec2.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	tags, _ := data["tags"].([]interface{})
	assert.Len(t, tags, 2)
}

func TestHandleAddStewardTags_InvalidTag(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-badtag", "test-tenant")

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-badtag/tags", apiKey,
		map[string]interface{}{"tags": []string{"UPPERCASE-INVALID"}})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleAddStewardTags_UnknownSteward(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/no-such/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleAddStewardTags_CrossTenant(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "other-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-cross-add", "test-tenant")

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-cross-add/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleAddStewardTags_Unauthenticated(t *testing.T) {
	server := setupTagServer(t)
	addTagTestSteward(t, server, "s-unauth-add", "test-tenant")

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-unauth-add/tags", "",
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleAddStewardTags_TagStoreNil(t *testing.T) {
	server := setupTestServer(t) // no tag store wired
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-nostore", "test-tenant")

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-nostore/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ---- handleDeleteStewardTags ----

func TestHandleDeleteStewardTags_HappyPath(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write", "steward:tag:read"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-del-ok", "test-tenant")

	// Seed tags.
	ts := server.tagStore
	require.NoError(t, ts.Set(context.Background(), "s-del-ok", []string{"prod", "web", "debug"}))

	// Remove one tag.
	rec := doTagRequest(server, http.MethodDelete, "/api/v1/stewards/s-del-ok/tags", apiKey,
		map[string]interface{}{"tags": []string{"debug"}})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	tags, _ := data["tags"].([]interface{})
	assert.Len(t, tags, 2)

	// Verify via GET.
	rec2 := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-del-ok/tags", apiKey, nil)
	require.Equal(t, http.StatusOK, rec2.Code)
	var resp2 APIResponse
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &resp2))
	data2, _ := resp2.Data.(map[string]interface{})
	tags2, _ := data2["tags"].([]interface{})
	assert.Len(t, tags2, 2)
}

func TestHandleDeleteStewardTags_RemoveNonexistent(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-del-noop", "test-tenant")

	// Remove a tag that was never set — should succeed with empty list.
	rec := doTagRequest(server, http.MethodDelete, "/api/v1/stewards/s-del-noop/tags", apiKey,
		map[string]interface{}{"tags": []string{"ghost"}})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, _ := resp.Data.(map[string]interface{})
	tags, _ := data["tags"].([]interface{})
	assert.Empty(t, tags)
}

func TestHandleDeleteStewardTags_UnknownSteward(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)

	rec := doTagRequest(server, http.MethodDelete, "/api/v1/stewards/no-such/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleDeleteStewardTags_CrossTenant(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "other-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-cross-del", "test-tenant")

	rec := doTagRequest(server, http.MethodDelete, "/api/v1/stewards/s-cross-del/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---- round-trip ----

func TestStewardTagsRoundTrip(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write", "steward:tag:read"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-roundtrip", "test-tenant")

	// Add tags.
	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-roundtrip/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod", "web"}})
	require.Equal(t, http.StatusOK, rec.Code)

	// List tags.
	rec2 := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-roundtrip/tags", apiKey, nil)
	require.Equal(t, http.StatusOK, rec2.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &resp))
	data, _ := resp.Data.(map[string]interface{})
	tags, _ := data["tags"].([]interface{})
	assert.Len(t, tags, 2)

	// Remove one.
	rec3 := doTagRequest(server, http.MethodDelete, "/api/v1/stewards/s-roundtrip/tags", apiKey,
		map[string]interface{}{"tags": []string{"web"}})
	require.Equal(t, http.StatusOK, rec3.Code)

	// List again — only prod remains.
	rec4 := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-roundtrip/tags", apiKey, nil)
	require.Equal(t, http.StatusOK, rec4.Code)
	var resp4 APIResponse
	require.NoError(t, json.Unmarshal(rec4.Body.Bytes(), &resp4))
	data4, _ := resp4.Data.(map[string]interface{})
	tags4, _ := data4["tags"].([]interface{})
	assert.Len(t, tags4, 1)
	assert.Equal(t, "prod", tags4[0])
}

// TestHandleListStewardTags_NilStore verifies a 503 when the tag store is not wired.
func TestHandleListStewardTags_NilStore(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:read"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-nostore-get", "test-tenant")

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-nostore-get/tags", apiKey, nil)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleDeleteStewardTags_NilStore verifies a 503 when the tag store is not wired.
func TestHandleDeleteStewardTags_NilStore(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-nostore-del", "test-tenant")

	rec := doTagRequest(server, http.MethodDelete, "/api/v1/stewards/s-nostore-del/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleAddStewardTags_SubtreeAccess verifies that a caller scoped to a parent tenant
// can tag stewards in child tenants (subtree access).
func TestHandleAddStewardTags_SubtreeAccess(t *testing.T) {
	server := setupTagServer(t)
	// API key scoped to "msp" can tag stewards in "msp/client-1".
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write"}, "msp", 5*time.Minute)
	addTagTestSteward(t, server, "s-child", "msp/client-1")

	rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-child/tags", apiKey,
		map[string]interface{}{"tags": []string{"prod"}})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// TestHandleListStewardTags_InvalidStewardID verifies that a malformed steward ID is rejected.
func TestHandleListStewardTags_InvalidStewardID(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:read"}, "test-tenant", 5*time.Minute)

	// The mux route parameter {id} does not match slashes / dots, so the router
	// returns 404 for paths it cannot match. The identifier validation test is
	// exercised via the direct handler path below.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/s-list-ok/tags", nil)
	req.Header.Set("X-API-Key", apiKey)
	ctx := req.Context()
	ctx = withTenantID(ctx, "test-tenant")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	// Inject an invalid steward ID via the principal context as if it came from a bad mux var.
	server.handleListStewardTags(w, withVars(req, map[string]string{"id": "bad..id"}))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// withTenantID injects a tenantID into the request context.
func withTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxkeys.TenantID, tenantID)
}

// ---- mergeTags unit tests ----

func TestMergeTags_BasicUnion(t *testing.T) {
	result := mergeTags([]string{"a", "b"}, []string{"b", "c"})
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestMergeTags_EmptyCurrent(t *testing.T) {
	result := mergeTags(nil, []string{"prod", "web"})
	assert.Equal(t, []string{"prod", "web"}, result)
}

func TestMergeTags_EmptyIncoming(t *testing.T) {
	result := mergeTags([]string{"prod"}, nil)
	assert.Equal(t, []string{"prod"}, result)
}

func TestMergeTags_BothEmpty(t *testing.T) {
	result := mergeTags(nil, nil)
	assert.Empty(t, result)
}

func TestMergeTags_Sorted(t *testing.T) {
	result := mergeTags([]string{"z"}, []string{"a", "m"})
	assert.Equal(t, []string{"a", "m", "z"}, result)
}

// ---- removeTags unit tests ----

func TestRemoveTags_Basic(t *testing.T) {
	result := removeTags([]string{"prod", "web", "debug"}, []string{"debug"})
	assert.Equal(t, []string{"prod", "web"}, result)
}

func TestRemoveTags_RemoveNonexistent(t *testing.T) {
	result := removeTags([]string{"prod"}, []string{"ghost"})
	assert.Equal(t, []string{"prod"}, result)
}

func TestRemoveTags_RemoveAll(t *testing.T) {
	result := removeTags([]string{"prod", "web"}, []string{"prod", "web"})
	assert.Empty(t, result)
}

func TestRemoveTags_EmptySource(t *testing.T) {
	result := removeTags(nil, []string{"prod"})
	assert.Empty(t, result)
}

// TestHandleAddStewardTags_Concurrent verifies that concurrent POST requests for the
// same steward accumulate all tag additions — no update is silently overwritten.
func TestHandleAddStewardTags_Concurrent(t *testing.T) {
	server := setupTagServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:tag:write", "steward:tag:read"}, "test-tenant", 5*time.Minute)
	addTagTestSteward(t, server, "s-concurrent", "test-tenant")

	const goroutines = 10
	tags := []string{"taga", "tagb", "tagc", "tagd", "tage", "tagf", "tagg", "tagh", "tagi", "tagj"}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		tag := tags[i]
		go func() {
			defer wg.Done()
			rec := doTagRequest(server, http.MethodPost, "/api/v1/stewards/s-concurrent/tags", apiKey,
				map[string]interface{}{"tags": []string{tag}})
			assert.Equal(t, http.StatusOK, rec.Code, "tag %s: %s", tag, rec.Body.String())
		}()
	}
	wg.Wait()

	rec := doTagRequest(server, http.MethodGet, "/api/v1/stewards/s-concurrent/tags", apiKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	got, _ := data["tags"].([]interface{})
	assert.Len(t, got, goroutines, "all %d concurrent tag additions must be preserved", goroutines)
}
