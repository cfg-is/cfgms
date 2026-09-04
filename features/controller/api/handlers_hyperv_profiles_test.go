// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupHypervProfileServer creates a test server wired with a hyperv-profile
// config store, mirroring setupRoleConfigServer.
func setupHypervProfileServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
	sm := pkgtesting.SetupTestStorage(t)
	server.SetHypervProfileConfigStore(sm.GetConfigStore())
	return server
}

// hypervProfileStrongPrincipal returns an ImplicitAdmin, AssuranceStrong
// principal scoped to tenantID — enough to satisfy both the permission check
// and the AssuranceStrong + RequireUserPresence gate on create/delete.
func hypervProfileStrongPrincipal(id, tenantID string) *Principal {
	return &Principal{
		ID:            id,
		Name:          "mtls-admin:" + id,
		Assurance:     session.AssuranceStrong,
		ImplicitAdmin: true,
		TenantID:      tenantID,
	}
}

// validHypervProfilePayload returns a JSON body for POST /api/v1/hyperv/profiles.
func validHypervProfilePayload(name string) []byte {
	b, _ := json.Marshal(hypervProfileRequest{
		Name:         name,
		OSFamily:     "linux",
		AnswerFormat: "preseed",
		Template:     "hostname={{ .VMName }}",
		Enroll: hypervProfileEnroll{
			RegistrationTokenSecretKey: "hyperv/enroll/regtoken",
			BundleURL:                  "https://controller.example/bundle",
		},
	})
	return b
}

// createHypervProfileReq builds and executes a POST request through the
// requirePermission("hyperv-profile","create") middleware, including a fresh
// presence token so the AssuranceStrong + RequireUserPresence gate passes.
func createHypervProfileReq(t *testing.T, s *Server, principal *Principal, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hyperv/profiles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, principal)
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, s, principal.ID))
	rec := httptest.NewRecorder()
	handler := s.requirePermission("hyperv-profile", "create")(http.HandlerFunc(s.handleCreateHypervProfile))
	handler.ServeHTTP(rec, req)
	return rec
}

// getHypervProfileReq builds and executes a GET request through the
// requirePermission("hyperv-profile","read") middleware.
func getHypervProfileReq(s *Server, principal *Principal, name string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hyperv/profiles/"+name, nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"name": name})
	rec := httptest.NewRecorder()
	handler := s.requirePermission("hyperv-profile", "read")(http.HandlerFunc(s.handleGetHypervProfile))
	handler.ServeHTTP(rec, req)
	return rec
}

// listHypervProfilesReq builds and executes a GET (list) request through the
// requirePermission("hyperv-profile","list") middleware.
func listHypervProfilesReq(s *Server, principal *Principal) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/hyperv/profiles", nil)
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	handler := s.requirePermission("hyperv-profile", "list")(http.HandlerFunc(s.handleListHypervProfiles))
	handler.ServeHTTP(rec, req)
	return rec
}

// deleteHypervProfileReq builds and executes a DELETE request through the
// requirePermission("hyperv-profile","delete") middleware, including a fresh
// presence token so the AssuranceStrong + RequireUserPresence gate passes.
func deleteHypervProfileReq(t *testing.T, s *Server, principal *Principal, name string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/hyperv/profiles/"+name, nil)
	req = withPrincipal(req, principal)
	req = withVars(req, map[string]string{"name": name})
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, s, principal.ID))
	rec := httptest.NewRecorder()
	handler := s.requirePermission("hyperv-profile", "delete")(http.HandlerFunc(s.handleDeleteHypervProfile))
	handler.ServeHTTP(rec, req)
	return rec
}

// TestHandleHypervProfile_CRUD_RoundTrip is the REQUIRED TEST from the AC: create
// -> show -> ls -> delete through the handler, backed by a real
// ConfigBackedProfileStore (via a real config store double, mirroring
// profile_store_test.go).
func TestHandleHypervProfile_CRUD_RoundTrip(t *testing.T) {
	server := setupHypervProfileServer(t)
	principal := hypervProfileStrongPrincipal("admin-1", "tenant-x")

	// Create.
	recCreate := createHypervProfileReq(t, server, principal, validHypervProfilePayload("debian-12-custom"))
	require.Equal(t, http.StatusCreated, recCreate.Code, "unexpected body: %s", recCreate.Body.String())

	var createResp APIResponse
	require.NoError(t, json.Unmarshal(recCreate.Body.Bytes(), &createResp))
	created, ok := createResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "debian-12-custom", created["name"])
	assert.Equal(t, "linux", created["os_family"])
	assert.Equal(t, "preseed", created["answer_format"])

	// Show.
	recShow := getHypervProfileReq(server, principal, "debian-12-custom")
	require.Equal(t, http.StatusOK, recShow.Code, "unexpected body: %s", recShow.Body.String())
	var showResp APIResponse
	require.NoError(t, json.Unmarshal(recShow.Body.Bytes(), &showResp))
	shown, ok := showResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "debian-12-custom", shown["name"])
	assert.Equal(t, "hostname={{ .VMName }}", shown["template"])

	// List.
	recList := listHypervProfilesReq(server, principal)
	require.Equal(t, http.StatusOK, recList.Code, "unexpected body: %s", recList.Body.String())
	var listResp APIResponse
	require.NoError(t, json.Unmarshal(recList.Body.Bytes(), &listResp))
	listData, ok := listResp.Data.(map[string]interface{})
	require.True(t, ok)
	profiles, ok := listData["profiles"].([]interface{})
	require.True(t, ok)
	assert.Contains(t, profiles, "debian-12-custom")

	// Delete.
	recDelete := deleteHypervProfileReq(t, server, principal, "debian-12-custom")
	require.Equal(t, http.StatusOK, recDelete.Code, "unexpected body: %s", recDelete.Body.String())

	// Show again -> 404.
	recShowAfterDelete := getHypervProfileReq(server, principal, "debian-12-custom")
	assert.Equal(t, http.StatusNotFound, recShowAfterDelete.Code)
}

// TestHandleDeleteHypervProfile_NotFound verifies DELETE for a non-existent
// profile returns 404.
func TestHandleDeleteHypervProfile_NotFound(t *testing.T) {
	server := setupHypervProfileServer(t)
	principal := hypervProfileStrongPrincipal("admin-1", "tenant-x")

	rec := deleteHypervProfileReq(t, server, principal, "nonexistent")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleCreateHypervProfile_InvalidProfile is the REQUIRED TEST from the AC:
// an invalid profile (bad name, unparseable template, or over the size cap) is
// rejected at author time with a clear 400 error.
func TestHandleCreateHypervProfile_InvalidProfile(t *testing.T) {
	server := setupHypervProfileServer(t)
	principal := hypervProfileStrongPrincipal("admin-1", "tenant-x")

	cases := []struct {
		name string
		req  hypervProfileRequest
		code string
	}{
		{
			name: "bad name",
			req: hypervProfileRequest{
				Name: "../etc/passwd", OSFamily: "linux", AnswerFormat: "preseed", Template: "x",
			},
			code: "INVALID_NAME",
		},
		{
			name: "bad answer format",
			req: hypervProfileRequest{
				Name: "bad-format", OSFamily: "linux", AnswerFormat: "nope", Template: "x",
			},
			code: "INVALID_ANSWER_FORMAT",
		},
		{
			name: "unparseable template",
			req: hypervProfileRequest{
				Name: "bad-template", OSFamily: "linux", AnswerFormat: "preseed", Template: "{{ .VMName",
			},
			code: "INVALID_TEMPLATE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.req)
			require.NoError(t, err)
			rec := createHypervProfileReq(t, server, principal, body)
			require.Equal(t, http.StatusBadRequest, rec.Code, "unexpected body: %s", rec.Body.String())

			var errResp ErrorResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, tc.code, errResp.Error.Code)
		})
	}
}

// TestHandleCreateHypervProfile_RejectsOversizedProfile verifies the size cap is
// enforced at the handler layer, not just the store layer.
func TestHandleCreateHypervProfile_RejectsOversizedProfile(t *testing.T) {
	server := setupHypervProfileServer(t)
	principal := hypervProfileStrongPrincipal("admin-1", "tenant-x")

	body, err := json.Marshal(hypervProfileRequest{
		Name:         "oversized",
		OSFamily:     "linux",
		AnswerFormat: "preseed",
		Template:     string(make([]byte, 300*1024)),
	})
	require.NoError(t, err)

	rec := createHypervProfileReq(t, server, principal, body)
	require.Equal(t, http.StatusBadRequest, rec.Code, "unexpected body: %s", rec.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "PROFILE_TOO_LARGE", errResp.Error.Code)
}

// TestHandleHypervProfile_TenantScoping is the REQUIRED TEST from the AC: a
// caller holding hyperv-profile in tenant A cannot create or read a profile in
// tenant B. Mirrors TestHandleRoleConfig_TenantScoping (#2548): a tenant-scoped
// caller is PINNED to its own tenant, so any cross-tenant attempt resolves
// against a namespace where the profile does not exist and returns 404 — never
// 403 (no existence disclosure).
func TestHandleHypervProfile_TenantScoping(t *testing.T) {
	server := setupHypervProfileServer(t)

	principalB := hypervProfileStrongPrincipal("admin-b", "tenant-b")
	recSeed := createHypervProfileReq(t, server, principalB, validHypervProfilePayload("tenant-b-profile"))
	require.Equal(t, http.StatusCreated, recSeed.Code, "seed tenant-b profile: %s", recSeed.Body.String())

	// A tenant-a caller cannot create into tenant-b: the ?tenant= query value is
	// never consulted while principal.TenantID != "" (hypervProfileTenantFromRequest),
	// so this always writes into tenant-a.
	principalA := hypervProfileStrongPrincipal("admin-a", "tenant-a")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hyperv/profiles?tenant=tenant-b", bytes.NewReader(validHypervProfilePayload("cross-tenant-attempt")))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, principalA)
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, principalA.ID))
	rec := httptest.NewRecorder()
	handler := server.requirePermission("hyperv-profile", "create")(http.HandlerFunc(server.handleCreateHypervProfile))
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, "create must succeed but land in tenant-a: %s", rec.Body.String())

	// A tenant-a caller cannot read tenant-b's profile by name — 404, not 403.
	recGet := getHypervProfileReq(server, principalA, "tenant-b-profile")
	assert.Equal(t, http.StatusNotFound, recGet.Code,
		"scoped caller is pinned to its own tenant; tenant-b-profile is not found there")

	// A tenant-a caller cannot delete tenant-b's profile — 404, not 403.
	recDelete := deleteHypervProfileReq(t, server, principalA, "tenant-b-profile")
	assert.Equal(t, http.StatusNotFound, recDelete.Code,
		"scoped caller is pinned to its own tenant; delete of tenant-b-profile must 404")

	// tenant-b's profile is untouched.
	recGetB := getHypervProfileReq(server, principalB, "tenant-b-profile")
	assert.Equal(t, http.StatusOK, recGetB.Code, "tenant-b's own profile must be unaffected")
}

// TestHandleCreateHypervProfile_APIKeyRejected verifies that an API-key
// principal (Machine assurance) is rejected on the create endpoint — it can
// never satisfy AssuranceStrong (Issue #3785, mirrors module:approve).
func TestHandleCreateHypervProfile_APIKeyRejected(t *testing.T) {
	server := setupHypervProfileServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"hyperv-profile:create"}, "tenant-x", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/hyperv/profiles", bytes.NewReader(validHypervProfilePayload("blocked")))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"API-key principal must be rejected with 403 on the create endpoint (AssuranceStrong gate)")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Machine-assurance 403 must not include a step-up challenge")
}

// TestHandleDeleteHypervProfile_APIKeyRejected verifies that an API-key
// principal (Machine assurance) is rejected on the delete endpoint.
func TestHandleDeleteHypervProfile_APIKeyRejected(t *testing.T) {
	server := setupHypervProfileServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"hyperv-profile:delete"}, "tenant-x", 5*time.Minute)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/hyperv/profiles/whatever", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"API-key principal must be rejected with 403 on the delete endpoint (AssuranceStrong gate)")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Machine-assurance 403 must not include a step-up challenge")
}

// TestHandleListHypervProfiles_ReachableByAPIKey verifies the list/read
// endpoints are reachable by a Machine-assurance API key (no elevated
// assurance floor on reads).
func TestHandleListHypervProfiles_ReachableByAPIKey(t *testing.T) {
	server := setupHypervProfileServer(t)
	apiKey := NewEphemeralTestKey(t, server, []string{"hyperv-profile:list"}, "tenant-x", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hyperv/profiles", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "unexpected body: %s", rec.Body.String())
}

// TestHandleHypervProfile_ServiceUnavailable verifies 503 when no hyperv-profile
// config store is wired.
func TestHandleHypervProfile_ServiceUnavailable(t *testing.T) {
	server := setupTestServer(t) // no hypervProfileConfigStore wired
	apiKey := NewEphemeralTestKey(t, server, []string{"hyperv-profile:list"}, "tenant-x", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hyperv/profiles", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleHypervProfile_RootAdminTenantTargeting verifies a root/global admin
// (empty principal tenant) must select the target tenant via ?tenant=, mirroring
// TestHandleRoleConfig_RootAdminTenantTargeting (#2548).
func TestHandleHypervProfile_RootAdminTenantTargeting(t *testing.T) {
	server := setupHypervProfileServer(t)
	rootPrincipal := &Principal{ID: "root-admin", Assurance: session.AssuranceStrong, ImplicitAdmin: true}

	// Without ?tenant= -> 400.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hyperv/profiles", bytes.NewReader(validHypervProfilePayload("infra-profile")))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, rootPrincipal))
	req.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, rootPrincipal.ID))
	rec := httptest.NewRecorder()
	handler := server.requirePermission("hyperv-profile", "create")(http.HandlerFunc(server.handleCreateHypervProfile))
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code,
		"root admin without ?tenant= must be rejected; body: %s", rec.Body.String())

	// With ?tenant=infra-x -> 201.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/hyperv/profiles?tenant=infra-x", bytes.NewReader(validHypervProfilePayload("infra-profile")))
	req2.Header.Set("Content-Type", "application/json")
	req2 = req2.WithContext(context.WithValue(req2.Context(), principalContextKey, rootPrincipal))
	req2.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, rootPrincipal.ID))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusCreated, rec2.Code,
		"root admin with ?tenant= must succeed; body: %s", rec2.Body.String())
}

// TestHypervProfileHandlers_SucceedOnNonAuthoritativeNode covers the same gap
// class as the [REQUIRED TEST] in handlers_cert_bindings_test.go (Issue #3761,
// ADR-031 Decision 1). handleCreateHypervProfile and handleDeleteHypervProfile
// used to sit behind a HasLeadership() gate; writes go through the git-backed
// ConfigStore, which is the serialization point now, not leadership. Both
// handlers must reach their normal success path against a real, deliberately
// non-authoritative *ha.Manager (ClusterMode, no lease ever acquired).
func TestHypervProfileHandlers_SucceedOnNonAuthoritativeNode(t *testing.T) {
	server := setupHypervProfileServer(t)
	server.haManager = newNonAuthoritativeHAManager(t)
	principal := hypervProfileStrongPrincipal("admin-non-leader", "tenant-x")

	recCreate := createHypervProfileReq(t, server, principal, validHypervProfilePayload("non-leader-profile"))
	require.Equal(t, http.StatusCreated, recCreate.Code,
		"create must succeed regardless of leadership; body: %s", recCreate.Body.String())

	recShow := getHypervProfileReq(server, principal, "non-leader-profile")
	require.Equal(t, http.StatusOK, recShow.Code,
		"the profile must actually be persisted on a non-authoritative node; body: %s", recShow.Body.String())

	recDelete := deleteHypervProfileReq(t, server, principal, "non-leader-profile")
	require.Equal(t, http.StatusOK, recDelete.Code,
		"delete must succeed regardless of leadership; body: %s", recDelete.Body.String())

	recShowAfterDelete := getHypervProfileReq(server, principal, "non-leader-profile")
	assert.Equal(t, http.StatusNotFound, recShowAfterDelete.Code,
		"the profile must actually be removed on a non-authoritative node")
}
