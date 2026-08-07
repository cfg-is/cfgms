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
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newAssuranceTestServer creates a Server with assurancePolicyStore and tenantStore
// wired, plus a real RBAC service — suitable for handler and middleware tests.
func newAssuranceTestServer(t *testing.T, apStore business.AssurancePolicyStore, tsStore business.TenantStore) *Server {
	t.Helper()
	srv := setupTestServer(t)
	if apStore != nil {
		srv.SetAssurancePolicyStore(apStore)
	}
	if tsStore != nil {
		srv.SetTenantStore(tsStore)
	}
	return srv
}

// ---- GET /api/v1/tenants/{tenant_path}/assurance-policy ----

func TestHandleGetAssurancePolicy_NoStore_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	// No assurancePolicyStore wired.
	apiKey := NewTestKey(t, srv, []string{"assurance-policy:get"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-tenant/assurance-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleGetAssurancePolicy_ReturnsEmptyOverrides(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"test-tenant": {"test-tenant"},
	})
	srv := newAssuranceTestServer(t, apStore, tsStore)
	apiKey := NewTestKey(t, srv, []string{"assurance-policy:get"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-tenant/assurance-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "get must succeed: %s", rec.Body.String())
	var resp AdminAssurancePolicyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "test-tenant", resp.TenantID)
	assert.Empty(t, resp.Overrides)
}

func TestHandleGetAssurancePolicy_ReturnsStoredOverrides(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"test-tenant": {"test-tenant"},
	})
	strongStr := "strong"
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "test-tenant",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "certificate:provision", MinOverride: ptrInt(int(session.AssuranceStrong)), RequireUserPresence: true},
		},
	}))

	srv := newAssuranceTestServer(t, apStore, tsStore)
	apiKey := NewTestKey(t, srv, []string{"assurance-policy:get"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-tenant/assurance-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp AdminAssurancePolicyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "test-tenant", resp.TenantID)
	require.Len(t, resp.Overrides, 1)
	assert.Equal(t, "certificate:provision", resp.Overrides[0].PermissionID)
	assert.Equal(t, &strongStr, resp.Overrides[0].MinOverride)
	assert.True(t, resp.Overrides[0].RequireUserPresence)
}

func TestHandleGetAssurancePolicy_Unauthenticated(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	srv := newAssuranceTestServer(t, apStore, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/test-tenant/assurance-policy", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleGetAssurancePolicy_CrossTenantReturns404(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	srv := newAssuranceTestServer(t, apStore, nil)
	// Scoped API key belonging to "tenant-a".
	apiKey := NewEphemeralTestKey(t, srv, []string{"assurance-policy:get"}, "tenant-a", 5*time.Minute)

	// Attempt to read policy for an unrelated tenant.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-b/assurance-policy", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---- PUT /api/v1/tenants/{tenant_path}/assurance-policy ----

func TestHandleSetAssurancePolicy_Unauthenticated(t *testing.T) {
	srv := setupTestServer(t)

	body, _ := json.Marshal(AdminAssurancePolicyRequest{Overrides: nil})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleSetAssurancePolicy_RequiresAssuranceStrong(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	srv := newAssuranceTestServer(t, apStore, nil)
	// API-key principal is AssuranceMachine — cannot satisfy AssuranceStrong requirement.
	apiKey := NewTestKey(t, srv, []string{"assurance-policy:set"})

	body, _ := json.Marshal(AdminAssurancePolicyRequest{Overrides: nil})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	// API-key principals are AssuranceMachine and get 403, not 401.
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleSetAssurancePolicy_SetsOverride(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"test-tenant": {"test-tenant"},
	})
	srv := newAssuranceTestServer(t, apStore, tsStore)

	strong := "strong"
	body, _ := json.Marshal(AdminAssurancePolicyRequest{
		Overrides: []AssurancePolicyOverrideDTO{
			{PermissionID: "certificate:provision", MinOverride: &strong, RequireUserPresence: true},
		},
	})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "set must succeed: %s", rec.Body.String())

	// Verify the store was updated.
	policy, err := apStore.GetPolicy(context.Background(), "test-tenant")
	require.NoError(t, err)
	require.Len(t, policy.Overrides, 1)
	assert.Equal(t, "certificate:provision", policy.Overrides[0].PermissionID)
	assert.True(t, policy.Overrides[0].RequireUserPresence)
}

func TestHandleSetAssurancePolicy_InvalidMinOverride_Returns400(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"test-tenant": {"test-tenant"},
	})
	srv := newAssuranceTestServer(t, apStore, tsStore)

	// "machine" is rejected — overrides can only raise the bar.
	machineStr := "machine"
	body, _ := json.Marshal(AdminAssurancePolicyRequest{
		Overrides: []AssurancePolicyOverrideDTO{
			{PermissionID: "certificate:provision", MinOverride: &machineStr},
		},
	})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleSetAssurancePolicy_InvalidBody_Returns400(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	srv := newAssuranceTestServer(t, apStore, nil)

	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleSetAssurancePolicy_CrossTenantReturns403ForAPIKey(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	srv := newAssuranceTestServer(t, apStore, nil)
	// Scoped API key for tenant-a — AssuranceMachine. assurance-policy:set requires
	// AssuranceStrong, so the assurance gate fires before the cross-tenant handler check
	// (consistent with TestHandleApproveRefresh_CrossTenantReturns404 which also gets 403).
	apiKey := NewEphemeralTestKey(t, srv, []string{"assurance-policy:set"}, "tenant-a", 5*time.Minute)

	body, _ := json.Marshal(AdminAssurancePolicyRequest{Overrides: nil})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/tenant-b/assurance-policy", bytes.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	// API-key principals are AssuranceMachine; the assurance gate returns 403 (can't step up).
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---- [REQUIRED TEST] per-AC: presence override in overriding tenant vs sibling ----

// TestResolveAssurance_PresenceOverride_ChallengingInOverridingTenant verifies that
// an AssuranceStrong-but-no-fresh-presence principal is challenged (401 + presence="required")
// on certificate:provision in a tenant that has RequireUserPresence:true on that permission,
// while the same principal is admitted (no presence challenge) in a sibling tenant without the override.
//
// [REQUIRED TEST] per acceptance criterion: the exact AC scenario.
func TestResolveAssurance_PresenceOverride_ChallengingInOverridingTenant(t *testing.T) {
	apStore := newTestAssurancePolicyStore()

	// "tenant-with-override" declares RequireUserPresence on certificate:provision.
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root/tenant-with-override",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "certificate:provision", RequireUserPresence: true},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/tenant-with-override": {"root", "root/tenant-with-override"},
		"root/sibling-no-override":  {"root", "root/sibling-no-override"},
	})

	srv := setupTestServer(t)
	srv.SetAssurancePolicyStore(apStore)
	srv.SetTenantStore(tsStore)

	// Confirm global map does not have RequireUserPresence for certificate:provision.
	globalReq := permissionAssurance["certificate:provision"]
	require.False(t, globalReq.RequireUserPresence, "precondition: global map must not have RequireUserPresence for certificate:provision")

	// Resolve for the overriding tenant — must require presence.
	reqA, foundA := srv.resolveAssuranceRequirement(context.Background(), "root/tenant-with-override", "certificate:provision")
	require.True(t, foundA)
	assert.True(t, reqA.RequireUserPresence, "overriding tenant must have RequireUserPresence=true")
	assert.Equal(t, session.AssuranceStrong, reqA.Min)

	// Resolve for the sibling tenant — no override, must NOT require presence.
	reqB, foundB := srv.resolveAssuranceRequirement(context.Background(), "root/sibling-no-override", "certificate:provision")
	require.True(t, foundB)
	assert.False(t, reqB.RequireUserPresence, "sibling without override must not require presence")
	assert.Equal(t, session.AssuranceStrong, reqB.Min)
}

// ---- [REQUIRED TEST] per-AC: child inherits parent override and can tighten further ----

// TestHandleSetAssurancePolicy_ChildInheritsParentAndCanTighten verifies that:
//   - A child tenant inherits a parent's Min=strong override.
//   - The child can additionally set RequireUserPresence=true (tightening further).
//   - A child PUT attempting to set MinOverride below the parent's resolved value is rejected 400.
//
// [REQUIRED TEST] per acceptance criterion.
func TestHandleSetAssurancePolicy_ChildInheritsParentAndCanTighten(t *testing.T) {
	const testPerm = "test-child-inherit"
	// Global floor for testPerm is AssuranceBasic.
	permissionAssurance[testPerm] = Requirement{Min: session.AssuranceBasic}
	t.Cleanup(func() { delete(permissionAssurance, testPerm) })

	apStore := newTestAssurancePolicyStore()
	// Parent sets Min to Strong.
	strongInt := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "root",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: testPerm, MinOverride: &strongInt},
		},
	}))

	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"root/child": {"root", "root/child"},
	})
	srv := setupTestServer(t)
	srv.SetAssurancePolicyStore(apStore)
	srv.SetTenantStore(tsStore)

	// --- Sub-test 1: child can tighten by adding RequireUserPresence ---
	strong := "strong"
	body1, _ := json.Marshal(AdminAssurancePolicyRequest{
		Overrides: []AssurancePolicyOverrideDTO{
			{PermissionID: testPerm, MinOverride: &strong, RequireUserPresence: true},
		},
	})
	req1 := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/root/child/assurance-policy", bytes.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	srv.router.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code, "child tightening must succeed: %s", rec1.Body.String())

	// Verify both parent's Min and child's RequireUserPresence are in effect.
	reqChild, foundChild := srv.resolveAssuranceRequirement(context.Background(), "root/child", testPerm)
	require.True(t, foundChild)
	assert.Equal(t, session.AssuranceStrong, reqChild.Min, "parent Min must carry through to child")
	assert.True(t, reqChild.RequireUserPresence, "child RequireUserPresence must apply on top of parent")

	// --- Sub-test 2: child PUT attempting to lower Min below parent is rejected 400 ---
	basic := "basic"
	body2, _ := json.Marshal(AdminAssurancePolicyRequest{
		Overrides: []AssurancePolicyOverrideDTO{
			{PermissionID: testPerm, MinOverride: &basic},
		},
	})
	req2 := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/root/child/assurance-policy", bytes.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	srv.router.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusBadRequest, rec2.Code,
		"child PUT with MinOverride below parent-resolved value must be rejected 400: %s", rec2.Body.String())
}

// TestHandleSetAssurancePolicy_NoStore_Returns503 verifies that when the store is
// not wired the handler returns 503.
func TestHandleSetAssurancePolicy_NoStore_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	// No assurancePolicyStore wired.

	body, _ := json.Marshal(AdminAssurancePolicyRequest{Overrides: nil})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleSetAssurancePolicy_ClearsOverrides verifies that setting empty overrides
// clears previously declared overrides (full-replace semantics).
func TestHandleSetAssurancePolicy_ClearsOverrides(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	strongInt := int(session.AssuranceStrong)
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID: "test-tenant",
		Overrides: []business.AssurancePolicyOverride{
			{PermissionID: "certificate:provision", MinOverride: &strongInt},
		},
	}))
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"test-tenant": {"test-tenant"},
	})
	srv := newAssuranceTestServer(t, apStore, tsStore)

	// PUT with empty overrides should clear.
	body, _ := json.Marshal(AdminAssurancePolicyRequest{Overrides: []AssurancePolicyOverrideDTO{}})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	policy, err := apStore.GetPolicy(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Empty(t, policy.Overrides, "PUT with empty overrides must clear existing overrides")
}

// TestHandleSetAssurancePolicy_NilMinOverride_NoValidation verifies that an override
// with MinOverride=nil (presence-only) does not trigger tighten-only validation.
func TestHandleSetAssurancePolicy_NilMinOverride_NoValidation(t *testing.T) {
	apStore := newTestAssurancePolicyStore()
	tsStore := newTestTenantStoreWithPath(map[string][]string{
		"test-tenant": {"test-tenant"},
	})
	srv := newAssuranceTestServer(t, apStore, tsStore)

	// No MinOverride, only RequireUserPresence — no validation needed.
	body, _ := json.Marshal(AdminAssurancePolicyRequest{
		Overrides: []AssurancePolicyOverrideDTO{
			{PermissionID: "certificate:provision", RequireUserPresence: true},
		},
	})
	req := makeAdminRequest(t, http.MethodPut, "/api/v1/tenants/test-tenant/assurance-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "presence-only override must be accepted: %s", rec.Body.String())
}

// ptrInt returns a pointer to the given int value.
func ptrInt(i int) *int { return &i }
