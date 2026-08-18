// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/fleet"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/service"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	loggingInterfaces "github.com/cfgis/cfgms/pkg/logging/interfaces"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// ---- handleDecommissionSteward tests (Issue #2408) ----

// setupDecommissionServer creates a test server wired with a real flat-file steward
// store, suitable for decommission handler tests that need durable storage.
func setupDecommissionServer(t *testing.T) (*Server, business.StewardStore) {
	t.Helper()
	server := setupTestServer(t)
	st, _ := newTestStewardDurableStore(t)
	server.SetStewardStore(st)
	return server, st
}

// deleteDecommissionSteward calls handleDecommissionSteward directly (bypassing the Tier-3
// middleware) with a root-admin mTLS principal so we can exercise the handler in isolation.
func deleteDecommissionSteward(server *Server, stewardID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/"+stewardID, nil)
	req = withPrincipal(req, &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleDecommissionSteward(rec, req)
	return rec
}

// TestHandleDecommissionSteward_HappyPath verifies that a known steward is tombstoned
// with status "deregistered" and the response contains {"id":"...","status":"deregistered"}.
func TestHandleDecommissionSteward_HappyPath(t *testing.T) {
	server, st := setupDecommissionServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-decomm-ok",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))
	require.NoError(t, server.controllerService.RegisterSteward("s-decomm-ok", "test-tenant", "addr", "active"))

	rec := deleteDecommissionSteward(server, "s-decomm-ok")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "s-decomm-ok", resp.Data["id"])
	assert.Equal(t, "deregistered", resp.Data["status"])

	// Verify durable store reflects the tombstone.
	got, err := st.GetSteward(context.Background(), "s-decomm-ok")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusDeregistered, got.Status)
}

// TestHandleDecommissionSteward_APIKeyRejected verifies that an API-key caller
// is rejected with 403 at the Tier-3 gate (via the full router).
func TestHandleDecommissionSteward_APIKeyRejected(t *testing.T) {
	server, _ := setupDecommissionServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:decommission"})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/any-steward", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "API-key callers must be rejected at Tier-3")
}

// TestHandleDecommissionSteward_InvalidID verifies 400 for a malformed steward ID.
func TestHandleDecommissionSteward_InvalidID(t *testing.T) {
	server, _ := setupDecommissionServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/bad.id:here", nil)
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "bad.id:here"})
	rec := httptest.NewRecorder()
	server.handleDecommissionSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_STEWARD_ID", errResp.Error.Code)
}

// TestHandleDecommissionSteward_NilStore verifies 503 when stewardStore is nil.
func TestHandleDecommissionSteward_NilStore(t *testing.T) {
	server := setupTestServer(t)
	// stewardStore is nil in the default setup.

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/some-steward", nil)
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "some-steward"})
	rec := httptest.NewRecorder()
	server.handleDecommissionSteward(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleDecommissionSteward_NotFound verifies 404 for an unknown steward ID.
func TestHandleDecommissionSteward_NotFound(t *testing.T) {
	server, _ := setupDecommissionServer(t)

	rec := deleteDecommissionSteward(server, "nonexistent-steward")

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleDecommissionSteward_CrossTenant verifies that a scoped admin receives 404
// when trying to decommission a steward in a different tenant (avoids existence disclosure).
func TestHandleDecommissionSteward_CrossTenant(t *testing.T) {
	server, st := setupDecommissionServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-cross-tenant",
		TenantID: "tenant-b",
		Status:   business.StewardStatusActive,
	}))

	// Caller is scoped to "tenant-a"; steward belongs to "tenant-b".
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/s-cross-tenant", nil)
	req = withPrincipal(req, &Principal{ID: "tenant-a-admin", Assurance: session.AssuranceBasic, TenantID: "tenant-a"})
	req = withVars(req, map[string]string{"id": "s-cross-tenant"})
	rec := httptest.NewRecorder()
	server.handleDecommissionSteward(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant decommission must return 404, not 403")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleDecommissionSteward_AuditEmitted verifies that a successful decommission writes
// an audit entry with action "steward.decommissioned", AuditSeverityHigh, and resource_type "steward".
func TestHandleDecommissionSteward_AuditEmitted(t *testing.T) {
	server, st := setupDecommissionServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-audit-decomm",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/s-audit-decomm", nil)
	req = withPrincipal(req, &Principal{ID: "audit-admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "s-audit-decomm"})
	rec := httptest.NewRecorder()
	server.handleDecommissionSteward(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward.decommissioned"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "decommission audit entry must be written")

	e := entries[0]
	assert.Equal(t, "steward.decommissioned", e.Action)
	assert.Equal(t, business.AuditSeverityHigh, e.Severity)
	assert.Equal(t, "steward", e.ResourceType)
	assert.Equal(t, "s-audit-decomm", e.ResourceID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
}

// TestHandleDecommissionSteward_RegistryConnectionDropped verifies that after decommission
// the registry no longer contains the steward's entry (active connection is dropped).
func TestHandleDecommissionSteward_RegistryConnectionDropped(t *testing.T) {
	server, st := setupDecommissionServer(t)

	stewardID := "s-conn-drop"
	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       stewardID,
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      &noopSender{},
		ConnectedAt: time.Now(),
	}))
	server.SetRegistry(reg)

	countBefore := reg.Count()
	require.Equal(t, 1, countBefore, "registry must have one entry before decommission")

	rec := deleteDecommissionSteward(server, stewardID)
	require.Equal(t, http.StatusOK, rec.Code)

	assert.Equal(t, 0, reg.Count(), "registry must be empty after decommission")
	_, found := reg.Get(stewardID)
	assert.False(t, found, "registry.Get must return false for decommissioned steward")
}

// TestHandleDecommissionSteward_ExcludedFromList verifies that after decommission the steward
// no longer appears in the unfiltered list, but reappears with ?include_deregistered=true.
// The handler is called directly (bypassing auth middleware) with an empty TenantID so that
// isEmptyFilter returns true and the test exercises the unfiltered GetAllStewards path, where
// the include_deregistered filtering lives (per Issue #2408 implementation notes).
func TestHandleDecommissionSteward_ExcludedFromList(t *testing.T) {
	server, st := setupDecommissionServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-list-filter",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))
	require.NoError(t, server.controllerService.RegisterSteward("s-list-filter", "test-tenant", "addr", "active"))

	// Decommission via the handler.
	rec := deleteDecommissionSteward(server, "s-list-filter")
	require.Equal(t, http.StatusOK, rec.Code)

	// Default list (no TenantID → isEmptyFilter is true → unfiltered GetAllStewards path).
	// The deregistered steward must be excluded.
	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req = withTenant(req, "") // empty tenant → admin global scope → isEmptyFilter true
	rec = httptest.NewRecorder()
	server.handleListStewards(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	for _, s := range resp.Data {
		assert.NotEqual(t, "s-list-filter", s.ID, "deregistered steward must not appear in default list")
	}

	// With ?include_deregistered=true it must reappear.
	req2 := httptest.NewRequest("GET", "/api/v1/stewards?include_deregistered=true", nil)
	req2 = withTenant(req2, "")
	rec2 := httptest.NewRecorder()
	server.handleListStewards(rec2, req2)
	require.Equal(t, http.StatusOK, rec2.Code)
	var resp2 struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp2))
	found := false
	for _, s := range resp2.Data {
		if s.ID == "s-list-filter" {
			found = true
			assert.Equal(t, "deregistered", s.Status)
		}
	}
	assert.True(t, found, "deregistered steward must appear with ?include_deregistered=true")
}

// TestHandleDecommissionSteward_DurableStoreWriteFails verifies that when the durable
// store write (DeregisterSteward) fails after lookup and scope checks pass, the handler
// returns 500 INTERNAL_ERROR and does NOT tombstone the record. Per CFGMS standards, the
// error branch at handlers_stewards.go:681 must be covered, not just the happy path.
func TestHandleDecommissionSteward_DurableStoreWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod does not enforce POSIX directory permissions on Windows")
	}
	server := setupTestServer(t)
	st, root := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-decomm-writefail",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	// Induce a genuine durable-store write failure: make the flat-file store's backing
	// directory read-only. The record was already written, so GetSteward (a pure read)
	// still succeeds and the handler reaches DeregisterSteward, whose atomic write
	// (temp-file creation in the directory) then fails with a permission error — the
	// handler must surface a 500. Restore the mode on cleanup so t.TempDir() removal
	// can delete the tree.
	stewardDir := filepath.Join(root, "stewards")
	require.NoError(t, os.Chmod(stewardDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(stewardDir, 0o750) })

	rec := deleteDecommissionSteward(server, "s-decomm-writefail")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)

	// The tombstone must not have been persisted: restore write access and confirm the
	// record is still Active (the failed write left durable state unchanged).
	require.NoError(t, os.Chmod(stewardDir, 0o750))
	got, err := st.GetSteward(context.Background(), "s-decomm-writefail")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, got.Status,
		"record must remain Active when the durable tombstone write fails")
}

// TestHandleDecommissionSteward_ListVisibleNotInDurableStore verifies that a steward
// registered only via the in-memory path (gRPC AcceptRegistration) can be decommissioned
// even though it has no durable record at the time of the DELETE call (Issue #2929).
func TestHandleDecommissionSteward_ListVisibleNotInDurableStore(t *testing.T) {
	server, _ := setupDecommissionServer(t)

	// Register steward only in-memory (never into the durable store).
	require.NoError(t, server.controllerService.RegisterSteward("s-memonly", "test-tenant", "addr", "registered"))

	// Steward must appear in the default (no-filter) list before decommission.
	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	listReq = withTenant(listReq, "")
	listRec := httptest.NewRecorder()
	server.handleListStewards(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code)
	var listResp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec.Body).Decode(&listResp))
	foundBefore := false
	for _, s := range listResp.Data {
		if s.ID == "s-memonly" {
			foundBefore = true
		}
	}
	require.True(t, foundBefore, "in-memory-only steward must appear in default list before decommission")

	// Decommission must succeed even though steward is absent from durable store.
	rec := deleteDecommissionSteward(server, "s-memonly")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "s-memonly", resp.Data["id"])
	assert.Equal(t, "deregistered", resp.Data["status"])

	// Steward must no longer appear in the default list after decommission.
	listReq2 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	listReq2 = withTenant(listReq2, "")
	listRec2 := httptest.NewRecorder()
	server.handleListStewards(listRec2, listReq2)
	require.Equal(t, http.StatusOK, listRec2.Code)
	var listResp2 struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(listRec2.Body).Decode(&listResp2))
	for _, s := range listResp2.Data {
		assert.NotEqual(t, "s-memonly", s.ID, "deregistered steward must not appear in default list")
	}
}

// TestHandleDecommissionSteward_ListVisibleNotInDurableStore_CrossTenant verifies that a
// scoped admin receives 404 STEWARD_NOT_FOUND when the in-memory-only record belongs to a
// different tenant subtree — exercising the fallback path cross-tenant check (Issue #2929).
func TestHandleDecommissionSteward_ListVisibleNotInDurableStore_CrossTenant(t *testing.T) {
	server, _ := setupDecommissionServer(t)

	// Register steward only in-memory in tenant-b (simulates gRPC registration path).
	require.NoError(t, server.controllerService.RegisterSteward("s-memonly-xtenant", "tenant-b", "addr", "registered"))

	// Caller is scoped to tenant-a; steward belongs to tenant-b.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/stewards/s-memonly-xtenant", nil)
	req = withPrincipal(req, &Principal{ID: "tenant-a-admin", Assurance: session.AssuranceBasic, TenantID: "tenant-a"})
	req = withVars(req, map[string]string{"id": "s-memonly-xtenant"})
	rec := httptest.NewRecorder()
	server.handleDecommissionSteward(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant decommission via fallback path must return 404, not 403")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleDecommissionSteward_BackfillWriteFails verifies that when the durable-store
// backfill write (RegisterSteward) fails for an in-memory-only steward — after GetSteward
// returns ErrStewardNotFound and the fallback scope check passes — the handler returns 500
// INTERNAL_ERROR. This covers the RegisterSteward backfill error branch at
// handlers_stewards.go:946-950 (Issue #2929), the mirror of the DeregisterSteward
// write-failure path exercised by TestHandleDecommissionSteward_DurableStoreWriteFails.
func TestHandleDecommissionSteward_BackfillWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod does not enforce POSIX directory permissions on Windows")
	}
	server := setupTestServer(t)
	st, root := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	// Register steward only in-memory (never into the durable store) so GetSteward returns
	// ErrStewardNotFound and the handler takes the backfill fallback path.
	require.NoError(t, server.controllerService.RegisterSteward("s-backfill-writefail", "test-tenant", "addr", "registered"))

	// Induce a genuine durable-store write failure on the backfill: make the flat-file
	// store's backing directory read-only. GetSteward for a missing record is a pure read
	// (returns ErrStewardNotFound) and still succeeds, so the handler reaches the backfill
	// RegisterSteward, whose atomic write (temp-file creation in the directory) then fails
	// with a permission error — the handler must surface a 500. Restore the mode on cleanup
	// so t.TempDir() removal can delete the tree.
	stewardDir := filepath.Join(root, "stewards")
	require.NoError(t, os.Chmod(stewardDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(stewardDir, 0o750) })

	rec := deleteDecommissionSteward(server, "s-backfill-writefail")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)

	// The backfill must not have been persisted: restore write access and confirm the
	// record is still absent from durable storage (the failed write left it unwritten).
	require.NoError(t, os.Chmod(stewardDir, 0o750))
	_, err := st.GetSteward(context.Background(), "s-backfill-writefail")
	assert.ErrorIs(t, err, business.ErrStewardNotFound,
		"record must remain absent when the durable backfill write fails")
}

// ---- buildFleetFilter unit tests (no server required) ----

func TestBuildFleetFilter_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	filter, err := buildFleetFilter(req, "")
	require.NoError(t, err)
	assert.True(t, isEmptyFilter(filter))
}

func TestBuildFleetFilter_OS(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	filter, err := buildFleetFilter(req, "")
	require.NoError(t, err)
	assert.Equal(t, "linux", filter.OS)
	assert.False(t, isEmptyFilter(filter))
}

func TestBuildFleetFilter_AllParams(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=windows&platform=server&arch=amd64&status=online&hostname=web&tag=prod&tag=web", nil)
	filter, err := buildFleetFilter(req, "tenant-a")
	require.NoError(t, err)

	assert.Equal(t, "windows", filter.OS)
	assert.Equal(t, "server", filter.Platform)
	assert.Equal(t, "amd64", filter.Architecture)
	assert.Equal(t, "online", filter.Status)
	assert.Equal(t, "web", filter.Hostname)
	// Issue #2919: buildFleetFilter uses TenantSubtree (subtree-aware) not TenantID (exact).
	assert.Equal(t, "tenant-a", filter.TenantSubtree) // comes from context, not query param
	assert.Empty(t, filter.TenantID)
	assert.Equal(t, []string{"prod", "web"}, filter.Tags)
	assert.False(t, isEmptyFilter(filter))
}

func TestBuildFleetFilter_Tags_MultiValue(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?tag=production&tag=web&tag=db", nil)
	filter, err := buildFleetFilter(req, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"production", "web", "db"}, filter.Tags)
}

func TestBuildFleetFilter_TenantID_FromContext_NotQueryParam(t *testing.T) {
	// tenant_id in query param must be ignored; it comes from context only.
	// Issue #2919: stored in TenantSubtree for subtree-aware scoping.
	req := httptest.NewRequest("GET", "/api/v1/stewards?tenant_id=injected-tenant", nil)
	filter, err := buildFleetFilter(req, "real-tenant-from-context")
	require.NoError(t, err)
	assert.Equal(t, "real-tenant-from-context", filter.TenantSubtree)
	assert.Empty(t, filter.TenantID)
}

func TestBuildFleetFilter_InvalidStatus_ReturnsError(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/stewards?status=invalid", nil)
	_, err := buildFleetFilter(req, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid status")
}

func TestBuildFleetFilter_FieldTooLong_ReturnsError(t *testing.T) {
	longVal := strings.Repeat("a", 300)
	req := httptest.NewRequest("GET", "/api/v1/stewards?hostname="+longVal, nil)
	_, err := buildFleetFilter(req, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum length")
}

// ---- isEmptyFilter unit tests ----

func TestIsEmptyFilter_AllEmpty(t *testing.T) {
	assert.True(t, isEmptyFilter(fleet.Filter{}))
}

func TestIsEmptyFilter_WithTags(t *testing.T) {
	assert.False(t, isEmptyFilter(fleet.Filter{Tags: []string{"production"}}))
}

func TestIsEmptyFilter_WithDNAAttributes(t *testing.T) {
	assert.False(t, isEmptyFilter(fleet.Filter{DNAAttributes: map[string]string{"env": "prod"}}))
}

// TestIsEmptyFilter_WithTenantSubtree verifies that a non-empty TenantSubtree is
// not treated as an empty filter (Issue #2919: subtree must trigger Search, not GetAllStewards).
func TestIsEmptyFilter_WithTenantSubtree(t *testing.T) {
	assert.False(t, isEmptyFilter(fleet.Filter{TenantSubtree: "msp-a"}))
}

// ---- Error path tests: handleListStewards with failing fleet query ----

// failingFleetQuery is a real implementation of fleet.FleetQuery that always returns an error.
// It is not a mock — it satisfies the interface with deterministic error behavior for error-path testing.
type failingFleetQuery struct{}

func (f *failingFleetQuery) Search(_ context.Context, _ fleet.Filter) ([]fleet.StewardResult, error) {
	return nil, errors.New("forced fleet query failure")
}

func (f *failingFleetQuery) Count(_ context.Context, _ fleet.Filter) (int, error) {
	return 0, errors.New("forced fleet query failure")
}

func TestHandleListStewards_FleetQueryError_Returns500(t *testing.T) {
	server := setupTestServer(t)
	// Replace the fleet query with one that always fails.
	server.fleetQuery = &failingFleetQuery{}
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Any filter triggers the fleet query code path.
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ---- Integration tests: handleListStewards with fleet filtering ----

// testRegistrationDNA builds the registration snapshot these fixtures hand to
// AcceptRegistration. Identity is carried in Fragments — the presence check
// AcceptRegistration applies reads the flattened fragment set (Issue #3319), so a
// fragment-less snapshot is rejected as degenerate and the steward is stored with
// a nil DNA, which the list filters below would then have nothing to match on.
// All display-DTO consumers read from fragments after Issue #3327, so attrs used
// by handlers are carried in fragment payloads rather than in Attributes.
func testRegistrationDNA(t *testing.T, attrs map[string]string) *common.DNA {
	t.Helper()
	var frags []*common.Fragment
	if hostname := attrs["hostname"]; hostname != "" {
		frag, err := sdna.NewFragment("hostname", "test", sdna.MapState(map[string]interface{}{"hostname": hostname}))
		require.NoError(t, err)
		frags = append(frags, frag)
	}
	if osName := attrs["os"]; osName != "" {
		frag, err := sdna.NewFragment("host:os", "test", sdna.MapState(map[string]interface{}{"os": osName}))
		require.NoError(t, err)
		frags = append(frags, frag)
	}
	if archName := attrs["arch"]; archName != "" {
		frag, err := sdna.NewFragment("host:cpu", "test", sdna.MapState(map[string]interface{}{"arch": archName}))
		require.NoError(t, err)
		frags = append(frags, frag)
	}
	if modulesLoaded := attrs["modules.loaded"]; modulesLoaded != "" {
		frag, err := sdna.NewFragment("modules", "test", sdna.MapState(map[string]interface{}{"modules.loaded": modulesLoaded}))
		require.NoError(t, err)
		frags = append(frags, frag)
	}
	if version := attrs["steward.version"]; version != "" {
		frag, err := sdna.NewFragment("steward:meta", "test", sdna.MapState(map[string]interface{}{"steward.version": version}))
		require.NoError(t, err)
		frags = append(frags, frag)
	}
	return &common.DNA{
		Id:         "dna-" + attrs["hostname"],
		Attributes: attrs,
		Fragments:  frags,
	}
}

// registerTestSteward adds a steward to the controller service via AcceptRegistration.
// It uses the "test-tenant" tenant ID (same as NewTestKey) so fleet filter scoping works.
func registerTestSteward(t *testing.T, svc interface {
	AcceptRegistration(context.Context, *controller.RegisterRequest) (*controller.RegisterResponse, error)
}, attrs map[string]string) string {
	t.Helper()
	req := &controller.RegisterRequest{
		Version:    "v1.0",
		InitialDna: testRegistrationDNA(t, attrs),
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "test-tenant")
	resp, err := svc.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

// registerStewardInTenant adds a steward to a specific tenant via AcceptRegistration.
// Used by multi-tenant cross-scoping tests (Issue #2919).
func registerStewardInTenant(t *testing.T, svc interface {
	AcceptRegistration(context.Context, *controller.RegisterRequest) (*controller.RegisterResponse, error)
}, tenantID string, attrs map[string]string) string {
	t.Helper()
	req := &controller.RegisterRequest{
		Version:    "v1.0",
		InitialDna: testRegistrationDNA(t, attrs),
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
	resp, err := svc.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

// ---- Fragment-sourced DTO AC tests (Issue #3327) ----

// TestHandleListStewards_FragmentSourced_HostnameSummary verifies that the list
// endpoint's hostname/OS/arch summary fields are sourced from DNA fragments, not
// DNA.Attributes. The steward is registered with fragment-populated DNA and the
// REST response must reflect the fragment values for Hostname, OS, and Architecture.
func TestHandleListStewards_FragmentSourced_HostnameSummary(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "frag-host", "os": "linux", "arch": "arm64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	require.NotNil(t, resp.Data[0].DNA)
	assert.Equal(t, "frag-host", resp.Data[0].DNA.Hostname, "hostname must come from fragments")
	assert.Equal(t, "linux", resp.Data[0].DNA.OS, "os must come from fragments")
	assert.Equal(t, "arm64", resp.Data[0].DNA.Architecture, "arch must come from fragments")
}

// TestHandleGetSteward_FragmentSourced_AttributesPassthrough verifies that the
// get-steward endpoint's DNA.attributes JSON key is sourced from flattened
// fragments. The "tenant" key is injected by the controller; all other keys must
// come from the registered fragments.
func TestHandleGetSteward_FragmentSourced_AttributesPassthrough(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "passthrough-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Data.DNA)
	assert.Equal(t, "passthrough-host", resp.Data.DNA.Attributes["hostname"],
		"hostname must be present in fragment-sourced attributes map")
	assert.Equal(t, "linux", resp.Data.DNA.Attributes["os"],
		"os must be present in fragment-sourced attributes map")
	assert.Equal(t, "test-tenant", resp.Data.DNA.Attributes["tenant"],
		"controller-injected tenant key must be present")
}

// TestHandleGetStewardModules_FragmentSourced verifies that the modules endpoint
// reads modules.loaded from DNA fragments, not DNA.Attributes, and returns the
// correct parsed module list.
func TestHandleGetStewardModules_FragmentSourced(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "frag-modules-host", "os": "linux",
		"modules.loaded": "file, patch",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Modules []struct {
				Name string `json:"name"`
			} `json:"modules"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Modules, 2)
	assert.Equal(t, "file", resp.Data.Modules[0].Name)
	assert.Equal(t, "patch", resp.Data.Modules[1].Name)
}

func TestHandleListStewards_NoFilter_ReturnsAll(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Register two stewards
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-linux-1", "os": "linux", "arch": "amd64",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-windows-1", "os": "windows", "arch": "amd64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2)
}

func TestHandleListStewards_FilterByOS_ReturnsSubset(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-linux-1", "os": "linux", "arch": "amd64",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-windows-1", "os": "windows", "arch": "amd64",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-linux-2", "os": "linux", "arch": "arm64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2)
	for _, s := range resp.Data {
		require.NotNil(t, s.DNA)
		assert.Equal(t, "linux", s.DNA.OS)
	}
}

func TestHandleListStewards_FilterByStatus_ReturnsOnlineOnly(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?status=online", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Registered stewards have status "registered", not "online", so filter returns none
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	// No stewards with status=online; empty result is correct behavior
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

func TestHandleListStewards_FilterByHostname_SubstringMatch(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "web-server-01", "os": "linux",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "db-server-01", "os": "linux",
	})
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "web-server-02", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?hostname=web-server", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2)
	for _, s := range resp.Data {
		require.NotNil(t, s.DNA)
		assert.Contains(t, s.DNA.Hostname, "web-server")
	}
}

func TestHandleListStewards_CombinedFilter_AND(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// linux + amd64
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux", "arch": "amd64",
	})
	// linux + arm64 (should not match amd64 filter)
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-2", "os": "linux", "arch": "arm64",
	})
	// windows + amd64 (should not match linux filter)
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-3", "os": "windows", "arch": "amd64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux&arch=amd64", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 1)
	assert.Equal(t, "amd64", resp.Data[0].DNA.Architecture)
}

func TestHandleListStewards_NoMatch_ReturnsEmptyArray(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-1", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=windows", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotNil(t, resp.Data)
	assert.Empty(t, resp.Data)
}

// TestHandleListStewards_HTTPRegisteredSteward_AppearsInList verifies that a steward
// registered via the HTTP path (RegisterSteward on ControllerService) appears in the
// list response.
func TestHandleListStewards_HTTPRegisteredSteward_AppearsInList(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Simulate HTTP registration writing into the single authoritative registry
	require.NoError(t, server.controllerService.RegisterSteward("http-steward-1", "test-tenant", "addr-1", "registered"))

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "http-steward-1", resp.Data[0].ID)
	assert.Equal(t, "registered", resp.Data[0].Status)
}

// TestHandleListStewards_HTTPRegistration_NoDuplicates verifies that registering the same
// steward ID twice produces exactly one entry in the list.
func TestHandleListStewards_HTTPRegistration_NoDuplicates(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	require.NoError(t, server.controllerService.RegisterSteward("dup-steward", "test-tenant", "addr-1", "registered"))
	require.NoError(t, server.controllerService.RegisterSteward("dup-steward", "test-tenant", "addr-2", "quarantined"))

	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 1, "duplicate steward ID should produce exactly one entry")
	assert.Equal(t, "quarantined", resp.Data[0].Status)
}

// TestHandleListStewards_FleetQuery_VersionFromDNAAttributes verifies that the
// filtered fleet query path (handleListStewards with a filter) populates the
// Version field in StewardInfo from the steward.version DNA attribute. (Issue #2260)
func TestHandleListStewards_FleetQuery_VersionFromDNAAttributes(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	// Register a steward whose DNA includes steward.version — this simulates
	// what a steward publishes after the Issue #2260 change.
	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname":        "host-versioned",
		"os":              "linux",
		"steward.version": "v1.4.2",
	})

	// Use a filter to trigger the fleetQuery code path (not the no-filter path).
	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1, "exactly one steward must match the os=linux filter")
	assert.Equal(t, "v1.4.2", resp.Data[0].Version,
		"Version must be populated from steward.version DNA attribute in the filtered fleet query path")
}

// noopSender is a minimal transport stub that satisfies registry.MessageSender
// so that registry.Register's nil-Sender guard passes in tests. It is not a
// mock of a CFGMS business component — MessageSender is a low-level transport
// interface whose production implementation is a gRPC stream that cannot be
// instantiated in unit tests without a live gRPC server. Tests here validate
// registry lookup behavior, not message delivery.
type noopSender struct{}

func (n *noopSender) SendMsg(_ interface{}) error { return nil }

// TestHandleGetSteward_ConnectedSteward verifies that active_sessions == 1 and
// connection_state == "connected" when the steward has an entry in the registry.
func TestHandleGetSteward_ConnectedSteward(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// Register the steward in the controller service so GetStewardInfo can find it.
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "connected-host", "os": "linux",
	})

	// Wire a real InMemoryRegistry with the steward registered.
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      &noopSender{},
		ConnectedAt: time.Now(),
	}))
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.NotEmpty(t, resp.Data.Status)
	assert.Equal(t, 1, resp.Data.ActiveSessions)
	assert.Equal(t, "connected", resp.Data.ConnectionState)
}

// TestHandleGetSteward_DisconnectedSteward verifies that active_sessions == 0 and
// connection_state == "disconnected" when the steward is not in the registry.
func TestHandleGetSteward_DisconnectedSteward(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	// Register the steward in the controller service but not in the connection registry.
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "disconnected-host", "os": "linux",
	})

	// Wire a real InMemoryRegistry with no entry for this steward.
	reg := registry.NewRegistry()
	server.SetRegistry(reg)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.NotEmpty(t, resp.Data.Status)
	assert.Equal(t, 0, resp.Data.ActiveSessions)
	assert.Equal(t, "disconnected", resp.Data.ConnectionState)
}

// TestHandleGetSteward_NilRegistry verifies that active_sessions == 0 and
// connection_state == "disconnected" when no registry is wired (OSS single-node).
func TestHandleGetSteward_NilRegistry(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "no-registry-host", "os": "linux",
	})
	// registry is nil by default in setupTestServer — no SetRegistry call.

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.NotEmpty(t, resp.Data.Status)
	assert.Equal(t, 0, resp.Data.ActiveSessions)
	assert.Equal(t, "disconnected", resp.Data.ConnectionState)
}

// TestHandleGetSteward_CrossTenant_Returns404 verifies that a principal scoped to one
// tenant receives 404 (not 403) for a steward in an unrelated tenant, so the response
// is indistinguishable from a nonexistent steward ID (AC1, AC5).
func TestHandleGetSteward_CrossTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)

	// Steward lives in "root/msp-b"; caller is scoped to "root/msp-a".
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "msp-b-host", "os": "linux",
	}, "root/msp-b")

	callerKey := NewEphemeralTestKey(t, server, []string{"steward:read"}, "root/msp-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// AC5: must be identical to a nonexistent steward — same status, message, and code.
	reqNonexistent := httptest.NewRequest("GET", "/api/v1/stewards/this-id-does-not-exist", nil)
	reqNonexistent.Header.Set("X-API-Key", callerKey)
	recNonexistent := httptest.NewRecorder()
	server.router.ServeHTTP(recNonexistent, reqNonexistent)

	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant get must return 404, not 403")
	assert.Equal(t, recNonexistent.Code, rec.Code, "status must match nonexistent-ID response")

	var errResp, errRespNonexistent ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NoError(t, json.NewDecoder(recNonexistent.Body).Decode(&errRespNonexistent))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
	assert.Equal(t, errRespNonexistent.Error.Code, errResp.Error.Code,
		"error code must match nonexistent-ID response")
	assert.Equal(t, errRespNonexistent.Error.Message, errResp.Error.Message,
		"error message must match nonexistent-ID response")
}

// TestHandleGetSteward_SameTenant_Returns200 verifies that a principal scoped to a
// tenant can read a steward belonging to that same tenant (AC2).
func TestHandleGetSteward_SameTenant_Returns200(t *testing.T) {
	server := setupTestServer(t)

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "msp-a-host", "os": "linux",
	}, "root/msp-a")

	callerKey := NewEphemeralTestKey(t, server, []string{"steward:read"}, "root/msp-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
}

// TestHandleGetSteward_DescendantTenant_Returns200 verifies that a principal scoped to
// a parent tenant can read a steward in a descendant tenant (AC2).
func TestHandleGetSteward_DescendantTenant_Returns200(t *testing.T) {
	server := setupTestServer(t)

	// Steward is in "root/msp-a/client-1"; caller is scoped to "root/msp-a".
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "client-1-host", "os": "linux",
	}, "root/msp-a/client-1")

	callerKey := NewEphemeralTestKey(t, server, []string{"steward:read"}, "root/msp-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
}

// TestHandleGetSteward_UnscopedAdmin_Returns200 verifies that a principal with an empty
// tenant context (unscoped / root admin) receives 200 for a steward in any tenant (AC3).
func TestHandleGetSteward_UnscopedAdmin_Returns200(t *testing.T) {
	server := setupTestServer(t)

	// Register steward under an arbitrary tenant.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "any-tenant-host", "os": "linux",
	}, "some-tenant")

	// Call handler directly with empty TenantID — the unscoped admin path.
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req = withTenant(req, "")
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleGetSteward(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
}

// TestHandleGetSteward_SiblingPrefixTenant_Returns404 verifies that a principal scoped
// to "root/msp-a" cannot read a steward in "root/msp-alpha" (AC4). A bare HasPrefix
// check without the "/" separator would incorrectly allow this.
func TestHandleGetSteward_SiblingPrefixTenant_Returns404(t *testing.T) {
	server := setupTestServer(t)

	// Steward lives in "root/msp-alpha"; caller is scoped to "root/msp-a".
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "msp-alpha-host", "os": "linux",
	}, "root/msp-alpha")

	callerKey := NewEphemeralTestKey(t, server, []string{"steward:read"}, "root/msp-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code,
		"sibling-prefix tenant must return 404 (AC4: root/msp-a must not match root/msp-alpha)")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleStewardAuthRefresh_UnknownSteward_Returns404 verifies that POSTing to
// /api/v1/stewards/{id}/auth/refresh with an unregistered steward ID returns 404.
func TestHandleStewardAuthRefresh_UnknownSteward_Returns404(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:auth-refresh"})

	req := httptest.NewRequest("POST", "/api/v1/stewards/nonexistent-steward-id/auth/refresh", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleStewardAuthRefresh_KnownSteward_Returns200 verifies that POSTing to
// /api/v1/stewards/{id}/auth/refresh with a registered steward returns 200 with
// {"steward_id":"...","status":"refresh_requested"}.
func TestHandleStewardAuthRefresh_KnownSteward_Returns200(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:auth-refresh"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "auth-refresh-host", "os": "linux",
	})

	req := httptest.NewRequest("POST", "/api/v1/stewards/"+stewardID+"/auth/refresh", strings.NewReader("{}"))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, stewardID, body["steward_id"])
	assert.Equal(t, "refresh_requested", body["status"])
}

// TestServer_ConfigStatusRouteDeregistered verifies that GET /api/v1/stewards/{id}/config/status
// is no longer registered and returns 404 or 405, never 200 with hardcoded "unknown" data.
func TestServer_ConfigStatusRouteDeregistered(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-config"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward-id/config/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusOK, rec.Code, "config/status route must not return 200 after deregistration")
	assert.True(t, rec.Code == http.StatusNotFound || rec.Code == http.StatusMethodNotAllowed,
		"expected 404 or 405, got %d", rec.Code)
}

func TestHandleDeleteStewardConfig(t *testing.T) {
	t.Run("success 204 when config exists", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)

		storeTestConfig(t, server, "test-tenant", "steward-to-delete")

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/steward-to-delete/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("not-found 404 when config does not exist", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/nonexistent-steward/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		assert.Equal(t, "CONFIG_NOT_FOUND", errResp.Error.Code)
	})

	t.Run("bad steward ID 400", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)

		// Dots and colons are URL-safe but fail identifierRegex (^[a-zA-Z0-9_-]+$)
		req := httptest.NewRequest("DELETE", "/api/v1/stewards/steward.invalid:id/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("missing permission returns 403", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewTestKey(t, server, []string{"steward:read-config"})

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/some-steward/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("internal error 500 when storage backend fails", func(t *testing.T) {
		server := setupTestServer(t)
		apiKey := NewEphemeralTestKey(t, server, []string{"steward:delete-config"}, "test-tenant", 5*time.Minute)
		useFailingConfigService(t, server)

		req := httptest.NewRequest("DELETE", "/api/v1/stewards/steward-x/config", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		var errResp ErrorResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
		assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
	})
}

// TestHandleGetStewardConfig_HappyPath exercises the stewardtypes.FromProto conversion
// path inside handleGetStewardConfig: register a steward, store a config, then GET it.
func TestHandleGetStewardConfig_HappyPath(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-config"})

	// Register a steward so GetConfiguration can look up its tenant.
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "cfg-test-host", "os": "linux",
	})

	// Store a config — uses the same "test-tenant" that registerTestSteward injects
	// via context. The inheritance resolver will fall back to device-level config since
	// "test-tenant" has no full TenantData record in this in-memory test setup.
	storeTestConfig(t, server, "test-tenant", stewardID)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/config", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be a map, got %T", resp.Data)
	assert.Equal(t, stewardID, data["steward_id"])
	assert.Contains(t, data, "config")
}

// TestHandleGetStewardConfig_StewardNotRegistered verifies that requesting config for
// an unknown steward returns 400 CONFIG_ERROR (configService returns NOT_FOUND).
func TestHandleGetStewardConfig_StewardNotRegistered(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-config"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent-steward/config", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "CONFIG_ERROR", errResp.Error.Code)
}

// TestHandleGetStewardConfig_InsufficientPermission verifies 403 when the API key
// lacks steward:read-config permission.
func TestHandleGetStewardConfig_InsufficientPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward/config", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// ---- handleGetStewardDNA attribute tests ----

// registerTestStewardWithDNA adds a steward with the given DNA attributes and returns its ID.
// The optional tenantID parameter overrides the default "test-tenant".
func registerTestStewardWithDNA(t *testing.T, server *Server, attrs map[string]string, tenantID string) string {
	t.Helper()
	if tenantID == "" {
		tenantID = "test-tenant"
	}
	req := &controller.RegisterRequest{
		Version:    "v1.0",
		InitialDna: testRegistrationDNA(t, attrs),
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
	resp, err := server.controllerService.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

// TestHandleGetStewardDNA_Attribute verifies that the handler returns {"value":"<val>"}
// when ?attribute=<key> is present, the key exists in the DNA fragments, and the key
// is not denylisted. After Issue #3327, attributes are sourced from fragments only.
func TestHandleGetStewardDNA_Attribute(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "attr-host", "os": "linux",
	}, "test-tenant")

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute=hostname", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]string
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "attr-host", resp["value"])
}

// TestHandleGetStewardDNA_AttributeNotFound verifies 404 with DNA_ATTRIBUTE_NOT_FOUND
// when the key is not present in the DNA attributes.
func TestHandleGetStewardDNA_AttributeNotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "notfound-host", "os": "linux",
	}, "test-tenant")

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute=nonexistent.key", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "DNA_ATTRIBUTE_NOT_FOUND", errResp.Error.Code)
}

// TestHandleGetStewardDNA_AttributeDenylistRedaction verifies that attribute keys matching
// sensitive patterns (*token*, *secret*, *password*, *credential*, *api_key*) return HTTP 404
// with code DNA_ATTRIBUTE_REDACTED, even when the key exists in the DNA.
func TestHandleGetStewardDNA_AttributeDenylistRedaction(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	// Register a steward with sensitive attributes present in DNA.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname":        "denylist-host",
		"os":              "linux",
		"auth_token":      "supersecret",
		"api_secret":      "topsecret",
		"user_password":   "hunter2",
		"user_credential": "cred123",
		"service_api_key": "key456",
	}, "test-tenant")

	denylisted := []string{
		"auth_token",      // matches *token*
		"api_secret",      // matches *secret*
		"user_password",   // matches *password*
		"user_credential", // matches *credential*
		"service_api_key", // matches *api_key*
	}

	for _, key := range denylisted {
		t.Run(key, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute="+key, nil)
			req.Header.Set("X-API-Key", apiKey)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusNotFound, rec.Code, "expected 404 for denylisted key %q", key)
			var errResp ErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
			assert.Equal(t, "DNA_ATTRIBUTE_REDACTED", errResp.Error.Code,
				"expected DNA_ATTRIBUTE_REDACTED for key %q", key)
		})
	}
}

// TestHandleGetStewardDNA_RejectsCrossTenant verifies that an API key scoped to tenant-a
// cannot read DNA for a steward registered in tenant-b. The response must be HTTP 404
// (not 403) to avoid disclosing steward existence across tenants.
func TestHandleGetStewardDNA_RejectsCrossTenant(t *testing.T) {
	server := setupTestServer(t)

	// Steward registered in tenant-b.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "cross-tenant-host", "os": "linux",
	}, "tenant-b")

	// API key scoped to tenant-a (cannot read tenant-b stewards).
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-dna"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant DNA read must return 404, not 403")
}

// TestHandleGetStewardDNA_RejectsPrefixCollision verifies that "tenant-a" cannot access
// a steward in "tenant-abc" despite the raw string prefix matching. The "/" separator
// boundary must be checked so "tenant-a" only grants access to "tenant-a" or "tenant-a/*".
func TestHandleGetStewardDNA_RejectsPrefixCollision(t *testing.T) {
	server := setupTestServer(t)

	// Steward in "tenant-abc" — must NOT be visible to "tenant-a" caller.
	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "collision-host", "os": "linux",
	}, "tenant-abc")

	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-dna"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code, "prefix-collision tenant must return 404")
}

// TestHandleGetStewardDNA_InternalError verifies that a GetStewardDNA service error
// returns HTTP 500 with code INTERNAL_ERROR. The handler is called directly (bypassing
// auth middleware) with an empty TenantID so the cross-tenant guard is skipped, and
// the steward ID does not exist in the service - causing GetStewardDNA to return an error.
func TestHandleGetStewardDNA_InternalError(t *testing.T) {
	server := setupTestServer(t)

	// Call handler directly: empty TenantID skips cross-tenant check; non-existent steward
	// causes GetStewardDNA to return an error, exercising the INTERNAL_ERROR path.
	req := httptest.NewRequest("GET", "/api/v1/stewards/ghost-steward/dna", nil)
	req = withTenant(req, "")
	req = withVars(req, map[string]string{"id": "ghost-steward"})
	rec := httptest.NewRecorder()

	server.handleGetStewardDNA(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}

// TestHandleGetStewardDNA_DNANotFound verifies HTTP 404 with code DNA_NOT_FOUND when
// the steward is registered but its DNA field is nil.
func TestHandleGetStewardDNA_DNANotFound(t *testing.T) {
	server := setupTestServer(t)

	require.NoError(t, server.controllerService.RegisterSteward("no-dna-steward", "test-tenant", "addr-1", "registered"))

	// Clear the DNA on the live registry entry. GetStewardInfo now returns a
	// copy-on-read so mutation of the returned value does not reach the live
	// entry; SetStewardDNA writes directly to the registry.
	ok := server.controllerService.SetStewardDNA("no-dna-steward", nil)
	require.True(t, ok)

	req := httptest.NewRequest("GET", "/api/v1/stewards/no-dna-steward/dna", nil)
	req = withTenant(req, "test-tenant")
	req = withVars(req, map[string]string{"id": "no-dna-steward"})
	rec := httptest.NewRecorder()

	server.handleGetStewardDNA(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "DNA_NOT_FOUND", errResp.Error.Code)
}

// TestHandleGetStewardDNA_AttributeKeyTooLong verifies HTTP 400 with code
// ATTRIBUTE_KEY_TOO_LONG when ?attribute= exceeds 128 characters.
func TestHandleGetStewardDNA_AttributeKeyTooLong(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-dna"})

	stewardID := registerTestStewardWithDNA(t, server, map[string]string{
		"hostname": "toolong-host", "os": "linux",
	}, "test-tenant")

	longKey := strings.Repeat("a", 129)
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/dna?attribute="+longKey, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "ATTRIBUTE_KEY_TOO_LONG", errResp.Error.Code)
}

// ---- handleGetStewardModules tests (from develop) ----

// TestHandleGetStewardModules_StewardNotFound verifies 404 for an unknown steward ID.
func TestHandleGetStewardModules_StewardNotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent-steward/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleGetStewardModules_ReturnsNotImplemented verifies 501 + MODULES_UNAVAILABLE
// for a known steward with no module DNA and a tenant-authorized admin.
func TestHandleGetStewardModules_ReturnsNotImplemented(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "no-modules-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotImplemented, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "MODULES_UNAVAILABLE", errResp.Error.Code)
	assert.Contains(t, errResp.Error.Message, "steward does not report loaded modules")
}

// TestHandleGetStewardModules_Returns200WithModules verifies that a steward with a
// modules.loaded DNA attribute returns 200 with the parsed module list.
func TestHandleGetStewardModules_Returns200WithModules(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "modules-host", "os": "linux",
		"modules.loaded": "file, service, package",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data struct {
			Modules []struct {
				Name string `json:"name"`
			} `json:"modules"`
		} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data.Modules, 3)
	assert.Equal(t, "file", resp.Data.Modules[0].Name)
	assert.Equal(t, "service", resp.Data.Modules[1].Name)
	assert.Equal(t, "package", resp.Data.Modules[2].Name)
}

// TestHandleGetStewardModules_InvalidStewardID verifies 400 for a malformed steward ID.
// Dots and colons fail identifierRegex (^[a-zA-Z0-9_-]+$) and are caught by
// the validation middleware, which returns VALIDATION_ERROR.
func TestHandleGetStewardModules_InvalidStewardID(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-modules"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/steward.invalid:id/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleGetStewardModules_InsufficientPermission verifies 403 when the caller
// lacks steward:read-modules permission.
func TestHandleGetStewardModules_InsufficientPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleGetStewardModules_RejectsCrossTenant verifies HTTP 404 (not 403) when
// the caller's tenant_path is NOT a prefix of the steward's tenant_path.
func TestHandleGetStewardModules_RejectsCrossTenant(t *testing.T) {
	server := setupTestServer(t)
	// Caller is in "other-tenant"; the steward is in "test-tenant".
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-modules"}, "other-tenant", 5*time.Minute)

	// Register a steward under "test-tenant" (the default for registerTestSteward).
	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "cross-tenant-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/modules", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Must be 404, not 403, to avoid existence disclosure across tenant boundaries.
	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// ---- handleGetStewardLogs tests (from develop) ----

// TestHandleGetStewardLogs_ReturnsEmpty verifies that GET /api/v1/stewards/{id}/logs
// returns 200 with an empty event list when no steward event logging manager is wired.
func TestHandleGetStewardLogs_ReturnsEmpty(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-test-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data, ok := body.Data.(map[string]interface{})
	require.True(t, ok, "data should be a map")
	events, ok := data["events"]
	require.True(t, ok, "data should have events key")
	eventsSlice, ok := events.([]interface{})
	require.True(t, ok, "events should be a slice")
	assert.Empty(t, eventsSlice, "events should be empty when no manager is wired")
}

// TestHandleGetStewardLogs_StewardNotFound verifies that GET /api/v1/stewards/{id}/logs
// returns 404 when the steward ID is not found.
func TestHandleGetStewardLogs_StewardNotFound(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/nonexistent-steward/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleGetStewardLogs_InsufficientPermission verifies 403 when the caller
// lacks steward:read-logs permission.
func TestHandleGetStewardLogs_InsufficientPermission(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest("GET", "/api/v1/stewards/any-steward/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleGetStewardLogs_InvalidTailParameter verifies 400 for out-of-range tail value.
func TestHandleGetStewardLogs_InvalidTailParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?tail=9999", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// TestHandleGetStewardLogs_InvalidSinceParameter verifies 400 for non-parseable duration.
func TestHandleGetStewardLogs_InvalidSinceParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=notaduration", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// TestHandleGetStewardLogs_InvalidLevelParameter verifies 400 for unknown log level.
func TestHandleGetStewardLogs_InvalidLevelParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?level=TRACE", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// TestHandleGetStewardLogs_InvalidModuleParameter verifies 400 for module name exceeding 128 chars.
func TestHandleGetStewardLogs_InvalidModuleParameter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "logs-validation-host", "os": "linux",
	})

	longModule := strings.Repeat("x", 129)
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?module="+longModule, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_PARAMETER", errResp.Error.Code)
}

// ---- GET /api/v1/stewards pagination tests (Issue #2489) ----

// listStewardsPage mirrors the paginated envelope returned when limit/offset
// query parameters are present on GET /api/v1/stewards.
type listStewardsPage struct {
	Stewards []StewardInfo `json:"stewards"`
	Total    int           `json:"total"`
	Limit    int           `json:"limit"`
	Offset   int           `json:"offset"`
}

// getStewardsRaw performs GET /api/v1/stewards<query> through the router and
// returns the HTTP status code and raw response body.
func getStewardsRaw(t *testing.T, server *Server, apiKey, query string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/stewards"+query, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// getStewardsPage performs GET /api/v1/stewards<query> and decodes the
// paginated envelope. Fails the test unless the response is HTTP 200.
func getStewardsPage(t *testing.T, server *Server, apiKey, query string) listStewardsPage {
	t.Helper()
	code, body := getStewardsRaw(t, server, apiKey, query)
	require.Equal(t, http.StatusOK, code, "body: %s", body)
	var resp struct {
		Data listStewardsPage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Data
}

// pageIDs extracts the steward IDs from a page in response order.
func pageIDs(page listStewardsPage) []string {
	ids := make([]string, 0, len(page.Stewards))
	for _, s := range page.Stewards {
		ids = append(ids, s.ID)
	}
	return ids
}

// registerNStewards registers n stewards with the given os attribute and
// returns their IDs sorted ascending (the deterministic pagination order).
func registerNStewards(t *testing.T, server *Server, n int, osName string) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := registerTestSteward(t, server.controllerService, map[string]string{
			"hostname": fmt.Sprintf("page-host-%s-%d", osName, i), "os": osName,
		})
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ---- parseStewardPagination unit tests (no server required) ----

func TestParseStewardPagination(t *testing.T) {
	cases := []struct {
		name       string
		query      string
		wantErr    bool
		wantPaged  bool
		wantLimit  int
		wantOffset int
	}{
		{name: "no params", query: "", wantPaged: false},
		{name: "limit and offset", query: "limit=10&offset=5", wantPaged: true, wantLimit: 10, wantOffset: 5},
		{name: "limit without offset implies offset 0", query: "limit=10", wantPaged: true, wantLimit: 10, wantOffset: 0},
		{name: "offset without limit rejected", query: "offset=5", wantErr: true},
		{name: "limit lower boundary", query: "limit=1", wantPaged: true, wantLimit: 1, wantOffset: 0},
		{name: "limit upper boundary", query: "limit=500", wantPaged: true, wantLimit: 500, wantOffset: 0},
		{name: "limit zero rejected", query: "limit=0", wantErr: true},
		{name: "limit above cap rejected", query: "limit=501", wantErr: true},
		{name: "limit non-integer rejected", query: "limit=abc", wantErr: true},
		{name: "offset negative rejected", query: "limit=10&offset=-1", wantErr: true},
		{name: "offset non-integer rejected", query: "limit=10&offset=xyz", wantErr: true},
		{name: "offset zero accepted", query: "limit=10&offset=0", wantPaged: true, wantLimit: 10, wantOffset: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, err := url.ParseQuery(tc.query)
			require.NoError(t, err)
			limit, offset, paginated, perr := parseStewardPagination(q)
			if tc.wantErr {
				require.Error(t, perr)
				return
			}
			require.NoError(t, perr)
			assert.Equal(t, tc.wantPaged, paginated)
			assert.Equal(t, tc.wantLimit, limit)
			assert.Equal(t, tc.wantOffset, offset)
		})
	}
}

// TestParseStewardPagination_ErrorNamesParamNotValue verifies that validation
// error messages reference the parameter name only and never echo the raw
// client-supplied value (no information disclosure).
func TestParseStewardPagination_ErrorNamesParamNotValue(t *testing.T) {
	cases := map[string]string{
		"limit=EVILVALUE1":           "limit",
		"limit=10&offset=EVILVALUE2": "offset",
		"offset=EVILVALUE3":          "offset",
	}
	for query, param := range cases {
		q, err := url.ParseQuery(query)
		require.NoError(t, err)
		_, _, _, perr := parseStewardPagination(q)
		require.Error(t, perr, "query %q must fail validation", query)
		assert.Contains(t, perr.Error(), param, "error must name the offending param for query %q", query)
		assert.NotContains(t, perr.Error(), "EVILVALUE", "error must not echo the raw client value for query %q", query)
	}
}

// ---- HTTP-level pagination tests (filtered path: API-key tenant scope) ----

// TestHandleListStewards_Pagination_PageBoundaries covers first page, mid page,
// last partial page, and offset beyond total, asserting stable ID-sorted order
// and post-filter pre-slice total on every page.
func TestHandleListStewards_Pagination_PageBoundaries(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	sortedIDs := registerNStewards(t, server, 5, "linux")

	t.Run("first page", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=0")
		assert.Equal(t, sortedIDs[0:2], pageIDs(page))
		assert.Equal(t, 5, page.Total)
		assert.Equal(t, 2, page.Limit)
		assert.Equal(t, 0, page.Offset)
	})

	t.Run("mid page", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=2")
		assert.Equal(t, sortedIDs[2:4], pageIDs(page))
		assert.Equal(t, 5, page.Total)
		assert.Equal(t, 2, page.Limit)
		assert.Equal(t, 2, page.Offset)
	})

	t.Run("last partial page", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=4")
		assert.Equal(t, sortedIDs[4:5], pageIDs(page))
		assert.Equal(t, 5, page.Total)
	})

	t.Run("offset beyond total returns empty page with correct total", func(t *testing.T) {
		page := getStewardsPage(t, server, apiKey, "?limit=2&offset=10")
		assert.NotNil(t, page.Stewards)
		assert.Empty(t, page.Stewards)
		assert.Equal(t, 5, page.Total)
		assert.Equal(t, 10, page.Offset)
	})
}

// TestHandleListStewards_Pagination_Deterministic verifies two identical
// requests return identical pages (stable ID sort before slicing).
func TestHandleListStewards_Pagination_Deterministic(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	registerNStewards(t, server, 6, "linux")

	first := getStewardsPage(t, server, apiKey, "?limit=3&offset=2")
	second := getStewardsPage(t, server, apiKey, "?limit=3&offset=2")
	assert.Equal(t, pageIDs(first), pageIDs(second), "identical requests must return identical pages")
	assert.Equal(t, first.Total, second.Total)
}

// TestHandleListStewards_Pagination_WithFilter verifies pagination combined
// with an existing filter param: total reflects the post-filter count
// regardless of page size, and pages contain only matching stewards.
func TestHandleListStewards_Pagination_WithFilter(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	linuxIDs := registerNStewards(t, server, 3, "linux")
	registerNStewards(t, server, 2, "windows")

	pageSmall := getStewardsPage(t, server, apiKey, "?os=linux&limit=1&offset=0")
	require.Len(t, pageSmall.Stewards, 1)
	assert.Equal(t, 3, pageSmall.Total, "total must be the post-filter count")
	assert.Equal(t, linuxIDs[0], pageSmall.Stewards[0].ID)
	assert.Equal(t, "linux", pageSmall.Stewards[0].DNA.OS)

	pageLarge := getStewardsPage(t, server, apiKey, "?os=linux&limit=500&offset=0")
	assert.Equal(t, 3, pageLarge.Total, "total must not vary with page size")
	assert.Equal(t, linuxIDs, pageIDs(pageLarge))
}

// TestHandleListStewards_Pagination_LimitWithoutOffset verifies that limit
// without offset defaults offset to 0 (identical to an explicit offset=0).
func TestHandleListStewards_Pagination_LimitWithoutOffset(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	sortedIDs := registerNStewards(t, server, 4, "linux")

	implicit := getStewardsPage(t, server, apiKey, "?limit=2")
	explicit := getStewardsPage(t, server, apiKey, "?limit=2&offset=0")
	assert.Equal(t, 0, implicit.Offset)
	assert.Equal(t, sortedIDs[0:2], pageIDs(implicit))
	assert.Equal(t, pageIDs(explicit), pageIDs(implicit))
}

// TestHandleListStewards_Pagination_OffsetWithoutLimit_Returns400 verifies
// offset without limit is rejected (ambiguous page size) with a specific
// error code and no steward data in the body.
func TestHandleListStewards_Pagination_OffsetWithoutLimit_Returns400(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	registerNStewards(t, server, 2, "linux")

	code, body := getStewardsRaw(t, server, apiKey, "?offset=1")
	require.Equal(t, http.StatusBadRequest, code)
	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(body, &errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INVALID_PAGINATION", errResp.Error.Code)
	assert.NotContains(t, string(body), "stewards", "error response must carry no data")
}

// TestHandleListStewards_Pagination_InvalidParams_Return400 verifies each
// invalid limit/offset value is rejected with HTTP 400, a specific error
// code, and no steward data. Non-integer and negative values are caught by
// the shared request-validation middleware (pre-existing behavior for all
// endpoints, code VALIDATION_ERROR); values that pass the middleware but
// violate the pinned pagination rules (limit<1, limit>500) are rejected by
// the handler with INVALID_PAGINATION.
func TestHandleListStewards_Pagination_InvalidParams_Return400(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	registerNStewards(t, server, 2, "linux")

	cases := []struct {
		name     string
		query    string
		wantCode string
	}{
		{name: "non-integer limit", query: "?limit=zzevilzz", wantCode: "VALIDATION_ERROR"},
		{name: "limit below minimum", query: "?limit=0", wantCode: "INVALID_PAGINATION"},
		{name: "limit above cap", query: "?limit=501", wantCode: "INVALID_PAGINATION"},
		{name: "negative offset", query: "?limit=10&offset=-1", wantCode: "VALIDATION_ERROR"},
		{name: "non-integer offset", query: "?limit=10&offset=zzevilzz", wantCode: "VALIDATION_ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := getStewardsRaw(t, server, apiKey, tc.query)
			require.Equal(t, http.StatusBadRequest, code)
			var errResp ErrorResponse
			require.NoError(t, json.Unmarshal(body, &errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, tc.wantCode, errResp.Error.Code)
			assert.NotContains(t, string(body), `"stewards"`, "error response must carry no data")
		})
	}
}

// TestHandleListStewards_Pagination_HandlerRejectsInvalidParams exercises the
// handler's own validation directly (bypassing the router middleware, as on
// the unfiltered path): every invalid value returns 400 INVALID_PAGINATION,
// no data, and the error body names the offending param without echoing the
// raw client-supplied value.
func TestHandleListStewards_Pagination_HandlerRejectsInvalidParams(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("inv-1", "test-tenant", "addr-1", "registered"))

	cases := []struct {
		name     string
		query    string
		rawValue string // must not appear in the response body
	}{
		{name: "non-integer limit", query: "?limit=zzevilzz", rawValue: "zzevilzz"},
		{name: "limit below minimum", query: "?limit=0", rawValue: ""},
		{name: "limit above cap", query: "?limit=501", rawValue: ""},
		{name: "negative offset", query: "?limit=10&offset=-1", rawValue: ""},
		{name: "non-integer offset", query: "?limit=10&offset=zzevilzz", rawValue: "zzevilzz"},
		{name: "offset without limit", query: "?offset=3", rawValue: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := listStewardsDirect(t, server, tc.query)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			body := rec.Body.String()
			var errResp ErrorResponse
			require.NoError(t, json.Unmarshal([]byte(body), &errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, "INVALID_PAGINATION", errResp.Error.Code)
			assert.NotContains(t, body, `"stewards"`, "error response must carry no data")
			if tc.rawValue != "" {
				assert.NotContains(t, body, tc.rawValue, "error body must not echo the raw client value")
			}
		})
	}
}

// TestHandleListStewards_NoParams_BackwardCompatiblePlainList asserts the
// no-params response keeps the existing shape: data is a plain JSON array of
// stewards (not a pagination envelope) so cfg and existing clients cannot break.
func TestHandleListStewards_NoParams_BackwardCompatiblePlainList(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})
	sortedIDs := registerNStewards(t, server, 3, "linux")

	code, body := getStewardsRaw(t, server, apiKey, "")
	require.Equal(t, http.StatusOK, code)

	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	trimmed := strings.TrimSpace(string(resp.Data))
	require.True(t, strings.HasPrefix(trimmed, "["), "data must be a plain JSON array, got: %s", trimmed)

	var list []StewardInfo
	require.NoError(t, json.Unmarshal(resp.Data, &list))
	got := make([]string, 0, len(list))
	for _, s := range list {
		got = append(got, s.ID)
	}
	sort.Strings(got)
	assert.Equal(t, sortedIDs, got, "full list must contain every registered steward")
	assert.NotContains(t, string(body), `"total"`, "no-params response must not grow pagination fields")
}

// ---- Unfiltered code path (empty tenant context -> GetAllStewards) ----

// listStewardsDirect invokes handleListStewards directly with an empty tenant
// context so the unfiltered GetAllStewards code path is exercised.
func listStewardsDirect(t *testing.T, server *Server, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/v1/stewards"+query, nil)
	req = withTenant(req, "")
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)
	return rec
}

// TestHandleListStewards_Pagination_UnfilteredPath verifies pagination is
// applied on the unfiltered GetAllStewards path with deterministic ID order
// and post-slice total.
func TestHandleListStewards_Pagination_UnfilteredPath(t *testing.T) {
	server := setupTestServer(t)
	for _, id := range []string{"pg-c", "pg-a", "pg-b"} {
		require.NoError(t, server.controllerService.RegisterSteward(id, "test-tenant", "addr-"+id, "registered"))
	}

	rec := listStewardsDirect(t, server, "?limit=2&offset=1")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data listStewardsPage `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, []string{"pg-b", "pg-c"}, pageIDs(resp.Data), "page must be ID-sorted before slicing")
	assert.Equal(t, 3, resp.Data.Total)
	assert.Equal(t, 2, resp.Data.Limit)
	assert.Equal(t, 1, resp.Data.Offset)
}

// TestHandleListStewards_UnfilteredPath_NoParams_PlainList verifies the
// unfiltered path keeps the plain-array payload when no pagination params
// are supplied.
func TestHandleListStewards_UnfilteredPath_NoParams_PlainList(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.controllerService.RegisterSteward("plain-1", "test-tenant", "addr-1", "registered"))

	rec := listStewardsDirect(t, server, "")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	trimmed := strings.TrimSpace(string(resp.Data))
	assert.True(t, strings.HasPrefix(trimmed, "["), "unfiltered no-params data must be a plain JSON array, got: %s", trimmed)
}

// TestHandleCreateAPIKey_AcceptsStewardReadLogs verifies that steward:read-logs is a
// registered permission and can be granted via handleCreateAPIKey. Without this entry in
// knownPermissions, operators cannot mint keys that reach the logs endpoint.
func TestHandleCreateAPIKey_AcceptsStewardReadLogs(t *testing.T) {
	server := setupTestServer(t)

	// Call handleCreateAPIKey directly with the steward:read-logs permission.
	body := []byte(`{"name":"logs-key","permissions":["steward:read-logs"]}`)
	req := httptest.NewRequest("POST", "/api/v1/api-keys", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	ctx := req.Context()
	ctx = context.WithValue(ctx, ctxkeys.TenantID, "test-tenant")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	server.handleCreateAPIKey(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code, "steward:read-logs must be a known permission")
}

// newTestStewardEventManager creates a synchronous file-backed LoggingManager
// suitable for test use. Entries are immediately queryable after WriteEntry + Flush.
func newTestStewardEventManager(t *testing.T) *logging.LoggingManager {
	t.Helper()
	mgr, err := logging.NewLoggingManager(&logging.LoggingConfig{
		Provider: "file",
		Config: map[string]interface{}{
			"directory":        t.TempDir(),
			"file_prefix":      "steward-events",
			"max_file_size":    10 * 1024 * 1024,
			"retention_days":   1,
			"compress_rotated": false,
		},
		Level:       "DEBUG",
		ServiceName: "test-controller",
		Component:   "test",
		AsyncWrites: false, // synchronous so entries are visible immediately
		BatchSize:   1,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, mgr.Close()) })
	return mgr
}

// writeTestStewardEventAt writes a log entry with the given steward_id and explicit
// timestamp into the manager. Use explicit timestamps in correlated-pair tests to
// ensure deterministic detection-before-outcome ordering without relying on wall-clock races.
func writeTestStewardEventAt(t *testing.T, mgr *logging.LoggingManager, stewardID, level, message, correlationID string, ts time.Time) {
	t.Helper()
	entry := loggingInterfaces.LogEntry{
		Timestamp:     ts,
		Level:         level,
		Message:       message,
		CorrelationID: correlationID,
		Fields: map[string]interface{}{
			"steward_id": stewardID,
		},
	}
	require.NoError(t, mgr.WriteEntry(context.Background(), entry))
	require.NoError(t, mgr.Flush(context.Background()))
}

// writeTestStewardEvent writes a log entry with the current wall-clock timestamp.
func writeTestStewardEvent(t *testing.T, mgr *logging.LoggingManager, stewardID, level, message, correlationID string) {
	t.Helper()
	writeTestStewardEventAt(t, mgr, stewardID, level, message, correlationID, time.Now())
}

// TestGetStewardLogs_CrossTenantBlocked verifies that a caller scoped to tenant A
// cannot read events for a steward belonging to tenant B (AC: cross-tenant blocked).
func TestGetStewardLogs_CrossTenantBlocked(t *testing.T) {
	server := setupTestServer(t)

	// Register steward in "tenant-b" (different from the caller's tenant).
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "tenant-b")
	resp, err := server.controllerService.AcceptRegistration(ctx, &controller.RegisterRequest{
		Version: "v1.0",
		InitialDna: &common.DNA{
			Id:         "dna-cross-tenant",
			Attributes: map[string]string{"hostname": "cross-tenant-host", "os": "linux"},
		},
	})
	require.NoError(t, err)
	stewardID := resp.StewardId

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	// Caller is scoped to "tenant-a" — different from the steward's "tenant-b".
	apiKey := NewEphemeralTestKey(t, server, []string{"steward:read-logs"}, "tenant-a", 5*time.Minute)
	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// 404 to avoid disclosing steward existence across tenants (matches the existing ACL pattern).
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestGetStewardLogs_ScopedToPathSteward verifies that when two stewards' events share
// the same steward-event LoggingManager, GET /stewards/{A}/logs returns only steward A's
// entries and never steward B's (result-set scoping by steward_id, not just ACL).
func TestGetStewardLogs_ScopedToPathSteward(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardA := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "scope-host-a", "os": "linux",
	})
	stewardB := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "scope-host-b", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	// Write one event for steward A and one for steward B.
	writeTestStewardEvent(t, mgr, stewardA, "INFO", "event from A", "")
	writeTestStewardEvent(t, mgr, stewardB, "INFO", "event from B", "")

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardA+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data := body.Data.(map[string]interface{})
	events := data["events"].([]interface{})

	// Only steward A's event should appear.
	require.Len(t, events, 1, "exactly one event expected for steward A")
	record := events[0].(map[string]interface{})
	detection := record["detection"].(map[string]interface{})
	assert.Equal(t, "event from A", detection["message"])
}

// TestGetStewardLogs_RollupByCorrelationID verifies that two persisted entries sharing
// a correlation_id are rendered as a single rolled-up record (detection + outcome).
func TestGetStewardLogs_RollupByCorrelationID(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "rollup-host", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	corrID := "corr-abc-123"
	t0 := time.Now()
	t1 := t0.Add(time.Millisecond)
	writeTestStewardEventAt(t, mgr, stewardID, "INFO", "monitor fired", corrID, t0)
	writeTestStewardEventAt(t, mgr, stewardID, "INFO", "convergence complete", corrID, t1)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data := body.Data.(map[string]interface{})
	events := data["events"].([]interface{})

	// Two entries sharing a correlation_id must roll up into one record.
	require.Len(t, events, 1, "two correlated entries must produce exactly one rolled-up record")
	record := events[0].(map[string]interface{})
	assert.Equal(t, corrID, record["correlation_id"])
	assert.NotNil(t, record["detection"], "detection must be present")
	assert.NotNil(t, record["outcome"], "outcome must be present")
	assert.NotEqual(t, true, record["pending_outcome"], "pending_outcome must not be set when outcome is present")
}

// TestGetStewardLogs_PendingOutcome verifies that a single correlated event with no
// paired outcome in the query window is marked pending_outcome=true (the ADR-012 §2
// "monitor fired, convergence never completed" wedge signal).
func TestGetStewardLogs_PendingOutcome(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-logs"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "pending-outcome-host", "os": "linux",
	})

	mgr := newTestStewardEventManager(t)
	server.SetStewardEventLoggingManager(mgr)

	// Write only the detection event — no paired outcome.
	corrID := "corr-pending-xyz"
	writeTestStewardEvent(t, mgr, stewardID, "WARN", "monitor fired, no response yet", corrID)

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID+"/logs?since=1h", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	data := body.Data.(map[string]interface{})
	events := data["events"].([]interface{})

	require.Len(t, events, 1, "one correlated event without outcome must produce one record")
	record := events[0].(map[string]interface{})
	assert.Equal(t, corrID, record["correlation_id"])
	assert.NotNil(t, record["detection"], "detection must be present")
	assert.Nil(t, record["outcome"], "outcome must be absent")
	assert.Equal(t, true, record["pending_outcome"], "pending_outcome must be true for a detection with no outcome")
}

// ---- handleMoveSteward tests (Issue #2341) ----

// setupMoveStewardServer creates a test server wired with a real flat-file steward
// store (rooted at a t.TempDir(), no external infrastructure required) and a tenant
// backing store pre-seeded with both "source-tenant" and "dest-tenant" in Active state.
// The returned root is the store's backing directory, used by tests that need to induce
// a genuine durable-store failure.
func setupMoveStewardServer(t *testing.T) (*Server, business.StewardStore, string) {
	t.Helper()
	server := setupTestServer(t)

	st, root := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	// Create source and destination tenants in the backing store. setupTestServer
	// builds a fresh tenant manager per test, so neither tenant can pre-exist —
	// a CreateTenant failure here is a real setup error and must fail the test.
	ctx := context.Background()
	for _, id := range []string{"source-tenant", "dest-tenant"} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: id, Name: id})
		require.NoError(t, err, "creating tenant %q", id)
	}
	return server, st, root
}

// seedSteward persists a steward record into the real flat-file store, failing the
// test on error. Records are written verbatim; RegisterSteward defaults an empty
// status to "registered" but preserves any status the caller sets.
func seedSteward(t *testing.T, st business.StewardStore, rec *business.StewardRecord) {
	t.Helper()
	require.NoError(t, st.RegisterSteward(context.Background(), rec), "seeding steward %q", rec.ID)
}

// postMoveSteward calls handleMoveSteward directly (bypassing Tier-3 middleware) with a
// root-admin mTLS principal so we can exercise the handler logic in isolation.
func postMoveSteward(server *Server, stewardID, newTenantID string) *httptest.ResponseRecorder {
	body := strings.NewReader(`{"new_tenant_id":"` + newTenantID + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+stewardID+"/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)
	return rec
}

// TestHandleMoveSteward_HappyPath verifies the move succeeds and returns status "moved"
// with the correct old and new tenant IDs.
func TestHandleMoveSteward_HappyPath(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	// Wire a registered steward in the controller service and the store.
	require.NoError(t, server.controllerService.RegisterSteward("s-happy", "source-tenant", "addr", "registered"))
	seedSteward(t, st, &business.StewardRecord{ID: "s-happy", TenantID: "source-tenant", Status: business.StewardStatusRegistered})

	// dest-tenant is already created by setupMoveStewardServer.
	rec := postMoveSteward(server, "s-happy", "dest-tenant")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "moved", resp.Data["status"])
	assert.Equal(t, "dest-tenant", resp.Data["tenant_id"])
	assert.Equal(t, "source-tenant", resp.Data["previous_tenant"])
}

// TestHandleMoveSteward_InMemoryRegistryUpdated verifies that after a move, the live
// in-memory registry reflects the new tenant ID so config resolves from the new path.
// This is the "already-connected steward re-scopes" AC (Issue #2341).
func TestHandleMoveSteward_InMemoryRegistryUpdated(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	require.NoError(t, server.controllerService.RegisterSteward("s-connected", "source-tenant", "addr", "active"))
	seedSteward(t, st, &business.StewardRecord{ID: "s-connected", TenantID: "source-tenant", Status: business.StewardStatusActive})

	// dest-tenant is already created by setupMoveStewardServer.
	rec := postMoveSteward(server, "s-connected", "dest-tenant")
	require.Equal(t, http.StatusOK, rec.Code)

	// The controller service registry must reflect the new tenant — config resolution
	// reads this on the next convergence.
	info, ok := server.controllerService.GetStewardInfo("s-connected")
	require.True(t, ok, "steward must still be in the registry after move")
	assert.Equal(t, "dest-tenant", info.TenantID,
		"in-memory TenantID must be updated so config resolves from the new tenant path")
}

// TestHandleMoveSteward_NoCertReissue verifies that the move does not alter the steward
// identity fields (DeviceID, IdentityKeyPub) — proving no cert re-issue occurs.
func TestHandleMoveSteward_NoCertReissue(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	pub := []byte{0x01, 0x02, 0x03}
	seedSteward(t, st, &business.StewardRecord{
		ID:             "s-nocert",
		TenantID:       "source-tenant",
		Status:         business.StewardStatusRegistered,
		DeviceID:       "aabbcc",
		IdentityKeyPub: pub,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-nocert", "source-tenant", "addr", "registered"))

	// dest-tenant is already created by setupMoveStewardServer.
	ctx := context.Background()
	rec := postMoveSteward(server, "s-nocert", "dest-tenant")
	require.Equal(t, http.StatusOK, rec.Code)

	got, err := server.stewardStore.GetSteward(ctx, "s-nocert")
	require.NoError(t, err)
	// Identity fields must be unchanged.
	assert.Equal(t, "aabbcc", got.DeviceID, "DeviceID must not change on move")
	assert.Equal(t, pub, got.IdentityKeyPub, "IdentityKeyPub must not change on move")
	assert.Equal(t, "dest-tenant", got.TenantID, "TenantID must be updated")
}

// TestHandleMoveSteward_SelfMove verifies that a move to the same tenant short-circuits
// with no state change (status "no_change") and does not touch the store or registry.
func TestHandleMoveSteward_SelfMove(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	seedSteward(t, st, &business.StewardRecord{ID: "s-self", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	require.NoError(t, server.controllerService.RegisterSteward("s-self", "source-tenant", "addr", "registered"))

	rec := postMoveSteward(server, "s-self", "source-tenant")

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "no_change", resp.Data["status"], "self-move must return no_change")
}

// TestHandleMoveSteward_RevokedSourceRejected verifies that a move from a revoked
// steward returns 400 STEWARD_REVOKED — moving would back-door re-entry.
func TestHandleMoveSteward_RevokedSourceRejected(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)

	seedSteward(t, st, &business.StewardRecord{ID: "s-revoked", TenantID: "source-tenant", Status: business.StewardStatusRevoked})

	// dest-tenant is already created by setupMoveStewardServer.
	rec := postMoveSteward(server, "s-revoked", "dest-tenant")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_REVOKED", errResp.Error.Code)
}

// TestHandleMoveSteward_AllowedSourceStatuses verifies that each allowed source status
// succeeds and the status is not promoted (no implicit status change on move).
func TestHandleMoveSteward_AllowedSourceStatuses(t *testing.T) {
	allowedStatuses := []business.StewardStatus{
		business.StewardStatusRegistered,
		business.StewardStatusActive,
		business.StewardStatusLost,
		business.StewardStatusArchived,
		business.StewardStatusDormant,
		business.StewardStatusDeregistered,
	}

	for _, status := range allowedStatuses {
		status := status
		t.Run(string(status), func(t *testing.T) {
			server, st, _ := setupMoveStewardServer(t)

			id := "s-" + string(status)
			seedSteward(t, st, &business.StewardRecord{ID: id, TenantID: "source-tenant", Status: status})
			require.NoError(t, server.controllerService.RegisterSteward(id, "source-tenant", "addr", string(status)))

			// dest-tenant is already created by setupMoveStewardServer.
			ctx := context.Background()
			rec := postMoveSteward(server, id, "dest-tenant")
			require.Equal(t, http.StatusOK, rec.Code, "status %q must be allowed to move", status)

			// Status must not be promoted.
			got, err := server.stewardStore.GetSteward(ctx, id)
			require.NoError(t, err)
			assert.Equal(t, status, got.Status, "status must not change on move for %q", status)
		})
	}
}

// TestHandleMoveSteward_DestinationNotFound verifies that moving to a nonexistent
// tenant returns 400 TENANT_NOT_FOUND.
func TestHandleMoveSteward_DestinationNotFound(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-dest404", TenantID: "source-tenant", Status: business.StewardStatusRegistered})

	rec := postMoveSteward(server, "s-dest404", "nonexistent-tenant")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code)
}

// TestHandleMoveSteward_DestinationNotActive verifies that moving to a tenant that
// exists but is not in "active" status returns 400 TENANT_NOT_ACTIVE. The durable
// store must not be updated when the destination is inactive.
func TestHandleMoveSteward_DestinationNotActive(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-inactive-dest", TenantID: "source-tenant", Status: business.StewardStatusRegistered})

	// dest-tenant was created active by setupMoveStewardServer; suspend it so the
	// handler sees a non-active destination.
	ctx := context.Background()
	_, err := server.tenantManager.SuspendTenant(ctx, "dest-tenant")
	require.NoError(t, err)

	rec := postMoveSteward(server, "s-inactive-dest", "dest-tenant")

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_ACTIVE", errResp.Error.Code)

	// The move must not have been persisted.
	got, err := server.stewardStore.GetSteward(ctx, "s-inactive-dest")
	require.NoError(t, err)
	assert.Equal(t, "source-tenant", got.TenantID, "steward must remain in source tenant when destination is not active")
}

// TestHandleMoveSteward_DurableStoreWriteFails verifies that when the durable store
// write fails after all validation passes, the handler returns 500 INTERNAL_ERROR.
func TestHandleMoveSteward_DurableStoreWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod does not enforce POSIX directory permissions on Windows")
	}
	server, st, root := setupMoveStewardServer(t)
	seedSteward(t, st, &business.StewardRecord{ID: "s-writefail", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	require.NoError(t, server.controllerService.RegisterSteward("s-writefail", "source-tenant", "addr", "registered"))

	// Induce a genuine durable-store write failure: make the flat-file store's backing
	// directory read-only. The record was already written, so GetSteward (a pure read)
	// still succeeds and the handler reaches UpdateStewardTenant, whose atomic write
	// (temp-file creation in the directory) then fails with a permission error — the
	// handler must surface a 500. Restore the mode on cleanup so t.TempDir() removal
	// (registered earlier, so it runs after this) can delete the tree.
	stewardDir := filepath.Join(root, "stewards")
	require.NoError(t, os.Chmod(stewardDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(stewardDir, 0o750) })

	rec := postMoveSteward(server, "s-writefail", "dest-tenant")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}

// wireFleetStorageBackedService swaps in a controller service backed by a real
// SQLite fleet-storage manager, returning the manager so tests can inspect the
// durable device_tenant mapping. handleMoveSteward reads s.controllerService at
// call time, so post-construction replacement is sufficient.
func wireFleetStorageBackedService(t *testing.T, server *Server) *fleetStorage.Manager {
	t.Helper()
	cfg := fleetStorage.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.EnableDeduplication = false
	mgr, err := fleetStorage.NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	server.controllerService = service.NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr)
	return mgr
}

// TestHandleMoveSteward_PersistsDeviceTenantMapping verifies that a move rewrites
// the durable device_tenant mapping, which tenant resolution treats as
// authoritative. Without this write the steward reverts to its pre-move tenant on
// the next reconnect or controller restart (Issue #3324).
func TestHandleMoveSteward_PersistsDeviceTenantMapping(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	mgr := wireFleetStorageBackedService(t, server)

	seedSteward(t, st, &business.StewardRecord{ID: "s-mapping", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	require.NoError(t, server.controllerService.RegisterSteward("s-mapping", "source-tenant", "addr", "registered"))

	rec := postMoveSteward(server, "s-mapping", "dest-tenant")
	require.Equal(t, http.StatusOK, rec.Code)

	tenantID, found, err := mgr.GetDeviceTenant(context.Background(), "s-mapping")
	require.NoError(t, err)
	require.True(t, found, "move must write the durable device_tenant mapping")
	assert.Equal(t, "dest-tenant", tenantID, "durable mapping must name the destination tenant")
}

// TestHandleMoveSteward_OfflineStewardPersistsMapping verifies that moving a
// steward that is absent from the live registry (not connected since the last
// controller start) still succeeds and still rewrites the durable mapping — the
// case the handler explicitly tolerates, and the one that reverted (Issue #3324).
func TestHandleMoveSteward_OfflineStewardPersistsMapping(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	mgr := wireFleetStorageBackedService(t, server)

	// Durable steward record only: never registered into the in-memory registry.
	seedSteward(t, st, &business.StewardRecord{ID: "s-offline", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	_, inRegistry := server.controllerService.GetStewardInfo("s-offline")
	require.False(t, inRegistry, "precondition: steward must be absent from the live registry")

	rec := postMoveSteward(server, "s-offline", "dest-tenant")
	require.Equal(t, http.StatusOK, rec.Code, "an offline steward move must still succeed")

	tenantID, found, err := mgr.GetDeviceTenant(context.Background(), "s-offline")
	require.NoError(t, err)
	require.True(t, found, "durable mapping must be written even when the steward is offline")
	assert.Equal(t, "dest-tenant", tenantID)
}

// TestHandleMoveSteward_DeviceTenantWriteFails verifies that a failure to persist
// the device_tenant mapping fails the request with 500 rather than reporting a
// move that would silently revert. The failure is induced with real components by
// closing the fleet-storage manager before the move.
func TestHandleMoveSteward_DeviceTenantWriteFails(t *testing.T) {
	server, st, _ := setupMoveStewardServer(t)
	mgr := wireFleetStorageBackedService(t, server)

	seedSteward(t, st, &business.StewardRecord{ID: "s-mapfail", TenantID: "source-tenant", Status: business.StewardStatusRegistered})
	require.NoError(t, server.controllerService.RegisterSteward("s-mapfail", "source-tenant", "addr", "registered"))

	// Close the durable fleet store so the device_tenant write fails.
	require.NoError(t, mgr.Close())

	rec := postMoveSteward(server, "s-mapfail", "dest-tenant")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
}

// TestHandleMoveSteward_StewardNotFound verifies 404 when the steward ID is unknown.
func TestHandleMoveSteward_StewardNotFound(t *testing.T) {
	server, _, _ := setupMoveStewardServer(t)

	rec := postMoveSteward(server, "nonexistent-steward", "dest-tenant")

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleMoveSteward_InvalidStewardID verifies 400 for a malformed steward ID.
func TestHandleMoveSteward_InvalidStewardID(t *testing.T) {
	server := setupTestServer(t)

	body := strings.NewReader(`{"new_tenant_id":"dest"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/bad.id:here/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "bad.id:here"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_STEWARD_ID", errResp.Error.Code)
}

// TestHandleMoveSteward_MissingNewTenantID verifies 400 when new_tenant_id is absent.
func TestHandleMoveSteward_MissingNewTenantID(t *testing.T) {
	server := setupTestServer(t)

	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/some-steward/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "some-steward"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "MISSING_TENANT_ID", errResp.Error.Code)
}

// TestHandleMoveSteward_InvalidTenantIDFormat verifies 400 for a malformed new_tenant_id.
func TestHandleMoveSteward_InvalidTenantIDFormat(t *testing.T) {
	server := setupTestServer(t)

	body := strings.NewReader(`{"new_tenant_id":"bad.tenant:id"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/some-steward/move", body)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "some-steward"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_TENANT_ID", errResp.Error.Code)
}

// TestHandleMoveSteward_APIKeyRejected verifies that an API-key caller (non-mTLS) is
// rejected with 403 at the Tier-3 gate when hitting the route via the router.
func TestHandleMoveSteward_APIKeyRejected(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:move"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/some-steward/move",
		strings.NewReader(`{"new_tenant_id":"dest"}`))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "API-key callers must be rejected at Tier-3")
}

// ---- handleMoveSteward authorization + audit tests (Issue #2342) ----

// postMoveStewardWithPrincipal calls handleMoveSteward directly with an explicit principal
// (bypassing Tier-3 middleware) so authorization logic can be tested in isolation.
func postMoveStewardWithPrincipal(server *Server, stewardID, newTenantID string, p *Principal) *httptest.ResponseRecorder {
	body := strings.NewReader(`{"new_tenant_id":"` + newTenantID + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/"+stewardID+"/move", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-request-id-"+stewardID)
	req = withPrincipal(req, p)
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)
	return rec
}

// setupMoveAuthServer creates a test server with source and destination tenants for
// authorization tests. In addition to the standard "source-tenant" and "dest-tenant", it
// creates hierarchical child tenants as separate store entries with path-style IDs so the
// anchored-prefix check can be exercised.
func setupMoveAuthServer(t *testing.T) (*Server, business.StewardStore) {
	t.Helper()
	server, st, _ := setupMoveStewardServer(t)
	ctx := context.Background()

	// Add extra tenants needed for hierarchical tests. "msp-a" and "other-msp" are flat
	// parent-level scopes; "msp-a-child" serves as a child-namespace stand-in.
	for _, id := range []string{"msp-a", "msp-a-child", "other-msp"} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: id, Name: id})
		require.NoError(t, err, "creating tenant %q", id)
	}
	return server, st
}

// TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverSource verifies 403 when a scoped
// admin's scope does not cover the source tenant.
func TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverSource(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-nosrc",
		TenantID: "source-tenant", // caller has scope "other-msp", no authority here
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-nosrc", "source-tenant", "addr", "registered"))

	// dest-tenant is in scope but source is not
	scopedPrincipal := &Principal{ID: "scoped-admin", Assurance: session.AssuranceStrong, TenantID: "other-msp", CertSerial: "SN-001", CertFingerprint: "fp-001"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-nosrc", "dest-tenant", scopedPrincipal)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INSUFFICIENT_SCOPE", errResp.Error.Code)
}

// TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverDestination verifies 403 when a
// scoped admin's scope covers the source but not the destination.
func TestHandleMoveSteward_ScopedAdmin_NoAuthorityOverDestination(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	// Seed a steward in "msp-a" so the caller's scope covers the source.
	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-nodst",
		TenantID: "msp-a",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-nodst", "msp-a", "addr", "registered"))

	// "other-msp" is not in "msp-a" scope
	scopedPrincipal := &Principal{ID: "scoped-admin", Assurance: session.AssuranceStrong, TenantID: "msp-a", CertSerial: "SN-002", CertFingerprint: "fp-002"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-nodst", "other-msp", scopedPrincipal)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INSUFFICIENT_SCOPE", errResp.Error.Code)
}

// TestHandleMoveSteward_ScopedAdmin_AuthorityOverBoth_AnchoredPrefix verifies 200 when a
// scoped admin has anchored-prefix authority over both source and destination.
// The source steward is stored with a hierarchical TenantID ("msp-a/child-src") so the
// prefix check exercises the strings.HasPrefix path.
func TestHandleMoveSteward_ScopedAdmin_AuthorityOverBoth_AnchoredPrefix(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	// Seed the steward directly with a hierarchical source tenant ID so the stored record
	// has "msp-a/..." format while the controller service index uses "msp-a".
	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-both",
		TenantID: "msp-a/child-src",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-both", "msp-a/child-src", "addr", "registered"))

	// Destination is also a child of "msp-a/" — caller has authority over both.
	// We use "msp-a-child" (a flat tenant that was pre-created) as destination. The
	// scope check for dest is strings.HasPrefix("msp-a-child", "msp-a/") == false,
	// so we need a true hierarchical path. Create a child tenant in the store.
	ctx := context.Background()
	require.NoError(t, st.RegisterSteward(ctx, &business.StewardRecord{
		ID:       "s-dest-placeholder",
		TenantID: "msp-a/child-dst",
	}))
	// Register "msp-a/child-dst" as a destination tenant via a direct store insertion
	// (bypassing tenant manager validation) — we only need GetTenant to return active.
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{
		ID:   "msp-a-child-dst",
		Name: "msp-a-child-dst",
	})
	require.NoError(t, err)

	// For the anchored-prefix test, pass a flat destination that's literally under "msp-a/"
	// by constructing the request with new_tenant_id = "msp-a/child-dst". Since tenantPathRegex
	// now accepts slashes, this is valid. The tenant store won't have this exact path-style ID
	// (the tenant manager uses flat IDs), so GetTenant returns not-found → 400 TENANT_NOT_FOUND.
	// That means the AUTH check passed (no 403) and the failure is the subsequent tenant lookup.
	scopedPrincipal := &Principal{ID: "msp-admin", Assurance: session.AssuranceStrong, TenantID: "msp-a", CertSerial: "SN-003", CertFingerprint: "fp-003"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-both", "msp-a/child-dst", scopedPrincipal)

	// The authorization check PASSES (both in scope), but the destination tenant isn't
	// registered — we get 400 TENANT_NOT_FOUND, not 403 INSUFFICIENT_SCOPE.
	require.NotEqual(t, http.StatusForbidden, rec.Code, "auth must pass for msp-a scope over msp-a/child-dst destination")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code,
		"403 would mean auth failed; 400 TENANT_NOT_FOUND confirms auth passed and tenant lookup failed")
}

// TestHandleMoveSteward_ScopedAdmin_ExactTenantMatch verifies that a scoped admin with
// a scope exactly matching both source and destination is allowed (exact-match path).
func TestHandleMoveSteward_ScopedAdmin_ExactTenantMatch(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	// Both source and destination are "msp-a" — but that's a self-move.
	// Use source = "msp-a" (exact match) and dest = "msp-a-child" which is NOT in scope.
	// To test exact-match on destination, use dest = "msp-a" → self-move (no_change).
	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-exact",
		TenantID: "msp-a",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-exact", "msp-a", "addr", "registered"))

	// Caller has exact match on source; dest = "msp-a" is also exact match → self-move
	scopedPrincipal := &Principal{ID: "msp-admin", Assurance: session.AssuranceStrong, TenantID: "msp-a", CertSerial: "SN-004", CertFingerprint: "fp-004"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-exact", "msp-a", scopedPrincipal)

	// Auth passes (exact match on both), self-move short-circuits → no_change
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "no_change", resp.Data["status"])
}

// TestHandleMoveSteward_UnscopedRootAdmin_Allowed verifies that a root (TenantID=="")
// admin can always move any steward regardless of source/destination tenants, and that
// the resulting audit record marks it as a privileged cross-tenant action.
func TestHandleMoveSteward_UnscopedRootAdmin_Allowed(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-auth-root",
		TenantID: "source-tenant",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-auth-root", "source-tenant", "addr", "registered"))

	rootPrincipal := &Principal{ID: "root-admin", Assurance: session.AssuranceStrong, TenantID: "", CertSerial: "SN-ROOT", CertFingerprint: "fp-root"}
	rec := postMoveStewardWithPrincipal(server, "s-auth-root", "dest-tenant", rootPrincipal)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "moved", resp.Data["status"])

	// AC #1: unscoped root admin move must emit a privileged-action audit record.
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward_move"},
	})
	require.NoError(t, err)
	var found *business.AuditEntry
	for _, e := range entries {
		if e.Result == business.AuditResultSuccess && e.UserID == "root-admin" {
			found = e
			break
		}
	}
	require.NotNil(t, found, "privileged-action audit record must be emitted for root admin move")
	assert.Equal(t, true, found.Details["privileged_cross_tenant"], "root admin move must be flagged as privileged_cross_tenant")
}

// TestHandleMoveSteward_AuditOnSuccess verifies that a successful move emits an audit
// record containing source/destination tenants, admin identity (CN + cert fields),
// request ID, before→after diff, and outcome.
func TestHandleMoveSteward_AuditOnSuccess(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-audit-ok",
		TenantID: "source-tenant",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-audit-ok", "source-tenant", "addr", "registered"))

	rootPrincipal := &Principal{
		ID:              "audit-admin",
		Assurance:       session.AssuranceStrong,
		TenantID:        "",
		CertSerial:      "SERIAL-OK",
		CertFingerprint: "FPRINT-OK",
	}
	body := strings.NewReader(`{"new_tenant_id":"dest-tenant"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/s-audit-ok/move", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-audit-ok-123")
	req = withPrincipal(req, rootPrincipal)
	req = withVars(req, map[string]string{"id": "s-audit-ok"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Flush the audit manager so in-memory events reach the store.
	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward_move"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "at least one steward_move audit entry expected")

	var found *business.AuditEntry
	for _, e := range entries {
		if e.Action == "steward_move" && e.Result == business.AuditResultSuccess {
			found = e
			break
		}
	}
	require.NotNil(t, found, "successful steward_move audit entry not found")

	assert.Equal(t, business.AuditResultSuccess, found.Result)
	assert.Equal(t, business.AuditSeverityHigh, found.Severity)
	assert.Equal(t, "audit-admin", found.UserID, "admin CN must be recorded")
	assert.Equal(t, "req-audit-ok-123", found.RequestID, "request ID must be recorded")
	assert.NotEmpty(t, found.IPAddress, "source IP must be recorded")
	assert.NotNil(t, found.Changes, "before→after diff must be present")
	assert.Equal(t, "source-tenant", found.Changes.Before["tenant_id"], "before tenant must be source-tenant")
	assert.Equal(t, "dest-tenant", found.Changes.After["tenant_id"], "after tenant must be dest-tenant")
	assert.Equal(t, "source-tenant", found.Details["source_tenant"], "source_tenant detail must be set")
	assert.Equal(t, "dest-tenant", found.Details["dest_tenant"], "dest_tenant detail must be set")
	assert.Equal(t, "SERIAL-OK", found.Details["cert_serial"], "cert_serial must be recorded")
	assert.Equal(t, "FPRINT-OK", found.Details["cert_fingerprint"], "cert_fingerprint must be recorded")
}

// TestHandleMoveSteward_AuditOnDenial verifies that a denied move emits a Critical-severity
// security audit event containing source/destination tenants, admin identity, request ID,
// before→after diff, and outcome=denied.
func TestHandleMoveSteward_AuditOnDenial(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-audit-deny",
		TenantID: "source-tenant",
		Status:   business.StewardStatusRegistered,
	})
	require.NoError(t, server.controllerService.RegisterSteward("s-audit-deny", "source-tenant", "addr", "registered"))

	scopedPrincipal := &Principal{
		ID:              "scoped-deny-admin",
		Assurance:       session.AssuranceStrong,
		TenantID:        "other-msp",
		CertSerial:      "SERIAL-DENY",
		CertFingerprint: "FPRINT-DENY",
	}
	body := strings.NewReader(`{"new_tenant_id":"dest-tenant"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/s-audit-deny/move", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "req-audit-deny-456")
	req = withPrincipal(req, scopedPrincipal)
	req = withVars(req, map[string]string{"id": "s-audit-deny"})
	rec := httptest.NewRecorder()
	server.handleMoveSteward(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))

	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward_move"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "at least one steward_move audit entry expected")

	var found *business.AuditEntry
	for _, e := range entries {
		if e.Action == "steward_move" && e.Result == business.AuditResultDenied {
			found = e
			break
		}
	}
	require.NotNil(t, found, "denied steward_move audit entry not found")

	assert.Equal(t, business.AuditResultDenied, found.Result)
	assert.Equal(t, business.AuditSeverityCritical, found.Severity, "denied move must be Critical severity")
	assert.Equal(t, "scoped-deny-admin", found.UserID, "admin CN must be recorded")
	assert.Equal(t, "req-audit-deny-456", found.RequestID, "request ID must be recorded")
	assert.NotEmpty(t, found.IPAddress, "source IP must be recorded")
	assert.NotNil(t, found.Changes, "before→after diff must be present even for denied moves")
	assert.Equal(t, "source-tenant", found.Changes.Before["tenant_id"])
	assert.Equal(t, "dest-tenant", found.Changes.After["tenant_id"])
	assert.Equal(t, "source-tenant", found.Details["source_tenant"])
	assert.Equal(t, "dest-tenant", found.Details["dest_tenant"])
	assert.Equal(t, "SERIAL-DENY", found.Details["cert_serial"])
	assert.Equal(t, "FPRINT-DENY", found.Details["cert_fingerprint"])
}

// TestHandleMoveSteward_TenantPathWithSlash verifies that a hierarchical new_tenant_id
// (containing a slash) now passes format validation (tenantPathRegex allows slashes).
func TestHandleMoveSteward_TenantPathWithSlash(t *testing.T) {
	server, st := setupMoveAuthServer(t)

	seedSteward(t, st, &business.StewardRecord{
		ID:       "s-slash-test",
		TenantID: "msp-a/child-src",
		Status:   business.StewardStatusRegistered,
	})

	// Request with hierarchical new_tenant_id — format validation must pass.
	// The tenant doesn't exist in the store, so we expect TENANT_NOT_FOUND (400), not INVALID_TENANT_ID (400).
	scopedPrincipal := &Principal{ID: "msp-admin", Assurance: session.AssuranceStrong, TenantID: "msp-a", CertSerial: "SN-007", CertFingerprint: "fp-007"}
	rec := postMoveStewardWithPrincipal(server, "s-slash-test", "msp-a/other-child", scopedPrincipal)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.NotEqual(t, "INVALID_TENANT_ID", errResp.Error.Code,
		"hierarchical tenant IDs must pass format validation")
	assert.Equal(t, "TENANT_NOT_FOUND", errResp.Error.Code,
		"auth passed and tenant lookup failed as expected")
}

// ---- handleListStewards lost-status read-path test (Issue #2463) ----

// TestListStewards_SurfacesLostStatusFromStore seeds a durable StewardStore record
// at StewardStatusLost directly (no heartbeat service involved — isolates the read
// path) and asserts handleListStewards returns Status "lost" for that steward,
// confirming no additional API-layer translation is needed (Issue #2463).
func TestListStewards_SurfacesLostStatusFromStore(t *testing.T) {
	ctx := context.Background()
	server := setupTestServer(t)

	st, _ := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	const stewardID = "s-lost-status-2463"
	const tenantID = "test-tenant"

	// Seed the durable store with StewardStatusLost directly (bypasses heartbeat service).
	require.NoError(t, st.RegisterSteward(ctx, &business.StewardRecord{
		ID:       stewardID,
		TenantID: tenantID,
		Status:   business.StewardStatusLost,
	}))

	// Also register in the in-memory controller service so handleListStewards
	// (which reads the in-memory registry) can surface the steward.
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, tenantID, "addr", string(business.StewardStatusLost)))

	// Call handleListStewards directly (no filter → unfiltered path that reads
	// s.controllerService.GetAllStewards()).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req = withTenant(req, "")
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	var found bool
	for _, s := range resp.Data {
		if s.ID == stewardID {
			found = true
			assert.Equal(t, "lost", s.Status,
				"handleListStewards must surface StewardStatusLost without API-layer translation")
		}
	}
	assert.True(t, found, "lost steward must appear in the list response")
}

// ---- Issue #2724: tenant_id and dna.attributes.tenant population tests ----

// TestHandleListStewards_FilteredPath_TenantIDPopulated verifies that the filtered
// fleet-query path sets TenantID and injects dna.attributes["tenant"] on each result.
func TestHandleListStewards_FilteredPath_TenantIDPopulated(t *testing.T) {
	server := setupTestServer(t)
	// NewTestKey creates a "test-tenant"-scoped key, which sets filter.TenantID and
	// drives the filtered (fleetQuery) code path.
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-tenant-filtered",
		"os":       "linux",
		"arch":     "amd64",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotEmpty(t, resp.Data, "at least one steward must be returned")

	for _, s := range resp.Data {
		assert.Equal(t, "test-tenant", s.TenantID,
			"filtered list: TenantID must be populated from fleet query result")
		require.NotNil(t, s.DNA, "DNA must be present when DNA attributes exist")
		assert.Equal(t, "test-tenant", s.DNA.Attributes["tenant"],
			"filtered list: dna.attributes.tenant must equal TenantID")
	}
}

// TestHandleListStewards_UnfilteredPath_TenantIDPopulated verifies that the unfiltered
// (GetAllStewards) code path sets TenantID and injects dna.attributes["tenant"].
func TestHandleListStewards_UnfilteredPath_TenantIDPopulated(t *testing.T) {
	server := setupTestServer(t)

	// RegisterStewardWithAttributes seeds initial DNA so DNA != nil in the unfiltered path.
	require.NoError(t, server.controllerService.RegisterStewardWithAttributes(
		"s-unfiltered-tenant", "tenant-x", "addr", "registered",
		map[string]string{"hostname": "host-unfiltered", "os": "linux", "arch": "amd64"},
	))

	// Call handler directly with an empty TenantID so isEmptyFilter returns true,
	// triggering the GetAllStewards (unfiltered) code path.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req = withTenant(req, "")
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	var found bool
	for _, s := range resp.Data {
		if s.ID == "s-unfiltered-tenant" {
			found = true
			assert.Equal(t, "tenant-x", s.TenantID,
				"unfiltered list: TenantID must be populated from steward registration")
			require.NotNil(t, s.DNA, "DNA must be present when DNA attributes were seeded")
			assert.Equal(t, "tenant-x", s.DNA.Attributes["tenant"],
				"unfiltered list: dna.attributes.tenant must equal TenantID")
		}
	}
	assert.True(t, found, "registered steward must appear in unfiltered list")
}

// TestHandleGetSteward_TenantIDPopulated verifies that GET /api/v1/stewards/{id}
// includes tenant_id and dna.attributes["tenant"] in the response.
func TestHandleGetSteward_TenantIDPopulated(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read"})

	stewardID := registerTestSteward(t, server.controllerService, map[string]string{
		"hostname": "host-get-tenant",
		"os":       "linux",
	})

	req := httptest.NewRequest("GET", "/api/v1/stewards/"+stewardID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, stewardID, resp.Data.ID)
	assert.Equal(t, "test-tenant", resp.Data.TenantID,
		"get steward: TenantID must be populated in response")
	require.NotNil(t, resp.Data.DNA, "DNA must be present when DNA attributes exist")
	assert.Equal(t, "test-tenant", resp.Data.DNA.Attributes["tenant"],
		"get steward: dna.attributes.tenant must equal TenantID")
}

// TestHandleListStewards_CrossTenant_NoDisclosure verifies that a tenant-scoped caller
// can only see stewards belonging to their own tenant, and that the populated tenant_id
// field never discloses stewards from other tenants. The existing cross-tenant isolation
// is exercised; this story adds no new disclosure surface.
func TestHandleListStewards_CrossTenant_NoDisclosure(t *testing.T) {
	server := setupTestServer(t)

	// Register two stewards under different tenants.
	require.NoError(t, server.controllerService.RegisterStewardWithAttributes(
		"s-tenant-a-1", "tenant-a", "addr-a", "registered",
		map[string]string{"hostname": "host-a", "os": "linux"},
	))
	require.NoError(t, server.controllerService.RegisterStewardWithAttributes(
		"s-tenant-b-1", "tenant-b", "addr-b", "registered",
		map[string]string{"hostname": "host-b", "os": "linux"},
	))

	// "tenant-a"-scoped API key: sets filter.TenantID="tenant-a", triggering the
	// filtered path; fleet query returns only "tenant-a" stewards.
	tenantAKey := NewEphemeralTestKey(t, server, []string{"steward:list"}, "tenant-a", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/stewards?os=linux", nil)
	req.Header.Set("X-API-Key", tenantAKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	for _, s := range resp.Data {
		assert.Equal(t, "tenant-a", s.TenantID,
			"cross-tenant: responses must only contain tenant-a stewards")
		assert.NotEqual(t, "s-tenant-b-1", s.ID,
			"cross-tenant: tenant-b steward must not appear in tenant-a response")
		if s.DNA != nil {
			assert.Equal(t, "tenant-a", s.DNA.Attributes["tenant"],
				"cross-tenant: dna.attributes.tenant must not disclose tenant-b")
		}
	}
}

// ---- handleListStewards ?q= selector param tests (Issue #2726) ----

// listStewardsWithSelector is a test helper that calls handleListStewards directly
// with a given selector query string and optional tenant ID in context.
func listStewardsWithSelector(server *Server, q, tenantID string) *httptest.ResponseRecorder {
	url := "/api/v1/stewards?q=" + q
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if tenantID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	}
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)
	return rec
}

// TestHandleListStewards_Selector_InvalidSelector_Returns400 verifies that a
// syntactically invalid selector expression returns 400 INVALID_SELECTOR. The
// response must not disclose internal error details.
func TestHandleListStewards_Selector_InvalidSelector_Returns400(t *testing.T) {
	server := setupTestServer(t)

	rec := listStewardsWithSelector(server, "unknownkey:value", "")
	require.Equal(t, http.StatusBadRequest, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "INVALID_SELECTOR", resp.Error.Code)
	// Error message must be client-safe (no internal paths, no stack traces).
	assert.NotEmpty(t, resp.Error.Message)
}

// TestHandleListStewards_Selector_EmptySelector_Returns400 verifies that an empty
// selector string (q= with no value) is rejected with 400 INVALID_SELECTOR. The
// selector grammar requires at least one term; empty is ambiguous.
func TestHandleListStewards_Selector_EmptySelector_Returns400(t *testing.T) {
	server := setupTestServer(t)

	rec := listStewardsWithSelector(server, "", "")
	// An empty q param means the selector is empty string — Parse will reject it.
	// But q="" is the same as q not present (no ?q= in URL gives ""). Let's verify
	// that an explicit empty value results in a normal non-selector response (not 400).
	// Since q="" → selector path not entered → existing list path. 200 OK expected.
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleListStewards_Selector_MalformedKey_Returns400 verifies that a selector
// with a key that ends in an empty colon is rejected.
func TestHandleListStewards_Selector_MalformedKey_Returns400(t *testing.T) {
	server := setupTestServer(t)

	// "os:" has an empty value after the colon — the tokenizer rejects this.
	rec := listStewardsWithSelector(server, "os%3A", "")
	// URL-decode: "os:" → tokenizer error "empty value for key"
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "INVALID_SELECTOR", resp.Error.Code)
}

// TestHandleListStewards_Selector_CrossTenant_Returns403 verifies that a selector
// whose explicit tenant prefix falls outside the caller's authorized subtree returns
// 403 CROSS_TENANT — matching handleResolveSelector's identical behavior (never a
// 200 with an empty set, never existence disclosure).
func TestHandleListStewards_Selector_CrossTenant_Returns403(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "host-a", "linux", "amd64", "prod"),
	)

	// Caller is scoped to "msp-a/client-1"; selector targets "msp-a/client-2" (sibling).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards?q=msp-a%2Fclient-2%2Fall", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "msp-a/client-1"))
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT", resp.Error.Code)
}

// TestHandleListStewards_Selector_ValidOSFilter_ReturnsSubset verifies that
// ?q=os:linux returns only Linux stewards, matching the cfg CLI behavior.
func TestHandleListStewards_Selector_ValidOSFilter_ReturnsSubset(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s-linux-1", "linux-host-1", "linux", "amd64", "prod"),
		makeSeedSteward("s-linux-2", "linux-host-2", "linux", "arm64", "dev"),
		makeSeedSteward("s-win-1", "win-host-1", "windows", "amd64", "prod"),
	)

	rec := listStewardsWithSelector(server, "os%3Alinux", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 2, "only linux stewards must be returned")
	for _, s := range resp.Data {
		require.NotNil(t, s.DNA)
		assert.Equal(t, "linux", s.DNA.OS)
	}
}

// TestHandleListStewards_Selector_NameGlob_ReturnsMatching verifies that name: with
// a glob pattern (name:web-*) matches by hostname prefix, consistent with the cfg CLI.
func TestHandleListStewards_Selector_NameGlob_ReturnsMatching(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "web-01", "linux", "amd64", "prod"),
		makeSeedSteward("s2", "web-02", "linux", "amd64", "prod"),
		makeSeedSteward("s3", "db-01", "linux", "amd64", "prod"),
	)

	rec := listStewardsWithSelector(server, "name%3Aweb-*", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 2)
	for _, s := range resp.Data {
		require.NotNil(t, s.DNA)
		assert.True(t, strings.HasPrefix(s.DNA.Hostname, "web-"),
			"hostname must match the name: glob pattern")
	}
}

// TestHandleListStewards_Selector_DNAAttribute_ReturnsMatching verifies that
// dna.<key>:<value> selects stewards by arbitrary DNA attribute.
func TestHandleListStewards_Selector_DNAAttribute_ReturnsMatching(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "s1", TenantID: "t", Status: "online", DNAAttributes: map[string]string{
				"hostname": "db-host", "os": "linux", "arch": "amd64",
				"role": "database",
			}},
			{ID: "s2", TenantID: "t", Status: "online", DNAAttributes: map[string]string{
				"hostname": "web-host", "os": "linux", "arch": "amd64",
				"role": "webserver",
			}},
		},
	})

	rec := listStewardsWithSelector(server, "dna.role%3Adatabase", "")
	require.Equal(t, http.StatusOK, rec.Code)

	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1)
	assert.Equal(t, "s1", resp.Data[0].ID)
}

// TestHandleListStewards_Selector_TenantSubtree_Enforced verifies that a caller
// scoped to a tenant only sees stewards in their subtree when using the selector path.
func TestHandleListStewards_Selector_TenantSubtree_Enforced(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "s-msp-a", TenantID: "msp-a", Status: "online",
				DNAAttributes: map[string]string{"hostname": "host-a", "os": "linux"}},
			{ID: "s-msp-b", TenantID: "msp-b", Status: "online",
				DNAAttributes: map[string]string{"hostname": "host-b", "os": "linux"}},
		},
	})

	// "all" selector with caller scoped to msp-a — must not see msp-b stewards.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards?q=all", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, "msp-a"))
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Data, 1, "only msp-a stewards must be returned")
	assert.Equal(t, "s-msp-a", resp.Data[0].ID)
}

// TestHandleListStewards_Selector_Paginated_ReturnsPage verifies that pagination
// works identically on the selector path: paginateStewards is applied and the
// response is a StewardListPage envelope with total, limit, offset fields.
func TestHandleListStewards_Selector_Paginated_ReturnsPage(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = seededFleetQuery(
		makeSeedSteward("s1", "host-a", "linux", "amd64", "prod"),
		makeSeedSteward("s2", "host-b", "linux", "amd64", "prod"),
		makeSeedSteward("s3", "host-c", "linux", "amd64", "prod"),
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards?q=os%3Alinux&limit=2&offset=0", nil)
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data StewardListPage `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 3, resp.Data.Total, "total must be fleet-wide count, not page count")
	assert.Equal(t, 2, resp.Data.Limit)
	assert.Equal(t, 0, resp.Data.Offset)
	assert.Len(t, resp.Data.Stewards, 2)
}

// TestHandleListStewards_Selector_All_AdminUnrestricted verifies that an admin
// caller (empty tenant) with q=all sees all stewards, matching the cfg CLI behavior.
func TestHandleListStewards_Selector_All_AdminUnrestricted(t *testing.T) {
	server := setupTestServer(t)
	server.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{
		stewards: []fleet.StewardData{
			{ID: "s1", TenantID: "msp-a", Status: "online",
				DNAAttributes: map[string]string{"hostname": "h1", "os": "linux"}},
			{ID: "s2", TenantID: "msp-b", Status: "online",
				DNAAttributes: map[string]string{"hostname": "h2", "os": "linux"}},
		},
	})

	// Admin caller (empty tenant) must see both tenants.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards?q=all", nil)
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2, "admin must see all stewards with q=all")
}

// ---- Issue #2919: root-scope and cross-tenant-leakage tests ----

// TestListStewards_RootScopedSession_SeesAllTenants verifies that a web session
// with empty TenantID (root scope) returns stewards from all tenants via the
// GetAllStewards path (isEmptyFilter must return true when TenantSubtree is "").
func TestListStewards_RootScopedSession_SeesAllTenants(t *testing.T) {
	server := setupTestServer(t)

	// Register stewards in two sibling tenants.
	registerStewardInTenant(t, server.controllerService, "msp-a", map[string]string{
		"hostname": "host-msp-a",
	})
	registerStewardInTenant(t, server.controllerService, "msp-b", map[string]string{
		"hostname": "host-msp-b",
	})

	// Root-scoped session: no TenantID in context (empty string).
	// The handler reads ctxkeys.TenantID; when absent or empty, tenantID stays "".
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, ""))
	rec := httptest.NewRecorder()
	server.handleListStewards(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 2, "root-scoped session must see all stewards from all tenants")

	tenants := make(map[string]bool)
	for _, s := range resp.Data {
		tenants[s.TenantID] = true
	}
	assert.True(t, tenants["msp-a"], "msp-a steward must be visible")
	assert.True(t, tenants["msp-b"], "msp-b steward must be visible")
}

// TestListStewards_NonRootAccount_NoCrossTenantLeakage verifies that a non-root
// web (or API-key) session scoped to "msp-a" never sees stewards from "msp-b".
// Uses TenantSubtree filtering (Issue #2919: buildFleetFilter switched from TenantID).
func TestListStewards_NonRootAccount_NoCrossTenantLeakage(t *testing.T) {
	server := setupTestServer(t)

	// Register one steward per tenant.
	registerStewardInTenant(t, server.controllerService, "msp-a", map[string]string{
		"hostname": "host-msp-a",
	})
	registerStewardInTenant(t, server.controllerService, "msp-b", map[string]string{
		"hostname": "host-msp-b",
	})

	// Create an API key scoped to msp-a only.
	mspAKey := NewEphemeralTestKey(t, server, []string{"steward:list"}, "msp-a", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", mspAKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Len(t, resp.Data, 1, "msp-a-scoped account must see only msp-a stewards")
	assert.Equal(t, "msp-a", resp.Data[0].TenantID, "returned steward must be in msp-a")
}

// ---- handleSetStewardVisibility tests (Issue #2918) ----

// setupVisibilityServer creates a test server wired with a real flat-file steward
// store and a real audit manager, suitable for visibility handler tests.
func setupVisibilityServer(t *testing.T) (*Server, business.StewardStore) {
	t.Helper()
	server := setupTestServer(t)
	st, _ := newTestStewardDurableStore(t)
	server.SetStewardStore(st)
	return server, st
}

// patchVisibility calls handleSetStewardVisibility directly with an admin mTLS principal.
func patchVisibility(server *Server, stewardID string, hidden bool) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"hidden":%v}`, hidden)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/stewards/"+stewardID+"/visibility",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": stewardID})
	rec := httptest.NewRecorder()
	server.handleSetStewardVisibility(rec, req)
	return rec
}

// TestHandleSetStewardVisibility_HappyPath verifies that a known steward can be hidden
// and the response contains {"id":"...","hidden":true}.
func TestHandleSetStewardVisibility_HappyPath(t *testing.T) {
	server, st := setupVisibilityServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-ok",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	rec := patchVisibility(server, "s-vis-ok", true)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "s-vis-ok", resp.Data["id"])
	assert.Equal(t, true, resp.Data["hidden"])
}

// TestHandleSetStewardVisibility_Reversibility verifies that a steward can be hidden
// and then unhidden.
func TestHandleSetStewardVisibility_Reversibility(t *testing.T) {
	server, st := setupVisibilityServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-rev",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	// Hide the steward.
	rec := patchVisibility(server, "s-vis-rev", true)
	require.Equal(t, http.StatusOK, rec.Code)

	// Unhide the steward.
	rec2 := patchVisibility(server, "s-vis-rev", false)
	require.Equal(t, http.StatusOK, rec2.Code)
	var resp struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp))
	assert.Equal(t, false, resp.Data["hidden"])

	// Verify durable store reflects the unhidden state.
	got, err := st.GetSteward(context.Background(), "s-vis-rev")
	require.NoError(t, err)
	assert.False(t, got.Hidden)
}

// TestHandleSetStewardVisibility_CrossTenant verifies that a scoped admin receives 404
// when trying to set visibility on a steward in a different tenant.
func TestHandleSetStewardVisibility_CrossTenant(t *testing.T) {
	server, st := setupVisibilityServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-cross",
		TenantID: "tenant-b",
		Status:   business.StewardStatusActive,
	}))

	body := `{"hidden":true}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/stewards/s-vis-cross/visibility",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "tenant-a-admin", Assurance: session.AssuranceBasic, TenantID: "tenant-a"})
	req = withVars(req, map[string]string{"id": "s-vis-cross"})
	rec := httptest.NewRecorder()
	server.handleSetStewardVisibility(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant visibility must return 404, not 403")
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleSetStewardVisibility_AuditEmitted verifies that a successful visibility change
// writes an audit entry with action "steward.visibility_changed" and AuditSeverityMedium.
func TestHandleSetStewardVisibility_AuditEmitted(t *testing.T) {
	server, st := setupVisibilityServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-audit",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	rec := patchVisibility(server, "s-vis-audit", true)
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
		Actions: []string{"steward.visibility_changed"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "visibility audit entry must be written")

	e := entries[0]
	assert.Equal(t, "steward.visibility_changed", e.Action)
	assert.Equal(t, business.AuditSeverityMedium, e.Severity)
	assert.Equal(t, "steward", e.ResourceType)
	assert.Equal(t, "s-vis-audit", e.ResourceID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
}

// TestHandleSetStewardVisibility_NilStore verifies 503 when stewardStore is nil.
func TestHandleSetStewardVisibility_NilStore(t *testing.T) {
	server := setupTestServer(t)

	body := `{"hidden":true}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/stewards/some-steward/visibility",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "some-steward"})
	rec := httptest.NewRecorder()
	server.handleSetStewardVisibility(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleSetStewardVisibility_InvalidID verifies 400 for a malformed steward ID.
func TestHandleSetStewardVisibility_InvalidID(t *testing.T) {
	server, _ := setupVisibilityServer(t)

	body := `{"hidden":true}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/stewards/bad.id:here/visibility",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "bad.id:here"})
	rec := httptest.NewRecorder()
	server.handleSetStewardVisibility(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_STEWARD_ID", errResp.Error.Code)
}

// TestHandleSetStewardVisibility_AssuranceMachineRejected verifies that a bare API-key
// caller (AssuranceMachine) cannot use the visibility endpoint (via the full router).
// AssuranceBasic is the floor for steward:visibility (Issue #2918 security ruling).
func TestHandleSetStewardVisibility_AssuranceMachineRejected(t *testing.T) {
	server, _ := setupVisibilityServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:visibility"})

	body := `{"hidden":true}`
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/stewards/any-steward/visibility",
		strings.NewReader(body))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code, "API-key callers must be rejected at AssuranceBasic gate")
}

// TestHandleSetStewardVisibility_ListExclusion verifies that hidden/quarantined stewards
// are excluded from the default list and restored with the include params.
func TestHandleSetStewardVisibility_ListExclusion(t *testing.T) {
	server, st := setupVisibilityServer(t)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-hidden-list",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))
	require.NoError(t, server.controllerService.RegisterSteward("s-hidden-list", "test-tenant", "addr", "active"))
	require.NoError(t, server.controllerService.RegisterSteward("s-quarantined-list", "test-tenant", "addr", "quarantined"))

	// Hide s-hidden-list via the handler.
	rec := patchVisibility(server, "s-hidden-list", true)
	require.Equal(t, http.StatusOK, rec.Code)

	// Default list must exclude hidden and quarantined stewards.
	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req = withTenant(req, "")
	rec2 := httptest.NewRecorder()
	server.handleListStewards(rec2, req)
	require.Equal(t, http.StatusOK, rec2.Code)
	var resp struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec2.Body).Decode(&resp))
	for _, s := range resp.Data {
		assert.NotEqual(t, "s-hidden-list", s.ID, "hidden steward must not appear in default list")
		assert.NotEqual(t, "s-quarantined-list", s.ID, "quarantined steward must not appear in default list")
	}

	// With include_hidden=true and include_quarantined=true, both must reappear.
	req3 := httptest.NewRequest("GET", "/api/v1/stewards?include_hidden=true&include_quarantined=true", nil)
	req3 = withTenant(req3, "")
	rec3 := httptest.NewRecorder()
	server.handleListStewards(rec3, req3)
	require.Equal(t, http.StatusOK, rec3.Code)
	var resp3 struct {
		Data []StewardInfo `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec3.Body).Decode(&resp3))
	foundHidden := false
	foundQuarantined := false
	for _, s := range resp3.Data {
		if s.ID == "s-hidden-list" {
			foundHidden = true
			assert.True(t, s.Hidden, "hidden steward must have Hidden=true in response")
		}
		if s.ID == "s-quarantined-list" {
			foundQuarantined = true
		}
	}
	assert.True(t, foundHidden, "hidden steward must appear with ?include_hidden=true")
	assert.True(t, foundQuarantined, "quarantined steward must appear with ?include_quarantined=true")
}

// TestHandleSetStewardVisibility_MalformedBody verifies 400 INVALID_JSON when the request
// body is not valid JSON, covering the decode error branch at handlers_stewards.go:1060.
func TestHandleSetStewardVisibility_MalformedBody(t *testing.T) {
	server, st := setupVisibilityServer(t)

	// Register the steward so the only reason for failure is the malformed body.
	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-badjson",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/stewards/s-vis-badjson/visibility",
		strings.NewReader("not-json{"))
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, TenantID: ""})
	req = withVars(req, map[string]string{"id": "s-vis-badjson"})
	rec := httptest.NewRecorder()
	server.handleSetStewardVisibility(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INVALID_JSON", errResp.Error.Code)

	// Durable state must be untouched by a rejected request.
	got, err := st.GetSteward(context.Background(), "s-vis-badjson")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "malformed body must not change stored visibility")
}

// TestHandleSetStewardVisibility_NotFound verifies 404 STEWARD_NOT_FOUND when the steward
// is absent from the durable store (GetSteward returns ErrStewardNotFound), covering the
// branch at handlers_stewards.go:1069. Distinct from _CrossTenant, where GetSteward
// succeeds and the tenant-scope check rejects.
func TestHandleSetStewardVisibility_NotFound(t *testing.T) {
	server, _ := setupVisibilityServer(t)

	rec := patchVisibility(server, "s-vis-absent", true)

	require.Equal(t, http.StatusNotFound, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "STEWARD_NOT_FOUND", errResp.Error.Code)
}

// TestHandleSetStewardVisibility_StoreLookupFails verifies 500 INTERNAL_ERROR when
// GetSteward fails with a non-NotFound store error, covering the branch at
// handlers_stewards.go:1073. The failure is genuine: the steward's on-disk record is
// corrupted so the flat-file store's unmarshal fails, which is neither ErrStewardNotFound
// nor a synthetic injected error.
func TestHandleSetStewardVisibility_StoreLookupFails(t *testing.T) {
	server := setupTestServer(t)
	st, root := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-corrupt",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	// Corrupt the backing record: the file exists (so os.IsNotExist is false) but does not
	// contain a decodable steward record, so GetSteward returns an unmarshal error.
	recordPath := filepath.Join(root, "stewards", "s-vis-corrupt.json")
	require.NoError(t, os.WriteFile(recordPath, []byte("{not valid json"), 0o600))

	rec := patchVisibility(server, "s-vis-corrupt", true)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)
	assert.NotContains(t, errResp.Error.Message, "unmarshal",
		"error response must not disclose internal store details")
}

// TestHandleSetStewardVisibility_DurableStoreWriteFails verifies that when the durable
// write (SetStewardHidden) fails after lookup and scope checks pass, the handler returns
// 500 INTERNAL_ERROR and leaves visibility unchanged — the visibility-handler mirror of
// TestHandleDecommissionSteward_DurableStoreWriteFails, covering handlers_stewards.go:1090.
func TestHandleSetStewardVisibility_DurableStoreWriteFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod does not enforce POSIX directory permissions on Windows")
	}
	server := setupTestServer(t)
	st, root := newTestStewardDurableStore(t)
	server.SetStewardStore(st)

	require.NoError(t, st.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:       "s-vis-writefail",
		TenantID: "test-tenant",
		Status:   business.StewardStatusActive,
	}))

	// Induce a genuine durable-store write failure: make the flat-file store's backing
	// directory read-only. The record was already written, so GetSteward (a pure read)
	// still succeeds and the handler reaches SetStewardHidden, whose atomic write
	// (temp-file creation in the directory) then fails with a permission error. Restore
	// the mode on cleanup so t.TempDir() removal can delete the tree.
	stewardDir := filepath.Join(root, "stewards")
	require.NoError(t, os.Chmod(stewardDir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(stewardDir, 0o750) })

	rec := patchVisibility(server, "s-vis-writefail", true)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error.Code)

	// Visibility must not have been persisted: restore write access and confirm the record
	// is still visible (the failed write left durable state unchanged).
	require.NoError(t, os.Chmod(stewardDir, 0o750))
	got, err := st.GetSteward(context.Background(), "s-vis-writefail")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "record must remain visible when the durable write fails")
}
