// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package api — handler-level tests for the tenant deletion pipeline
// (ADR-027 Decisions 3-4, Issue #3182).
//
// Covers all four handlers introduced in handlers_tenants.go —
// handleRequestTenantDeletion, handleCancelTenantDeletion, handleGetPendingDeletion
// and handleApproveTenantDeletion — across their success, not-found,
// missing-permission, scope-guard and error-mapping paths, following the pattern
// established by handlers_tenants_test.go for suspend/restore.
//
// The security-relevant paths pinned here are: 403 SAME_APPROVER (the dual-control
// invariant), 404-not-403 for cross-tenant access (the tenant enumeration guard),
// 409 SUBTREE_NOT_SUSPENDED naming the unsuspended tenant, 409 HOLD_NOT_ELAPSED and
// 409 MEMBERSHIP_CHANGED.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// mtlsAdminPrincipalID is the principal ID makeAdminRequest authenticates as —
// the admin test certificate's CommonName. Tests that need the requester and the
// approver to be the same principal over the router rely on this.
const mtlsAdminPrincipalID = "test-admin"

// setupTenantDeletionServer builds a test server exactly like setupTestServer but also
// returns the underlying TenantStore. Direct store access is required because the
// manager deliberately refuses to create a tenant under a suspended parent, so a
// suspended root with an unsuspended descendant — the state that must produce
// 409 SUBTREE_NOT_SUSPENDED — is not reachable through the public API.
func setupTenantDeletionServer(t *testing.T) (*Server, business.TenantStore) {
	t.Helper()
	setTestSecretsEnv(t)
	withDefaultEmbeddedSPA(t)

	cfg := config.DefaultConfig()
	cfg.ExternalURL = "https://localhost:8080"
	cfg.Certificate.EnableCertManagement = false

	logger := logging.NewNoopLogger()
	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(t, rbacManager.Initialize(context.Background()))
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := storageManager.GetTenantStore()
	tenantManager := tenant.NewManager(tenant.NewStorageAdapter(tenantStore), rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	return server, tenantStore
}

// setMinimalHold configures the shortest hold period the config knob accepts, so a
// deletion requested through the API becomes eligible for approval almost at once. The
// value is non-zero on purpose: GetDeleteHoldPeriod treats zero as "unset" and
// substitutes the 30-day default. This exercises the real config knob rather than
// seeding storage behind the handler.
//
// "Almost at once" is not "at once". Call waitUntilHoldElapsed after requesting the
// deletion and before approving it.
func setMinimalHold(t *testing.T, s *Server, requireDualControl bool) {
	t.Helper()
	s.cfg.TenantAdmin = &config.TenantAdminConfig{
		DeleteHoldPeriod:          config.Duration(time.Nanosecond),
		DeleteRequiresDualControl: &requireDualControl,
	}
}

// waitUntilHoldElapsed blocks until the wall clock has passed the pending deletion's
// EligibleAt, so the approval issued next reaches the dual-control and membership checks
// instead of being refused with HOLD_NOT_ELAPSED.
//
// A 1ns hold is far below the resolution of the system wall clock on Windows (~0.5-15ms),
// so the time.Now() taken when the deletion is approved routinely returns the very same
// instant as the one taken when it was requested. EligibleAt = RequestedAt+1ns is then
// still in the future and the store refuses the approval. Waiting for the clock to tick
// makes these tests platform-independent without weakening the hold semantics they cover.
// On Linux the loop exits on its first check.
func waitUntilHoldElapsed(t *testing.T, s *Server, tenantID string) {
	t.Helper()
	pending, err := s.tenantManager.GetPendingDeletion(context.Background(), tenantID)
	require.NoError(t, err, "a pending deletion must exist before waiting on its hold")

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(pending.EligibleAt) {
		if time.Now().After(deadline) {
			t.Fatalf("wall clock did not advance past EligibleAt %s within 5s", pending.EligibleAt)
		}
		time.Sleep(time.Millisecond)
	}
}

// createSuspendedTenant creates a tenant and suspends it so it is a legal deletion target.
func createSuspendedTenant(t *testing.T, s *Server, id string) {
	t.Helper()
	ctx := context.Background()
	_, err := s.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: id})
	require.NoError(t, err)
	_, err = s.tenantManager.SuspendTenant(ctx, id)
	require.NoError(t, err)
}

// deletionRequest builds a request against a deletion route with {id} bound and the
// given principal installed in the context, so the handler can be called directly.
func deletionRequest(method, path, targetID string, principal *Principal) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	ctx := req.Context()
	if principal != nil {
		ctx = context.WithValue(ctx, ctxkeys.TenantID, principal.TenantID)
		ctx = context.WithValue(ctx, principalContextKey, principal)
	}
	return req.WithContext(ctx)
}

// requestDeletionAs drives handleRequestTenantDeletion directly as principal.
func requestDeletionAs(s *Server, principal *Principal, targetID string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handleRequestTenantDeletion(rec, deletionRequest(
		http.MethodPost, "/api/v1/tenants/"+targetID+"/delete", targetID, principal))
	return rec
}

// approveDeletionAs drives handleApproveTenantDeletion directly as principal.
func approveDeletionAs(s *Server, principal *Principal, targetID string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	s.handleApproveTenantDeletion(rec, deletionRequest(
		http.MethodPost, "/api/v1/tenants/"+targetID+"/delete/approve", targetID, principal))
	return rec
}

// decodeErrorCode reads the machine-readable error code from an error response body.
func decodeErrorCode(t *testing.T, rec *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	return errResp
}

// decodeAPIData decodes a success response body and returns its Data object.
func decodeAPIData(t *testing.T, rec *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be a JSON object")
	return data
}

// ── Request deletion ─────────────────────────────────────────────────────────

func TestHandleRequestTenantDeletion_Success202(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "del-req-root")

	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-req-root/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())

	data := decodeAPIData(t, w)
	assert.Equal(t, "del-req-root", data["subtree_root_id"])
	assert.Equal(t, string(business.DeletionStateHold), data["state"])
	assert.Equal(t, mtlsAdminPrincipalID, data["requested_by"],
		"requested_by must record the acting principal for the later dual-control check")
	assert.Contains(t, data["pinned_member_ids"], "del-req-root",
		"the pinned member set must include the subtree root")

	// The pipeline entry must be readable back through the manager.
	pending, err := server.tenantManager.GetPendingDeletion(context.Background(), "del-req-root")
	require.NoError(t, err)
	assert.Equal(t, mtlsAdminPrincipalID, pending.RequestedBy)
}

// TestHandleRequestTenantDeletion_SubtreeNotSuspended409 pins the 409 that guards the
// pipeline entry condition, and — the part that matters operationally — that the
// unsuspended tenant is named in the response body so the operator knows what to fix.
func TestHandleRequestTenantDeletion_SubtreeNotSuspended409(t *testing.T) {
	server, store := setupTenantDeletionServer(t)
	ctx := context.Background()

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "del-ns-root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "del-ns-child", ParentID: "del-ns-root"})
	require.NoError(t, err)

	// Suspend only the root, leaving the child active. SuspendTenant cascades, and
	// CreateTenant refuses a suspended parent, so this state is only reachable
	// through the store.
	root, err := store.GetTenant(ctx, "del-ns-root")
	require.NoError(t, err)
	root.Status = business.TenantStatusSuspended
	root.DirectlySuspended = true
	require.NoError(t, store.UpdateTenant(ctx, root))

	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-ns-root/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
	errResp := decodeErrorCode(t, w)
	assert.Equal(t, "SUBTREE_NOT_SUSPENDED", errResp.Error.Code)
	assert.Contains(t, errResp.Error.Message, "del-ns-child",
		"the response must name the unsuspended descendant that blocked the request")

	// No pipeline entry may be created by a rejected request.
	_, err = server.tenantManager.GetPendingDeletion(ctx, "del-ns-root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

func TestHandleRequestTenantDeletion_NotFound404(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)

	req := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/no-such-tenant/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	assert.Equal(t, "TENANT_NOT_FOUND", decodeErrorCode(t, w).Error.Code)
}

func TestHandleRequestTenantDeletion_Duplicate409(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "del-dup-root")

	first := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-dup-root/delete", nil)
	w1 := httptest.NewRecorder()
	server.router.ServeHTTP(w1, first)
	require.Equal(t, http.StatusAccepted, w1.Code, w1.Body.String())

	second := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-dup-root/delete", nil)
	w2 := httptest.NewRecorder()
	server.router.ServeHTTP(w2, second)

	require.Equal(t, http.StatusConflict, w2.Code, w2.Body.String())
	assert.Equal(t, "PENDING_DELETION_EXISTS", decodeErrorCode(t, w2).Error.Code)
}

// TestHandleRequestTenantDeletion_MissingTenantID400 pins the empty-ID guard. The route
// pattern cannot produce an empty {id}, so the handler is called directly.
func TestHandleRequestTenantDeletion_MissingTenantID400(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)

	rec := requestDeletionAs(server, &Principal{ID: "admin"}, "")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "MISSING_TENANT_ID", decodeErrorCode(t, rec).Error.Code)
}

func TestHandleRequestTenantDeletion_MissingPermission403(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:read"})
	createSuspendedTenant(t, server, "del-perm-root")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/del-perm-root/delete", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"tenant:read must not authorize a deletion request")

	// The refusal must not have started a hold timer.
	_, err := server.tenantManager.GetPendingDeletion(context.Background(), "del-perm-root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

// ── Read pending deletion ────────────────────────────────────────────────────

func TestHandleGetPendingDeletion_Success200(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "del-get-root")

	post := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-get-root/delete", nil)
	wPost := httptest.NewRecorder()
	server.router.ServeHTTP(wPost, post)
	require.Equal(t, http.StatusAccepted, wPost.Code, wPost.Body.String())

	get := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants/del-get-root/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, get)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	data := decodeAPIData(t, w)
	assert.Equal(t, "del-get-root", data["subtree_root_id"])
	assert.Equal(t, string(business.DeletionStateHold), data["state"])
	assert.NotEmpty(t, data["eligible_at"], "the caller must be able to see when the hold expires")
}

func TestHandleGetPendingDeletion_NoPending404(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "del-get-none")

	req := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants/del-get-none/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	assert.Equal(t, "PENDING_DELETION_NOT_FOUND", decodeErrorCode(t, w).Error.Code,
		"an existing tenant with no pending deletion must be distinguishable from a missing tenant")
}

func TestHandleGetPendingDeletion_TenantNotFound404(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)

	req := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants/no-such-tenant/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	assert.Equal(t, "TENANT_NOT_FOUND", decodeErrorCode(t, w).Error.Code)
}

// ── Cancel deletion ──────────────────────────────────────────────────────────

func TestHandleCancelTenantDeletion_Success200(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	ctx := context.Background()
	createSuspendedTenant(t, server, "del-cancel-root")

	post := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-cancel-root/delete", nil)
	wPost := httptest.NewRecorder()
	server.router.ServeHTTP(wPost, post)
	require.Equal(t, http.StatusAccepted, wPost.Code, wPost.Body.String())

	del := makeAdminRequest(t, http.MethodDelete, "/api/v1/tenants/del-cancel-root/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, del)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	data := decodeAPIData(t, w)
	assert.Equal(t, "del-cancel-root", data["id"])
	assert.Equal(t, string(business.TenantStatusSuspended), data["status"],
		"cancel must return the subtree to plain Suspended, never Active")

	// Pipeline entry gone; the tenant itself survives.
	_, err := server.tenantManager.GetPendingDeletion(ctx, "del-cancel-root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
	td, err := server.tenantManager.GetTenant(ctx, "del-cancel-root")
	require.NoError(t, err)
	assert.Equal(t, business.TenantStatusSuspended, td.Status)
}

func TestHandleCancelTenantDeletion_NoPending404(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "del-cancel-none")

	req := makeAdminRequest(t, http.MethodDelete, "/api/v1/tenants/del-cancel-none/delete", nil)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code, w.Body.String())
	assert.Equal(t, "PENDING_DELETION_NOT_FOUND", decodeErrorCode(t, w).Error.Code)
}

func TestHandleCancelTenantDeletion_MissingPermission403(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:read"})
	createSuspendedTenant(t, server, "del-cancel-perm")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/tenants/del-cancel-perm/delete", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ── Approve deletion ─────────────────────────────────────────────────────────

// TestHandleApproveTenantDeletion_HoldNotElapsed409 uses the default 30-day hold, so
// an approval issued immediately after the request must be refused.
func TestHandleApproveTenantDeletion_HoldNotElapsed409(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	ctx := context.Background()
	createSuspendedTenant(t, server, "del-hold-root")

	require.Equal(t, http.StatusAccepted,
		requestDeletionAs(server, &Principal{ID: "alice", TenantID: "del-hold-root"}, "del-hold-root").Code)

	rec := approveDeletionAs(server, &Principal{ID: "bob", TenantID: "del-hold-root"}, "del-hold-root")
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "HOLD_NOT_ELAPSED", decodeErrorCode(t, rec).Error.Code)

	// The tenant must survive a refused approval.
	_, err := server.tenantManager.GetTenant(ctx, "del-hold-root")
	require.NoError(t, err)
}

// TestHandleApproveTenantDeletion_SameApprover403 pins the dual-control invariant:
// the principal who requested a deletion may never approve their own request. This is
// the single most security-relevant path in the pipeline — a compromised admin account
// must not be able to destroy a tenant subtree without a second operator.
func TestHandleApproveTenantDeletion_SameApprover403(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	ctx := context.Background()
	setMinimalHold(t, server, true)
	createSuspendedTenant(t, server, "del-dual-root")

	alice := &Principal{ID: "alice", TenantID: "del-dual-root"}
	require.Equal(t, http.StatusAccepted, requestDeletionAs(server, alice, "del-dual-root").Code)
	waitUntilHoldElapsed(t, server, "del-dual-root")

	rec := approveDeletionAs(server, alice, "del-dual-root")
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, "SAME_APPROVER", decodeErrorCode(t, rec).Error.Code)

	// Nothing may be deleted, and the pipeline entry must survive so a second
	// operator can still approve it.
	_, err := server.tenantManager.GetTenant(ctx, "del-dual-root")
	require.NoError(t, err, "a same-approver refusal must not delete the tenant")
	_, err = server.tenantManager.GetPendingDeletion(ctx, "del-dual-root")
	require.NoError(t, err, "a same-approver refusal must leave the pending request intact")
}

// TestHandleApproveTenantDeletion_SecondApproverSucceeds is the positive half of the
// dual-control pair: without it, a handler that refused every approval would pass the
// SAME_APPROVER test for the wrong reason.
func TestHandleApproveTenantDeletion_SecondApproverSucceeds(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	ctx := context.Background()
	setMinimalHold(t, server, true)

	// A two-tenant subtree proves the whole subtree is removed, not just the root.
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "del-ok-root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "del-ok-child", ParentID: "del-ok-root"})
	require.NoError(t, err)
	_, err = server.tenantManager.SuspendTenant(ctx, "del-ok-root")
	require.NoError(t, err)

	require.Equal(t, http.StatusAccepted,
		requestDeletionAs(server, &Principal{ID: "alice", TenantID: "del-ok-root"}, "del-ok-root").Code)
	waitUntilHoldElapsed(t, server, "del-ok-root")

	rec := approveDeletionAs(server, &Principal{ID: "bob", TenantID: "del-ok-root"}, "del-ok-root")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	data := decodeAPIData(t, rec)
	assert.Equal(t, "del-ok-root", data["id"])
	assert.ElementsMatch(t, []interface{}{"del-ok-root", "del-ok-child"}, data["deleted"])

	_, err = server.tenantManager.GetTenant(ctx, "del-ok-root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	_, err = server.tenantManager.GetTenant(ctx, "del-ok-child")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
	_, err = server.tenantManager.GetPendingDeletion(ctx, "del-ok-root")
	assert.ErrorIs(t, err, business.ErrPendingDeletionNotFound)
}

// TestHandleApproveTenantDeletion_MembershipChanged409 covers the time-of-check /
// time-of-use guard: a tenant added to the subtree after the request was pinned must
// invalidate the approval rather than being silently swept into the deletion.
func TestHandleApproveTenantDeletion_MembershipChanged409(t *testing.T) {
	server, store := setupTenantDeletionServer(t)
	ctx := context.Background()
	setMinimalHold(t, server, true)
	createSuspendedTenant(t, server, "del-drift-root")

	require.Equal(t, http.StatusAccepted,
		requestDeletionAs(server, &Principal{ID: "alice", TenantID: "del-drift-root"}, "del-drift-root").Code)
	waitUntilHoldElapsed(t, server, "del-drift-root")

	// Insert a child directly: the manager refuses to create one under a parent with a
	// pending deletion, which is exactly the defence this guard backstops.
	require.NoError(t, store.CreateTenant(ctx, &business.TenantData{
		ID:        "del-drift-child",
		Name:      "del-drift-child",
		ParentID:  "del-drift-root",
		Status:    business.TenantStatusSuspended,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	rec := approveDeletionAs(server, &Principal{ID: "bob", TenantID: "del-drift-root"}, "del-drift-root")
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Equal(t, "MEMBERSHIP_CHANGED", decodeErrorCode(t, rec).Error.Code)

	// Neither tenant may be deleted by a refused approval.
	_, err := server.tenantManager.GetTenant(ctx, "del-drift-root")
	require.NoError(t, err)
	_, err = server.tenantManager.GetTenant(ctx, "del-drift-child")
	require.NoError(t, err)
}

func TestHandleApproveTenantDeletion_NoPending404(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	createSuspendedTenant(t, server, "del-approve-none")

	rec := approveDeletionAs(server, &Principal{ID: "bob", TenantID: "del-approve-none"}, "del-approve-none")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Equal(t, "PENDING_DELETION_NOT_FOUND", decodeErrorCode(t, rec).Error.Code)
}

func TestHandleApproveTenantDeletion_TenantNotFound404(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)

	rec := approveDeletionAs(server, &Principal{ID: "bob"}, "no-such-tenant")
	require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
	assert.Equal(t, "TENANT_NOT_FOUND", decodeErrorCode(t, rec).Error.Code)
}

func TestHandleApproveTenantDeletion_MissingTenantID400(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)

	rec := approveDeletionAs(server, &Principal{ID: "bob"}, "")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Equal(t, "MISSING_TENANT_ID", decodeErrorCode(t, rec).Error.Code)
}

// TestHandleApproveTenantDeletion_RouterRequiresPresenceToken drives the approval over
// the real router. tenant:approve-delete carries RequireUserPresence, so the route must
// refuse an mTLS admin with no presence token and accept the same caller once a fresh
// single-use token is supplied. Dual control is disabled here so the router-level
// caller (always the admin cert's principal) can be both requester and approver.
func TestHandleApproveTenantDeletion_RouterRequiresPresenceToken(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	ctx := context.Background()
	setMinimalHold(t, server, false)
	createSuspendedTenant(t, server, "del-presence-root")

	post := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-presence-root/delete", nil)
	wPost := httptest.NewRecorder()
	server.router.ServeHTTP(wPost, post)
	require.Equal(t, http.StatusAccepted, wPost.Code, wPost.Body.String())
	waitUntilHoldElapsed(t, server, "del-presence-root")

	// Without a presence token the route must challenge, not delete.
	noPresence := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-presence-root/delete/approve", nil)
	wNo := httptest.NewRecorder()
	server.router.ServeHTTP(wNo, noPresence)
	require.Equal(t, http.StatusUnauthorized, wNo.Code, wNo.Body.String())
	assert.Contains(t, wNo.Header().Get("WWW-Authenticate"), `presence="required"`)
	_, err := server.tenantManager.GetTenant(ctx, "del-presence-root")
	require.NoError(t, err, "a challenged approval must not delete the tenant")

	// With a fresh presence token bound to the same principal the approval proceeds.
	withPresence := makeAdminRequest(t, http.MethodPost, "/api/v1/tenants/del-presence-root/delete/approve", nil)
	withPresence.Header.Set(presenceTokenHeader, mintPresenceToken(t, server, mtlsAdminPrincipalID))
	wYes := httptest.NewRecorder()
	server.router.ServeHTTP(wYes, withPresence)
	require.Equal(t, http.StatusOK, wYes.Code, wYes.Body.String())

	_, err = server.tenantManager.GetTenant(ctx, "del-presence-root")
	assert.ErrorIs(t, err, business.ErrTenantDoesNotExist)
}

func TestHandleApproveTenantDeletion_MissingPermission403(t *testing.T) {
	server, _ := setupTenantDeletionServer(t)
	apiKey := NewTestKey(t, server, []string{"tenant:read", "tenant:delete"})
	createSuspendedTenant(t, server, "del-approve-perm")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/del-approve-perm/delete/approve", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code,
		"tenant:delete must not authorize the dual-control approval step")
}

// ── Cross-tenant enumeration guard ───────────────────────────────────────────

// TestTenantDeletionHandlers_CrossTenantReturns404 pins the enumeration guard on all
// four handlers: a caller outside the target's subtree must receive 404 TENANT_NOT_FOUND,
// never 403. A 403 would confirm the tenant exists and turn these routes into a tenant
// enumeration oracle. The target has a live pending deletion so every handler reaches
// its scope guard with real state behind it, and none of them may mutate that state.
func TestTenantDeletionHandlers_CrossTenantReturns404(t *testing.T) {
	handlers := []struct {
		name   string
		method string
		suffix string
		invoke func(s *Server, w http.ResponseWriter, r *http.Request)
	}{
		{"request", http.MethodPost, "/delete", (*Server).handleRequestTenantDeletion},
		{"cancel", http.MethodDelete, "/delete", (*Server).handleCancelTenantDeletion},
		{"get", http.MethodGet, "/delete", (*Server).handleGetPendingDeletion},
		{"approve", http.MethodPost, "/delete/approve", (*Server).handleApproveTenantDeletion},
	}

	for _, tc := range handlers {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := setupTenantDeletionServer(t)
			ctx := context.Background()
			setMinimalHold(t, server, true)
			createSuspendedTenant(t, server, "del-x-victim")

			// The outsider's own tenant is real, so the guard is exercised on the
			// "not an ancestor" branch rather than on the fail-closed path taken when
			// the ancestry lookup itself errors.
			_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "del-x-outsider"})
			require.NoError(t, err)

			require.Equal(t, http.StatusAccepted,
				requestDeletionAs(server, &Principal{ID: "alice", TenantID: "del-x-victim"}, "del-x-victim").Code)

			outsider := &Principal{ID: "mallory", TenantID: "del-x-outsider"}
			rec := httptest.NewRecorder()
			tc.invoke(server, rec, deletionRequest(
				tc.method, "/api/v1/tenants/del-x-victim"+tc.suffix, "del-x-victim", outsider))

			require.Equal(t, http.StatusNotFound, rec.Code, rec.Body.String())
			assert.Equal(t, "TENANT_NOT_FOUND", decodeErrorCode(t, rec).Error.Code,
				"a cross-tenant caller must not be able to distinguish an existing tenant from a missing one")

			// The refused call must leave both the tenant and its pipeline entry untouched.
			_, err = server.tenantManager.GetTenant(ctx, "del-x-victim")
			require.NoError(t, err)
			_, err = server.tenantManager.GetPendingDeletion(ctx, "del-x-victim")
			require.NoError(t, err)
		})
	}
}
