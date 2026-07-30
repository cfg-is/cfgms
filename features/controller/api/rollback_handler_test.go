// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configgit "github.com/cfgis/cfgms/features/config/git"
	gitstorage "github.com/cfgis/cfgms/features/config/git/storage"
	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// rollbackStack holds the controller's real rollback components for handler tests.
//
// Every component is the production implementation, wired exactly as
// initializeRollbackManager does in features/controller/server/server.go:
// rollback.DefaultRollbackManager over rollback.DefaultRollbackValidator, a real
// features/config/git DefaultGitManager backed by the go-git LocalRepositoryStore, the
// durable rollback.StorageRollbackStore over a real flatfile+sqlite storage manager in
// t.TempDir(), a real features/rbac Manager over the same storage, and the shipped
// rollback.DefaultRollbackNotifier. No CFGMS behaviour is substituted or re-implemented.
type rollbackStack struct {
	manager rollback.RollbackManager
	store   rollback.RollbackStore
}

// noOpModuleRegistry is the module registry the controller wires into the rollback
// validator (server.go noOpModuleRegistry): CFGMS resolves module versions through the
// module distribution service, and the rollback validator runs against defaults until a
// registry is configured. Reproduced here so handler tests wire the validator the way
// production wires it.
type noOpModuleRegistry struct{}

func (r *noOpModuleRegistry) GetModuleVersion(_ context.Context, _ string) (string, error) {
	return "latest", nil
}

func (r *noOpModuleRegistry) GetModuleDependencies(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}

func (r *noOpModuleRegistry) IsModuleCompatible(_ context.Context, _, _ string) (bool, error) {
	return true, nil
}

// newRollbackStack builds the production rollback manager over real storage in t.TempDir().
func newRollbackStack(t *testing.T) *rollbackStack {
	t.Helper()

	dir := t.TempDir()
	logger := logging.NewNoopLogger()

	storageManager, err := interfaces.CreateOSSStorageManager(
		filepath.Join(dir, "flatfile"),
		filepath.Join(dir, "cfgms.db"),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = storageManager.Close() })

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(ctx)
	})

	store := rollback.NewStorageRollbackStore(storageManager.GetConfigStore())
	validator := rollback.NewRollbackValidator(&noOpModuleRegistry{}, nil, rbacManager)
	gitManager := configgit.NewGitManager(nil, gitstorage.NewLocalRepositoryStore("", ""), configgit.GitManagerConfig{
		DefaultBranch: "main",
		AutoSync:      false,
		CacheDir:      filepath.Join(dir, "git-cache"),
	}, logger)

	return &rollbackStack{
		manager: rollback.NewRollbackManager(gitManager, validator, store, rollback.NewDefaultRollbackNotifier(logger)),
		store:   store,
	}
}

// seedLiveOperation records a live (in-progress) rollback operation for a target in the
// real rollback store and returns its ID.
//
// A target with a live operation makes the production manager's own concurrency guard
// (rollback.DefaultRollbackManager.checkNoRollbackInProgress) the first thing an admitted
// request hits, so handler tests can tell "the cross-tenant guard admitted the request and
// the real rollback manager answered it" (409, from CFGMS's own concurrency logic) apart
// from "the cross-tenant guard rejected the request before the manager saw it"
// (400 CROSS_TENANT_ROLLBACK) without substituting the manager.
func (s *rollbackStack) seedLiveOperation(t *testing.T, targetType rollback.TargetType, targetID string) string {
	t.Helper()

	id := uuid.NewString()
	require.NoError(t, s.store.SaveOperation(context.Background(), &rollback.RollbackOperation{
		ID:          id,
		Status:      rollback.RollbackStatusInProgress,
		InitiatedBy: "ops@example.com",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   targetType,
			TargetID:     targetID,
			RollbackType: rollback.RollbackTypeFull,
			RollbackTo:   "seed0000000000",
			Reason:       "earlier rollback still running",
		},
	}))
	return id
}

// seedOperation records an operation with the given status in the real rollback store.
func (s *rollbackStack) seedOperation(t *testing.T, targetType rollback.TargetType, targetID string, status rollback.RollbackStatus) string {
	t.Helper()

	id := uuid.NewString()
	require.NoError(t, s.store.SaveOperation(context.Background(), &rollback.RollbackOperation{
		ID:          id,
		Status:      status,
		InitiatedBy: "ops@example.com",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   targetType,
			TargetID:     targetID,
			RollbackType: rollback.RollbackTypeFull,
			RollbackTo:   "seed0000000000",
			Reason:       "revert bad config",
		},
	}))
	return id
}

// operationsFor reads a target's rollback operations back through the production manager.
func (s *rollbackStack) operationsFor(t *testing.T, targetType rollback.TargetType, targetID string) []rollback.RollbackOperation {
	t.Helper()

	ops, err := s.manager.ListRollbackHistory(context.Background(), targetType, targetID, 0)
	require.NoError(t, err)
	return ops
}

// requireGuardRejected asserts the handler's cross-tenant guard rejected the request
// before the rollback manager was called: the seeded live operation must still be the only
// operation on record for the target.
func (s *rollbackStack) requireGuardRejected(t *testing.T, rec *httptest.ResponseRecorder, targetType rollback.TargetType, targetID string) {
	t.Helper()

	require.Equal(t, http.StatusBadRequest, rec.Code, "body: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])

	ops := s.operationsFor(t, targetType, targetID)
	require.Len(t, ops, 1, "no rollback may be initiated after a cross-tenant rejection")
	assert.Equal(t, rollback.RollbackStatusInProgress, ops[0].Status)
}

// requireGuardAdmitted asserts the request passed the cross-tenant guard and was answered
// by the production rollback manager's concurrency guard.
func (s *rollbackStack) requireGuardAdmitted(t *testing.T, rec *httptest.ResponseRecorder, targetType rollback.TargetType, targetID string) {
	t.Helper()

	require.Equal(t, http.StatusConflict, rec.Code, "body: %s", rec.Body.String())

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, rollback.ErrRollbackInProgress.Message, resp["error"],
		"the response must come from the rollback manager's concurrency guard")

	ops := s.operationsFor(t, targetType, targetID)
	require.Len(t, ops, 1, "a rejected concurrent rollback must not create a second operation")
}

// scopedPrincipalExtractor returns an extractor that yields a principal with the given TenantID.
func scopedPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:        "admin-api-key",
			TenantID:  tenantID,
			Assurance: session.AssuranceMachine,
		}
	}
}

func adminPrincipalExtractor() func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:          "admin-cert-cn",
			Assurance:   session.AssuranceBasic,
			GlobalScope: true,
		}
	}
}

// sessionPrincipalExtractor returns an extractor that yields a session principal with
// GlobalScope=true (as set by middleware) but a non-empty TenantID. This mirrors
// the middleware.go bug described in Issue #3143.
func sessionPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:          "web-session-" + tenantID,
			GlobalScope: true, // middleware.go bug: hardcoded true for all session principals
			TenantID:    tenantID,
			Assurance:   session.AssuranceBasic,
		}
	}
}

// newRollbackRequest builds a POST /api/v1/rollback/execute request carrying the given JSON
// body, with actor identity in the context exactly as authenticationMiddleware sets it.
func newRollbackRequest(body, actor string) *http.Request {
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	return req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, actor))
}

func TestConfigRollback_RejectsCrossTenantVersion(t *testing.T) {
	// Principal scoped to "root/msp-a" must not reach stewards in "root/msp-b".
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-b")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-b"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-b")
}

func TestConfigRollback_BlocksSiblingTenant(t *testing.T) {
	// "root/msp-ab" is a sibling, not a child of "root/msp-a" — prefix matching
	// without a segment boundary would incorrectly allow this.
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-ab")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-msp-ab","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-ab"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-ab")
}

func TestConfigRollback_AllowsSameTenant(t *testing.T) {
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-x")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-a"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-x")
}

func TestConfigRollback_AllowsChildTenant(t *testing.T) {
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-client-1")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	// "root/msp-a/client-1" is a child of "root/msp-a" — must be allowed.
	body := `{"target_type":"steward","target_id":"steward-client-1","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-a/client-1"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-client-1")
}

func TestConfigRollback_AdminPrincipalSkipsTenantCheck(t *testing.T) {
	// Full admin (Assurance >= AssuranceBasic, TenantID="") can access any tenant.
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-any")
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-any","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/any-tenant"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-any")
}

func TestConfigRollback_NoTenantPathSkipsCheck(t *testing.T) {
	// When steward_tenant_path is omitted, the early-rejection check is skipped.
	// The rollback manager remains the authoritative access check.
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-xyz")
	handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-xyz","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

	stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-xyz")
}

func TestConfigRollback_UnauthenticatedRequestIsRejectedByManager(t *testing.T) {
	// No user identity in the request context: the production manager refuses to execute
	// (DefaultRollbackManager.getCurrentUser) and nothing is recorded for the target.
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-noauth","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, stack.operationsFor(t, rollback.TargetTypeSteward, "steward-noauth"),
		"an unauthenticated rollback must not be recorded")
}

func TestConfigRollback_InvalidBody(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

	rec := httptest.NewRecorder()
	handler.ExecuteRollback(rec, newRollbackRequest("not json", "admin-cert-cn"))

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, stack.operationsFor(t, rollback.TargetTypeSteward, "steward-x"))
}

func TestConfigRollback_ServerSideTenantLookup(t *testing.T) {
	// When stewardTenantLookup returns a different tenant from the principal's scope,
	// the handler must reject the request even if steward_tenant_path is absent or
	// matches the correct tenant — the server-side check is authoritative.
	t.Run("rejects cross-tenant steward via server-side lookup", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-b")
		lookup := func(_ string) string { return "root/msp-b" }
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		// No steward_tenant_path in body — server-side lookup must catch this anyway.
		body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

		stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-b")
	})

	t.Run("allows same-tenant steward via server-side lookup", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-a")
		lookup := func(_ string) string { return "root/msp-a" }
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-msp-a","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

		stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-msp-a")
	})

	t.Run("lookup returns empty string skips check", func(t *testing.T) {
		// Steward not in registry yet (pre-registration edge case): lookup returns "".
		// The handler must NOT block — the rollback manager is the authoritative gatekeeper.
		stack := newRollbackStack(t)
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-unknown")
		lookup := func(_ string) string { return "" }
		handler := NewRollbackHandler(stack.manager, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-unknown","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-api-key"))

		stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-unknown")
	})

	t.Run("admin principal skips server-side lookup entirely", func(t *testing.T) {
		stack := newRollbackStack(t)
		stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-any")
		// lookup would return a cross-tenant result but admin bypasses the check
		lookup := func(_ string) string { return "root/msp-z" }
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-any","rollback_type":"full","rollback_to":"abc123","reason":"revert bad config"}`
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, newRollbackRequest(body, "admin-cert-cn"))

		stack.requireGuardAdmitted(t, rec, rollback.TargetTypeSteward, "steward-any")
	})
}

// TestConfigRollback_SessionPrincipal_CrossTenantBlocked verifies the Issue #3143 fix
// for rollback_handler.go: a web-session principal has GlobalScope=true set by middleware
// even when scoped to a specific tenant. Before the fix, the !principal.GlobalScope guard
// would always pass (GlobalScope=true → !true=false → check skipped), allowing a session
// caller to roll back any tenant's steward. After the fix, only principal.TenantID governs
// the cross-tenant check.
func TestConfigRollback_SessionPrincipal_CrossTenantBlocked(t *testing.T) {
	stack := newRollbackStack(t)
	stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-msp-b")
	// Session principal scoped to "root/msp-a" with GlobalScope=true (the bug).
	handler := NewRollbackHandler(stack.manager, sessionPrincipalExtractor("root/msp-a"), nil, nil)

	// Target steward belongs to "root/msp-b" — a sibling tenant, not a child.
	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_type":"full","rollback_to":"abc1234567890","reason":"revert bad config","dry_run":false,"steward_tenant_path":"root/msp-b"}`
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, newRollbackRequest(body, "web-session-root/msp-a"))

	stack.requireGuardRejected(t, rec, rollback.TargetTypeSteward, "steward-msp-b")
}

func TestConfigRollback_ListRollbackPointsRequiresTarget(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

	req := httptest.NewRequest("GET", "/api/v1/rollback/points?target_type=steward", nil)
	rec := httptest.NewRecorder()
	handler.ListRollbackPoints(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestConfigRollback_GetRollbackStatus(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

	t.Run("unknown rollback id returns 404", func(t *testing.T) {
		req := mux.SetURLVars(httptest.NewRequest("GET", "/api/v1/rollback/missing/status", nil),
			map[string]string{"rollback_id": "missing"})
		rec := httptest.NewRecorder()
		handler.GetRollbackStatus(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("recorded operation is returned", func(t *testing.T) {
		id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-status", rollback.RollbackStatusPending)

		req := mux.SetURLVars(httptest.NewRequest("GET", "/api/v1/rollback/"+id+"/status", nil),
			map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.GetRollbackStatus(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		var resp struct {
			Rollback rollback.RollbackOperation `json:"rollback"`
		}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, id, resp.Rollback.ID)
		assert.Equal(t, rollback.RollbackStatusPending, resp.Rollback.Status)
		assert.Equal(t, "steward-status", resp.Rollback.Request.TargetID)
	})
}

func TestConfigRollback_CancelRollback(t *testing.T) {
	t.Run("cancellable operation is cancelled in the store", func(t *testing.T) {
		stack := newRollbackStack(t)
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)
		id := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-cancel", rollback.RollbackStatusPending)

		req := httptest.NewRequest("POST", "/api/v1/rollback/"+id+"/cancel", strings.NewReader(`{"reason":"superseded"}`))
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-cert-cn"))
		req = mux.SetURLVars(req, map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

		// The production manager must have persisted the cancellation.
		operation, err := stack.store.GetOperation(context.Background(), id)
		require.NoError(t, err)
		require.NotNil(t, operation)
		assert.Equal(t, rollback.RollbackStatusCancelled, operation.Status)
		require.NotNil(t, operation.CompletedAt)
	})

	t.Run("in-progress operation cannot be cancelled", func(t *testing.T) {
		stack := newRollbackStack(t)
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)
		id := stack.seedLiveOperation(t, rollback.TargetTypeSteward, "steward-live")

		req := httptest.NewRequest("POST", "/api/v1/rollback/"+id+"/cancel", strings.NewReader(`{"reason":"stop it"}`))
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-cert-cn"))
		req = mux.SetURLVars(req, map[string]string{"rollback_id": id})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		assert.Equal(t, http.StatusConflict, rec.Code)

		operation, err := stack.store.GetOperation(context.Background(), id)
		require.NoError(t, err)
		require.NotNil(t, operation)
		assert.Equal(t, rollback.RollbackStatusInProgress, operation.Status,
			"a non-cancellable operation must keep its status")
	})

	t.Run("unknown rollback id returns 404", func(t *testing.T) {
		stack := newRollbackStack(t)
		handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

		req := httptest.NewRequest("POST", "/api/v1/rollback/missing/cancel", strings.NewReader(`{"reason":"n/a"}`))
		req = req.WithContext(context.WithValue(req.Context(), ctxkeys.UserIDKey, "admin-cert-cn"))
		req = mux.SetURLVars(req, map[string]string{"rollback_id": "missing"})
		rec := httptest.NewRecorder()
		handler.CancelRollback(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestConfigRollback_ListRollbackHistory(t *testing.T) {
	stack := newRollbackStack(t)
	handler := NewRollbackHandler(stack.manager, adminPrincipalExtractor(), nil, nil)

	wanted := stack.seedOperation(t, rollback.TargetTypeSteward, "steward-history", rollback.RollbackStatusCompleted)
	stack.seedOperation(t, rollback.TargetTypeSteward, "steward-other", rollback.RollbackStatusCompleted)

	req := httptest.NewRequest("GET", "/api/v1/rollback/history?target_type=steward&target_id=steward-history", nil)
	rec := httptest.NewRecorder()
	handler.ListRollbackHistory(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
	var resp struct {
		Operations []rollback.RollbackOperation `json:"rollback_operations"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Len(t, resp.Operations, 1, "history must be scoped to the requested target")
	assert.Equal(t, wanted, resp.Operations[0].ID)

	// Missing parameters are rejected before the manager is consulted.
	rec = httptest.NewRecorder()
	handler.ListRollbackHistory(rec, httptest.NewRequest("GET", "/api/v1/rollback/history?target_type=steward", nil))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
