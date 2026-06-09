// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/rollback"
)

// testRollbackManager implements rollback.RollbackManager for handler-level tests.
// It records calls and allows configuring the result or error to be returned.
type testRollbackManager struct {
	executeCalled bool
	executeErr    error
	executeOp     *rollback.RollbackOperation
}

func (m *testRollbackManager) ListRollbackPoints(_ context.Context, _ rollback.TargetType, _ string, _ int) ([]rollback.RollbackPoint, error) {
	return nil, nil
}

func (m *testRollbackManager) PreviewRollback(_ context.Context, _ rollback.RollbackRequest) (*rollback.RollbackPreview, error) {
	return &rollback.RollbackPreview{}, nil
}

func (m *testRollbackManager) ExecuteRollback(_ context.Context, _ rollback.RollbackRequest) (*rollback.RollbackOperation, error) {
	m.executeCalled = true
	if m.executeErr != nil {
		return nil, m.executeErr
	}
	if m.executeOp != nil {
		return m.executeOp, nil
	}
	return &rollback.RollbackOperation{ID: "op-test", Status: rollback.RollbackStatusPending}, nil
}

func (m *testRollbackManager) GetRollbackStatus(_ context.Context, _ string) (*rollback.RollbackOperation, error) {
	return &rollback.RollbackOperation{ID: "op-test", Status: rollback.RollbackStatusCompleted}, nil
}

func (m *testRollbackManager) CancelRollback(_ context.Context, _ string, _ string) error {
	return nil
}

func (m *testRollbackManager) ListRollbackHistory(_ context.Context, _ rollback.TargetType, _ string, _ int) ([]rollback.RollbackOperation, error) {
	return nil, nil
}

// scopedPrincipalExtractor returns an extractor that yields a principal with the given TenantID.
func scopedPrincipalExtractor(tenantID string) func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:       "admin-api-key",
			TenantID: tenantID,
			IsAdmin:  false,
		}
	}
}

func adminPrincipalExtractor() func(*http.Request) *Principal {
	return func(_ *http.Request) *Principal {
		return &Principal{
			ID:      "admin-cert-cn",
			IsAdmin: true,
		}
	}
}

func TestConfigRollback_RejectsCrossTenantVersion(t *testing.T) {
	// Principal scoped to "root/msp-a" must not reach stewards in "root/msp-b".
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_to":"abc1234567890","dry_run":false,"steward_tenant_path":"root/msp-b"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])

	// Rollback manager must NOT have been called.
	assert.False(t, mgr.executeCalled, "rollback manager must not be invoked after cross-tenant rejection")
}

func TestConfigRollback_BlocksSiblingTenant(t *testing.T) {
	// "root/msp-ab" is a sibling, not a child of "root/msp-a" — prefix matching
	// without a segment boundary would incorrectly allow this.
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-msp-ab","rollback_to":"abc1234567890","dry_run":false,"steward_tenant_path":"root/msp-ab"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
	assert.False(t, mgr.executeCalled)
}

func TestConfigRollback_AllowsSameTenant(t *testing.T) {
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_to":"abc1234567890","dry_run":false,"steward_tenant_path":"root/msp-a"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.True(t, mgr.executeCalled)
}

func TestConfigRollback_AllowsChildTenant(t *testing.T) {
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	// "root/msp-a/client-1" is a child of "root/msp-a" — must be allowed.
	body := `{"target_type":"steward","target_id":"steward-client-1","rollback_to":"abc1234567890","dry_run":false,"steward_tenant_path":"root/msp-a/client-1"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.True(t, mgr.executeCalled)
}

func TestConfigRollback_AdminPrincipalSkipsTenantCheck(t *testing.T) {
	// Full admin (IsAdmin=true, TenantID="") can access any tenant.
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-any","rollback_to":"abc1234567890","dry_run":false,"steward_tenant_path":"root/any-tenant"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.True(t, mgr.executeCalled)
}

func TestConfigRollback_NoTenantPathSkipsCheck(t *testing.T) {
	// When steward_tenant_path is omitted, the early-rejection check is skipped.
	// The rollback manager remains the authoritative access check.
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-xyz","rollback_to":"abc1234567890","dry_run":false}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.True(t, mgr.executeCalled)
}

func TestConfigRollback_ApprovalRequired(t *testing.T) {
	mgr := &testRollbackManager{
		executeErr: &rollback.RollbackError{Code: "APPROVAL_REQUIRED", Message: "requires approval"},
	}
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_to":"abc123"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusPreconditionFailed, rec.Code)
}

func TestConfigRollback_InProgress(t *testing.T) {
	mgr := &testRollbackManager{
		executeErr: &rollback.RollbackError{Code: "ROLLBACK_IN_PROGRESS", Message: "in progress"},
	}
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_to":"abc123"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
}

func TestConfigRollback_PermissionDenied(t *testing.T) {
	mgr := &testRollbackManager{
		executeErr: &rollback.RollbackError{Code: "ROLLBACK_PERMISSION_DENIED", Message: "permission denied"},
	}
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_to":"abc123"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestConfigRollback_ValidationFailed(t *testing.T) {
	mgr := &testRollbackManager{
		executeErr: &rollback.RollbackError{Code: "ROLLBACK_VALIDATION_FAILED", Message: "validation failed"},
	}
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	body := `{"target_type":"steward","target_id":"steward-x","rollback_to":"abc123"}`
	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestConfigRollback_InvalidBody(t *testing.T) {
	mgr := &testRollbackManager{}
	handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), nil, nil)

	req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader("not json"))
	rec := httptest.NewRecorder()

	handler.ExecuteRollback(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, mgr.executeCalled)
}

func TestConfigRollback_ServerSideTenantLookup(t *testing.T) {
	// When stewardTenantLookup returns a different tenant from the principal's scope,
	// the handler must reject the request even if steward_tenant_path is absent or
	// matches the correct tenant — the server-side check is authoritative.
	t.Run("rejects cross-tenant steward via server-side lookup", func(t *testing.T) {
		mgr := &testRollbackManager{}
		lookup := func(_ string) string { return "root/msp-b" }
		handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		// No steward_tenant_path in body — server-side lookup must catch this anyway.
		body := `{"target_type":"steward","target_id":"steward-msp-b","rollback_to":"abc123"}`
		req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var resp map[string]interface{}
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.Equal(t, "CROSS_TENANT_ROLLBACK", resp["code"])
		assert.False(t, mgr.executeCalled)
	})

	t.Run("allows same-tenant steward via server-side lookup", func(t *testing.T) {
		mgr := &testRollbackManager{}
		lookup := func(_ string) string { return "root/msp-a" }
		handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-msp-a","rollback_to":"abc123"}`
		req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, req)

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.True(t, mgr.executeCalled)
	})

	t.Run("lookup returns empty string skips check", func(t *testing.T) {
		// Steward not in registry yet (pre-registration edge case): lookup returns "".
		// The handler must NOT block — the rollback manager is the authoritative gatekeeper.
		mgr := &testRollbackManager{}
		lookup := func(_ string) string { return "" }
		handler := NewRollbackHandler(mgr, scopedPrincipalExtractor("root/msp-a"), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-unknown","rollback_to":"abc123"}`
		req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, req)

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.True(t, mgr.executeCalled)
	})

	t.Run("admin principal skips server-side lookup entirely", func(t *testing.T) {
		mgr := &testRollbackManager{}
		// lookup would return a cross-tenant result but admin bypasses the check
		lookup := func(_ string) string { return "root/msp-z" }
		handler := NewRollbackHandler(mgr, adminPrincipalExtractor(), lookup, nil)

		body := `{"target_type":"steward","target_id":"steward-any","rollback_to":"abc123"}`
		req := httptest.NewRequest("POST", "/api/v1/rollback/execute", strings.NewReader(body))
		rec := httptest.NewRecorder()

		handler.ExecuteRollback(rec, req)

		assert.Equal(t, http.StatusAccepted, rec.Code)
		assert.True(t, mgr.executeCalled)
	})
}
