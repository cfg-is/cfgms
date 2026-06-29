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
)

// TestRequireTierMTLSOnly_RejectsAPIKeyPrincipal verifies that a caller with an API-key
// principal (IsAdmin: false) is rejected with HTTP 403 and MTLS_REQUIRED error code,
// and that the inner handler is never invoked.
func TestRequireTierMTLSOnly_RejectsAPIKeyPrincipal(t *testing.T) {
	server := setupTestServer(t)

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{
		IsAdmin:     false,
		Permissions: []string{"api-key:create", "rbac:create-role"},
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, handlerCalled, "inner handler must not be called for API-key principal")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "MTLS_REQUIRED", errResp.Error.Code)
}

// TestRequireTierMTLSOnly_AcceptsAdminCertPrincipal verifies that an mTLS admin principal
// passes through the TierMTLSOnly middleware and the inner handler is called.
func TestRequireTierMTLSOnly_AcceptsAdminCertPrincipal(t *testing.T) {
	server := setupTestServer(t)

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{
		IsAdmin:    true,
		CertSerial: "abc123",
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "admin cert principal must receive 200 from probe handler")
	assert.True(t, handlerCalled, "inner handler must be called for admin cert principal")
}

// TestRequireTierMTLSOnly_AuditsDenial verifies that a Tier-3 rejection emits an
// authorization audit event with decision=DENY and auth_method=api_key via
// auditAuthorizationDecision.
func TestRequireTierMTLSOnly_AuditsDenial(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{
		IsAdmin:     false,
		Permissions: []string{"api-key:create"},
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)

	output := capLog.formattedOutput()
	assert.Contains(t, output, "decision=DENY", "audit log must record DENY decision")
	assert.Contains(t, output, "auth_method=api_key", "audit log must record api_key auth method")
	assert.True(t, capLog.hasLevel("WARN"), "denial must be logged at WARN level")
}

// TestRequireTier_PassesThrough_TierPublic verifies TierPublic is a no-op passthrough.
func TestRequireTier_PassesThrough_TierPublic(t *testing.T) {
	server := setupTestServer(t)
	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierPublic)(probe)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestRequireTier_PassesThrough_TierAny verifies TierAny is a no-op passthrough.
func TestRequireTier_PassesThrough_TierAny(t *testing.T) {
	server := setupTestServer(t)
	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierAny)(probe)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestRequireTier_PassesThrough_TierElevated verifies TierElevated is a no-op passthrough.
func TestRequireTier_PassesThrough_TierElevated(t *testing.T) {
	server := setupTestServer(t)
	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierElevated)(probe)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestRequireTierMTLSOnly_RejectsNilPrincipal verifies that a request with no principal
// in context is also rejected with 403 MTLS_REQUIRED and emits a denial audit event.
func TestRequireTierMTLSOnly_RejectsNilPrincipal(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	// no principal in context
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, handlerCalled, "inner handler must not be called when no principal in context")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "MTLS_REQUIRED", errResp.Error.Code)

	// Nil-principal denials must also be audited.
	output := capLog.formattedOutput()
	assert.Contains(t, output, "decision=DENY", "nil-principal denial must be audited as DENY")
	assert.True(t, capLog.hasLevel("WARN"), "nil-principal denial must be logged at WARN level")
}

// TestTier3Permissions_SourceOfTruth validates that the canonical Tier-3 permission set
// is non-empty and that every entry is a non-empty string in the expected "resource:action"
// format. This test is the compile-time anchor for the S3/S4 consumers of this map.
func TestTier3Permissions_SourceOfTruth(t *testing.T) {
	require.NotEmpty(t, tier3Permissions, "tier3Permissions must declare at least one Tier-3 permission")
	for perm := range tier3Permissions {
		assert.NotEmpty(t, perm, "tier3Permissions must not contain empty permission IDs")
		assert.Contains(t, perm, ":", "permission ID %q must use resource:action format", perm)
	}
}
