// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRaftStatus_UnauthenticatedRequest_Returns401 verifies that GET /api/v1/raft/status
// rejects requests that carry no API key with 401 Unauthorized.
func TestRaftStatus_UnauthenticatedRequest_Returns401(t *testing.T) {
	server := setupTestServer(t)

	req := httptest.NewRequest("GET", "/api/v1/raft/status", nil)
	// No X-API-Key or Authorization header
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	assert.Equal(t, 401, w.Code,
		"/api/v1/raft/status must return 401 for unauthenticated requests")
}

// TestRaftStatus_AuthorizedRequest_PassesAuth verifies that GET /api/v1/raft/status
// accepts a request carrying an API key with the ha:read-status permission.
// In OSS builds GetRaftTransport() returns nil, so the handler returns 503; the
// important property is that the auth layer admits the request (not 401/403).
func TestRaftStatus_AuthorizedRequest_PassesAuth(t *testing.T) {
	server := setupTestServer(t)

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/raft/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	assert.NotEqual(t, 401, w.Code, "/api/v1/raft/status must not return 401 for an authorized request")
	assert.NotEqual(t, 403, w.Code, "/api/v1/raft/status must not return 403 for a request with ha:read-status permission")
	// OSS build: haManager is nil → handler returns 503 (Raft transport not available).
	// This confirms the request reached the handler rather than being blocked by auth.
	assert.Equal(t, 503, w.Code, "OSS build with no HA manager: handler must return 503, not an auth error")
}
