// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestRaftStatus_AuthorizedRequest_Returns200 verifies that an authenticated request
// with the ha:read-status permission returns 200 when a real ClusterMode HA manager
// is available. A real raftTransport is wired by newClusterModeHAManager so that
// handleRaftStatus can delegate to transport.HandleStatus.
func TestRaftStatus_AuthorizedRequest_Returns200(t *testing.T) {
	haManager := newClusterModeHAManager(t, "")

	// Set up a fully-wired test server and inject the commercial HA manager.
	// The router and authentication middleware were registered during New(), so
	// changing haManager here only affects what the handler reads at request time.
	server := setupTestServer(t)
	server.mu.Lock()
	server.haManager = haManager
	server.mu.Unlock()

	apiKey := NewEphemeralTestKey(t, server, []string{"ha:read-status"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest("GET", "/api/v1/raft/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	server.GetRouter().ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code,
		"authorized request with ha:read-status permission and a running HA manager must return 200")
}
