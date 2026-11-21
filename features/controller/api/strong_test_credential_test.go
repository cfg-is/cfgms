// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// newStrongBearerHeader returns an Authorization header value for a real AssuranceStrong
// session bound to an account in tenantID that holds permissions. An API key is always
// AssuranceMachine, so it cannot reach a permission whose permissionAssurance entry sets
// Min above Machine without AllowMachine (role:write, refresh:reject); tests of those routes
// use this instead. The session is elevated from the IP httptest requests carry.
func newStrongBearerHeader(t *testing.T, server *Server, permissions []string, tenantID string) string {
	t.Helper()
	if server.sessionManager == nil {
		cfg := session.DefaultConfig()
		store := session.NewMemStore(cfg, time.Now)
		t.Cleanup(store.Close)
		server.SetSessionManager(session.NewManager(cfg, store, time.Now))
	}
	username := "strong-" + strings.ReplaceAll(strings.Join(permissions, "-"), ":", "_") + "-" + strings.ReplaceAll(tenantID, "/", "_")
	server.cacheAccount(&account{
		ID:          "acct-" + username,
		Username:    username,
		TenantID:    tenantID,
		Permissions: permissions,
	})
	ctx := context.Background()
	sess, _, err := server.sessionManager.Issue(ctx, "acct-"+username, "cfg-cli", tenantID)
	require.NoError(t, err)
	elevated, token, err := server.sessionManager.Elevate(ctx, sess.ID, []byte("test-credential-id"), "192.0.2.1")
	require.NoError(t, err)
	require.Equal(t, session.AssuranceStrong, elevated.Assurance)
	return "Bearer " + token
}

// withPresenceTap sets an X-Presence-Token on req for the session credential
// newStrongBearerHeader already put on it: a token minted for that session's principal and
// bound to req's method, path, body and permissionID, the shape a real passkey tap produces
// (Issue #5142). For routes whose permission sets RequireUserPresence (ADR-021
// Amendment 13). req must carry its Authorization header and body before the call.
func withPresenceTap(t *testing.T, server *Server, req *http.Request, permissionID string) {
	t.Helper()
	token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	require.NotEmpty(t, token, "withPresenceTap needs a Bearer session credential on the request")
	sess, err := server.sessionManager.Validate(session.WithSourceIP(context.Background(), "192.0.2.1"), token)
	require.NoError(t, err)
	req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, sess.PrincipalID, req, permissionID))
}
