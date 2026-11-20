// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
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
