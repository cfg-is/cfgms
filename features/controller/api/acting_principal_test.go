// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// noActorCase is one way a request can reach a handler without an actor to record:
// no principal on the context at all, or a principal whose ID is empty.
type noActorCase struct {
	name      string
	principal *Principal
}

// noActorCases returns the two no-actor shapes. The empty-ID principal otherwise holds
// everything a handler checks (implicit admin, strong assurance, tenantID), so the
// missing ID is the only reason it can be refused.
func noActorCases(tenantID string) []noActorCase {
	return []noActorCase{
		{name: "no principal in context"},
		{name: "principal with empty ID", principal: &Principal{
			ID: "", TenantID: tenantID, Assurance: session.AssuranceStrong, ImplicitAdmin: true,
		}},
	}
}

// withActor puts p on ctx as the authenticated principal, or leaves ctx without one
// when p is nil.
func withActor(ctx context.Context, p *Principal) context.Context {
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, principalContextKey, p)
}

// assertAuthenticationRequired checks the response is the 401 a handler writes when it
// has no actor to record.
func assertAuthenticationRequired(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Equal(t, "AUTHENTICATION_REQUIRED", errorCode(t, rec))
}

func TestRequireActingPrincipal(t *testing.T) {
	server := setupTestServer(t)

	for _, tc := range noActorCases("tenant-a") {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			req = req.WithContext(withActor(req.Context(), tc.principal))
			rec := httptest.NewRecorder()
			p, ok := server.requireActingPrincipal(rec, req)
			assert.False(t, ok)
			assert.Nil(t, p)
			assertAuthenticationRequired(t, rec)
		})
	}

	t.Run("principal with an ID", func(t *testing.T) {
		want := &Principal{ID: "operator-7", TenantID: "tenant-a"}
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = req.WithContext(withActor(req.Context(), want))
		rec := httptest.NewRecorder()
		p, ok := server.requireActingPrincipal(rec, req)
		require.True(t, ok)
		assert.Same(t, want, p)
		assert.Equal(t, http.StatusOK, rec.Code, "nothing is written for an authenticated principal")
		assert.Empty(t, rec.Body.String())
	})
}
