// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//

package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeBoundToken stores a presence token bound to req and permissionID, minted by the
// relay (relay=true) or the browser step-up flow (relay=false).
func storeBoundToken(t *testing.T, s *Server, req *http.Request, permissionID string, relay bool) string {
	t.Helper()
	bodyHash, err := hashRequestBodyForPresenceBinding(req)
	require.NoError(t, err)
	raw := make([]byte, 32)
	_, err = rand.Read(raw)
	require.NoError(t, err)
	token := base64.RawURLEncoding.EncodeToString(raw)
	storePresenceTokenForTest(t, s, hashPresenceToken(token), &presenceTokenRecord{
		principalID:       "test-admin",
		expires:           time.Now().Add(presenceTokenTTL),
		boundMethod:       req.Method,
		boundPath:         canonicalRequestTarget(req.URL.Path, req.URL.RawQuery),
		boundBodyHash:     bodyHash,
		boundPermissionID: permissionID,
		relayMinted:       relay,
	})
	return token
}

// [REQUIRED TEST] Issue #5272: every presence-gated permission is relay required unless
// it opts into the browser flow in code. The test iterates permissionAssurance, so a new
// presence-gated permission without the opt-in is covered automatically.
func TestRequirePermission_PresenceRelayRequired_EveryPresenceGatedPermission(t *testing.T) {
	var ids []string
	for id, r := range permissionAssurance {
		if r.RequireUserPresence && strings.Contains(id, ":") && !strings.HasPrefix(id, "test:") {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	require.NotEmpty(t, ids)

	adminCert := makeSelfSignedAdminCert(t)
	for _, id := range ids {
		parts := strings.SplitN(id, ":", 2)
		path := "/api/v1/test/presence-action"
		newHandler := func(s *Server) http.Handler {
			return wrapWithAuth(s, parts[0], parts[1],
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		}
		serve := func(s *Server, relay bool) *httptest.ResponseRecorder {
			req := requestWithTLSCert(http.MethodPost, path, adminCert)
			req.Header.Set(presenceTokenHeader, storeBoundToken(t, s, req, id, relay))
			rec := httptest.NewRecorder()
			newHandler(s).ServeHTTP(rec, req)
			return rec
		}

		t.Run(id+"/browser", func(t *testing.T) {
			rec := serve(setupTestServer(t), false)
			if permissionAssurance[id].BrowserPresenceAllowed {
				assert.Equal(t, http.StatusOK, rec.Code, "browser-allowed permission accepts a browser token")
				return
			}
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Body.String(), "presence_relay_required")
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `relay="required"`)
		})
		t.Run(id+"/relay", func(t *testing.T) {
			rec := serve(setupTestServer(t), true)
			assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		})
	}
}

// Only module:reject opts into the browser flow, and a refused browser token is consumed.
func TestRequirePermission_PresenceRelayRequired_OptInSetAndTokenConsumed(t *testing.T) {
	var optedIn []string
	for id, r := range permissionAssurance {
		if r.BrowserPresenceAllowed {
			optedIn = append(optedIn, id)
		}
	}
	assert.Equal(t, []string{"module:reject"}, optedIn)

	s := setupTestServer(t)
	adminCert := makeSelfSignedAdminCert(t)
	handler := wrapWithAuth(s, "module", "approve",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
	token := storeBoundToken(t, s, req, "module:approve", false)
	for i, want := range []string{"presence_relay_required", "presence_token_invalid"} {
		r := requestWithTLSCert(http.MethodPost, "/api/v1/test/presence-action", adminCert)
		r.Header.Set(presenceTokenHeader, token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		require.Equal(t, http.StatusUnauthorized, rec.Code, "attempt %d", i)
		assert.Contains(t, rec.Body.String(), want, "attempt %d", i)
	}
}
