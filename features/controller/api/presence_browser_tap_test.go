// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//

package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// storeBoundTokenWithExpiry stores a presence token bound to the given action fields.
func storeBoundTokenWithExpiry(t *testing.T, s *Server, bound *http.Request, permissionID string, relay bool, expires time.Time) string {
	t.Helper()
	bodyHash, err := hashRequestBodyForPresenceBinding(bound)
	require.NoError(t, err)
	raw := make([]byte, 32)
	_, err = rand.Read(raw)
	require.NoError(t, err)
	token := base64.RawURLEncoding.EncodeToString(raw)
	storePresenceTokenForTest(t, s, hashPresenceToken(token), &presenceTokenRecord{
		principalID:       "test-admin",
		expires:           expires,
		boundMethod:       bound.Method,
		boundPath:         canonicalRequestTarget(bound.URL.Path, bound.URL.RawQuery),
		boundBodyHash:     bodyHash,
		boundPermissionID: permissionID,
	})
	return token
}

func presenceGatedIDs(t *testing.T) []string {
	t.Helper()
	var ids []string
	for id, r := range permissionAssurance {
		if r.RequireUserPresence && strings.Contains(id, ":") && !strings.HasPrefix(id, "test:") {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	require.NotEmpty(t, ids)
	return ids
}

// [REQUIRED TEST] Issue #5297, ADR-021 Amendment 9: every presence-gated permission
// accepts a fresh passkey tap minted either in the browser step-up flow or through the
// cfg relay, provided the token is bound to the exact request. The test iterates
// permissionAssurance, so a new presence-gated permission is covered automatically.
func TestRequirePermission_PresenceBrowserTap_EveryPresenceGatedPermission(t *testing.T) {
	const path = "/api/v1/test/presence-action"
	adminCert := makeSelfSignedAdminCert(t)

	for _, id := range presenceGatedIDs(t) {
		parts := strings.SplitN(id, ":", 2)
		newReq := func(method, target, body string) *http.Request {
			req := requestWithTLSCert(method, target, adminCert)
			req.Body = http.NoBody
			if body != "" {
				req.Body = ioNopCloser(body)
				req.ContentLength = int64(len(body))
			}
			return req
		}
		// serve binds a token to `bound`, then presents it on `actual`.
		serve := func(s *Server, bound, actual *http.Request, permID string, relay bool, expires time.Time) *httptest.ResponseRecorder {
			actual.Header.Set(presenceTokenHeader, storeBoundTokenWithExpiry(t, s, bound, permID, relay, expires))
			rec := httptest.NewRecorder()
			wrapWithAuth(s, parts[0], parts[1],
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }).ServeHTTP(rec, actual)
			return rec
		}
		valid := time.Now().Add(presenceTokenTTL)

		for _, relay := range []bool{false, true} {
			name := "browser"
			if relay {
				name = "relay"
			}
			t.Run(id+"/"+name+"-minted-exact-request-passes", func(t *testing.T) {
				rec := serve(setupTestServer(t), newReq(http.MethodPost, path+"?a=1", `{"x":1}`),
					newReq(http.MethodPost, path+"?a=1", `{"x":1}`), id, relay, valid)
				assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
			})
		}

		mismatches := map[string]func() (bound, actual *http.Request, permID string){
			"method": func() (*http.Request, *http.Request, string) {
				return newReq(http.MethodPut, path, ""), newReq(http.MethodPost, path, ""), id
			},
			"path": func() (*http.Request, *http.Request, string) {
				return newReq(http.MethodPost, path+"/other", ""), newReq(http.MethodPost, path, ""), id
			},
			"query": func() (*http.Request, *http.Request, string) {
				return newReq(http.MethodPost, path+"?a=1", ""), newReq(http.MethodPost, path+"?a=2", ""), id
			},
			"body-hash": func() (*http.Request, *http.Request, string) {
				return newReq(http.MethodPost, path, `{"x":1}`), newReq(http.MethodPost, path, `{"x":2}`), id
			},
			"permission": func() (*http.Request, *http.Request, string) {
				return newReq(http.MethodPost, path, ""), newReq(http.MethodPost, path, ""), id + "-other"
			},
		}
		for field, mk := range mismatches {
			t.Run(id+"/mismatched-"+field+"-refused", func(t *testing.T) {
				bound, actual, permID := mk()
				rec := serve(setupTestServer(t), bound, actual, permID, false, valid)
				require.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Contains(t, rec.Body.String(), "presence_token_action_mismatch")
			})
		}

		t.Run(id+"/second-use-refused", func(t *testing.T) {
			s := setupTestServer(t)
			token := storeBoundTokenWithExpiry(t, s, newReq(http.MethodPost, path, ""), id, false, valid)
			handler := wrapWithAuth(s, parts[0], parts[1],
				func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			for i, want := range []int{http.StatusOK, http.StatusUnauthorized} {
				req := newReq(http.MethodPost, path, "")
				req.Header.Set(presenceTokenHeader, token)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				require.Equal(t, want, rec.Code, "attempt %d body: %s", i, rec.Body.String())
				if want != http.StatusOK {
					assert.Contains(t, rec.Body.String(), "presence_token_invalid")
				}
			}
		})

		t.Run(id+"/expired-refused", func(t *testing.T) {
			rec := serve(setupTestServer(t), newReq(http.MethodPost, path, ""),
				newReq(http.MethodPost, path, ""), id, false, time.Now().Add(-time.Second))
			require.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Body.String(), "presence_token_expired")
		})
	}
}

func ioNopCloser(s string) io.ReadCloser { return io.NopCloser(bytes.NewReader([]byte(s))) }
