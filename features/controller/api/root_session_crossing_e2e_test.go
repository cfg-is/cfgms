// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestRootSessionCrossingBoundary_EndToEnd guards Issue #4665 through the real
// router: a genuine bearer session for a root-scope account — resolved by
// authenticationMiddleware, account-bound, so subject to the ADR-025 crossing
// boundary — is sent against one route of each class that decides a stored
// record's tenant outside requirePermission's path-variable gate. Without a
// crossing each is challenged (or, for a bulk route, skips the client tenant's
// record); with an active grant on that tenant each succeeds.
func TestRootSessionCrossingBoundary_EndToEnd(t *testing.T) {
	server, _, _ := setupProvisionTestServer(t)
	server = wireCrossingStore(t, server)
	ctx := context.Background()

	sessCfg := session.DefaultConfig()
	sessStore := session.NewMemStore(sessCfg, time.Now)
	t.Cleanup(sessStore.Close)
	sessMgr := session.NewManager(sessCfg, sessStore, time.Now)
	server.SetSessionManager(sessMgr)

	sm := pkgtesting.SetupTestStorage(t)
	pendingStore := sm.GetPendingRegistrationStore()
	server.SetPendingStore(pendingStore)
	server.SetRollbackManager(newRollbackStack(t).manager)

	require.NoError(t, ensureTestRootTenant(ctx, server.tenantManager))
	const msp = "e2e-msp"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: msp, ParentID: testRootTenantID})
	require.NoError(t, err)

	const stewardID = "e2e-msp-steward"
	require.NoError(t, server.stewardStore.RegisterSteward(ctx, &business.StewardRecord{
		ID: stewardID, TenantID: msp, Status: business.StewardStatusActive,
	}))
	require.NoError(t, server.controllerService.RegisterSteward(stewardID, msp, "localhost:7100", "online"))

	// The client tenant's account a cert-binding route acts on.
	rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
		Username: "e2e-msp-user", TenantID: msp, Permissions: []string{"steward:list"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// rootSession returns a bearer token for a fresh root-scope account, elevated to
	// AssuranceStrong so every route below clears its assurance floor and only the
	// tenant decision is in play.
	rootSession := func(t *testing.T, id string) string {
		t.Helper()
		server.cacheAccount(&account{ID: id, Username: id, RootScope: true})
		sess, _, err := sessMgr.Issue(ctx, id, "cfg-cli", testRootTenantID)
		require.NoError(t, err)
		elevated, token, err := sessMgr.Elevate(ctx, sess.ID, []byte("e2e-credential"), "192.0.2.1")
		require.NoError(t, err)
		require.Equal(t, session.AssuranceStrong, elevated.Assurance)
		return token
	}
	send := func(t *testing.T, token, method, path string, body interface{}) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			var err error
			raw, err = json.Marshal(body)
			require.NoError(t, err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
	}
	seedPending := func(t *testing.T, id string) {
		t.Helper()
		require.NoError(t, pendingStore.AddPending(ctx, &business.PendingRegistrationEntry{
			PendingID: id, StewardID: id + "-steward", TenantID: msp, TokenStr: "tok-" + id,
			SourceIP: "10.0.0.1", RegisteredAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour),
			Status: business.PendingRegistrationStatusPending,
		}))
	}
	pendingStatus := func(t *testing.T, id string) string {
		t.Helper()
		entry, err := pendingStore.GetPendingByID(ctx, id)
		require.NoError(t, err)
		return entry.Status
	}

	server.SetCasesStore(sm.GetCaseStore())
	// newMSPSteward registers a steward of the client tenant for a route that
	// consumes it (decommission, move).
	newMSPSteward := func(t *testing.T, id string) string {
		t.Helper()
		require.NoError(t, server.stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID: id, TenantID: msp, Status: business.StewardStatusActive,
		}))
		require.NoError(t, server.controllerService.RegisterSteward(id, msp, "localhost:7101", "online"))
		return id
	}
	notChallenged := func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
		assert.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "tenant_crossing_required")
		assert.NotEqual(t, http.StatusNotFound, rec.Code, "the route must act on the record: %s", rec.Body.String())
	}

	routes := []struct {
		name string
		// call sends the request; it may seed per-call state first.
		call func(t *testing.T, token, suffix string) *httptest.ResponseRecorder
		// allowed checks the response once the caller holds a crossing.
		allowed func(t *testing.T, rec *httptest.ResponseRecorder, suffix string)
		// bulk routes skip the client tenant's records instead of challenging.
		bulk        bool
		bulkSkipped func(t *testing.T, rec *httptest.ResponseRecorder, suffix string)
	}{
		{
			name: "certificate provision",
			call: func(t *testing.T, token, _ string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodPost, "/api/v1/certificates/provision", map[string]string{"steward_id": stewardID})
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				assert.Equal(t, http.StatusCreated, rec.Code, "provision must succeed")
			},
		},
		{
			name: "rollback points",
			call: func(t *testing.T, token, _ string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodGet, "/api/v1/rollback/points?target_type=device&target_id="+stewardID, nil)
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				// Past the tenant decision the rollback manager answers on its own
				// terms; with no configuration history seeded for the steward that is
				// a repository-not-found error, never the crossing challenge.
				assert.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
				assert.NotContains(t, rec.Body.String(), "tenant_crossing_required")
				assert.Contains(t, rec.Body.String(), "repository not found", "the request must reach the rollback manager")
			},
		},
		{
			name: "cert-binding bind",
			call: func(t *testing.T, token, suffix string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodPost, "/api/v1/accounts/e2e-msp-user/certs/bind", map[string]string{"serial": "e2e" + suffix})
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				assert.Less(t, rec.Code, 300, rec.Body.String())
			},
		},
		{
			name: "enrolment-token mint",
			call: func(t *testing.T, token, _ string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodPost, "/api/v1/enrolment-tokens", map[string]string{"tenant_id": msp})
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				assert.Less(t, rec.Code, 300, rec.Body.String())
			},
		},
		{
			name: "steward visibility",
			call: func(t *testing.T, token, _ string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodPatch, "/api/v1/stewards/"+stewardID+"/visibility", map[string]bool{"hidden": false})
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				assert.Less(t, rec.Code, 300, rec.Body.String())
			},
		},
		{
			name: "steward decommission",
			call: func(t *testing.T, token, suffix string) *httptest.ResponseRecorder {
				id := newMSPSteward(t, "e2e-decom-"+suffix)
				return send(t, token, http.MethodDelete, "/api/v1/stewards/"+id, nil)
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				assert.Less(t, rec.Code, 300, rec.Body.String())
			},
		},
		{
			name: "steward move",
			call: func(t *testing.T, token, suffix string) *httptest.ResponseRecorder {
				id := newMSPSteward(t, "e2e-move-"+suffix)
				return send(t, token, http.MethodPost, "/api/v1/stewards/"+id+"/move", map[string]string{"new_tenant_id": testRootTenantID})
			},
			allowed: notChallenged,
		},
		{
			name: "session revoke",
			call: func(t *testing.T, token, suffix string) *httptest.ResponseRecorder {
				target, _, err := sessMgr.Issue(ctx, "e2e-msp-user-"+suffix, "cfg-cli", msp)
				require.NoError(t, err)
				return send(t, token, http.MethodDelete, "/api/v1/sessions/"+target.ID, nil)
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, _ string) {
				assert.Less(t, rec.Code, 300, rec.Body.String())
			},
		},
		{
			name: "case create",
			call: func(t *testing.T, token, _ string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodPost, "/api/v1/cases", map[string]interface{}{
					"tenant_id": msp,
					"ticket":    map[string]interface{}{"title": map[string]string{"value": "e2e", "source": "operator"}},
				})
			},
			allowed: notChallenged,
		},
		{
			name: "config push",
			call: func(t *testing.T, token, suffix string) *httptest.ResponseRecorder {
				return send(t, token, http.MethodPost, "/api/v1/config/push", map[string]string{
					"config_id": "e2e-cfg-" + suffix, "version": "1", "tenant_id": msp, "selector": "all",
				})
			},
			allowed: notChallenged,
		},
		{
			name: "registration approve-all",
			bulk: true,
			call: func(t *testing.T, token, suffix string) *httptest.ResponseRecorder {
				seedPending(t, "e2e-pending-"+suffix)
				return send(t, token, http.MethodPost, "/api/v1/registration/approve-all", nil)
			},
			bulkSkipped: func(t *testing.T, rec *httptest.ResponseRecorder, suffix string) {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.Equal(t, business.PendingRegistrationStatusPending, pendingStatus(t, "e2e-pending-"+suffix),
					"a bulk approve must skip a client tenant's registration without a crossing")
			},
			allowed: func(t *testing.T, rec *httptest.ResponseRecorder, suffix string) {
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.Equal(t, business.PendingRegistrationStatusApproved, pendingStatus(t, "e2e-pending-"+suffix))
			},
		},
	}

	for i, rt := range routes {
		suffix := string(rune('a' + i))
		t.Run(rt.name, func(t *testing.T) {
			t.Run("no crossing", func(t *testing.T) {
				rec := rt.call(t, rootSession(t, "e2e-root-without-"+suffix), "n"+suffix)
				if rt.bulk {
					rt.bulkSkipped(t, rec, "n"+suffix)
					return
				}
				assertCrossingChallenge(t, rec, msp)
			})
			t.Run("active crossing", func(t *testing.T) {
				operator := "e2e-root-with-" + suffix
				token := rootSession(t, operator)
				grantCrossing(t, server, operator, msp)
				rt.allowed(t, rt.call(t, token, "y"+suffix), "y"+suffix)
			})
		})
	}

	// A rollback target whose owner neither the registry nor the durable store
	// knows cannot be held to the crossing, so a boundary-subject root is refused
	// before the rollback manager — which would otherwise admit any root caller —
	// is reached (Issue #4665).
	t.Run("rollback points for an unresolved target", func(t *testing.T) {
		rec := send(t, rootSession(t, "e2e-root-unresolved"), http.MethodGet,
			"/api/v1/rollback/points?target_type=device&target_id=e2e-unknown-steward", nil)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), `"rollback_points":[]`)
		assert.NotContains(t, rec.Body.String(), "repository not found", "the request must not reach the rollback manager")
	})
}
