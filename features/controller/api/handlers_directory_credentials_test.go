// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/credentials"
	"github.com/cfgis/cfgms/features/tenant"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	_ "github.com/cfgis/cfgms/pkg/secrets/providers/sops"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

const credTestPassword = "Zq7!-initial-pw-for-tests"

type credFixture struct {
	t     *testing.T
	srv   *Server
	store credentials.CredentialStore
	clock *dirClock
}

// newCredFixture wires the real credential store (flatfile config store, SOPS
// secret store) into a real server with two real tenants under root.
func newCredFixture(t *testing.T) *credFixture {
	t.Helper()
	srv := setupTestServer(t)
	for _, id := range []string{"tenant-a", "tenant-b"} {
		_, err := srv.tenantManager.CreateTenant(t.Context(), &tenant.TenantRequest{ID: id, ParentID: testRootTenantID})
		require.NoError(t, err)
	}
	cfg := pkgtesting.SetupTestStorage(t).GetConfigStore()

	base := t.TempDir()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyPath := filepath.Join(base, "secrets.key")
	require.NoError(t, os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(key)), 0o600))
	secrets, err := secretsif.CreateSecretStoreFromConfig("sops", map[string]interface{}{
		"storage_provider": "flatfile",
		"storage_config":   map[string]interface{}{"root": filepath.Join(base, "data")},
		"cache_enabled":    false,
		"key_file":         keyPath,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = secrets.Close() })

	clock := &dirClock{t: time.Now().UTC()}
	store, err := credentials.NewStore(cfg, secrets, credentials.WithClock(clock.now))
	require.NoError(t, err)
	srv.SetCredentialStore(store)
	srv.credentialClock = clock.now
	return &credFixture{t: t, srv: srv, store: store, clock: clock}
}

func (f *credFixture) put(tenantID, resourceID string) *credentials.Record {
	f.t.Helper()
	id, err := credentials.NewRecordID()
	require.NoError(f.t, err)
	now := f.clock.now()
	rec := &credentials.Record{
		ID: id, TenantID: tenantID, StewardID: "steward-1", ResourceID: resourceID,
		CreatedAt: now, ExpiresAt: now.Add(credentials.DefaultTTL), State: credentials.StatePending,
	}
	require.NoError(f.t, f.store.Put(f.t.Context(), rec, credTestPassword, nil))
	return rec
}

func credAdmin(id, tenantID string) *Principal {
	return &Principal{
		ID: id, Name: id, TenantID: tenantID, Assurance: session.AssuranceStrong,
		Permissions: []string{"directory:credential-list", "directory:credential-reveal"},
	}
}

// reveal drives the reveal route through the same wrapper the router registers, with
// a presence token bound to the request unless p is machine or noTap is set.
func (f *credFixture) reveal(p *Principal, id string, noTap bool) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/directory/credentials/"+id+"/reveal", nil)
	req = withVars(withPrincipal(req, p), map[string]string{"id": id})
	if !noTap {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.t, f.srv, p.ID, req, "directory:credential-reveal"))
	}
	return f.serveReveal(req)
}

func (f *credFixture) serveReveal(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	noStore(f.srv.requirePermission("directory", "credential-reveal")(http.HandlerFunc(f.srv.handleRevealDirectoryCredential))).ServeHTTP(rec, req)
	return rec
}

func (f *credFixture) list(p *Principal) *httptest.ResponseRecorder {
	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/directory/credentials", nil), p)
	rec := httptest.NewRecorder()
	noStore(f.srv.requirePermission("directory", "credential-list")(http.HandlerFunc(f.srv.handleListDirectoryCredentials))).ServeHTTP(rec, req)
	return rec
}

func (f *credFixture) current(rec *credentials.Record) *credentials.Credential {
	f.t.Helper()
	cred, err := f.store.Get(f.t.Context(), rec.Key())
	require.NoError(f.t, err)
	return cred
}

func revealedPassword(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body directoryCredentialReveal
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), rec.Body.String())
	return body.Password
}

func TestReveal_OnceOnly_SecondCallFails(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-jdoe")
	admin := credAdmin("admin-a", "tenant-a")

	first := f.reveal(admin, rec.ID, false)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	assert.Equal(t, credTestPassword, revealedPassword(t, first))
	assert.Equal(t, "no-store", first.Header().Get("Cache-Control"))

	second := f.reveal(admin, rec.ID, false)
	assert.Equal(t, http.StatusGone, second.Code, second.Body.String())
	assert.NotContains(t, second.Body.String(), credTestPassword)
	assert.Equal(t, "no-store", second.Header().Get("Cache-Control"))

	cur := f.current(rec)
	assert.Equal(t, credentials.StateRevealed, cur.State)
	assert.Empty(t, cur.Password, "the secret must be deleted after the reveal")
}

func TestReveal_ConcurrentOnlyOneWins(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-race")
	admin := credAdmin("admin-a", "tenant-a")

	const callers = 8
	reqs := make([]*http.Request, callers)
	for i := range reqs {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/directory/credentials/"+rec.ID+"/reveal", nil)
		r = withVars(withPrincipal(r, admin), map[string]string{"id": rec.ID})
		r.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, f.srv, admin.ID, r, "directory:credential-reveal"))
		reqs[i] = r
	}
	results := make([]*httptest.ResponseRecorder, callers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = f.serveReveal(reqs[i])
		}(i)
	}
	close(start)
	wg.Wait()

	winners := 0
	for _, res := range results {
		switch res.Code {
		case http.StatusOK:
			winners++
			assert.Equal(t, credTestPassword, revealedPassword(t, res))
		case http.StatusConflict, http.StatusGone:
			assert.NotContains(t, res.Body.String(), credTestPassword)
		default:
			t.Errorf("unexpected status %d: %s", res.Code, res.Body.String())
		}
	}
	assert.Equal(t, 1, winners, "exactly one concurrent reveal may receive the password")
}

func TestReveal_CrashWhileRevealing_RecoversOrReports410(t *testing.T) {
	admin := credAdmin("admin-a", "tenant-a")

	t.Run("secret present: in progress, then claimable after 60 seconds", func(t *testing.T) {
		f := newCredFixture(t)
		rec := f.put("tenant-a", "user-crash1")
		_, err := f.store.Claim(t.Context(), rec.Key(), rec.ID, credentials.StatePending, credentials.StateRevealing)
		require.NoError(t, err)

		early := f.reveal(admin, rec.ID, false)
		assert.Equal(t, http.StatusConflict, early.Code, early.Body.String())
		assert.NotContains(t, early.Body.String(), credTestPassword)

		f.clock.advance(credentials.RevealStaleAfter + time.Second)
		late := f.reveal(admin, rec.ID, false)
		require.Equal(t, http.StatusOK, late.Code, late.Body.String())
		assert.Equal(t, credTestPassword, revealedPassword(t, late))
		assert.Equal(t, http.StatusGone, f.reveal(admin, rec.ID, false).Code)
	})

	t.Run("stale reclaim does not revive an expired record", func(t *testing.T) {
		f := newCredFixture(t)
		rec := f.put("tenant-a", "user-crash3")
		_, err := f.store.Claim(t.Context(), rec.Key(), rec.ID, credentials.StatePending, credentials.StateRevealing)
		require.NoError(t, err)
		f.clock.advance(credentials.DefaultTTL + time.Minute)

		res := f.reveal(admin, rec.ID, false)
		assert.Equal(t, http.StatusGone, res.Code, res.Body.String())
		assert.NotContains(t, res.Body.String(), credTestPassword)
	})

	t.Run("secret gone: 410 at any age", func(t *testing.T) {
		f := newCredFixture(t)
		rec := f.put("tenant-a", "user-crash2")
		claimed, err := f.store.Claim(t.Context(), rec.Key(), rec.ID, credentials.StatePending, credentials.StateRevealing)
		require.NoError(t, err)
		require.NoError(t, f.store.DeleteSecret(t.Context(), claimed))

		res := f.reveal(admin, rec.ID, false)
		assert.Equal(t, http.StatusGone, res.Code, res.Body.String())
		assert.NotContains(t, res.Body.String(), credTestPassword)
		f.clock.advance(time.Hour)
		assert.Equal(t, http.StatusGone, f.reveal(admin, rec.ID, false).Code)
	})
}

func TestReveal_CrossTenantIsDenied(t *testing.T) {
	f := newCredFixture(t)
	recB := f.put("tenant-b", "user-in-b")
	f.put("tenant-a", "user-in-a")
	adminA := credAdmin("admin-a", "tenant-a")
	adminB := credAdmin("admin-b", "tenant-b")

	res := f.reveal(adminA, recB.ID, false)
	assert.Equal(t, http.StatusNotFound, res.Code, res.Body.String())
	assert.NotContains(t, res.Body.String(), credTestPassword)
	cur := f.current(recB)
	assert.Equal(t, credentials.StatePending, cur.State, "a denied reveal must not touch the record")
	assert.Equal(t, credTestPassword, cur.Password, "a denied reveal must not touch the secret")

	// The same id is 404 whether it exists in another tenant or not at all.
	missing := f.reveal(adminA, "00000000000000000000000000000000", false)
	assert.Equal(t, http.StatusNotFound, missing.Code)

	// The list shows only the caller's tenant.
	list := f.list(adminA)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	assert.Contains(t, list.Body.String(), "user-in-a")
	assert.NotContains(t, list.Body.String(), "user-in-b")
	assert.NotContains(t, list.Body.String(), credTestPassword)

	owner := f.reveal(adminB, recB.ID, false)
	require.Equal(t, http.StatusOK, owner.Code, owner.Body.String())
	assert.Equal(t, credTestPassword, revealedPassword(t, owner))
}

func TestReveal_RequiresPresenceTap(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-tap")

	t.Run("strong without a presence token is challenged", func(t *testing.T) {
		res := f.reveal(credAdmin("admin-a", "tenant-a"), rec.ID, true)
		assert.Equal(t, http.StatusUnauthorized, res.Code)
		assert.Contains(t, res.Header().Get("WWW-Authenticate"), `presence="required"`)
		assert.Contains(t, res.Header().Get("WWW-Authenticate"), `permission="directory:credential-reveal"`)
		assert.NotContains(t, res.Body.String(), credTestPassword)
	})

	t.Run("basic assurance is challenged", func(t *testing.T) {
		p := credAdmin("admin-a", "tenant-a")
		p.Assurance = session.AssuranceBasic
		assert.Equal(t, http.StatusUnauthorized, f.reveal(p, rec.ID, true).Code)
	})

	t.Run("machine key is refused", func(t *testing.T) {
		p := credAdmin("key-a", "tenant-a")
		p.Assurance = session.AssuranceMachine
		res := f.reveal(p, rec.ID, true)
		assert.Equal(t, http.StatusForbidden, res.Code, res.Body.String())
		assert.NotContains(t, res.Body.String(), credTestPassword)
	})

	cur := f.current(rec)
	assert.Equal(t, credentials.StatePending, cur.State)
	assert.Equal(t, credTestPassword, cur.Password, "refused attempts must leave the secret in place")
}

func TestReveal_ViewerRoleLacksCredentialPermissions(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-viewer")

	assert.True(t, knownPermissions["directory:credential-list"])
	assert.True(t, knownPermissions["directory:credential-reveal"])
	req, ok := permissionAssurance["directory:credential-reveal"]
	require.True(t, ok)
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.True(t, req.RequireUserPresence)
	assert.False(t, req.AllowMachine)
	_, listGated := permissionAssurance["directory:credential-list"]
	assert.False(t, listGated, "the list route has no elevated floor")

	viewer := f.srv.requirePermissionTestKey(t, []string{"directory:read", "steward:list"}, "tenant-a")
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/directory/credentials"},
		{http.MethodPost, "/api/v1/directory/credentials/" + rec.ID + "/reveal"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Header.Set("X-API-Key", viewer)
		w := httptest.NewRecorder()
		f.srv.router.ServeHTTP(w, r)
		assert.Equal(t, http.StatusForbidden, w.Code, "%s %s: %s", tc.method, tc.path, w.Body.String())
	}

	// credential-list alone lists, with no-store; it cannot reveal.
	lister := f.srv.requirePermissionTestKey(t, []string{"directory:credential-list"}, "tenant-a")
	r := httptest.NewRequest(http.MethodGet, "/api/v1/directory/credentials", nil)
	r.Header.Set("X-API-Key", lister)
	w := httptest.NewRecorder()
	f.srv.router.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Contains(t, w.Body.String(), rec.ID)
	assert.NotContains(t, w.Body.String(), credTestPassword)
	assert.Equal(t, http.StatusForbidden, f.reveal(&Principal{ID: "l", TenantID: "tenant-a", Assurance: session.AssuranceStrong,
		Permissions: []string{"directory:credential-list"}}, rec.ID, true).Code)
}

func (s *Server) requirePermissionTestKey(t *testing.T, perms []string, tenantID string) string {
	t.Helper()
	return NewEphemeralTestKey(t, s, perms, tenantID, 5*time.Minute)
}

func TestReveal_AuditHasResourceIDAndPrincipalNotSecret(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-audited")
	admin := credAdmin("admin-a", "tenant-a")

	require.Equal(t, http.StatusOK, f.reveal(admin, rec.ID, false).Code)
	require.Equal(t, http.StatusGone, f.reveal(admin, rec.ID, false).Code)

	entries := auditEntriesByAction(t, f.srv, "credential.reveal")
	require.Len(t, entries, 2)
	var sawSuccess, sawFailure bool
	for _, e := range entries {
		assert.Equal(t, "user-audited", e.ResourceID, "the audit resource id is the cfg-declared id")
		assert.Equal(t, "admin-a", e.UserID)
		assert.Equal(t, "tenant-a", e.TenantID)
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), credTestPassword)
		switch e.Result {
		case business.AuditResultSuccess:
			sawSuccess = true
		case business.AuditResultFailure:
			sawFailure = true
		}
	}
	assert.True(t, sawSuccess && sawFailure, "both the success and the failure are audited")
}

func TestReveal_ClusterModeWithNonAtomicStore_FailsClosed(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-cluster")
	require.False(t, cfgconfig.ClusterAtomic(pkgtesting.SetupTestStorage(t).GetConfigStore()), "the flatfile store is not cluster-atomic")

	cfgconfig.SetClusterConfigured(true)
	t.Cleanup(func() { cfgconfig.SetClusterConfigured(false) })

	res := f.reveal(credAdmin("admin-a", "tenant-a"), rec.ID, false)
	assert.Equal(t, http.StatusServiceUnavailable, res.Code, res.Body.String())
	assert.NotContains(t, res.Body.String(), credTestPassword)

	cfgconfig.SetClusterConfigured(false)
	cur := f.current(rec)
	assert.Equal(t, credentials.StatePending, cur.State)
	assert.Equal(t, credTestPassword, cur.Password)
}

func TestReveal_ExpiredAndUnknownIDs(t *testing.T) {
	f := newCredFixture(t)
	rec := f.put("tenant-a", "user-expired")
	admin := credAdmin("admin-a", "tenant-a")
	f.clock.advance(credentials.DefaultTTL + time.Minute)

	assert.Equal(t, http.StatusGone, f.reveal(admin, rec.ID, false).Code)
	assert.NotContains(t, f.list(admin).Body.String(), rec.ID, "an expired record is not listed")
	assert.Equal(t, http.StatusNotFound, f.reveal(admin, "not-a-record-id", false).Code)
}
