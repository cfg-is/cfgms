// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const rolloutCredTestTenant = "rollout-cred-tenant"

// rolloutCredFixture is a real server (real secret store on t.TempDir(), real audit
// manager) with the real rollout-credential route behind the real requirePermission
// middleware. Minted keys are then presented to the server's own routers.
type rolloutCredFixture struct {
	tb  *testing.T
	srv *Server
	mux *mux.Router
}

func newRolloutCredFixture(t *testing.T) *rolloutCredFixture {
	t.Helper()
	srv := setupTestServer(t)
	r := mux.NewRouter()
	registerRolloutCredentialRoutes(srv, r.PathPrefix("/api/v1").Subrouter())
	return &rolloutCredFixture{tb: t, srv: srv, mux: r}
}

// rolloutCredAdmin holds the create permission and all four credential permissions.
func rolloutCredAdmin() *Principal {
	return &Principal{
		ID: "rollout-admin", Assurance: session.AssuranceStrong, TenantID: rolloutCredTestTenant,
		Permissions: append([]string{"rollout-credential:create"}, rolloutCredentialPermissions...),
	}
}

func (f *rolloutCredFixture) post(body string, p *Principal, presence bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout-credentials", strings.NewReader(body))
	req = withPrincipal(req, p)
	if presence {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.tb, f.srv, p.ID, req, "rollout-credential:create"))
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

type rolloutCredResponse struct {
	Data struct {
		ID          string     `json:"id"`
		Name        string     `json:"name"`
		Key         string     `json:"key"`
		Permissions []string   `json:"permissions"`
		TenantID    string     `json:"tenant_id"`
		ExpiresAt   *time.Time `json:"expires_at"`
	} `json:"data"`
}

func rolloutBody(expires time.Time) string {
	return `{"name":"deploy-agent","expires_at":"` + expires.UTC().Format(time.RFC3339) + `"}`
}

// mint mints a rollout credential through the route and returns the parsed response.
func (f *rolloutCredFixture) mint() rolloutCredResponse {
	f.tb.Helper()
	rec := f.post(rolloutBody(time.Now().Add(24*time.Hour)), rolloutCredAdmin(), true)
	require.Equal(f.tb, http.StatusCreated, rec.Code, rec.Body.String())
	var resp rolloutCredResponse
	require.NoError(f.tb, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(f.tb, resp.Data.Key)
	return resp
}

// mintGeneric mints a key through POST /api/v1/api-keys as an admin, with the given
// permissions and extra JSON fields merged into the body.
func (f *rolloutCredFixture) mintGeneric(perms []string, extra map[string]interface{}) rolloutCredResponse {
	f.tb.Helper()
	body := map[string]interface{}{"name": "generic", "permissions": perms}
	for k, v := range extra {
		body[k] = v
	}
	raw, err := json.Marshal(body)
	require.NoError(f.tb, err)
	caller := &Principal{ID: "key-admin", TenantID: rolloutCredTestTenant, ImplicitAdmin: true}
	rec := callHandleCreateAPIKeyAsPrincipal(f.srv, raw, rolloutCredTestTenant, caller)
	require.Equal(f.tb, http.StatusCreated, rec.Code, rec.Body.String())
	var resp rolloutCredResponse
	require.NoError(f.tb, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// principalFor authenticates the key the way the middleware does and returns the
// principal it builds, loading the key from the secret store when it is not cached.
func (f *rolloutCredFixture) principalFor(key string) *Principal {
	f.tb.Helper()
	f.srv.mu.RLock()
	info := f.srv.apiKeys[key]
	f.srv.mu.RUnlock()
	if info == nil {
		var err error
		info, err = f.srv.loadAPIKeyFromStore(f.tb.Context(), key)
		require.NoError(f.tb, err)
	}
	return apiKeyPrincipal(info)
}

// dropCache forgets every cached key and the key index, as a restart does.
func (f *rolloutCredFixture) dropCache() {
	f.srv.mu.Lock()
	f.srv.apiKeys = map[string]*APIKey{}
	f.srv.mu.Unlock()
	f.srv.apiKeyIdx = newAPIKeyIndex()
}

func (f *rolloutCredFixture) callWithKey(handler http.Handler, method, path, key, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-API-Key", key)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestCreateRolloutCredentialPermissionSetAndKind(t *testing.T) {
	f := newRolloutCredFixture(t)
	resp := f.mint()

	assert.Equal(t, []string{
		"installer:dispatch:steward", "installer:read", "installer:publish:steward", "monitoring:write-markers",
	}, resp.Data.Permissions)
	assert.Equal(t, rolloutCredTestTenant, resp.Data.TenantID, "bound to the caller's tenant")
	require.NotNil(t, resp.Data.ExpiresAt)
	assert.True(t, resp.Data.ExpiresAt.After(time.Now()))

	// The durable record carries the kind beside id and permissions.
	hash := hashAPIKey(resp.Data.Key)
	rec, err := f.srv.readAPIKeyRecord(t.Context(), rolloutCredTestTenant, hash)
	require.NoError(t, err)
	require.NotNil(t, rec)
	assert.Equal(t, "rollout", rec.Metadata["credential_kind"])
	assert.Equal(t, resp.Data.ID, rec.Metadata["id"])
	assert.Equal(t, "installer:dispatch:steward,installer:read,installer:publish:steward,monitoring:write-markers", rec.Metadata["permissions"])
	assert.NotContains(t, rec.Value, resp.Data.Key, "the plaintext is never stored")

	p := f.principalFor(resp.Data.Key)
	assert.Equal(t, "rollout", p.CredentialKind)
	assert.True(t, isRolloutCredential(p))

	// The request cannot add or remove permissions, name a tenant or set the kind.
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for name, body := range map[string]string{
		"permissions":     `{"expires_at":"` + exp + `","permissions":["steward:read"]}`,
		"tenant":          `{"expires_at":"` + exp + `","tenant_id":"other"}`,
		"credential_kind": `{"expires_at":"` + exp + `","credential_kind":"rollout"}`,
		"not json":        `expires_at=tomorrow`,
		"trailing value":  `{"expires_at":"` + exp + `"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.post(body, rolloutCredAdmin(), true)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		})
	}

	// A missing or past expiry, and an over-long name, are refused.
	assert.Equal(t, http.StatusBadRequest, f.post(`{"name":"x"}`, rolloutCredAdmin(), true).Code)
	assert.Equal(t, http.StatusBadRequest, f.post(rolloutBody(time.Now().Add(-time.Hour)), rolloutCredAdmin(), true).Code)
	long := `{"name":"` + strings.Repeat("n", rolloutCredentialMaxNameLen+1) + `","expires_at":"` + exp + `"}`
	assert.Equal(t, http.StatusBadRequest, f.post(long, rolloutCredAdmin(), true).Code)

	// Without a tenant on the request context the key would have none: refused.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout-credentials", strings.NewReader(rolloutBody(time.Now().Add(time.Hour))))
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, rolloutCredAdmin()))
	noTenant := httptest.NewRecorder()
	f.srv.handleCreateRolloutCredential(noTenant, req)
	assert.Equal(t, http.StatusForbidden, noTenant.Code, noTenant.Body.String())
}

func TestCreateRolloutCredentialRequiresTap(t *testing.T) {
	f := newRolloutCredFixture(t)
	p := rolloutCredAdmin()

	rec := f.post(rolloutBody(time.Now().Add(time.Hour)), p, false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	assert.Empty(t, auditEntriesByAction(t, f.srv, "rollout_credential_created"))
	assert.Empty(t, f.srv.apiKeys, "a challenged request mints nothing")

	assert.Equal(t, http.StatusCreated, f.post(rolloutBody(time.Now().Add(time.Hour)), p, true).Code)

	// A machine principal is refused outright, with or without a token.
	apiKey := &Principal{
		ID: "key-1", Channel: AuthChannelAPIKey, Assurance: session.AssuranceMachine, TenantID: rolloutCredTestTenant,
		Permissions: p.Permissions,
	}
	assert.Equal(t, http.StatusForbidden, f.post(rolloutBody(time.Now().Add(time.Hour)), apiKey, true).Code)
}

func TestRolloutCredentialAuditsCreation(t *testing.T) {
	f := newRolloutCredFixture(t)
	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	rec := f.post(rolloutBody(expires), rolloutCredAdmin(), true)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp rolloutCredResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	entries := auditEntriesByAction(t, f.srv, "rollout_credential_created")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "rollout-admin", e.UserID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, resp.Data.ID, e.ResourceID)
	assert.Equal(t, "rollout-admin", e.Details["principal"])
	assert.Equal(t, resp.Data.ID, e.Details["key_id"])
	assert.Equal(t, expires.Format(time.RFC3339), e.Details["expires_at"])
	assert.NotContains(t, e.Details, "key", "the plaintext is never audited")

	// No audit manager, no credential.
	f.srv.auditManager = nil
	before := len(f.srv.apiKeys)
	rec = f.post(rolloutBody(expires), rolloutCredAdmin(), true)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Len(t, f.srv.apiKeys, before)
}

func TestKindSurvivesRestartAndStoreReload(t *testing.T) {
	f := newRolloutCredFixture(t)
	resp := f.mint()
	key := resp.Data.Key

	// Cached path.
	assert.True(t, isRolloutCredential(f.principalFor(key)))

	// A restart: no cache, no index. The key loads from the store and keeps its kind.
	f.dropCache()
	loaded, err := f.srv.loadAPIKeyFromStore(t.Context(), key)
	require.NoError(t, err)
	assert.Equal(t, "rollout", loaded.Kind)
	assert.True(t, isRolloutCredential(apiKeyPrincipal(loaded)))

	// A request after a restart authenticates the reloaded key.
	f.dropCache()
	rec := f.callWithKey(f.srv.router, http.MethodGet, "/api/v1/installer/steward-binaries/1.0.0/linux/amd64", key, "")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	f.srv.mu.RLock()
	cached := f.srv.apiKeys[key]
	f.srv.mu.RUnlock()
	require.NotNil(t, cached)
	assert.Equal(t, "rollout", cached.Kind)

	// The periodic re-validation replaces the cache entry from the record and keeps the kind.
	refreshed, err := f.srv.revalidateCachedAPIKey(t.Context(), key, cached, time.Now())
	require.NoError(t, err)
	assert.Equal(t, "rollout", refreshed.Kind)
	assert.True(t, isRolloutCredential(apiKeyPrincipal(refreshed)))

	// The tracker used for long-lived requests keeps it too.
	tracker := f.srv.newAPIKeyTracker(refreshed)
	require.True(t, tracker.live(t.Context()))
	assert.True(t, isRolloutCredential(tracker.principal()))
}

func TestGenericAPIKeyRouteCannotSetKind(t *testing.T) {
	f := newRolloutCredFixture(t)
	for name, extra := range map[string]map[string]interface{}{
		"credential_kind":       {"credential_kind": "rollout"},
		"kind":                  {"kind": "rollout"},
		"nested metadata":       {"metadata": map[string]string{"credential_kind": "rollout"}},
		"credential_kind blank": {"credential_kind": ""},
	} {
		t.Run(name, func(t *testing.T) {
			resp := f.mintGeneric(rolloutCredentialPermissions, extra)
			rec, err := f.srv.readAPIKeyRecord(t.Context(), rolloutCredTestTenant, hashAPIKey(resp.Data.Key))
			require.NoError(t, err)
			require.NotNil(t, rec)
			assert.NotContains(t, rec.Metadata, "credential_kind", "an ordinary key has no kind")
			assert.False(t, isRolloutCredential(f.principalFor(resp.Data.Key)))
			f.dropCache()
			assert.False(t, isRolloutCredential(f.principalFor(resp.Data.Key)), "nor after a reload")
		})
	}
}

// TestCredentialKindWrittenOnlyByRolloutCredentialRoute is a source scan, in the manner
// of TestContentApprovalNamespaces_OnlyStoreWrites: across every non-test Go file under
// features, pkg and cmd, the literal credential_kind appears in exactly one file, and
// the constant that carries it is used as a key to write a value (a composite-literal
// key or an index assignment) in that file only.
func TestCredentialKindWrittenOnlyByRolloutCredentialRoute(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	literal := map[string]bool{}
	constWrites := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range []string{"features", "pkg", "cmd"} {
		require.NoError(t, filepath.Walk(filepath.Join(root, dir), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			isKey := func(e ast.Expr) bool {
				switch k := e.(type) {
				case *ast.Ident:
					return k.Name == "metadataKeyCredentialKind"
				case *ast.BasicLit:
					v, uerr := strconv.Unquote(k.Value)
					return k.Kind == token.STRING && uerr == nil && v == "credential_kind"
				}
				return false
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if v, uerr := strconv.Unquote(x.Value); x.Kind == token.STRING && uerr == nil && v == "credential_kind" {
						literal[rel] = true
					}
				case *ast.KeyValueExpr:
					if isKey(x.Key) {
						constWrites[rel] = true
					}
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						if ix, ok := lhs.(*ast.IndexExpr); ok && isKey(ix.Index) {
							constWrites[rel] = true
						}
					}
				}
				return true
			})
			return nil
		}))
	}
	keys := func(m map[string]bool) []string {
		var out []string
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	assert.Equal(t, []string{"features/controller/api/handlers_rollout_credentials.go"}, keys(literal),
		"the credential_kind literal belongs to the rollout credential route only")
	assert.Equal(t, []string{"features/controller/api/handlers_rollout_credentials.go"}, keys(constWrites),
		"only the rollout credential route writes the kind")

	// The generic mint path passes no extra metadata, and no registered route other than
	// POST /rollout-credentials reaches the handler.
	srv := setupTestServer(t)
	var routes []string
	require.NoError(t, srv.router.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, _ := r.GetPathTemplate()
		if strings.Contains(tpl, "rollout-credentials") {
			m, _ := r.GetMethods()
			routes = append(routes, strings.Join(m, ",")+" "+tpl)
		}
		return nil
	}))
	assert.Equal(t, []string{"POST /api/v1/rollout-credentials"}, routes)
}

func TestSamePermissionsViaGenericRouteIsNotRolloutCredential(t *testing.T) {
	f := newRolloutCredFixture(t)
	resp := f.mintGeneric(rolloutCredentialPermissions, nil)
	p := f.principalFor(resp.Data.Key)
	assert.ElementsMatch(t, rolloutCredentialPermissions, p.Permissions)
	assert.Empty(t, p.CredentialKind)
	assert.False(t, isRolloutCredential(p))

	f.dropCache()
	assert.False(t, isRolloutCredential(f.principalFor(resp.Data.Key)))
}

func TestThreeOfFourKeyIsNotRolloutCredential(t *testing.T) {
	f := newRolloutCredFixture(t)
	for _, drop := range rolloutCredentialPermissions {
		var three []string
		for _, p := range rolloutCredentialPermissions {
			if p != drop {
				three = append(three, p)
			}
		}
		resp := f.mintGeneric(three, nil)
		assert.False(t, isRolloutCredential(f.principalFor(resp.Data.Key)), "without %s", drop)
	}
}

func TestSupersetKeyIsNotRolloutCredential(t *testing.T) {
	f := newRolloutCredFixture(t)
	resp := f.mintGeneric(append([]string{"steward:read"}, rolloutCredentialPermissions...), nil)
	p := f.principalFor(resp.Data.Key)
	assert.Len(t, p.Permissions, 5)
	assert.False(t, isRolloutCredential(p))

	assert.False(t, isRolloutCredential(nil))
	assert.False(t, isRolloutCredential(&Principal{ID: "human", Permissions: rolloutCredentialPermissions}))
	assert.False(t, isRolloutCredential(&Principal{CredentialKind: "Rollout"}), "the kind is matched exactly")
	assert.True(t, isRolloutCredential(&Principal{CredentialKind: "rollout"}))
}

func TestCreateRolloutCredentialRefusesCallerWithoutPermissions(t *testing.T) {
	f := newRolloutCredFixture(t)
	for _, missing := range rolloutCredentialPermissions {
		t.Run(missing, func(t *testing.T) {
			p := rolloutCredAdmin()
			var perms []string
			for _, have := range p.Permissions {
				if have != missing {
					perms = append(perms, have)
				}
			}
			p.Permissions = perms
			rec := f.post(rolloutBody(time.Now().Add(time.Hour)), p, true)
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "PERMISSION_ESCALATION")
		})
	}
	assert.Empty(t, f.srv.apiKeys, "nothing is minted for a caller without the permissions")
	assert.Empty(t, auditEntriesByAction(t, f.srv, "rollout_credential_created"))

	// Holding the create permission alone is not enough; an implicit admin is.
	only := &Principal{ID: "only-create", Assurance: session.AssuranceStrong, TenantID: rolloutCredTestTenant, Permissions: []string{"rollout-credential:create"}}
	assert.Equal(t, http.StatusForbidden, f.post(rolloutBody(time.Now().Add(time.Hour)), only, true).Code)
	admin := &Principal{ID: "root-admin", Assurance: session.AssuranceStrong, TenantID: rolloutCredTestTenant, ImplicitAdmin: true}
	assert.Equal(t, http.StatusCreated, f.post(rolloutBody(time.Now().Add(time.Hour)), admin, true).Code)
}

func TestRolloutCredentialRefusesOverLimitExpiry(t *testing.T) {
	f := newRolloutCredFixture(t)
	assert.Equal(t, 90*24*time.Hour, rolloutCredentialMaxExpiry)

	rec := f.post(rolloutBody(time.Now().Add(rolloutCredentialMaxExpiry+time.Hour)), rolloutCredAdmin(), true)
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "EXPIRY_TOO_LONG")
	assert.Empty(t, f.srv.apiKeys)
	assert.Empty(t, auditEntriesByAction(t, f.srv, "rollout_credential_created"))

	rec = f.post(rolloutBody(time.Now().Add(rolloutCredentialMaxExpiry-time.Hour)), rolloutCredAdmin(), true)
	assert.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
}

// TestRolloutCredentialReachIsLimited: a rollout credential reaches the routes its four
// permissions gate and nothing else, including the routes that mint keys.
func TestRolloutCredentialReachIsLimited(t *testing.T) {
	f := newRolloutCredFixture(t)
	key := f.mint().Data.Key

	allowed := []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/installer/steward-binaries/1.0.0/linux/amd64", ""},
		{http.MethodPost, "/api/v1/installer/steward-binaries/1.0.0/linux/amd64", "{}"},
		{http.MethodPost, "/api/v1/rollout", "{}"},
		{http.MethodGet, "/api/v1/rollout/rollout-1", ""},
		{http.MethodPost, "/api/v1/rollout/rollout-1/halt", ""},
		{http.MethodPost, "/api/v1/stewards/upgrade", "{}"},
		{http.MethodGet, "/api/v1/stewards/upgrade/upgrade-1", ""},
		{http.MethodPost, "/api/v1/stewards/upgrade/upgrade-1/rollback", ""},
	}
	for _, c := range allowed {
		rec := f.callWithKey(f.srv.router, c.method, c.path, key, c.body)
		assert.NotContains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
	}
	rec := f.callWithKey(f.srv.metricsRouter, http.MethodPost, "/api/v1/monitoring/markers", key, "{}")
	assert.NotContains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, rec.Code, "markers: %s", rec.Body.String())

	denied := []struct{ method, path, body string }{
		{http.MethodPost, "/api/v1/api-keys", `{"name":"x","permissions":["steward:read"]}`},
		{http.MethodPost, "/api/v1/config/push", "{}"},
		{http.MethodPost, "/api/v1/rollout-credentials", rolloutBody(time.Now().Add(time.Hour))},
		{http.MethodGet, "/api/v1/api-keys", ""},
		{http.MethodGet, "/api/v1/stewards", ""},
		{http.MethodPut, "/api/v1/rollout-settings/unattended", `{"enabled":true}`},
	}
	for _, c := range denied {
		rec := f.callWithKey(f.srv.router, c.method, c.path, key, c.body)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s: %s", c.method, c.path, rec.Body.String())
	}
	f.srv.mu.RLock()
	before := len(f.srv.apiKeys)
	f.srv.mu.RUnlock()
	assert.Equal(t, 1, before, "the refused mint routes created no key")
}

func TestRolloutCredentialRevocation(t *testing.T) {
	f := newRolloutCredFixture(t)
	resp := f.mint()
	key := resp.Data.Key
	path := "/api/v1/installer/steward-binaries/1.0.0/linux/amd64"

	rec := f.callWithKey(f.srv.router, http.MethodGet, path, key, "")
	require.NotEqual(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/api-keys/"+resp.Data.ID, bytes.NewReader(nil))
	req = mux.SetURLVars(withPrincipal(req, rolloutCredAdmin()), map[string]string{"id": resp.Data.ID})
	del := httptest.NewRecorder()
	f.srv.handleDeleteAPIKey(del, req)
	require.Equal(t, http.StatusOK, del.Code, del.Body.String())

	rec = f.callWithKey(f.srv.router, http.MethodGet, path, key, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "the next request after revocation is refused")
	rec = f.callWithKey(f.srv.metricsRouter, http.MethodPost, "/api/v1/monitoring/markers", key, "{}")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
