// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestCallerTenantFilter guards Issue #4665: "" (no tenant filter) only for an
// explicit root caller or a context marked system-internal; a tenant caller gets
// its own tenant; anything else gets the noTenantScope sentinel, which matches no
// tenant.
func TestCallerTenantFilter(t *testing.T) {
	bg := context.Background()
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"root scope", withCallerTenant(bg, ""), ""},
		{"tenant scope", withCallerTenant(bg, "tenant-a"), "tenant-a"},
		{"tenant ID only", context.WithValue(bg, ctxkeys.TenantID, "tenant-a"), "tenant-a"},
		{"system-internal", ctxkeys.WithSystem(bg), ""},
		{"no caller", bg, noTenantScope},
		{"empty tenant ID", context.WithValue(bg, ctxkeys.TenantID, ""), noTenantScope},
		{"unset scope", context.WithValue(bg, ctxkeys.TenantScopeKey, ctxkeys.TenantScope{}), noTenantScope},
		{"empty-path tenant scope", context.WithValue(bg, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope("")), noTenantScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, callerTenantFilter(tc.ctx))
		})
	}
}

// listCaller is a caller shape the list-site table runs every handler under.
type listCaller struct {
	name string
	ctx  func(context.Context) context.Context
	// want is the set of tenants whose records the caller sees.
	want []string
}

var listCallers = []listCaller{
	{"root", func(ctx context.Context) context.Context {
		return context.WithValue(withCallerTenant(ctx, ""), principalContextKey, &Principal{ID: "root-op", GlobalScope: true, TenantID: testRootTenantID})
	}, []string{"tenant-a", "tenant-b"}},
	{"tenant", func(ctx context.Context) context.Context {
		return context.WithValue(withCallerTenant(ctx, "tenant-a"), principalContextKey, &Principal{ID: "tenant-op", TenantID: "tenant-a"})
	}, []string{"tenant-a"}},
	{"no scope", func(ctx context.Context) context.Context {
		return context.WithValue(ctx, principalContextKey, &Principal{ID: "unscoped"})
	}, nil},
}

// TestCallerTenantFilter_ListSites runs the account and session list handlers —
// two of the sites that scope reads through callerTenantFilter — under a root, a
// tenant and a scopeless caller (Issue #4665): root sees every tenant, a tenant
// caller its own, and a caller with no scope nothing.
func TestCallerTenantFilter_ListSites(t *testing.T) {
	t.Run("accounts", func(t *testing.T) {
		server := setupTestServer(t)
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
				Username: "list-" + tenant, TenantID: tenant, Permissions: []string{"steward:list"},
			})
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		}
		for _, c := range listCallers {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
				req = req.WithContext(c.ctx(req.Context()))
				rec := httptest.NewRecorder()
				server.handleListAccounts(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var resp struct {
					Data []AccountInfo `json:"data"`
				}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				assert.Equal(t, c.want, tenantsOf(resp.Data, func(a AccountInfo) string { return a.TenantID }))
			})
		}
	})

	t.Run("sessions", func(t *testing.T) {
		server, mgr, _ := setupTestServerWithSession(t)
		issued := map[string]string{}
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			sess, _, err := mgr.Issue(context.Background(), "op-"+tenant, "list-"+tenant, tenant)
			require.NoError(t, err)
			issued[sess.ID] = tenant
		}
		for _, c := range listCallers {
			t.Run(c.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
				req = req.WithContext(c.ctx(req.Context()))
				rec := httptest.NewRecorder()
				server.handleSessionList(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				var resp sessionListResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
				assert.Equal(t, c.want, tenantsOf(resp.Sessions, func(s sessionListItem) string { return issued[s.SessionID] }))
			})
		}
	})
}

// tenantsOf returns the sorted, de-duplicated tenants of items, or nil for none.
func tenantsOf[T any](items []T, tenant func(T) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		if t := tenant(it); t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// ---- tenantReadScope / authorizeRecordRead (Issue #4714) ----

const readRoute = "TEST /records"

// readScopeFixture is a server with root > msp-r > client-r (and msp-other), the real
// tenant manager, and a SQLite crossing store.
func readScopeFixture(t *testing.T, logger logging.Logger) *Server {
	t.Helper()
	server := seedRootTenant(t, setupCrossingTestServerWithLogger(t, logger))
	ctx := context.Background()
	for _, tn := range []struct{ id, parent string }{
		{"msp-r", testRootTenantID}, {"client-r", "msp-r"}, {"msp-other", testRootTenantID}, {"client-other", "msp-other"},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: tn.id, ParentID: tn.parent})
		require.NoError(t, err)
	}
	return server
}

func putCrossing(t *testing.T, server *Server, c *business.TenantCrossing) {
	t.Helper()
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now.Add(-time.Minute)
	}
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = now.Add(time.Hour)
	}
	if c.GrantedBy == "" {
		c.GrantedBy = "granter"
	}
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), c))
}

func grantOn(id, tenantID string) *business.TenantCrossing {
	return &business.TenantCrossing{ID: id, TenantID: tenantID, Kind: business.TenantCrossingKindGrant}
}

func breakGlassFor(id, tenantID, principal string) *business.TenantCrossing {
	return &business.TenantCrossing{ID: id, TenantID: tenantID, PrincipalID: principal,
		Kind: business.TenantCrossingKindBreakGlass, Justification: "fixture"}
}

func readRequest(principal *Principal, scope ctxkeys.TenantScope) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/records", nil)
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, principal.TenantID)
	ctx = context.WithValue(ctx, principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	return req.WithContext(ctx)
}

func TestTenantReadScope_DecisionTable(t *testing.T) {
	server := readScopeFixture(t, logging.NewNoopLogger())
	ctx := context.Background()
	operator := boundRootOperator("reader")
	root := ctxkeys.NewRootScope()

	revoked := grantOn("g-revoked", "msp-other")
	putCrossing(t, server, revoked)
	require.NoError(t, server.tenantCrossingStore.RevokeTenantCrossing(ctx, revoked.ID))

	cases := []struct {
		name      string
		setup     func()
		principal *Principal
		scope     ctxkeys.TenantScope
		want      map[string]bool
	}{
		{"no crossing", func() {}, operator, root,
			map[string]bool{testRootTenantID: true, "": true, "msp-r": false, "client-r": false}},
		{"active grant on the MSP", func() { putCrossing(t, server, grantOn("g1", "msp-r")) }, operator, root,
			map[string]bool{testRootTenantID: true, "msp-r": true, "client-r": true, "msp-other": false}},
		{"grant admits another root principal", func() {}, boundRootOperator("someone-else"), root,
			map[string]bool{"msp-r": true, "client-r": true, "msp-other": false}},
		{"own break-glass", func() { putCrossing(t, server, breakGlassFor("b1", "msp-other", operator.ID)) }, operator, root,
			map[string]bool{"msp-other": true, "client-other": true}},
		{"another principal's break-glass", func() {}, boundRootOperator("third"), root,
			map[string]bool{"msp-other": false, "client-other": false}},
		{"expired", func() {
			c := grantOn("g-expired", "client-other")
			c.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
			c.ExpiresAt = time.Now().UTC().Add(-time.Hour)
			putCrossing(t, server, c)
		}, boundRootOperator("fourth"), root, map[string]bool{"client-other": false}},
		{"pending", func() {
			c := breakGlassFor("b-pending", "client-other", "fifth")
			c.ApprovalState = business.TenantCrossingApprovalPending
			putCrossing(t, server, c)
		}, boundRootOperator("fifth"), root, map[string]bool{"client-other": false}},
		{"unrestricted cert admin", func() {}, &Principal{ID: "bootstrap", GlobalScope: true, CertSerial: "01"}, root,
			map[string]bool{"msp-r": true, "client-other": true, "no-such-tenant": true}},
		{"tenant-scoped caller", func() {}, &Principal{ID: "t", TenantID: "msp-r"}, ctxkeys.NewTenantScope("msp-r"),
			map[string]bool{"msp-r": true, "client-r": true, "msp-other": false, testRootTenantID: false, "": false}},
		{"unknown tenant", func() {}, operator, root, map[string]bool{"no-such-tenant": false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			rs := server.tenantReadScope(readRequest(tc.principal, tc.scope), readRoute)
			for tn, want := range tc.want {
				assert.Equal(t, want, rs.Allows(tn), "tenant %q", tn)
				// The helper and the write-side decision must never drift.
				req := readRequest(tc.principal, tc.scope)
				assert.Equal(t, server.tenantAccessForScope(req.Context(), tc.scope, tn, readRoute) == tenantAuthAllowed,
					rs.Allows(tn), "parity with tenantAccessForScope for %q", tn)
			}
		})
	}
}

func TestTenantReadScope_CrossingTenants(t *testing.T) {
	server := readScopeFixture(t, logging.NewNoopLogger())
	ctx := context.Background()
	operator := boundRootOperator("ct-op")
	root := ctxkeys.NewRootScope()

	putCrossing(t, server, grantOn("ct-grant", "msp-r"))
	putCrossing(t, server, breakGlassFor("ct-bg", "client-other", operator.ID))
	putCrossing(t, server, breakGlassFor("ct-other-bg", "msp-other", "someone"))
	exp := breakGlassFor("ct-exp", "msp-other", operator.ID)
	exp.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	exp.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	putCrossing(t, server, exp)
	rev := breakGlassFor("ct-rev", "msp-other", operator.ID)
	putCrossing(t, server, rev)
	require.NoError(t, server.tenantCrossingStore.RevokeTenantCrossing(ctx, rev.ID))
	pend := breakGlassFor("ct-pend", "msp-other", operator.ID)
	pend.ApprovalState = business.TenantCrossingApprovalPending
	putCrossing(t, server, pend)

	rs := server.tenantReadScope(readRequest(operator, root), readRoute)
	assert.Equal(t, []string{"client-other", "msp-r"}, rs.CrossingTenants())
	assert.False(t, rs.RootTenantOnly())

	none := server.tenantReadScope(readRequest(boundRootOperator("nobody-new"), root), readRoute)
	assert.Equal(t, []string{"msp-r"}, none.CrossingTenants(), "a grant admits any root principal")

	cert := server.tenantReadScope(readRequest(&Principal{ID: "c", GlobalScope: true, CertSerial: "01"}, root), readRoute)
	assert.Empty(t, cert.CrossingTenants())
	assert.False(t, cert.RootTenantOnly())

	tenantCaller := server.tenantReadScope(readRequest(&Principal{ID: "t", TenantID: "msp-r"}, ctxkeys.NewTenantScope("msp-r")), readRoute)
	assert.Empty(t, tenantCaller.CrossingTenants())
	assert.False(t, tenantCaller.RootTenantOnly())

	// With every crossing gone the caller is confined to root.
	bare := readScopeFixture(t, logging.NewNoopLogger())
	assert.True(t, bare.tenantReadScope(readRequest(operator, root), readRoute).RootTenantOnly())
}

func TestTenantReadScope_GrantUseAuditedOncePerPrincipal(t *testing.T) {
	server := readScopeFixture(t, logging.NewNoopLogger())
	ctx := context.Background()
	root := ctxkeys.NewRootScope()
	putCrossing(t, server, grantOn("audit-grant", "msp-r"))

	countUsed := func() int {
		require.NoError(t, server.auditManager.Flush(ctx))
		entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "msp-r"})
		require.NoError(t, err)
		n := 0
		for _, e := range entries {
			if e.Action == "tenant.crossing_grant_used" {
				n++
			}
		}
		return n
	}

	alice := boundRootOperator("alice")
	for i := 0; i < 2; i++ {
		rs := server.tenantReadScope(readRequest(alice, root), readRoute)
		assert.True(t, rs.Allows("client-r"))
		assert.True(t, rs.Allows("msp-r"))
	}
	assert.Equal(t, 1, countUsed(), "two reads under one grant by one principal write one entry")

	rs := server.tenantReadScope(readRequest(boundRootOperator("bob"), root), readRoute)
	assert.True(t, rs.Allows("client-r"))
	assert.Equal(t, 2, countUsed(), "a second principal writes its own entry")

	// A break-glass on the same tenant is the reason for the read, not the grant.
	putCrossing(t, server, breakGlassFor("carol-bg", "msp-r", "carol"))
	rs = server.tenantReadScope(readRequest(boundRootOperator("carol"), root), readRoute)
	assert.True(t, rs.Allows("client-r"))
	assert.Equal(t, 2, countUsed(), "a read allowed by the principal's own break-glass is not grant use")
}

// countingCrossingStore wraps the real crossing store and counts calls.
type countingCrossingStore struct {
	business.TenantCrossingStore
	calls atomic.Int64
}

func (c *countingCrossingStore) ListActiveTenantCrossings(ctx context.Context, now time.Time) ([]*business.TenantCrossing, error) {
	c.calls.Add(1)
	return c.TenantCrossingStore.ListActiveTenantCrossings(ctx, now)
}

func (c *countingCrossingStore) HasActiveTenantCrossing(ctx context.Context, p, tn string) (bool, error) {
	c.calls.Add(1)
	return c.TenantCrossingStore.HasActiveTenantCrossing(ctx, p, tn)
}

// countingTenantStore wraps the real tenant store and counts path lookups.
type countingTenantStore struct {
	tenant.Store
	paths atomic.Int64
}

func (c *countingTenantStore) GetTenantPath(ctx context.Context, id string) ([]string, error) {
	c.paths.Add(1)
	return c.Store.GetTenantPath(ctx, id)
}

func TestTenantReadScope_CostBound(t *testing.T) {
	server := readScopeFixture(t, logging.NewNoopLogger())
	ctx := context.Background()
	v, ok := testTenantStores.Load(server.tenantManager)
	require.True(t, ok)
	counting := &countingTenantStore{Store: v.(tenant.Store)}
	server.tenantManager = tenant.NewManager(counting, nil)

	const tenants = 500
	ids := make([]string, tenants)
	for i := range ids {
		ids[i] = fmt.Sprintf("bulk-%d", i)
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: ids[i], ParentID: "msp-r"})
		require.NoError(t, err)
	}
	putCrossing(t, server, grantOn("bulk-grant", "msp-r"))
	crossings := &countingCrossingStore{TenantCrossingStore: server.tenantCrossingStore}
	server.tenantCrossingStore = crossings
	counting.paths.Store(0)

	rs := server.tenantReadScope(readRequest(boundRootOperator("bulk-op"), ctxkeys.NewRootScope()), readRoute)
	allowed := 0
	for row := 0; row < 20000; row++ {
		if rs.Allows(ids[row%tenants]) {
			allowed++
		}
	}
	assert.Equal(t, 20000, allowed)
	assert.EqualValues(t, 1, crossings.calls.Load(), "crossings are fetched once per request, not per row")
	assert.LessOrEqual(t, counting.paths.Load(), int64(tenants), "at most one path lookup per distinct tenant")
}

func TestTenantReadScope_RefusalsLogNoPerTenantInfo(t *testing.T) {
	logger := &captureAllLogger{}
	server := readScopeFixture(t, logger)
	rs := server.tenantReadScope(readRequest(boundRootOperator("quiet"), ctxkeys.NewRootScope()), readRoute)
	before := len(logger.captured())
	for _, tn := range []string{"msp-r", "client-r", "msp-other", "client-other", "msp-r"} {
		assert.False(t, rs.Allows(tn))
	}
	rs.LogSummary()
	rs.LogSummary()
	added := logger.captured()[before:]
	assert.NotContains(t, added, "refused at the crossing boundary")
	assert.Equal(t, 1, strings.Count(added, "Tenant read scope skipped tenants"), "one summary line per request")
	assert.Contains(t, added, readRoute)
}

func TestAuthorizeRecordRead(t *testing.T) {
	server := readScopeFixture(t, logging.NewNoopLogger())
	root := ctxkeys.NewRootScope()
	putCrossing(t, server, grantOn("rr-grant", "msp-r"))

	run := func(principal *Principal, scope ctxkeys.TenantScope, tn string) (bool, *httptest.ResponseRecorder, bool) {
		rec := httptest.NewRecorder()
		notFound := false
		ok := server.authorizeRecordRead(rec, readRequest(principal, scope), tn, readRoute, func() {
			notFound = true
			server.writeErrorResponse(rec, http.StatusNotFound, "not found", "RECORD_NOT_FOUND")
		})
		return ok, rec, notFound
	}

	ok, _, nf := run(boundRootOperator("rr-op"), root, "client-r")
	assert.True(t, ok)
	assert.False(t, nf)

	ok, rec, nf := run(boundRootOperator("rr-op"), root, "client-other")
	assert.False(t, ok)
	assert.False(t, nf, "the challenge replaces notFound")
	assertCrossingChallenge(t, rec, "client-other")

	ok, rec, nf = run(boundRootOperator("rr-op"), root, "no-such-tenant")
	assert.False(t, ok)
	assert.True(t, nf)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	ok, _, nf = run(&Principal{ID: "t", TenantID: "msp-other"}, ctxkeys.NewTenantScope("msp-other"), "client-r")
	assert.False(t, ok)
	assert.True(t, nf, "a tenant caller outside its subtree gets the handler's not-found")

	ok, _, _ = run(&Principal{ID: "c", GlobalScope: true, CertSerial: "01"}, root, "client-other")
	assert.True(t, ok)
}

// failingCrossingStore fails the active-crossing query.
type failingCrossingStore struct{ business.TenantCrossingStore }

func (failingCrossingStore) ListActiveTenantCrossings(context.Context, time.Time) ([]*business.TenantCrossing, error) {
	return nil, errors.New("crossing store unavailable")
}

func TestTenantReadScope_StoreErrorFailsClosed(t *testing.T) {
	server := readScopeFixture(t, logging.NewNoopLogger())
	putCrossing(t, server, grantOn("fc-grant", "msp-r"))
	server.tenantCrossingStore = failingCrossingStore{server.tenantCrossingStore}
	operator := boundRootOperator("fc-op")

	rs := server.tenantReadScope(readRequest(operator, ctxkeys.NewRootScope()), readRoute)
	assert.False(t, rs.Allows("client-r"), "a list skips the row")
	assert.True(t, rs.Allows(testRootTenantID), "root's own records stay readable")
	assert.True(t, rs.RootTenantOnly())
	assert.Empty(t, rs.CrossingTenants())

	rec := httptest.NewRecorder()
	ok := server.authorizeRecordRead(rec, readRequest(operator, ctxkeys.NewRootScope()), "client-r", readRoute, func() {
		t.Fatal("a store error must challenge, not 404")
	})
	assert.False(t, ok)
	assertCrossingChallenge(t, rec, "client-r")
}
