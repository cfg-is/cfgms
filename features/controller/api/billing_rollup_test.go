// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// countingStewardStore wraps a real steward store and counts ListStewards calls.
type countingStewardStore struct {
	business.StewardStore
	lists atomic.Int32
}

func (c *countingStewardStore) ListStewards(ctx context.Context) ([]*business.StewardRecord, error) {
	c.lists.Add(1)
	return c.StewardStore.ListStewards(ctx)
}

// seedBillingTree builds root -> bill-msp-a -> {bill-a1 -> bill-a1x -> bill-a1xy, bill-a2},
// root -> bill-msp-b -> bill-b1, plus bill-msp-a-evil (parent root; ID has bill-msp-a as a
// string prefix but is not its descendant). Returns the counting steward store.
func seedBillingTree(t *testing.T, server *Server) *countingStewardStore {
	t.Helper()
	ctx := context.Background()
	for _, tr := range []*tenant.TenantRequest{
		{ID: "bill-msp-a", ParentID: testRootTenantID},
		{ID: "bill-a1", ParentID: "bill-msp-a"},
		{ID: "bill-a1x", ParentID: "bill-a1"},
		{ID: "bill-a1xy", ParentID: "bill-a1x"},
		{ID: "bill-a2", ParentID: "bill-msp-a"},
		{ID: "bill-msp-b", ParentID: testRootTenantID},
		{ID: "bill-b1", ParentID: "bill-msp-b"},
		{ID: "bill-msp-a-evil", ParentID: testRootTenantID},
	} {
		_, err := server.tenantManager.CreateTenant(ctx, tr)
		require.NoError(t, err)
	}
	st := &countingStewardStore{StewardStore: newTestSQLiteStewardStore(t)}
	server.SetStewardStore(st)
	return st
}

func seedBillingAccount(t *testing.T, server *Server, username, tenantID string, rootScope, disabled bool) {
	t.Helper()
	acct := &account{
		ID: "id-" + username, Username: username, TenantID: tenantID,
		RootScope: rootScope, Disabled: disabled, CreatedAt: time.Now(),
	}
	require.NoError(t, server.persistAccount(context.Background(), acct, "test"))
}

func seedBillingStewards(t *testing.T, st business.StewardStore) {
	t.Helper()
	// bill-msp-a own: 1; bill-a1: 2; bill-a1xy (3 levels deep): 1; bill-a2: 0
	seedSteward(t, st, &business.StewardRecord{ID: "s-a-own", TenantID: "bill-msp-a", Status: business.StewardStatusActive, Platform: "linux", Version: "1.0"})
	seedSteward(t, st, &business.StewardRecord{ID: "s-a1-1", TenantID: "bill-a1", Status: business.StewardStatusLost, Platform: "windows", Version: "1.0"})
	seedSteward(t, st, &business.StewardRecord{ID: "s-a1-2", TenantID: "bill-a1", Status: business.StewardStatusRegistered, Platform: "Darwin", Version: "2.0", Hidden: true})
	seedSteward(t, st, &business.StewardRecord{ID: "s-a1xy", TenantID: "bill-a1xy", Status: business.StewardStatusActive, Platform: "freebsd"})
	for _, s := range []business.StewardStatus{
		business.StewardStatusDeregistered, business.StewardStatusRevoked,
		business.StewardStatusArchived, business.StewardStatusDormant,
	} {
		seedSteward(t, st, &business.StewardRecord{ID: "s-term-" + string(s), TenantID: "bill-a1", Status: s})
	}
	// MSP B and the prefix-lookalike tenant
	seedSteward(t, st, &business.StewardRecord{ID: "s-b1", TenantID: "bill-b1", Status: business.StewardStatusActive})
	seedSteward(t, st, &business.StewardRecord{ID: "s-evil", TenantID: "bill-msp-a-evil", Status: business.StewardStatusActive})
}

func TestAggregateBilling_InvariantAndIsolation(t *testing.T) {
	server := setupTestServer(t)
	st := seedBillingTree(t, server)
	seedBillingStewards(t, st)
	seedBillingAccount(t, server, "tech-a-own", "bill-msp-a", false, false)
	seedBillingAccount(t, server, "tech-a1", "bill-a1", false, false)
	seedBillingAccount(t, server, "tech-a1xy", "bill-a1xy", false, false)
	seedBillingAccount(t, server, "tech-a-disabled", "bill-a1", false, true)
	seedBillingAccount(t, server, "tech-b1", "bill-b1", false, false)
	seedBillingAccount(t, server, "tech-evil", "bill-msp-a-evil", false, false)

	a, err := server.aggregateBilling(context.Background(), "bill-msp-a")
	require.NoError(t, err)

	assert.Equal(t, 4, a.EndpointCount, "active+lost+registered(hidden)+3-deep active; terminal excluded")
	assert.Equal(t, 3, a.TechCount, "own + a1 + 3-deep; disabled excluded")
	assert.Equal(t, billingCounts{Techs: 1, Endpoints: 1}, a.MSPOwn)

	sumT, sumE := a.MSPOwn.Techs, a.MSPOwn.Endpoints
	byID := map[string]billingClient{}
	for _, c := range a.Clients {
		sumT += c.Techs
		sumE += c.Endpoints
		byID[c.ID] = c
	}
	assert.Equal(t, a.EndpointCount, sumE)
	assert.Equal(t, a.TechCount, sumT)
	assert.Equal(t, 2, a.ClientCount)
	require.Len(t, a.Clients, 2, "3-deep tenant is rolled into bill-a1, never listed")
	assert.Equal(t, billingClient{ID: "bill-a1", Name: byID["bill-a1"].Name, BillingLabel: byID["bill-a1"].BillingLabel, Techs: 2, Endpoints: 3}, byID["bill-a1"])
	assert.NotEmpty(t, byID["bill-a1"].BillingLabel)
	assert.Equal(t, billingClient{ID: "bill-a2", Name: byID["bill-a2"].Name, BillingLabel: byID["bill-a2"].BillingLabel}, byID["bill-a2"], "client with no accounts or stewards: zero, no error")
	assert.NotContains(t, byID, "bill-a1xy")

	assert.Equal(t, 2, a.Metrics.EndpointsOnline)
	assert.Equal(t, 1, a.Metrics.EndpointsOffline)
	assert.Equal(t, 1, a.Metrics.EndpointsPending)
	assert.Equal(t, platformCounts{Windows: 1, Linux: 1, Darwin: 1, Other: 1}, a.Metrics.EndpointsByPlatform)
	assert.Equal(t, map[string]int{"1.0": 2, "2.0": 1, unknownStewardVersion: 1}, a.Metrics.EndpointsByVersion)

	b, err := server.aggregateBilling(context.Background(), "bill-msp-b")
	require.NoError(t, err)
	assert.Equal(t, 1, b.EndpointCount, "MSP A's stewards never appear in MSP B")
	assert.Equal(t, 1, b.TechCount)
	require.Len(t, b.Clients, 1)

	evil, err := server.aggregateBilling(context.Background(), "bill-msp-a-evil")
	require.NoError(t, err)
	assert.Equal(t, 1, evil.EndpointCount, "ID-prefix lookalike is not an MSP A descendant (ParentID ancestry)")
	assert.Equal(t, 1, evil.TechCount)

	_, err = server.aggregateBilling(context.Background(), "no-such-tenant")
	assert.ErrorIs(t, err, errBillingTenantNotFound)
}

func TestAggregateBilling_RootScopeAndTenantlessAccountsCountNowhere(t *testing.T) {
	server := setupTestServer(t)
	seedBillingTree(t, server)
	seedBillingAccount(t, server, "root-scoped", "", true, false)
	seedBillingAccount(t, server, "tenantless", "", false, false)
	seedBillingAccount(t, server, "real", "bill-a1", false, false)

	rollup, err := server.rollupTenantCounts(context.Background())
	require.NoError(t, err)
	total := 0
	for _, tr := range rollup {
		total += tr.OwnTechs
	}
	assert.Equal(t, 1, total, "only the tenant-bound account counts")
	assert.Equal(t, 0, rollup[testRootTenantID].OwnTechs, "root-scope account is attributed to no tenant, root included")
	assert.Equal(t, 1, rollup[testRootTenantID].SubtreeTechs, "root's subtree holds only the tenant-bound account")
	assert.Equal(t, 1, rollup["bill-msp-a"].SubtreeTechs)
}

func TestBillingMetrics_JSONHasOnlyCountKeysAndNoIdentifiers(t *testing.T) {
	server := setupTestServer(t)
	st := seedBillingTree(t, server)
	seedSteward(t, st, &business.StewardRecord{
		ID: "steward-secret-id-77", TenantID: "bill-a1", Status: business.StewardStatusActive,
		Hostname: "distinctive-host.example", DeviceID: "devid-distinctive-0123", IPAddress: "203.0.113.77",
		Platform: "linux", Version: "3.1.4",
	})
	a, err := server.aggregateBilling(context.Background(), "bill-msp-a")
	require.NoError(t, err)

	raw, err := json.Marshal(a.Metrics)
	require.NoError(t, err)
	for _, leaked := range []string{"distinctive-host.example", "devid-distinctive-0123", "203.0.113.77", "steward-secret-id-77"} {
		assert.NotContains(t, string(raw), leaked)
	}
	var keys map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &keys))
	got := make([]string, 0, len(keys))
	for k := range keys {
		got = append(got, k)
	}
	assert.ElementsMatch(t, []string{
		"endpoints_online", "endpoints_offline", "endpoints_pending",
		"endpoints_by_platform", "endpoints_by_version",
	}, got)
	var platform map[string]int
	require.NoError(t, json.Unmarshal(keys["endpoints_by_platform"], &platform))
	assert.Len(t, platform, 4)
	assert.Equal(t, map[string]int{"3.1.4": 1}, func() map[string]int {
		var v map[string]int
		require.NoError(t, json.Unmarshal(keys["endpoints_by_version"], &v))
		return v
	}())
}

func TestRollupTenantCounts_ReadsStewardsOnce(t *testing.T) {
	server := setupTestServer(t)
	st := seedBillingTree(t, server)
	seedBillingStewards(t, st)

	rollup, err := server.rollupTenantCounts(context.Background())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rollup), 8, "counts for every tenant in the tree")
	assert.Equal(t, int32(1), st.lists.Load(), "one ListStewards for the whole tree")

	_, err = server.aggregateBilling(context.Background(), "bill-msp-a")
	require.NoError(t, err)
	assert.Equal(t, int32(2), st.lists.Load(), "one more read per aggregateBilling, never one per tenant")
}

func TestHandleListTenants_DeviceCountEqualsBillingEndpointCount(t *testing.T) {
	server := setupTestServer(t)
	st := seedBillingTree(t, server)
	seedBillingStewards(t, st)

	req := makeAdminRequest(t, http.MethodGet, "/api/v1/tenants", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	counts := deviceCountsFromListResponse(t, rec.Body.Bytes())

	for _, id := range []string{"bill-msp-a", "bill-a1", "bill-a1x", "bill-a1xy", "bill-a2", "bill-msp-b", "bill-b1", "bill-msp-a-evil", testRootTenantID} {
		a, err := server.aggregateBilling(context.Background(), id)
		require.NoError(t, err)
		assert.Equal(t, float64(a.EndpointCount), counts[id], "device_count == billing EndpointCount for %s", id)
	}
}

func TestHandleListTenants_ScopedDeviceCountsUnchanged(t *testing.T) {
	server := setupTestServer(t)
	st := seedBillingTree(t, server)
	seedBillingStewards(t, st)

	callerKey := NewEphemeralTestKey(t, server, []string{"tenant:list"}, "bill-msp-a", 5*time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req.Header.Set("X-API-Key", callerKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Values the #4590 in-handler roll-up produced for this fixture.
	assert.Equal(t, map[string]float64{
		"bill-msp-a": 4, "bill-a1": 3, "bill-a1x": 1, "bill-a1xy": 1, "bill-a2": 0,
	}, deviceCountsFromListResponse(t, rec.Body.Bytes()))
}

func TestSubtreeDeviceCounts_HiddenTenantExcludedFromVisibleAncestor(t *testing.T) {
	server := setupTestServer(t)
	st := seedBillingTree(t, server)
	seedBillingStewards(t, st)
	ctx := context.Background()
	all, err := server.tenantManager.ListTenants(ctx, &business.TenantFilter{})
	require.NoError(t, err)

	// A caller who sees bill-msp-a and bill-a1xy but not the tenants between them.
	var visible []*business.TenantData
	for _, td := range all {
		if td.ID == "bill-msp-a" || td.ID == "bill-a1xy" {
			visible = append(visible, td)
		}
	}
	counts, err := server.subtreeDeviceCounts(ctx, all, visible)
	require.NoError(t, err)
	assert.Equal(t, 2, counts["bill-msp-a"], "own (1) + visible descendant (1); hidden bill-a1's two stewards excluded")
	assert.Equal(t, 1, counts["bill-a1xy"])
}
