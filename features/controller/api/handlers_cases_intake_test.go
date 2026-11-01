// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
)

// newIntakeTestServer wires a real SQLite entity graph provider into a test server
// and returns both so tests can inject entities.
func newIntakeTestServer(t *testing.T) (*Server, *sqlite.SQLiteEntityGraphProvider) {
	t.Helper()
	p := newTestEntityGraphProvider(t)
	srv := setupTestServer(t)
	srv.SetEntityGraphProvider(p)
	return srv, p
}

// reportEntityWithClaims injects an entity with hostname and optional machineSID
// identity claims into the provider under the given tenant.
func reportEntityWithClaims(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, eid, tenant, hostname, machineSID string) {
	t.Helper()
	now := time.Now().UTC()
	payload := map[string]interface{}{
		"entity_kind":   "host",
		"owning_tenant": tenant,
		"hostname":      hostname,
	}
	if machineSID != "" {
		payload["machine_sid"] = machineSID
	}
	err := p.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:intake-reporter",
		Observations: []egtypes.Observation{
			{
				Source:     "test:intake-reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid,
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload:    payload,
			},
		},
	})
	require.NoError(t, err, "reportEntityWithClaims: %s", eid)
}

// splitEGProvider serves GetEntity from one entity graph provider and every other
// read from another. Both halves are real *sqlite.SQLiteEntityGraphProvider values;
// pairing a live provider with a closed one is how the tests reach the handler's
// two 500 branches independently — the errors are produced by the real SQLite
// driver ("sql: database is closed"), not synthesized.
type splitEGProvider struct {
	egReadProvider                // live provider serves ResolveIdentity and the rest
	getEntitySrc   egReadProvider // provider that serves GetEntity
}

func (p splitEGProvider) GetEntity(ctx context.Context, eid eginterfaces.EIDRef, opts eginterfaces.GetEntityOpts) (*egtypes.EntityView, error) {
	return p.getEntitySrc.GetEntity(ctx, eid, opts)
}

// newIntakeBody encodes claims as a JSON request body.
func newIntakeBody(t *testing.T, claims eginterfaces.IdentityClaims) *bytes.Buffer {
	t.Helper()
	data, err := json.Marshal(claims)
	require.NoError(t, err)
	return bytes.NewBuffer(data)
}

// ---- /api/v1/cases/intake-assist ----

func TestHandleCasesIntakeAssist_NoProvider_Returns503(t *testing.T) {
	srv := setupTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{Hostname: "some-pc"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleCasesIntakeAssist_EmptyClaims_Returns400(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "empty claims must return 400, not 200: %s", rec.Body.String())
}

func TestHandleCasesIntakeAssist_MACAddrsAllEmpty_Returns400(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{MACAddrs: []string{"", ""}}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code, "all-empty MACAddrs must return 400")
}

func TestHandleCasesIntakeAssist_InvalidJSON_Returns400(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		bytes.NewBufferString("not-json"))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleCasesIntakeAssist_NoPermission_Returns403(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"entity:read"}) // wrong permission

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{Hostname: "some-pc"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleCasesIntakeAssist_MatchingEntity_ReturnsCandidate(t *testing.T) {
	srv, p := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	// NewTestKey defaults to "test-tenant"; entity is in the same tenant.
	reportEntityWithClaims(t, p, "host:intake-pc1", "test-tenant", "intake-pc1", "")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{Hostname: "intake-pc1"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "matching entity must return 200: %s", rec.Body.String())
	var candidates []egtypes.EID
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
	require.Len(t, candidates, 1)
	assert.Equal(t, "host:intake-pc1", candidates[0].String())
}

func TestHandleCasesIntakeAssist_NoMatch_ReturnsEmptyList(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{Hostname: "no-such-host"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "no-match must return 200 with empty list: %s", rec.Body.String())
	var candidates []egtypes.EID
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
	assert.Empty(t, candidates)
}

// TestHandleCasesIntakeAssist_CrossTenantEIDDropped is the REQUIRED AC test (Issue #3604):
// an eid resolved by ResolveIdentity that lies outside the caller's tenant subtree
// must be silently dropped from the response — not returned and not surfaced as an error.
func TestHandleCasesIntakeAssist_CrossTenantEIDDropped(t *testing.T) {
	srv, p := newIntakeTestServer(t)

	// Entity owned by "other-tenant" — invisible to "test-tenant" callers.
	reportEntityWithClaims(t, p, "host:secret-pc", "other-tenant", "secret-hostname", "")

	apiKey := NewEphemeralTestKey(t, srv, []string{"case:intake-assist"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{Hostname: "secret-hostname"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	// Must be 200 with an empty list — not 404, not 403.
	// The cross-tenant eid is silently dropped (ADR-022 §7).
	require.Equal(t, http.StatusOK, rec.Code,
		"cross-tenant resolve must return 200 with empty list, not 404/403: %s", rec.Body.String())
	var candidates []egtypes.EID
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
	assert.Empty(t, candidates,
		"cross-tenant eid must be silently dropped, not returned: %v", candidates)
}

// TestHandleCasesIntakeAssist_MixedTenants_OnlyCallerEIDsReturned verifies that
// when ResolveIdentity returns eids from multiple tenants, only the eids owned by
// the caller's tenant are included in the response.
func TestHandleCasesIntakeAssist_MixedTenants_OnlyCallerEIDsReturned(t *testing.T) {
	srv, p := newIntakeTestServer(t)

	// Both entities share the same hostname claim; caller owns "test-tenant".
	reportEntityWithClaims(t, p, "host:intake-mix1", "test-tenant", "shared-hostname", "")
	reportEntityWithClaims(t, p, "host:intake-mix2", "rival-tenant", "shared-hostname", "")

	apiKey := NewEphemeralTestKey(t, srv, []string{"case:intake-assist"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{Hostname: "shared-hostname"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "mixed-tenant resolve must return 200: %s", rec.Body.String())
	var candidates []egtypes.EID
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
	require.Len(t, candidates, 1, "only the caller-tenant eid must be returned; rival-tenant eid must be dropped")
	assert.Equal(t, "host:intake-mix1", candidates[0].String())
}

// reportEntityWithMACs injects an entity whose mac_addrs index column is the
// comma-joined list of macs, matching the steward self-registration layout.
func reportEntityWithMACs(t *testing.T, p *sqlite.SQLiteEntityGraphProvider, eid, tenant string, macs []string) {
	t.Helper()
	now := time.Now().UTC()
	err := p.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: "test:intake-reporter",
		Observations: []egtypes.Observation{
			{
				Source:     "test:intake-reporter",
				ObservedAt: now,
				RecordedAt: now,
				Subject:    eid,
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind":   "host",
					"owning_tenant": tenant,
					"mac_addrs":     macs,
				},
			},
		},
	})
	require.NoError(t, err, "reportEntityWithMACs: %s", eid)
}

// postIntake sends an authenticated intake-assist request and returns the recorder.
func postIntake(t *testing.T, srv *Server, apiKey string, claims eginterfaces.IdentityClaims) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist", newIntakeBody(t, claims))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)
	return rec
}

// TestHandleCasesIntakeAssist_ResolveFailure_Returns500 exercises the ResolveIdentity
// error branch: the real SQLite provider is closed before the request, so the driver
// returns a genuine failure and the handler must answer 500 without leaking the
// underlying error text.
func TestHandleCasesIntakeAssist_ResolveFailure_Returns500(t *testing.T) {
	srv, p := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	require.NoError(t, p.Close(), "closing provider to induce a real resolve failure")

	rec := postIntake(t, srv, apiKey, eginterfaces.IdentityClaims{Hostname: "intake-pc1"})

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"a provider failure in ResolveIdentity must surface as 500: %s", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "sql:",
		"the provider error must not be echoed to the caller")
}

// TestHandleCasesIntakeAssist_EntityAccessFailure_Returns500 exercises the
// verifyEntityAccess error branch: ResolveIdentity succeeds against a live SQLite
// provider while GetEntity is served by a second, closed SQLite provider, so the
// per-eid tenant check fails for a reason that is not not-found.
func TestHandleCasesIntakeAssist_EntityAccessFailure_Returns500(t *testing.T) {
	live := newTestEntityGraphProvider(t)
	closed := newTestEntityGraphProvider(t)
	require.NoError(t, closed.Close(), "closing provider to induce a real GetEntity failure")

	srv := setupTestServer(t)
	srv.SetEntityGraphProvider(splitEGProvider{egReadProvider: live, getEntitySrc: closed})
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	// ResolveIdentity must return an eid so the access check actually runs.
	reportEntityWithClaims(t, live, "host:intake-access-fail", "test-tenant", "access-fail-pc", "")

	rec := postIntake(t, srv, apiKey, eginterfaces.IdentityClaims{Hostname: "access-fail-pc"})

	require.Equal(t, http.StatusInternalServerError, rec.Code,
		"a provider failure in the tenant access check must surface as 500: %s", rec.Body.String())
	assert.NotContains(t, rec.Body.String(), "host:intake-access-fail",
		"no eid may be disclosed when the access check could not be completed")
}

// TestHandleCasesIntakeAssist_WildcardMACClaim_Rejected verifies that a LIKE
// metacharacter in a MAC claim is rejected instead of being interpolated into the
// provider's unescaped `mac_addrs LIKE '%,%'` pattern, which would match every
// indexed multi-NIC host and hand a case:intake-assist principal a bulk
// intra-tenant eid enumeration primitive (CWE-155).
func TestHandleCasesIntakeAssist_WildcardMACClaim_Rejected(t *testing.T) {
	srv, p := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	// Multi-NIC hosts in the caller's own tenant: the enumeration target.
	reportEntityWithMACs(t, p, "host:intake-nic1", "test-tenant",
		[]string{"00:11:22:33:44:55", "00:11:22:33:44:66"})
	reportEntityWithMACs(t, p, "host:intake-nic2", "test-tenant",
		[]string{"00:AA:BB:CC:DD:EE", "00:AA:BB:CC:DD:FF"})

	for _, wildcard := range []string{"%", "%,%", "_", "00:11:22:33:44:_5"} {
		rec := postIntake(t, srv, apiKey, eginterfaces.IdentityClaims{MACAddrs: []string{wildcard}})

		require.Equal(t, http.StatusBadRequest, rec.Code,
			"MAC claim %q must be rejected as malformed: %s", wildcard, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "host:intake-nic",
			"wildcard MAC claim %q must not enumerate entities", wildcard)
	}
}

// TestHandleCasesIntakeAssist_WildcardTextClaims_Rejected verifies the same
// metacharacter rejection for the remaining claim fields, and that over-long
// values are rejected.
func TestHandleCasesIntakeAssist_WildcardTextClaims_Rejected(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	cases := map[string]eginterfaces.IdentityClaims{
		"hostname wildcard":        {Hostname: "%"},
		"hostname underscore":      {Hostname: "intake_pc1"},
		"hostname over-long":       {Hostname: strings.Repeat("a", 254)},
		"machine_sid wildcard":     {MachineSID: "S-1-5-21-%"},
		"guid wildcard":            {DirectoryObjectGUID: "%"},
		"serial wildcard":          {SerialNumber: "ABC%"},
		"cloud_object_id wildcard": {CloudObjectID: "%"},
	}
	for name, claims := range cases {
		t.Run(name, func(t *testing.T) {
			rec := postIntake(t, srv, apiKey, claims)
			assert.Equal(t, http.StatusBadRequest, rec.Code,
				"invalid claim must be rejected before reaching the provider: %s", rec.Body.String())
		})
	}
}

// TestHandleCasesIntakeAssist_TooManyMACs_Returns400 verifies the MACAddrs bound.
// Each accepted MAC adds four bound parameters and three unindexable LIKE
// predicates to the provider query, so an unbounded slice is a query-amplification
// primitive.
func TestHandleCasesIntakeAssist_TooManyMACs_Returns400(t *testing.T) {
	srv, _ := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	macs := make([]string, 0, maxIntakeMACClaims+1)
	for i := 0; i <= maxIntakeMACClaims; i++ {
		macs = append(macs, fmt.Sprintf("00:11:22:33:%02X:%02X", i/256, i%256))
	}

	rec := postIntake(t, srv, apiKey, eginterfaces.IdentityClaims{MACAddrs: macs})

	require.Equal(t, http.StatusBadRequest, rec.Code,
		"more than %d MAC claims must be rejected: %s", maxIntakeMACClaims, rec.Body.String())
}

// TestHandleCasesIntakeAssist_WellFormedMAC_ResolvesCandidate verifies that
// validation does not break the legitimate lookup: MAC notations that the entity
// index actually stores are accepted and still resolve.
func TestHandleCasesIntakeAssist_WellFormedMAC_ResolvesCandidate(t *testing.T) {
	srv, p := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	reportEntityWithMACs(t, p, "host:intake-mac-colon", "test-tenant",
		[]string{"00:11:22:33:44:55", "00:11:22:33:44:66"})
	reportEntityWithMACs(t, p, "host:intake-mac-hyphen", "test-tenant",
		[]string{"00-11-22-33-44-77"})
	reportEntityWithMACs(t, p, "host:intake-mac-bare", "test-tenant",
		[]string{"001122334488"})

	for _, tc := range []struct{ mac, wantEID string }{
		{"00:11:22:33:44:66", "host:intake-mac-colon"},
		{"00-11-22-33-44-77", "host:intake-mac-hyphen"},
		{"001122334488", "host:intake-mac-bare"},
	} {
		rec := postIntake(t, srv, apiKey, eginterfaces.IdentityClaims{MACAddrs: []string{tc.mac}})

		require.Equal(t, http.StatusOK, rec.Code,
			"well-formed MAC %q must be accepted: %s", tc.mac, rec.Body.String())
		var candidates []egtypes.EID
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
		require.Len(t, candidates, 1, "MAC %q must resolve exactly one candidate", tc.mac)
		assert.Equal(t, tc.wantEID, candidates[0].String())
	}
}

// TestCaseIntakePermission_EnforcedOnRouteIsGrantable verifies that the permission
// enforced by requirePermission on POST /api/v1/cases/intake-assist is present in
// the knownPermissions allow-list. A permission enforced on a route but absent from
// the allow-list is unusable: enforced but ungrantable, so only implicit-admin
// principals reach the route.
func TestCaseIntakePermission_EnforcedOnRouteIsGrantable(t *testing.T) {
	assert.True(t, isKnownPermission("case:intake-assist"),
		"case:intake-assist is enforced by requirePermission on /cases/intake-assist but "+
			"absent from knownPermissions, so no scoped API key or web account can ever hold it")
}

// TestHandleCreateAPIKey_AcceptsCaseIntakeAssist verifies that case:intake-assist is
// grantable through the real key-minting path and that the resulting least-privilege
// key reaches the route.
//
// The other tests in this file mint keys via NewTestKey/NewEphemeralTestKey, which
// call generateEphemeralKey directly and bypass isKnownPermission. That path cannot
// detect a permission enforced on a route but missing from knownPermissions: with
// such a gap handleCreateAPIKey (and the web-account handlers) reject it with 400
// INVALID_PERMISSION, leaving an implicit-admin principal as the only one able to
// reach the endpoint. This test goes through handleCreateAPIKey so that gap fails
// the suite.
func TestHandleCreateAPIKey_AcceptsCaseIntakeAssist(t *testing.T) {
	srv, p := newIntakeTestServer(t)

	const tenantID = "test-tenant"
	reportEntityWithClaims(t, p, "host:intake-grant-pc", tenantID, "intake-grant-pc", "")

	createBody := []byte(`{"name":"intake-assist-key","tenant_id":"` + tenantID +
		`","permissions":["case:intake-assist"]}`)
	createRec := callHandleCreateAPIKey(srv, createBody, tenantID)
	require.Equal(t, http.StatusCreated, createRec.Code,
		"case:intake-assist must be a known permission and grantable to a scoped API key: %s",
		createRec.Body.String())

	var created struct {
		Data struct {
			Key         string   `json:"key"`
			Permissions []string `json:"permissions"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEmpty(t, created.Data.Key, "plaintext key must be returned on creation")
	assert.ElementsMatch(t, []string{"case:intake-assist"}, created.Data.Permissions,
		"created key must carry exactly the requested permission")

	// The scoped key really is scoped: it must not inherit blanket authority.
	srv.mu.RLock()
	stored := srv.apiKeys[created.Data.Key]
	srv.mu.RUnlock()
	require.NotNil(t, stored, "created key must be registered for authentication")
	require.NotNil(t, stored.Permissions,
		"created key must carry an explicit permission set, not the blanket-allow nil set")

	// And it reaches the route it was minted for.
	rec := postIntake(t, srv, created.Data.Key, eginterfaces.IdentityClaims{Hostname: "intake-grant-pc"})
	require.Equal(t, http.StatusOK, rec.Code,
		"scoped case:intake-assist key must be authorised for POST /cases/intake-assist: %s",
		rec.Body.String())
	var candidates []egtypes.EID
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
	require.Len(t, candidates, 1)
	assert.Equal(t, "host:intake-grant-pc", candidates[0].String())
}

// TestHandleCasesIntakeAssist_MachineSID_ResolvesCandidate verifies resolution by MachineSID claim.
func TestHandleCasesIntakeAssist_MachineSID_ResolvesCandidate(t *testing.T) {
	srv, p := newIntakeTestServer(t)
	apiKey := NewTestKey(t, srv, []string{"case:intake-assist"})

	reportEntityWithClaims(t, p, "host:sid-pc1", "test-tenant", "", "S-1-5-21-TEST")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/cases/intake-assist",
		newIntakeBody(t, eginterfaces.IdentityClaims{MachineSID: "S-1-5-21-TEST"}))
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "MachineSID resolution must return 200: %s", rec.Body.String())
	var candidates []egtypes.EID
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &candidates))
	require.Len(t, candidates, 1)
	assert.Equal(t, "host:sid-pc1", candidates[0].String())
}
