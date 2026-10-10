// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// rootScopedPrincipal returns a Principal shaped like a root-scoped SaaS-operator
// (ADR-025 Amendment 1 A1.3): unscoped (TenantID == "") but explicitly marked, as
// opposed to an ordinary unscoped superadmin (RootScoped == false).
func rootScopedPrincipal(id string) *Principal {
	return &Principal{
		ID:            id,
		Name:          "root-scoped:" + id,
		Assurance:     session.AssuranceStrong,
		GlobalScope:   true,
		TenantID:      "",
		RootScoped:    true,
		ImplicitAdmin: true,
	}
}

// accountBoundLowAssuranceRootPrincipal returns a Principal shaped like a Bearer/web
// session bound to a root-scope account (acct.RootScope == true) whose CURRENT request
// is below the phishing-resistant assurance threshold — exactly the middleware.go:926/
// :1079 rootScopeFromAssertion shape that leaves RootScoped false even though the
// account's own scope has not changed (Issue #4337, ADR-025 Amendment 5). AccountBound
// is what makes GlobalScope (not RootScoped) the crossing-boundary signal for this
// principal — see subjectToTenantCrossingBoundary.
func accountBoundLowAssuranceRootPrincipal(id string) *Principal {
	return &Principal{
		ID:            id,
		Name:          "session:" + id,
		Assurance:     session.AssuranceBasic,
		GlobalScope:   true,
		TenantID:      "",
		RootScoped:    false,
		AccountBound:  true,
		ImplicitAdmin: true, // mirrors middleware.go's acct.RootScope branch (implicitAdmin/implicitAdminWeb = true)
	}
}

// requestAsPrincipal builds a direct-handler-call request (bypassing the router and
// authenticationMiddleware, matching putTenantAsScopedCaller's established pattern)
// carrying principal in context, with mux vars populated for {id}.
func requestAsPrincipal(t *testing.T, method, path string, targetID string, principal *Principal, body []byte) *http.Request {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req = mux.SetURLVars(req, map[string]string{"id": targetID})
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, principal.TenantID)
	ctx = context.WithValue(ctx, principalContextKey, principal)
	// Issue #4335: also carry the ctxkeys.TenantScope authenticationMiddleware sets
	// alongside ctxkeys.TenantID, mirroring scopeForVerifiedAdminCert — otherwise a
	// handler migrated to read TenantScope sees an unset scope and fails closed even
	// for this helper's root-scoped principals.
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scopeForVerifiedAdminCert(principal.TenantID))
	return req.WithContext(ctx)
}

// setupCrossingTestServer builds a Server with a SQLite-backed TenantCrossingStore
// wired. The OSS storage manager's bundle path always populates one (see
// pkg/testing.SetupTestStorage), but the Server itself only reads it once explicitly
// wired via SetTenantCrossingStore — mirroring the assurancePolicyStore convention
// (handlers_assurance_policy_test.go's newAssuranceTestServer).
func setupCrossingTestServer(t *testing.T) *Server {
	t.Helper()
	return wireCrossingStore(t, setupTestServer(t))
}

// seedRootTenant creates the deployment's "root" tenant (ADR-032: exactly one root,
// MSPs are its children) so tests' MSP tenants are never mistaken for the root by
// tenant.Manager.RootTenantID (Issue #4542).
func seedRootTenant(t *testing.T, server *Server) *Server {
	t.Helper()
	err := ensureTestRootTenant(context.Background(), server.tenantManager)
	require.NoError(t, err)
	return server
}

// setupCrossingTestServerWithLogger is setupCrossingTestServer with the logger supplied
// at construction. Tests that capture authorization audit records must use this rather
// than assigning server.logger afterwards: New() starts background sweep goroutines
// (startCliPresenceRequestSweep, startCredentialRequestSweep) that read s.logger, so a
// post-construction assignment onto a running server is a data race under -race.
func setupCrossingTestServerWithLogger(t *testing.T, logger logging.Logger) *Server {
	t.Helper()
	return wireCrossingStore(t, setupTestServerWithLogger(t, logger))
}

// wireCrossingStore attaches a SQLite-backed TenantCrossingStore to an already
// constructed test server and returns it.
func wireCrossingStore(t *testing.T, server *Server) *Server {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	tcs := sm.GetTenantCrossingStore()
	require.NotNil(t, tcs, "OSS bundle path must populate TenantCrossingStore")
	server.SetTenantCrossingStore(tcs)
	return server
}

// TestAuthorizeRootScopedCaller_DeniedRealDescendantWithoutCrossing is the REQUIRED
// TEST from ADR-025 Decision 1 / Amendment 1 A1.3: a root-scoped caller without an
// active grant or break-glass session must not see a genuine descendant of "root".
func TestAuthorizeRootScopedCaller_DeniedRealDescendantWithoutCrossing(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()

	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"a root-scoped caller absent a crossing must get a step-up-shaped challenge, not silent denial")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "tenant_crossing_required", body["error"])
	assert.Equal(t, "/api/v1/tenants/msp-a/break-glass", body["break_glass_endpoint"])
}

// TestAuthorizeRootScopedCaller_AllowedWithActiveGrant is the REQUIRED TEST's
// counterpart: the same root-scoped caller, same descendant, but with an active grant
// (ADR-025 Decision 2(a)) must be let through.
func TestAuthorizeRootScopedCaller_AllowedWithActiveGrant(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()

	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:        "grant-1",
		TenantID:  "msp-a",
		Kind:      business.TenantCrossingKindGrant,
		GrantedBy: "msp-a-admin",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}))

	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "an active grant must let the root-scoped caller through")
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "msp-a", data["id"])
}

// TestAuthorizeAccountBoundCaller_LowAssuranceStillGatedByBoundary is the REQUIRED
// TEST for Issue #4337's GlobalScope-binding decision: a root-scope account's session,
// currently below phishing-resistant assurance, must still be evaluated by the ADR-025
// crossing boundary (not silently treated as unbounded, and not flatly denied) — the
// same step-up-shaped challenge a high-assurance root-scoped caller gets.
func TestAuthorizeAccountBoundCaller_LowAssuranceStillGatedByBoundary(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()

	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := accountBoundLowAssuranceRootPrincipal("low-assurance-root-1")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"a low-assurance root-scope-account session absent a crossing must get a step-up-shaped "+
			"challenge — not silent, unconditional access")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
}

// TestAuthorizeAccountBoundCaller_LowAssuranceAllowedWithActiveGrant is the REQUIRED
// TEST's positive counterpart: the same low-assurance root-scope-account session, with
// an active crossing grant, must be let through — Issue #4337's binding decision must
// not turn into a blanket deny for every session that is not currently phishing-resistant.
func TestAuthorizeAccountBoundCaller_LowAssuranceAllowedWithActiveGrant(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()

	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := accountBoundLowAssuranceRootPrincipal("low-assurance-root-2")

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:        "grant-low-assurance-1",
		TenantID:  "msp-a",
		Kind:      business.TenantCrossingKindGrant,
		GrantedBy: "msp-a-admin",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}))

	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"an active grant must let the low-assurance root-scope-account session through")
}

// TestAuthorizeRootScopedCaller_RootItselfAlwaysAllowed verifies "root" is not itself
// gated by the boundary — only strict descendants are (ADR-025 Decision 1).
func TestAuthorizeRootScopedCaller_RootItselfAlwaysAllowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/root", "root", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

// TestAuthorizeRootScopedCaller_UnrelatedTopLevelTenant_Returns404NotChallenge verifies
// that a second, unrelated top-level tenant (a legacy multi-root store; the manager
// refuses to create one, Issue #4542) is an ordinary out-of-scope 404, not a crossing
// case. With two parentless tenants the root is ambiguous, so root-scoped
// authorization denies outright: there is nothing ADR-025 Decision 2 can remedy.
func TestAuthorizeRootScopedCaller_UnrelatedTopLevelTenant_Returns404NotChallenge(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	require.NoError(t, ensureTestRootTenant(ctx, server.tenantManager))
	seedLegacyTopLevelTenant(t, server, "second-root")

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/second-root", "second-root", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestAuthorizeRootScopedCaller_ListSilentlyFilters verifies handleListTenants returns
// descendants the root-scoped caller lacks a crossing for only as boundary rows (Issue
// #4647), rather than issuing a challenge per item (a bulk list has no single resource to attach one to).
func TestAuthorizeRootScopedCaller_ListSilentlyFilters(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-b", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-msp-a", TenantID: "msp-a",
		Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-a-admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants", "", caller, nil)
	rec := httptest.NewRecorder()
	server.handleListTenants(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	ids := tenantIDsFromListResponse(t, rec.Body.Bytes())
	assert.Contains(t, ids, "root")
	assert.Contains(t, ids, "msp-a", "caller holds an active crossing for msp-a")
	byID := rowsByID(listAsPrincipal(t, server, caller))
	require.Len(t, byID["msp-b"], 1, "no crossing for msp-b — a boundary row, not a challenge")
	assert.Equal(t, true, byID["msp-b"][0]["boundary"])
	require.Len(t, byID["msp-a"], 1)
	assert.Equal(t, false, byID["msp-a"][0]["boundary"])
}

// TestEmptyCallerTenant_NoRootScopeMarker_RetainsUnscopedAccess is the regression
// counterpart: an ordinary unscoped CERTIFICATE-authenticated principal (TenantID == "",
// RootScoped == false, CertSerial != "" — every admin cert issued before the root-scope
// marker existed) must see every tenant exactly as before, including a genuine
// descendant, with no crossing required at all. The certificate authentication path is
// explicitly out of scope for ADR-025 Amendment 4 and must be provably unchanged by it —
// CertSerial is what distinguishes this caller from the non-certificate case
// TestUnscopedAndUnmarked_NonCertificateCaller_NoLongerUnrestricted denies.
func TestEmptyCallerTenant_NoRootScopeMarker_RetainsUnscopedAccess(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	unscopedAdmin := &Principal{
		ID: "admin-1", TenantID: "", RootScoped: false, GlobalScope: true,
		Assurance: session.AssuranceStrong, CertSerial: "unscoped-admin-cert-serial",
	}
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", unscopedAdmin, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusOK, rec.Code,
		"an unscoped certificate-authenticated principal without the explicit root-scope marker must retain today's unrestricted access")
}

// TestExtractAdminPrincipal_RootScopeMarker verifies extractAdminPrincipal reads
// RootScoped from the certificate extension (ADR-025 Amendment 1 A1.3) — never
// inferred from TenantID, which is always "" for every admin cert regardless.
func TestExtractAdminPrincipal_RootScopeMarker(t *testing.T) {
	server := setupTestServer(t)

	ordinaryAdminCert := makeSelfSignedAdminCert(t)
	ordinaryReq := requestWithTLSCert(http.MethodGet, "/api/v1/tenants/x", ordinaryAdminCert)
	ordinaryPrincipal := server.extractAdminPrincipal(ordinaryReq)
	require.NotNil(t, ordinaryPrincipal)
	assert.False(t, ordinaryPrincipal.RootScoped, "an ordinary admin cert must not be treated as root-scoped")
	assert.Equal(t, testRootTenantID, ordinaryPrincipal.TenantID, "a root admin is bound to the root tenant (Issue #4665)")

	rootScopedCert := makeRootScopedAdminTestCert(t)
	rootScopedReq := requestWithTLSCert(http.MethodGet, "/api/v1/tenants/x", rootScopedCert)
	rootScopedPrincipalGot := server.extractAdminPrincipal(rootScopedReq)
	require.NotNil(t, rootScopedPrincipalGot)
	assert.True(t, rootScopedPrincipalGot.RootScoped)
	assert.Equal(t, testRootTenantID, rootScopedPrincipalGot.TenantID, "a root admin is bound to the root tenant regardless of the marker (Issue #4665)")
}

// makeRootScopedAdminTestCert builds a self-signed cert carrying both the admin marker
// and the ADR-025 A1.3 root-scope marker, mirroring makeAdminTestCert's shape.
func makeRootScopedAdminTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key := sharedTestRSAKey()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(5678),
		Subject:      pkix.Name{CommonName: "test-root-operator"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	cert.SetAdminMarker(template)
	cert.SetRootScopeMarker(template)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return parsed
}

// TestHandleCreateTenantCrossingGrant_Success verifies an MSP admin scoped to its own
// tenant can create a grant for a root-scoped support principal (ADR-025 Decision 2(a)).
func TestHandleCreateTenantCrossingGrant_Success(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	body, _ := json.Marshal(map[string]interface{}{"principal_id": "root-operator-1", "duration_minutes": 60})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/access-grants", "msp-a", mspAdmin, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// A grant names no principal: it admits any root principal on the tenant.
	for _, p := range []string{"root-operator-1", "root-operator-2"} {
		active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, p, "msp-a")
		require.NoError(t, err)
		assert.True(t, active, "grant must admit %s", p)
	}
	list, err := server.tenantCrossingStore.ListTenantCrossings(ctx, "msp-a")
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Empty(t, list[0].PrincipalID)
}

// TestHandleCreateTenantCrossingGrant_CrossTenantRefused verifies an MSP admin cannot
// grant access into a tenant outside its own subtree.
func TestHandleCreateTenantCrossingGrant_CrossTenantRefused(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-b", ParentID: testRootTenantID})
	require.NoError(t, err)

	mspAAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	body, _ := json.Marshal(map[string]interface{}{"principal_id": "root-operator-1", "duration_minutes": 60})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-b/access-grants", "msp-b", mspAAdmin, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleCreateTenantCrossingGrant_RootTenantRefused is the regression test for the
// root-tenant skeleton-key escalation: a grant recorded on "root" would sit on every
// tenant's ancestry path (hasActiveTenantCrossing walks GetTenantPath, which begins at
// "root"), converting one 24h record into fleet-wide access with no MSP consent, no
// justification and no 30-minute cap — strictly weaker controls than the break-glass
// path it circumvents (ADR-025 Decision 1, Decision 2).
func TestHandleCreateTenantCrossingGrant_RootTenantRefused(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	// The most privileged caller shape that reaches this handler: an unscoped superadmin,
	// which authorizeTenantAccess admits for every tenant unconditionally.
	unscopedAdmin := &Principal{ID: "admin-1", TenantID: "", GlobalScope: true, Assurance: session.AssuranceStrong}
	body, _ := json.Marshal(map[string]interface{}{"principal_id": "root-operator-1", "duration_minutes": 1440})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/root/access-grants", "root", unscopedAdmin, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-1", "root")
	require.NoError(t, err)
	assert.False(t, active, "no crossing may be recorded on the root tenant")
}

// TestHandleCreateTenantCrossingGrant_RootScopedCallerRefused verifies a root-scoped
// caller cannot mint its own grant. A grant is the MSP's consent (ADR-025 Decision 2(a));
// a root-scoped caller issuing one would be consenting on the MSP's behalf, bypassing
// break-glass's justification, 30-minute cap and critical-severity audit trail.
func TestHandleCreateTenantCrossingGrant_RootScopedCallerRefused(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	// Grant an unrelated principal, so the refusal is attributable to the caller's scope
	// rather than to the self-grant guard.
	body, _ := json.Marshal(map[string]interface{}{"principal_id": "root-operator-2", "duration_minutes": 1440})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/access-grants", "msp-a", caller, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-2", "msp-a")
	require.NoError(t, err)
	assert.False(t, active, "a root-scoped caller must not be able to create a grant")
}

// TestHandleCreateTenantCrossingGrant_SelfGrantRefused verifies a caller cannot name
// itself as the granted principal — the only use for which is laundering the access it
// already holds into a longer-lived, differently gated crossing record.
func TestHandleCreateTenantCrossingGrant_SelfGrantRefused(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	body, _ := json.Marshal(map[string]interface{}{"principal_id": mspAdmin.ID, "duration_minutes": 60})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/access-grants", "msp-a", mspAdmin, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, mspAdmin.ID, "msp-a")
	require.NoError(t, err)
	assert.False(t, active, "a self-grant must not be recorded")
}

// TestCrossingOnRootDoesNotCoverDescendants is the defense-in-depth half of the
// skeleton-key fix: even if a crossing on "root" exists (written by an earlier build or
// directly into the store), it must not satisfy the boundary check for any MSP tenant.
// Root is the operator's own scope, not an MSP subtree that can consent for its
// descendants (ADR-025 Decision 1).
func TestCrossingOnRootDoesNotCoverDescendants(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-on-root", TenantID: "root",
		Kind: business.TenantCrossingKindGrant, GrantedBy: caller.ID,
		CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	}))

	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"a crossing recorded on \"root\" must not grant access to an MSP descendant")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
}

// TestHandleTenantBreakGlass_RootTenantRefused verifies break-glass cannot be pointed at
// "root" either — a root-scoped caller already reaches "root" without any crossing, so
// the only effect of such a record would be the same tree-wide escalation.
func TestHandleTenantBreakGlass_RootTenantRefused(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/root/break-glass", "root", caller, []byte(`{"reason_category":"account_recovery"}`))
	req.Header.Set("X-Justification", "Customer P1 outage, ticket INC-4821, need config diff now")
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, caller.ID, "root")
	require.NoError(t, err)
	assert.False(t, active, "no break-glass crossing may be recorded on the root tenant")
}

// TestHandleTenantBreakGlass_Success verifies a root-scoped caller can self-invoke a
// justified break-glass elevation and then reach the tenant (ADR-025 Decision 2(b)).
func TestHandleTenantBreakGlass_Success(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", caller, []byte(`{"reason_category":"account_recovery"}`))
	req.Header.Set("X-Justification", "Customer P1 outage, ticket INC-4821, need config diff now")
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	getReq := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil)
	getRec := httptest.NewRecorder()
	server.handleGetTenant(getRec, getReq)
	assert.Equal(t, http.StatusOK, getRec.Code, "the break-glass session must immediately grant access")
}

// TestHandleTenantBreakGlass_RequiresRootScoped verifies a non-root-scoped caller
// (any ordinary tenant-scoped or unscoped-superadmin principal) cannot invoke
// break-glass — it exists only to remedy the ADR-025 boundary, which never applies
// to them.
func TestHandleTenantBreakGlass_RequiresRootScoped(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	notRootScoped := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", notRootScoped, []byte(`{"reason_category":"account_recovery"}`))
	req.Header.Set("X-Justification", "Customer P1 outage, ticket INC-4821, need config diff now")
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleTenantBreakGlass_RequiresJustification verifies a missing or too-short
// X-Justification is rejected before any crossing is created.
func TestHandleTenantBreakGlass_RequiresJustification(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", caller, []byte("{}"))
	// No X-Justification header set.
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, caller.ID, "msp-a")
	require.NoError(t, err)
	assert.False(t, active, "a rejected break-glass request must not create a crossing")
}

// TestHandleListTenantCrossings_ReturnsActivity verifies the MSP's own tenant-crossing
// activity view surfaces both grant and break-glass records (ADR-025 Decision 2:
// neither crossing kind may be hidden from the affected MSP).
func TestHandleListTenantCrossings_ReturnsActivity(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-1", TenantID: "msp-a",
		Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-a-admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "bg-1", TenantID: "msp-a", PrincipalID: "root-operator-2",
		Kind: business.TenantCrossingKindBreakGlass, GrantedBy: "root-operator-2",
		Justification: "outage response", CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}))

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a/access-grants", "msp-a", mspAdmin, nil)
	rec := httptest.NewRecorder()
	server.handleListTenantCrossings(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	items, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2)
}

// accountBoundRootScopePrincipal is a principal resolved from a root-scope account
// whose request carries no ADR-025 root-scope marker: an mTLS admin cert bound to
// the account but issued before the marker existed, or a browser/CLI session below
// phishing-resistant assurance. subjectToTenantCrossingBoundary judges it on
// GlobalScope (Issue #4337), so the boundary treats it as root-scoped.
func accountBoundRootScopePrincipal(id string) *Principal {
	return &Principal{
		ID:            id,
		Name:          "mtls-admin:" + id,
		Assurance:     session.AssuranceStrong,
		GlobalScope:   true,
		RootScoped:    false,
		AccountBound:  true,
		ImplicitAdmin: true,
	}
}

// TestHandleTenantBreakGlass_AccountBoundRootScope_Allowed guards that a principal the
// tenant boundary challenges for a crossing can actually obtain one: the boundary
// and the break-glass handler must agree on who is root-scoped. Before the fix the
// boundary returned tenant_crossing_required while break-glass refused the same
// caller with NOT_ROOT_SCOPED, leaving no path into any child tenant.
func TestHandleTenantBreakGlass_AccountBoundRootScope_Allowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	caller := accountBoundRootScopePrincipal("root-account-1")
	require.True(t, subjectToTenantCrossingBoundary(caller), "precondition: the boundary treats this caller as root-scoped")
	require.Equal(t, tenantAuthNeedsCrossing, server.authorizeTenantAccess(ctx, caller, "msp-a"))

	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", caller, []byte(`{"reason_category":"account_recovery"}`))
	req.Header.Set("X-Justification", "Customer P1 outage, ticket INC-4821, need config diff now")
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	assert.Equal(t, tenantAuthAllowed, server.authorizeTenantAccess(ctx, caller, "msp-a"),
		"after break-glass the boundary must admit the caller")
}

// TestHandleCreateTenantCrossingGrant_AccountBoundRootScope_Refused guards the
// self-dealing rule for the same principal shape: a caller the boundary treats as
// root-scoped must not mint a grant (consent belongs to the MSP); break-glass is its
// only path. Before the fix the RootScoped-only check let it through once the caller
// held a break-glass crossing — turning a justified 30-minute crossing into a
// self-issued grant of any duration.
func TestHandleCreateTenantCrossingGrant_AccountBoundRootScope_Refused(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	err := ensureTestRootTenant(ctx, server.tenantManager)
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)

	caller := accountBoundRootScopePrincipal("root-account-1")
	now := time.Now()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:            "bound-root-break-glass",
		TenantID:      "msp-a",
		PrincipalID:   caller.ID,
		Kind:          business.TenantCrossingKindBreakGlass,
		GrantedBy:     caller.ID,
		Justification: "Customer P1 outage, ticket INC-4821, need config diff now",
		CreatedAt:     now,
		ExpiresAt:     now.Add(30 * time.Minute),
	}))
	require.Equal(t, tenantAuthAllowed, server.authorizeTenantAccess(ctx, caller, "msp-a"),
		"precondition: the break-glass crossing admits the caller")

	// Grant a colleague, not itself: SELF_GRANT_FORBIDDEN already covers self-grants.
	body, _ := json.Marshal(map[string]interface{}{"principal_id": "root-operator-2", "duration_minutes": 60})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/access-grants", "msp-a", caller, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)
	require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "ROOT_SCOPED_CANNOT_GRANT")

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-2", "msp-a")
	require.NoError(t, err)
	assert.False(t, active, "a root-scoped caller must not consent on the MSP's behalf")
}

// seedCrossing stores an unrevoked crossing on tenantID for the end-crossing tests.
func seedCrossing(t *testing.T, server *Server, id, tenantID, principalID, grantedBy string, kind business.TenantCrossingKind) {
	t.Helper()
	now := time.Now().UTC()
	if kind == business.TenantCrossingKindGrant {
		principalID = "" // a grant names no principal
	}
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID: id, TenantID: tenantID, PrincipalID: principalID, Kind: kind, GrantedBy: grantedBy,
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}))
}

// endCrossingRequest builds a DELETE request carrying both mux vars.
func endCrossingRequest(t *testing.T, pathTenant, crossingID string, principal *Principal) *http.Request {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodDelete, "/api/v1/tenants/"+pathTenant+"/access-grants/"+crossingID, pathTenant, principal, nil)
	return mux.SetURLVars(req, map[string]string{"id": pathTenant, "crossing_id": crossingID})
}

func setupEndCrossingServer(t *testing.T) *Server {
	t.Helper()
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	for _, id := range []string{"msp-a", "msp-b"} {
		_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: id, ParentID: testRootTenantID})
		require.NoError(t, err)
	}
	return server
}

func TestHandleEndTenantCrossing_GrantRevoked(t *testing.T) {
	server := setupEndCrossingServer(t)
	seedCrossing(t, server, "grant-1", "msp-a", "root-operator-1", "msp-a-admin", business.TenantCrossingKindGrant)

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	rec := httptest.NewRecorder()
	server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "grant-1", mspAdmin))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(context.Background(), "root-operator-1", "msp-a")
	require.NoError(t, err)
	assert.False(t, active)

	// Idempotent on an already revoked crossing.
	rec = httptest.NewRecorder()
	server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "grant-1", mspAdmin))
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestHandleEndTenantCrossing_WrongTenantPath404(t *testing.T) {
	server := setupEndCrossingServer(t)
	seedCrossing(t, server, "grant-1", "msp-a", "root-operator-1", "msp-a-admin", business.TenantCrossingKindGrant)

	mspBAdmin := &Principal{ID: "msp-b-admin", TenantID: "msp-b", Assurance: session.AssuranceStrong}
	rec := httptest.NewRecorder()
	server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-b", "grant-1", mspBAdmin))
	assert.Equal(t, http.StatusNotFound, rec.Code)

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(context.Background(), "root-operator-1", "msp-a")
	require.NoError(t, err)
	assert.True(t, active, "a mismatched path must not revoke")
}

func TestHandleEndTenantCrossing_RootScopedCannotEndGrant(t *testing.T) {
	server := setupEndCrossingServer(t)
	seedCrossing(t, server, "grant-1", "msp-a", "root-operator-1", "msp-a-admin", business.TenantCrossingKindGrant)

	// root-operator-1 holds the grant, so it passes the boundary; it still may not end it.
	caller := rootScopedPrincipal("root-operator-1")
	rec := httptest.NewRecorder()
	server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "grant-1", caller))
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(context.Background(), "root-operator-1", "msp-a")
	require.NoError(t, err)
	assert.True(t, active)
}

func TestHandleEndTenantCrossing_BreakGlassWho(t *testing.T) {
	ctx := context.Background()

	t.Run("non-invoking root principal refused", func(t *testing.T) {
		server := setupEndCrossingServer(t)
		seedCrossing(t, server, "bg-1", "msp-a", "root-operator-1", "root-operator-1", business.TenantCrossingKindBreakGlass)
		// root-operator-2 has its own crossing so it passes the boundary.
		seedCrossing(t, server, "bg-2", "msp-a", "root-operator-2", "root-operator-2", business.TenantCrossingKindBreakGlass)

		rec := httptest.NewRecorder()
		server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "bg-1", rootScopedPrincipal("root-operator-2")))
		assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-1", "msp-a")
		require.NoError(t, err)
		assert.True(t, active)
	})

	t.Run("invoker can end", func(t *testing.T) {
		server := setupEndCrossingServer(t)
		seedCrossing(t, server, "bg-1", "msp-a", "root-operator-1", "root-operator-1", business.TenantCrossingKindBreakGlass)
		rec := httptest.NewRecorder()
		server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "bg-1", rootScopedPrincipal("root-operator-1")))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-1", "msp-a")
		require.NoError(t, err)
		assert.False(t, active)
	})

	t.Run("owning MSP admin can end", func(t *testing.T) {
		server := setupEndCrossingServer(t)
		seedCrossing(t, server, "bg-1", "msp-a", "root-operator-1", "root-operator-1", business.TenantCrossingKindBreakGlass)
		mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
		rec := httptest.NewRecorder()
		server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "bg-1", mspAdmin))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-1", "msp-a")
		require.NoError(t, err)
		assert.False(t, active)
	})
}

func TestHandleEndTenantCrossing_BoundaryRejectsAfterEnd(t *testing.T) {
	server := setupEndCrossingServer(t)
	caller := rootScopedPrincipal("root-operator-1")
	seedCrossing(t, server, "bg-1", "msp-a", "root-operator-1", "root-operator-1", business.TenantCrossingKindBreakGlass)

	getRec := httptest.NewRecorder()
	server.handleGetTenant(getRec, requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil))
	require.Equal(t, http.StatusOK, getRec.Code, "crossing grants access before it is ended")

	rec := httptest.NewRecorder()
	server.handleEndTenantCrossing(rec, endCrossingRequest(t, "msp-a", "bg-1", caller))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	getRec = httptest.NewRecorder()
	server.handleGetTenant(getRec, requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a", "msp-a", caller, nil))
	assert.Equal(t, http.StatusUnauthorized, getRec.Code, "the boundary must challenge once the crossing is ended")
}

func breakGlassBody(t *testing.T, category, justification string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"reason_category": category, "justification": justification})
	require.NoError(t, err)
	return b
}

func invokeBreakGlass(t *testing.T, server *Server, body []byte, header string) *httptest.ResponseRecorder {
	t.Helper()
	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", caller, body)
	if header != "" {
		req.Header.Set("X-Justification", header)
	}
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)
	return rec
}

func breakGlassServer(t *testing.T) *Server {
	t.Helper()
	server := seedRootTenant(t, setupCrossingTestServer(t))
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)
	return server
}

func crossingErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp.Error.Code
}

func TestHandleTenantBreakGlass_ReasonCategory(t *testing.T) {
	const just = "Customer P1 outage, ticket INC-4821, need config diff now"
	for _, cat := range []business.TenantCrossingReasonCategory{
		business.TenantCrossingReasonAccountRecovery,
		business.TenantCrossingReasonSecurityIncident,
		business.TenantCrossingReasonLegalRequest,
		business.TenantCrossingReasonBillingDispute,
	} {
		t.Run(string(cat), func(t *testing.T) {
			server := breakGlassServer(t)
			rec := invokeBreakGlass(t, server, breakGlassBody(t, string(cat), just), "")
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

			var got struct {
				Data map[string]interface{} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, string(cat), got.Data["reason_category"])

			list, err := server.tenantCrossingStore.ListTenantCrossings(context.Background(), "msp-a")
			require.NoError(t, err)
			require.Len(t, list, 1)
			assert.Equal(t, cat, list[0].ReasonCategory)
			assert.Equal(t, just, list[0].Justification)
		})
	}
}

func TestHandleTenantBreakGlass_ReasonCategoryRejected(t *testing.T) {
	const just = "Customer P1 outage, ticket INC-4821, need config diff now"
	cases := []struct {
		name, body, header, code string
	}{
		{"missing", `{"justification":"` + just + `"}`, "", "REASON_CATEGORY_REQUIRED"},
		{"empty body with header", ``, just, "REASON_CATEGORY_REQUIRED"},
		{"unknown", `{"reason_category":"because","justification":"` + just + `"}`, "", "INVALID_REASON_CATEGORY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := breakGlassServer(t)
			rec := invokeBreakGlass(t, server, []byte(tc.body), tc.header)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, tc.code, crossingErrorCode(t, rec))
			list, err := server.tenantCrossingStore.ListTenantCrossings(context.Background(), "msp-a")
			require.NoError(t, err)
			assert.Empty(t, list)
		})
	}
}

func TestHandleTenantBreakGlass_JustificationBounds(t *testing.T) {
	long := strings.Repeat("x", 1001)
	ok1000 := strings.Repeat("x", 1000)
	for name, tc := range map[string]struct {
		body   func() ([]byte, string)
		status int
	}{
		"body too short":   {func() ([]byte, string) { return breakGlassBody(t, "legal_request", "too short"), "" }, 400},
		"body too long":    {func() ([]byte, string) { return breakGlassBody(t, "legal_request", long), "" }, 400},
		"body max":         {func() ([]byte, string) { return breakGlassBody(t, "legal_request", ok1000), "" }, 201},
		"header too short": {func() ([]byte, string) { return breakGlassBody(t, "legal_request", ""), "short" }, 400},
		"header too long":  {func() ([]byte, string) { return breakGlassBody(t, "legal_request", ""), long }, 400},
		"header fallback":  {func() ([]byte, string) { return breakGlassBody(t, "legal_request", ""), "  legal hold request 42  " }, 201},
	} {
		t.Run(name, func(t *testing.T) {
			server := breakGlassServer(t)
			body, header := tc.body()
			rec := invokeBreakGlass(t, server, body, header)
			require.Equal(t, tc.status, rec.Code, rec.Body.String())
			if tc.status == 400 {
				assert.Equal(t, "JUSTIFICATION_REQUIRED", crossingErrorCode(t, rec))
			}
		})
	}
}

func TestHandleTenantBreakGlass_AuditDetailCarriesCategory(t *testing.T) {
	server := breakGlassServer(t)
	rec := invokeBreakGlass(t, server, breakGlassBody(t, "billing_dispute", "Customer P1 outage, ticket INC-4821"), "")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	require.NotNil(t, server.auditManager)
	require.NoError(t, server.auditManager.Flush(context.Background()))
	entries, err := server.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: "msp-a"})
	require.NoError(t, err)
	entry := findAuditEntryByAction(t, entries, "tenant.crossing_break_glass_invoked")
	assert.Equal(t, "billing_dispute", entry.Details["reason_category"])
}

func TestHandleListTenantCrossings_ReasonCategoryOnlyOnBreakGlass(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: testRootTenantID})
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-1", TenantID: "msp-a", Kind: business.TenantCrossingKindGrant, GrantedBy: "a",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "bg-1", TenantID: "msp-a", PrincipalID: "r", Kind: business.TenantCrossingKindBreakGlass, GrantedBy: "r",
		Justification: "outage response", ReasonCategory: business.TenantCrossingReasonSecurityIncident,
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}))
	mspAdmin := &Principal{ID: "a", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/msp-a/access-grants", "msp-a", mspAdmin, nil)
	rec := httptest.NewRecorder()
	server.handleListTenantCrossings(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp struct {
		Data []map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 2)
	for _, row := range resp.Data {
		if row["ID"] == "bg-1" {
			assert.Equal(t, "security_incident", row["reason_category"])
		} else {
			assert.NotContains(t, row, "reason_category")
		}
	}
}

func TestWriteTenantCrossingChallenge_ReasonCategories(t *testing.T) {
	rec := httptest.NewRecorder()
	writeTenantCrossingChallenge(rec, "msp-a")
	var body struct {
		ReasonCategories []string `json:"reason_categories"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, []string{"account_recovery", "security_incident", "legal_request", "billing_dispute"}, body.ReasonCategories)
}
