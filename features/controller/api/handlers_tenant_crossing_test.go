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
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
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
	return req.WithContext(ctx)
}

// setupCrossingTestServer builds a Server with a SQLite-backed TenantCrossingStore
// wired. The OSS storage manager's bundle path always populates one (see
// pkg/testing.SetupTestStorage), but the Server itself only reads it once explicitly
// wired via SetTenantCrossingStore — mirroring the assurancePolicyStore convention
// (handlers_assurance_policy_test.go's newAssuranceTestServer).
func setupCrossingTestServer(t *testing.T) *Server {
	t.Helper()
	server := setupTestServer(t)
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

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
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

	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID:          "grant-1",
		TenantID:    "msp-a",
		PrincipalID: caller.ID,
		Kind:        business.TenantCrossingKindGrant,
		GrantedBy:   "msp-a-admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
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

// TestAuthorizeRootScopedCaller_RootItselfAlwaysAllowed verifies "root" is not itself
// gated by the boundary — only strict descendants are (ADR-025 Decision 1).
func TestAuthorizeRootScopedCaller_RootItselfAlwaysAllowed(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/root", "root", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
}

// TestAuthorizeRootScopedCaller_UnrelatedTopLevelTenant_Returns404NotChallenge verifies
// that a tenant outside "root"'s own subtree entirely (a second, unrelated top-level
// tenant — multi-root deployments) is an ordinary out-of-scope 404, not a crossing
// case: there is nothing ADR-025 Decision 2 can remedy for a tenant that isn't part of
// root's subtree at all.
func TestAuthorizeRootScopedCaller_UnrelatedTopLevelTenant_Returns404NotChallenge(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "second-root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/tenants/second-root", "second-root", caller, nil)
	rec := httptest.NewRecorder()
	server.handleGetTenant(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestAuthorizeRootScopedCaller_ListSilentlyFilters verifies handleListTenants omits
// descendants the root-scoped caller lacks a crossing for, rather than issuing a
// challenge per item (a bulk list has no single resource to attach one to).
func TestAuthorizeRootScopedCaller_ListSilentlyFilters(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-b", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-msp-a", TenantID: "msp-a", PrincipalID: caller.ID,
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
	assert.NotContains(t, ids, "msp-b", "caller has no crossing for msp-b — silently omitted, not challenged")
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
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
	assert.Equal(t, "", ordinaryPrincipal.TenantID)

	rootScopedCert := makeRootScopedAdminTestCert(t)
	rootScopedReq := requestWithTLSCert(http.MethodGet, "/api/v1/tenants/x", rootScopedCert)
	rootScopedPrincipalGot := server.extractAdminPrincipal(rootScopedReq)
	require.NotNil(t, rootScopedPrincipalGot)
	assert.True(t, rootScopedPrincipalGot.RootScoped)
	assert.Equal(t, "", rootScopedPrincipalGot.TenantID, "RootScoped must not change TenantID's empty-string convention")
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
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
	require.NoError(t, err)

	mspAdmin := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	body, _ := json.Marshal(map[string]interface{}{"principal_id": "root-operator-1", "duration_minutes": 60})
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/access-grants", "msp-a", mspAdmin, body)
	rec := httptest.NewRecorder()
	server.handleCreateTenantCrossingGrant(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	active, err := server.tenantCrossingStore.HasActiveTenantCrossing(ctx, "root-operator-1", "msp-a")
	require.NoError(t, err)
	assert.True(t, active)
}

// TestHandleCreateTenantCrossingGrant_CrossTenantRefused verifies an MSP admin cannot
// grant access into a tenant outside its own subtree.
func TestHandleCreateTenantCrossingGrant_CrossTenantRefused(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-b"})
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-on-root", TenantID: "root", PrincipalID: caller.ID,
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/root/break-glass", "root", caller, []byte("{}"))
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "root"})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a", ParentID: "root"})
	require.NoError(t, err)

	caller := rootScopedPrincipal("root-operator-1")
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", caller, []byte("{}"))
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
	require.NoError(t, err)

	notRootScoped := &Principal{ID: "msp-a-admin", TenantID: "msp-a", Assurance: session.AssuranceStrong}
	req := requestAsPrincipal(t, http.MethodPost, "/api/v1/tenants/msp-a/break-glass", "msp-a", notRootScoped, []byte("{}"))
	req.Header.Set("X-Justification", "Customer P1 outage, ticket INC-4821, need config diff now")
	rec := httptest.NewRecorder()
	server.handleTenantBreakGlass(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestHandleTenantBreakGlass_RequiresJustification verifies a missing or too-short
// X-Justification is rejected before any crossing is created.
func TestHandleTenantBreakGlass_RequiresJustification(t *testing.T) {
	server := setupCrossingTestServer(t)
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
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
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-a"})
	require.NoError(t, err)

	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(ctx, &business.TenantCrossing{
		ID: "grant-1", TenantID: "msp-a", PrincipalID: "root-operator-1",
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
