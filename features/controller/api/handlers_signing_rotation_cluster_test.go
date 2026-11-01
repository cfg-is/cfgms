// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const clusterRotationTenant = "cluster-ca-tenant"

// newClusterRotationManager builds a Manager in cluster mode: a shared secret
// store holding the signing keys, with the cluster's shared identity either
// provisioned (shared) or left as the node-local legacy identity.
func newClusterRotationManager(t *testing.T, shared bool) *cert.Manager {
	t.Helper()
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)
	dir := t.TempDir()
	build := func(withKeyStore bool) *cert.Manager {
		cfg := &cert.ManagerConfig{
			StoragePath:        dir,
			CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
			SigningCursorStore: cursor,
		}
		if withKeyStore {
			ks, ksErr := cert.NewSecretStoreSigningKeyStore(secrets, clusterRotationTenant, "")
			require.NoError(t, ksErr)
			cfg.SigningKeyStore = ks
		}
		m, mErr := cert.NewManagerFromSecretStore(context.Background(), secrets, clusterRotationTenant, "cluster-ca", cfg)
		require.NoError(t, mErr)
		return m
	}
	signingCfg := &cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}
	if shared {
		m := build(true)
		require.NoError(t, m.EnsureSigningCertificate(signingCfg))
		return m
	}
	require.NoError(t, build(false).EnsureSigningCertificate(signingCfg))
	return build(true)
}

func adminCertRequest(t *testing.T, m *cert.Manager) *http.Request {
	t.Helper()
	issued, err := m.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "operator-admin", Organization: "CFGMS", ValidityDays: 1, TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	x509Cert, err := cert.ParseCertificateFromPEM(issued.CertificatePEM)
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{x509Cert}}
	return req
}

func TestHandleRotateSigningCert_ClusterAuditsRotation(t *testing.T) {
	m := newClusterRotationManager(t, true)
	server, _, auditMgr := setupRotationTestServerWith(t, m)

	req := adminCertRequest(t, m)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data RotateSigningCertResponse `json:"data"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: audit.SystemTenantID})
	require.NoError(t, err)
	entry := findAuditEntryByAction(t, entries, "signing_certificate_rotated")

	assert.Equal(t, resp.Data.NewSerial, entry.ResourceID)
	assert.NotEmpty(t, entry.UserID, "operator serial")
	assert.Equal(t, entry.UserID, entry.Details["operator_serial"])
	assert.Equal(t, resp.Data.OldSerial, entry.Details["old_serial"])
	assert.Equal(t, resp.Data.NewSerial, entry.Details["new_serial"])
	assert.Equal(t, "node-test-1", entry.Details["node_id"])

	raw, err := json.Marshal(entry)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "-----BEGIN", "audit entry must not carry PEM or key material")
}

func TestHandleRotateSigningCert_LegacyLocalReturns409MigrationPending(t *testing.T) {
	m := newClusterRotationManager(t, false)
	server, _, auditMgr := setupRotationTestServerWith(t, m)

	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, adminCertRequest(t, m))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	assert.Equal(t, "SIGNING_MIGRATION_PENDING", errResp.Error.Code)

	require.NoError(t, auditMgr.Flush(context.Background()))
	entries, err := auditMgr.QueryEntries(context.Background(), &business.AuditFilter{TenantID: audit.SystemTenantID})
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotEqual(t, "signing_certificate_rotated", e.Action, "a refused rotation is not audited as performed")
	}
}

func TestHandleRotateSigningCert_ClusterModeStillDeniesWeakPrincipals(t *testing.T) {
	m := newClusterRotationManager(t, true)
	server, _, _ := setupRotationTestServerWith(t, m)
	before, err := m.GetSigningCursorState()
	require.NoError(t, err)

	cases := map[string]struct {
		principal *Principal
		scope     ctxkeys.TenantScope
	}{
		"non_strong": {&Principal{ID: "weak", Assurance: session.AssuranceMachine, CertSerial: "s"}, ctxkeys.NewRootScope()},
		"tenant_scoped": {&Principal{ID: "scoped", Assurance: session.AssuranceStrong, TenantID: "client-1", CertSerial: "s"},
			ctxkeys.NewTenantScope("client-1")},
		"no_cert_serial": {&Principal{ID: "noserial", Assurance: session.AssuranceStrong}, ctxkeys.NewRootScope()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), principalContextKey, tc.principal)
			ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, tc.scope)
			req := httptest.NewRequest("POST", "/api/v1/certificates/signing/rotate", nil).WithContext(ctx)
			rec := httptest.NewRecorder()
			server.handleRotateSigningCert(rec, req)
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}

	after, err := m.GetSigningCursorState()
	require.NoError(t, err)
	assert.Equal(t, before, after, "a denied request must not move the cursor")
}
