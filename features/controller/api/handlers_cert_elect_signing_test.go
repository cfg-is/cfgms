// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/cert"
	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const electTestTenant = "cluster-ca-tenant"

type electFixture struct {
	server  *Server
	audit   *audit.Manager
	cursor  certinterfaces.SigningCursorStore
	serials []string // imported local signing serials, one per simulated node
	nodes   []*cert.Manager
}

// newElectFixture builds a three-node cluster whose nodes each held their own
// signing certificate before the shared store existed, then imported them.
func newElectFixture(t *testing.T) *electFixture {
	t.Helper()
	setTestSecretsEnv(t)
	secrets := testutil.NewMemSecretStore()
	cursor, err := cert.NewFileSigningCursorStore(t.TempDir())
	require.NoError(t, err)

	f := &electFixture{cursor: cursor}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		dir := t.TempDir()
		build := func(withKeys bool) *cert.Manager {
			cfg := &cert.ManagerConfig{
				StoragePath:        dir,
				CAConfig:           &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 365, KeySize: 2048},
				SigningCursorStore: cursor,
			}
			if withKeys {
				ks, err := cert.NewSecretStoreSigningKeyStore(secrets, electTestTenant, "")
				require.NoError(t, err)
				cfg.SigningKeyStore = ks
			}
			m, err := cert.NewManagerFromSecretStore(ctx, secrets, electTestTenant, "cluster-ca", cfg)
			require.NoError(t, err)
			return m
		}
		legacy := build(false)
		require.NoError(t, legacy.EnsureSigningCertificate(&cert.SigningCertConfig{CommonName: "cfgms-config-signer", ValidityDays: 365, KeySize: 2048}))
		local, err := legacy.GetCurrentCertForPurpose(cert.PurposeSigning)
		require.NoError(t, err)

		node := build(true)
		results, err := node.ImportLocalSigningCertificates(ctx)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.True(t, results[0].Imported, results[0].Reason)
		f.nodes = append(f.nodes, node)
		f.serials = append(f.serials, local.SerialNumber)
	}
	f.server, _, f.audit = setupRotationTestServerWith(t, f.nodes[0])
	return f
}

func electRequest(principal *Principal, scope ctxkeys.TenantScope, body string) *http.Request {
	ctx := context.WithValue(context.Background(), principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	return httptest.NewRequest("POST", "/api/v1/certificates/signing/elect", bytes.NewBufferString(body)).WithContext(ctx)
}

func TestHandleElectSigningCert_DeniesUnderprivilegedCallers(t *testing.T) {
	f := newElectFixture(t)
	body := `{"serial":"` + f.serials[0] + `"}`

	cases := map[string]struct {
		principal *Principal
		scope     ctxkeys.TenantScope
	}{
		"non_strong":     {&Principal{ID: "weak", Assurance: session.AssuranceMachine, CertSerial: "s"}, ctxkeys.NewRootScope()},
		"tenant_scoped":  {&Principal{ID: "scoped", Assurance: session.AssuranceStrong, TenantID: "client-1", CertSerial: "s"}, ctxkeys.NewTenantScope("client-1")},
		"no_cert_serial": {&Principal{ID: "noserial", Assurance: session.AssuranceStrong}, ctxkeys.NewRootScope()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.server.handleElectSigningCert(rec, electRequest(tc.principal, tc.scope, body))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
		})
	}
	cursor, err := f.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor, "a denied request elects nothing")
}

func TestHandleElectSigningCert_RejectsBadInput(t *testing.T) {
	f := newElectFixture(t)

	rec := httptest.NewRecorder()
	f.server.handleElectSigningCert(rec, electRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), `{"serial":"123456789"}`))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "SERIAL_NOT_MIGRATED")

	for _, body := range []string{`{"serial":"../../etc"}`, `{"serial":""}`, `not json`} {
		rec = httptest.NewRecorder()
		f.server.handleElectSigningCert(rec, electRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), body))
		assert.Equal(t, http.StatusBadRequest, rec.Code, "body %q: %s", body, rec.Body.String())
	}
	cursor, err := f.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor, "a refused election creates no cursor")
}

func TestHandleElectSigningCert_ElectsOnceAndNeverOverrides(t *testing.T) {
	f := newElectFixture(t)

	rec := httptest.NewRecorder()
	f.server.handleElectSigningCert(rec, electRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), `{"serial":"`+f.serials[0]+`"}`))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	cursor, err := f.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Equal(t, f.serials[0], cursor.CurrentSerial)
	assert.Empty(t, cursor.RotatingSerial)
	for _, n := range f.nodes {
		mode, err := n.SigningIdentityMode(context.Background())
		require.NoError(t, err)
		assert.Equal(t, cert.SigningIdentityShared, mode)
	}

	rec = httptest.NewRecorder()
	f.server.handleElectSigningCert(rec, electRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), `{"serial":"`+f.serials[1]+`"}`))
	require.Equal(t, http.StatusConflict, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), f.serials[0])

	require.NoError(t, f.audit.Flush(context.Background()))
	all, err := f.audit.QueryEntries(context.Background(), &business.AuditFilter{TenantID: audit.SystemTenantID})
	require.NoError(t, err)
	var elected int
	for _, e := range all {
		if e.Action == "signing_certificate_elected" {
			elected++
			assert.Equal(t, f.serials[0], e.ResourceID)
		}
	}
	assert.Equal(t, 1, elected, "one election, one audit event")
}

func TestHandleElectSigningCert_ConcurrentElectionsProduceOneCursor(t *testing.T) {
	f := newElectFixture(t)

	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for _, serial := range f.serials {
		wg.Add(1)
		go func(serial string) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			f.server.handleElectSigningCert(rec, electRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), `{"serial":"`+serial+`"}`))
			mu.Lock()
			codes[rec.Code]++
			mu.Unlock()
		}(serial)
	}
	wg.Wait()
	assert.Equal(t, 1, codes[http.StatusOK], "codes: %v", codes)
	assert.Equal(t, len(f.serials)-1, codes[http.StatusConflict], "codes: %v", codes)

	cursor, err := f.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	require.NotNil(t, cursor)
	assert.Empty(t, cursor.RotatingSerial)
}

func TestHandleElectSigningCert_RefusesRevokedSerial(t *testing.T) {
	f := newElectFixture(t)
	require.NoError(t, f.nodes[0].Revoke(f.serials[0]))

	rec := httptest.NewRecorder()
	f.server.handleElectSigningCert(rec, electRequest(strongRootPrincipal(), ctxkeys.NewRootScope(), `{"serial":"`+f.serials[0]+`"}`))
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "SERIAL_REVOKED")

	cursor, err := f.cursor.LoadCursor(context.Background())
	require.NoError(t, err)
	assert.Nil(t, cursor, "a revoked serial is never elected")
}
