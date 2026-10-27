// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/graph"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"
)

const entraName = "entraid"

func TestRegisterDirectoryProviders_EntraRegisteredUnconnected(t *testing.T) {
	mgr, err := registerDirectoryProviders(testutil.NewMemSecretStore(), logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, mgr)

	assert.Equal(t, []string{entraName}, mgr.ListProviders())
	p, err := mgr.GetProvider(entraName)
	require.NoError(t, err)
	assert.False(t, p.IsConnected(context.Background()), "registration must not connect")
}

func TestRegisterDirectoryProviders_NilSecretStoreSkipsEntra(t *testing.T) {
	mgr, err := registerDirectoryProviders(nil, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Empty(t, mgr.ListProviders())
}

// entraFixture is an httptest server standing in for both the token authority
// and Microsoft Graph, recording which client the token requests were made for.
type entraFixture struct {
	mu       sync.Mutex
	clientID []string
	graphHit int
	srv      *httptest.Server
}

func newEntraFixture(t *testing.T) *entraFixture {
	t.Helper()
	f := &entraFixture{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token") {
			require.NoError(t, r.ParseForm())
			f.mu.Lock()
			f.clientID = append(f.clientID, r.PostForm.Get("client_id"))
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"access_token":"tok-` + r.PostForm.Get("client_id") + `","token_type":"Bearer","expires_in":3600}`))
			return
		}
		f.mu.Lock()
		f.graphHit++
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *entraFixture) clients() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.clientID...)
}

// tenantMemStore addresses secrets by the explicit (tenant, key) pair, the way
// the controller's SOPS store does, over the in-memory store.
type tenantMemStore struct{ *testutil.MemSecretStore }

func (s tenantMemStore) GetTenantSecret(ctx context.Context, tenantID, key string) (*secretsif.Secret, error) {
	sec, err := s.GetSecret(ctx, tenantID+"/"+key)
	if err != nil {
		return nil, err
	}
	sec.TenantID = tenantID
	return sec, nil
}

func (s tenantMemStore) DeleteTenantSecret(ctx context.Context, tenantID, key string) error {
	return s.DeleteSecret(ctx, tenantID+"/"+key)
}

func newTenantStore() tenantMemStore { return tenantMemStore{testutil.NewMemSecretStore()} }

func seedTenant(t *testing.T, store secretsif.SecretStore, f *entraFixture, tenant, clientID string) {
	t.Helper()
	require.NoError(t, auth.NewSecretStoreCredentialStore(store).StoreConfig(tenant, &auth.OAuth2Config{
		ClientID:             clientID,
		ClientSecret:         "secret-" + clientID,
		TenantID:             "m365-" + clientID,
		AuthorityURL:         f.srv.URL,
		Scopes:               []string{"https://graph.microsoft.com/.default"},
		UseClientCredentials: true,
	}))
}

func listUsers(ctx context.Context, mgr *interfaces.DirectoryProviderManager) error {
	return mgr.ExecuteProviderOp(ctx, entraName, func(p interfaces.DirectoryProvider) error {
		_, err := p.ListUsers(ctx, &interfaces.SearchFilters{})
		return err
	})
}

func TestEntraDirectory_CallForTenantXResolvesTenantXCredential(t *testing.T) {
	f := newEntraFixture(t)
	store := newTenantStore()
	seedTenant(t, store, f, "root/tenant-x", "client-x")
	seedTenant(t, store, f, "root/tenant-y", "client-y")

	mgr, err := registerDirectoryProviders(store, logging.NewNoopLogger(), graph.WithBaseURL(f.srv.URL))
	require.NoError(t, err)

	ctxX := context.WithValue(context.Background(), ctxkeys.TenantID, "root/tenant-x")
	ctxY := context.WithValue(context.Background(), ctxkeys.TenantID, "root/tenant-y")

	require.NoError(t, listUsers(ctxX, mgr))
	assert.Equal(t, []string{"client-x"}, f.clients())
	require.NoError(t, listUsers(ctxY, mgr))
	assert.Equal(t, []string{"client-x", "client-y"}, f.clients())

	// A tenant with no connection on file fails; it never borrows another's.
	ctxZ := context.WithValue(context.Background(), ctxkeys.TenantID, "root/tenant-z")
	require.Error(t, listUsers(ctxZ, mgr))
	assert.Equal(t, []string{"client-x", "client-y"}, f.clients())
}

func TestEntraDirectory_StatisticsMoveThroughManager(t *testing.T) {
	f := newEntraFixture(t)
	store := newTenantStore()
	seedTenant(t, store, f, "root/tenant-x", "client-x")

	mgr, err := registerDirectoryProviders(store, logging.NewNoopLogger(), graph.WithBaseURL(f.srv.URL))
	require.NoError(t, err)
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "root/tenant-x")

	require.NoError(t, listUsers(ctx, mgr))
	stats, err := mgr.GetProviderStatistics(ctx, entraName)
	require.NoError(t, err)
	assert.EqualValues(t, 1, stats.RequestCount)
	assert.EqualValues(t, 0, stats.ErrorCount)
}

func TestServerStop_ClosesDirectoryManager(t *testing.T) {
	mgr, err := registerDirectoryProviders(testutil.NewMemSecretStore(), logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotEmpty(t, mgr.ListProviders())

	srv := &Server{directoryManager: mgr, logger: logging.NewNoopLogger()}
	require.NoError(t, srv.Stop())
	assert.Empty(t, mgr.ListProviders(), "Stop must close the directory manager")
}
