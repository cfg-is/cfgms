// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gdap

// BenchmarkM365TenantManager_DiscoverAndSyncTenants exercises the full
// DiscoverAndSyncTenants path with a real GDAPProvider backed by an in-process
// httptest.Server. It lives in package gdap (not features/saas) because
// gdap_provider.go imports features/saas, making the reverse import a cycle.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	saas "github.com/cfgis/cfgms/features/saas"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow/modules/m365/auth"
	storageInterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"

	"github.com/stretchr/testify/require"
)

var benchDiscoverSeq int64

func BenchmarkM365TenantManager_DiscoverAndSyncTenants(b *testing.B) {
	ctx := context.Background()
	const n = 100

	// Build an in-process test server handling both the OAuth2 token endpoint
	// and the Partner Center GDAP relationships endpoint.
	mux := http.NewServeMux()

	mux.HandleFunc("/bench-partner-tenant/oauth2/v2.0/token",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "bench-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}); err != nil {
				http.Error(w, "encode error", http.StatusInternalServerError)
			}
		})

	mux.HandleFunc("/customers/relationships/delegatedAdminRelationships",
		func(w http.ResponseWriter, r *http.Request) {
			items := make([]map[string]interface{}, n)
			for i := range items {
				items[i] = map[string]interface{}{
					"id":          fmt.Sprintf("rel-%d", i),
					"displayName": fmt.Sprintf("Relationship %d", i),
					"customer": map[string]interface{}{
						"tenantId":    fmt.Sprintf("m365-bench-%d", i),
						"displayName": fmt.Sprintf("Bench Tenant %d", i),
					},
					"details":              map[string]interface{}{"unifiedRoles": []interface{}{}},
					"status":               "Active",
					"createdDateTime":      "2025-01-01T00:00:00Z",
					"lastModifiedDateTime": "2025-01-01T00:00:00Z",
					"endDateTime":          "2027-01-01T00:00:00Z",
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]interface{}{
				"totalCount": n,
				"items":      items,
			}); err != nil {
				http.Error(w, "encode error", http.StatusInternalServerError)
			}
		})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	for range b.N {
		b.StopTimer()

		seq := atomic.AddInt64(&benchDiscoverSeq, 1)
		sm, err := storageInterfaces.CreateOSSStorageManager(
			b.TempDir(),
			fmt.Sprintf("file:cfgms-gdap-bench-%d?mode=memory&cache=shared", seq),
		)
		require.NoError(b, err)

		tenantStore := sm.GetTenantStore()

		credStore := &testCredentialStore{
			config: &auth.OAuth2Config{
				ClientID:     "bench-cid",
				ClientSecret: "bench-secret",
			},
		}

		// Real GDAPProvider: credential store, test-server HTTP client, partner tenant ID.
		gdapProvider := NewGDAPProvider(credStore, srv.Client(), "bench-partner-tenant")
		// gdapClient's credStore must be set explicitly — NewGDAPProvider wires it to
		// MicrosoftMultiTenantProvider but not to GDAPClient.
		gdapProvider.gdapClient.SetCredentialStore(credStore)
		gdapProvider.gdapClient.baseURL = srv.URL
		gdapProvider.gdapClient.tokenBaseURL = srv.URL

		cfgmsTenantManager := tenant.NewManager(tenantStore, nil)
		// m365Provider is not invoked during GDAP discovery; a bare http.Client suffices.
		m365Provider := saas.NewMicrosoftMultiTenantProvider(credStore, &http.Client{})
		manager := saas.NewM365TenantManager(cfgmsTenantManager, m365Provider, nil, gdapProvider)

		// Pre-seed n tenants so all sync iterations hit the update path.
		for i := range n {
			meta := &tenant.M365TenantMetadata{
				M365TenantID:    fmt.Sprintf("m365-bench-%d", i),
				PrimaryDomain:   fmt.Sprintf("bench%d.example.com", i),
				DiscoveryMethod: "gdap",
				HealthStatus:    tenant.HealthStatusUnknown,
			}
			metaJSON, merr := json.Marshal(meta)
			require.NoError(b, merr)
			require.NoError(b, tenantStore.CreateTenant(ctx, &business.TenantData{
				ID:   fmt.Sprintf("cfgms-bench-%d", i),
				Name: fmt.Sprintf("Bench-Tenant-%d", i),
				Metadata: map[string]string{
					"m365_metadata": string(metaJSON),
					"tenant_type":   "m365",
				},
			}))
		}

		b.StartTimer()
		result, berr := manager.DiscoverAndSyncTenants(ctx, "gdap")
		b.StopTimer()

		require.NoError(b, berr)
		require.Equal(b, n, result.Metadata["synced_count"],
			"expected %d synced tenants, got %v", n, result.Metadata["synced_count"])

		_ = sm.Close()
	}
}
