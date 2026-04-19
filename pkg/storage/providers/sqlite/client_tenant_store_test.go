// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newClientTenantStore(t *testing.T) business.ClientTenantStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateClientTenantStore(map[string]interface{}{"path": filepath.Join(dir, "ct.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestClientTenantStore_StoreAndGet(t *testing.T) {
	store := newClientTenantStore(t)

	client := &business.ClientTenant{
		TenantID:         "azure-tenant-001",
		TenantName:       "Contoso Ltd",
		DomainName:       "contoso.com",
		AdminEmail:       "admin@contoso.com",
		ConsentedAt:      time.Now().UTC().Truncate(time.Second),
		Status:           business.ClientTenantStatusActive,
		ClientIdentifier: "cfgms-contoso",
		Metadata:         map[string]interface{}{"region": "us-east"},
	}

	require.NoError(t, store.StoreClientTenant(client))

	got, err := store.GetClientTenant("azure-tenant-001")
	require.NoError(t, err)
	assert.Equal(t, client.TenantID, got.TenantID)
	assert.Equal(t, client.TenantName, got.TenantName)
	assert.Equal(t, client.AdminEmail, got.AdminEmail)
	assert.Equal(t, client.Status, got.Status)
	assert.Equal(t, "us-east", got.Metadata["region"])
}

func TestClientTenantStore_GetNotFound(t *testing.T) {
	store := newClientTenantStore(t)
	_, err := store.GetClientTenant("nonexistent")
	assert.Error(t, err)
}

func TestClientTenantStore_GetByIdentifier(t *testing.T) {
	store := newClientTenantStore(t)

	client := &business.ClientTenant{
		TenantID:         "azure-tenant-002",
		TenantName:       "Fabrikam",
		DomainName:       "fabrikam.com",
		AdminEmail:       "admin@fabrikam.com",
		ConsentedAt:      time.Now().UTC(),
		Status:           business.ClientTenantStatusActive,
		ClientIdentifier: "cfgms-fabrikam",
	}
	require.NoError(t, store.StoreClientTenant(client))

	got, err := store.GetClientTenantByIdentifier("cfgms-fabrikam")
	require.NoError(t, err)
	assert.Equal(t, "azure-tenant-002", got.TenantID)
}

func TestClientTenantStore_M365ExtensionFields(t *testing.T) {
	store := newClientTenantStore(t)

	// Store a client tenant with M365 extension fields embedded in Metadata
	client := &business.ClientTenant{
		TenantID:         "azure-m365",
		TenantName:       "M365 Corp",
		DomainName:       "m365corp.com",
		AdminEmail:       "admin@m365corp.com",
		ConsentedAt:      time.Now().UTC(),
		Status:           business.ClientTenantStatusActive,
		ClientIdentifier: "cfgms-m365",
		Metadata: map[string]interface{}{
			"m365_tenant_id":    "m365-tenant-uuid",
			"m365_admin_email":  "m365admin@m365corp.com",
			"m365_consented_at": time.Now().UTC().Format(time.RFC3339Nano),
			"m365_status":       "active",
		},
	}
	require.NoError(t, store.StoreClientTenant(client))

	got, err := store.GetClientTenant("azure-m365")
	require.NoError(t, err)

	// M365 extension fields must round-trip without the separate M365 interface
	assert.Equal(t, "m365-tenant-uuid", got.Metadata["m365_tenant_id"])
	assert.Equal(t, "m365admin@m365corp.com", got.Metadata["m365_admin_email"])
	assert.Equal(t, "active", got.Metadata["m365_status"])
}

func TestClientTenantStore_UpdateStatus(t *testing.T) {
	store := newClientTenantStore(t)

	client := &business.ClientTenant{
		TenantID:         "azure-tenant-upd",
		TenantName:       "UpdateTest",
		DomainName:       "update.com",
		AdminEmail:       "a@update.com",
		ConsentedAt:      time.Now().UTC(),
		Status:           business.ClientTenantStatusPending,
		ClientIdentifier: "cfgms-upd",
	}
	require.NoError(t, store.StoreClientTenant(client))
	require.NoError(t, store.UpdateClientTenantStatus("azure-tenant-upd", business.ClientTenantStatusActive))

	got, err := store.GetClientTenant("azure-tenant-upd")
	require.NoError(t, err)
	assert.Equal(t, business.ClientTenantStatusActive, got.Status)
}

func TestClientTenantStore_UpdateStatus_NotFound(t *testing.T) {
	store := newClientTenantStore(t)
	assert.Error(t, store.UpdateClientTenantStatus("nonexistent", business.ClientTenantStatusActive))
}

func TestClientTenantStore_Delete(t *testing.T) {
	store := newClientTenantStore(t)

	client := &business.ClientTenant{
		TenantID:         "azure-del",
		TenantName:       "ToDelete",
		DomainName:       "del.com",
		AdminEmail:       "a@del.com",
		ConsentedAt:      time.Now().UTC(),
		Status:           business.ClientTenantStatusActive,
		ClientIdentifier: "cfgms-del",
	}
	require.NoError(t, store.StoreClientTenant(client))
	require.NoError(t, store.DeleteClientTenant("azure-del"))
	_, err := store.GetClientTenant("azure-del")
	assert.Error(t, err)
}

func TestClientTenantStore_List(t *testing.T) {
	store := newClientTenantStore(t)

	for _, c := range []*business.ClientTenant{
		{TenantID: "az-1", TenantName: "A", DomainName: "a.com", AdminEmail: "x@a.com", ConsentedAt: time.Now().UTC(), Status: business.ClientTenantStatusActive, ClientIdentifier: "ci-1"},
		{TenantID: "az-2", TenantName: "B", DomainName: "b.com", AdminEmail: "x@b.com", ConsentedAt: time.Now().UTC(), Status: business.ClientTenantStatusPending, ClientIdentifier: "ci-2"},
		{TenantID: "az-3", TenantName: "C", DomainName: "c.com", AdminEmail: "x@c.com", ConsentedAt: time.Now().UTC(), Status: business.ClientTenantStatusActive, ClientIdentifier: "ci-3"},
	} {
		require.NoError(t, store.StoreClientTenant(c))
	}

	all, err := store.ListClientTenants("")
	require.NoError(t, err)
	assert.Len(t, all, 3)

	active, err := store.ListClientTenants(business.ClientTenantStatusActive)
	require.NoError(t, err)
	assert.Len(t, active, 2)
}

func TestClientTenantStore_AdminConsentRequest(t *testing.T) {
	store := newClientTenantStore(t)

	req := &business.AdminConsentRequest{
		ClientIdentifier: "cfgms-consent",
		ClientName:       "Consent Corp",
		RequestedBy:      "msp@example.com",
		State:            "oauth2-state-xyz",
		ExpiresAt:        time.Now().UTC().Add(1 * time.Hour),
		Metadata:         map[string]interface{}{"source": "api"},
	}
	require.NoError(t, store.StoreAdminConsentRequest(req))

	got, err := store.GetAdminConsentRequest("oauth2-state-xyz")
	require.NoError(t, err)
	assert.Equal(t, req.ClientIdentifier, got.ClientIdentifier)
	assert.Equal(t, req.State, got.State)

	require.NoError(t, store.DeleteAdminConsentRequest("oauth2-state-xyz"))
	_, err = store.GetAdminConsentRequest("oauth2-state-xyz")
	assert.Error(t, err)
}

func TestClientTenantStore_AdminConsentRequest_Expired(t *testing.T) {
	store := newClientTenantStore(t)

	req := &business.AdminConsentRequest{
		ClientIdentifier: "cfgms-expired",
		ClientName:       "Expired Corp",
		RequestedBy:      "msp@example.com",
		State:            "expired-state",
		ExpiresAt:        time.Now().UTC().Add(-1 * time.Hour), // already expired
	}
	require.NoError(t, store.StoreAdminConsentRequest(req))

	_, err := store.GetAdminConsentRequest("expired-state")
	assert.Error(t, err, "expected error for expired request")
}
