// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package saas

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// contractConsentStore verifies that any ConsentStore implementation preserves all
// ConsentStatus fields through a store/retrieve round-trip. Run this against every
// implementation to confirm contract compliance.
func contractConsentStore(t *testing.T, store ConsentStore) {
	t.Helper()
	provider := "contract-provider"

	flow := &OAuth2Flow{
		Provider:      provider,
		State:         "state-abc123",
		CodeVerifier:  "verifier-xyz",
		CodeChallenge: "challenge-xyz",
		AuthURL:       "https://auth.example.com/authorize",
		RedirectURI:   "https://app.example.com/callback",
		Created:       time.Now().UTC().Truncate(time.Millisecond),
		ExpiresAt:     time.Now().UTC().Add(10 * time.Minute).Truncate(time.Millisecond),
	}

	original := &ConsentStatus{
		Provider:            provider,
		HasAdminConsent:     true,
		ConsentGrantedAt:    time.Now().UTC().Truncate(time.Millisecond),
		LastTenantDiscovery: time.Now().UTC().Truncate(time.Millisecond),
		AccessibleTenants: []TenantInfo{
			{
				TenantID:         "tenant-aaa",
				DisplayName:      "Tenant AAA",
				Domain:           "aaa.example.com",
				CountryCode:      "US",
				TenantType:       "AAD",
				HasAccess:        true,
				LastTokenRefresh: time.Now().UTC().Truncate(time.Millisecond),
			},
			{
				TenantID:    "tenant-bbb",
				DisplayName: "Tenant BBB",
				Domain:      "bbb.example.com",
				HasAccess:   false,
			},
		},
		ConsentFlow: flow,
	}

	// Round-trip: store then retrieve.
	err := store.StoreConsent(provider, original)
	require.NoError(t, err)

	got, err := store.GetConsent(provider)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, original.Provider, got.Provider)
	assert.Equal(t, original.HasAdminConsent, got.HasAdminConsent)
	assert.True(t, original.ConsentGrantedAt.Equal(got.ConsentGrantedAt),
		"ConsentGrantedAt mismatch: want %v got %v", original.ConsentGrantedAt, got.ConsentGrantedAt)
	assert.True(t, original.LastTenantDiscovery.Equal(got.LastTenantDiscovery),
		"LastTenantDiscovery mismatch")

	require.Len(t, got.AccessibleTenants, 2, "AccessibleTenants slice length must be preserved")
	assert.Equal(t, original.AccessibleTenants[0].TenantID, got.AccessibleTenants[0].TenantID)
	assert.Equal(t, original.AccessibleTenants[0].DisplayName, got.AccessibleTenants[0].DisplayName)
	assert.Equal(t, original.AccessibleTenants[0].Domain, got.AccessibleTenants[0].Domain)
	assert.Equal(t, original.AccessibleTenants[0].CountryCode, got.AccessibleTenants[0].CountryCode)
	assert.Equal(t, original.AccessibleTenants[0].TenantType, got.AccessibleTenants[0].TenantType)
	assert.Equal(t, original.AccessibleTenants[0].HasAccess, got.AccessibleTenants[0].HasAccess)
	assert.True(t, original.AccessibleTenants[0].LastTokenRefresh.Equal(got.AccessibleTenants[0].LastTokenRefresh),
		"LastTokenRefresh mismatch")
	assert.Equal(t, original.AccessibleTenants[1].TenantID, got.AccessibleTenants[1].TenantID)
	assert.Equal(t, original.AccessibleTenants[1].HasAccess, got.AccessibleTenants[1].HasAccess)

	require.NotNil(t, got.ConsentFlow, "ConsentFlow must be preserved")
	assert.Equal(t, original.ConsentFlow.Provider, got.ConsentFlow.Provider)
	assert.Equal(t, original.ConsentFlow.State, got.ConsentFlow.State)
	assert.Equal(t, original.ConsentFlow.CodeVerifier, got.ConsentFlow.CodeVerifier)
	assert.Equal(t, original.ConsentFlow.CodeChallenge, got.ConsentFlow.CodeChallenge)
	assert.Equal(t, original.ConsentFlow.AuthURL, got.ConsentFlow.AuthURL)
	assert.Equal(t, original.ConsentFlow.RedirectURI, got.ConsentFlow.RedirectURI)

	// Overwrite with minimal status (nil flow, empty tenants).
	cleared := &ConsentStatus{
		Provider:          provider,
		HasAdminConsent:   false,
		AccessibleTenants: []TenantInfo{},
		ConsentFlow:       nil,
	}
	err = store.StoreConsent(provider, cleared)
	require.NoError(t, err)

	got2, err := store.GetConsent(provider)
	require.NoError(t, err)
	require.NotNil(t, got2)
	assert.False(t, got2.HasAdminConsent)
	assert.Empty(t, got2.AccessibleTenants)
	assert.Nil(t, got2.ConsentFlow)

	// Delete then confirm nil-not-found.
	err = store.DeleteConsent(provider)
	require.NoError(t, err)

	missing, err := store.GetConsent(provider)
	assert.NoError(t, err)
	assert.Nil(t, missing, "GetConsent after delete must return nil, nil")
}

func TestInMemoryConsentStore_ContractRoundTrip(t *testing.T) {
	contractConsentStore(t, NewInMemoryConsentStore())
}

func TestInMemoryConsentStore_NilNotFound(t *testing.T) {
	store := NewInMemoryConsentStore()
	result, err := store.GetConsent("nonexistent-provider")
	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestInMemoryConsentStore_Delete(t *testing.T) {
	store := NewInMemoryConsentStore()

	err := store.StoreConsent("p", &ConsentStatus{Provider: "p", HasAdminConsent: true})
	require.NoError(t, err)

	got, err := store.GetConsent("p")
	require.NoError(t, err)
	require.NotNil(t, got)

	err = store.DeleteConsent("p")
	require.NoError(t, err)

	gone, err := store.GetConsent("p")
	assert.NoError(t, err)
	assert.Nil(t, gone)

	// Deleting a non-existent entry is idempotent.
	err = store.DeleteConsent("p")
	assert.NoError(t, err)
}

func TestInMemoryConsentStore_MultipleProviders(t *testing.T) {
	store := NewInMemoryConsentStore()
	providers := []string{"microsoft", "google", "okta"}

	for _, p := range providers {
		err := store.StoreConsent(p, &ConsentStatus{Provider: p, HasAdminConsent: true})
		require.NoError(t, err)
	}

	for _, p := range providers {
		got, err := store.GetConsent(p)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, p, got.Provider)
		assert.True(t, got.HasAdminConsent)
	}

	err := store.DeleteConsent("google")
	require.NoError(t, err)

	for _, p := range []string{"microsoft", "okta"} {
		got, err := store.GetConsent(p)
		require.NoError(t, err)
		assert.NotNil(t, got)
	}

	deleted, err := store.GetConsent("google")
	assert.NoError(t, err)
	assert.Nil(t, deleted)
}

func TestInMemoryConsentStore_OldFormatReturnsError(t *testing.T) {
	store := NewInMemoryConsentStore()

	// Inject old flat-string format directly to simulate encountering legacy data.
	store.mu.Lock()
	if store.data == nil {
		store.data = make(map[string][]byte)
	}
	store.data["microsoft"] = []byte("consent_granted:true;tenants:1;flow:none")
	store.mu.Unlock()

	result, err := store.GetConsent("microsoft")
	assert.Error(t, err, "old-format data must return an error")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "re-grant admin consent")
}

func TestInMemoryConsentStore_InvalidJSONReturnsError(t *testing.T) {
	store := NewInMemoryConsentStore()

	// Inject malformed JSON to simulate storage corruption.
	store.mu.Lock()
	if store.data == nil {
		store.data = make(map[string][]byte)
	}
	store.data["broken"] = []byte("{invalid json")
	store.mu.Unlock()

	result, err := store.GetConsent("broken")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "re-grant admin consent")
}

func TestInMemoryConsentStore_AccessibleTenantsPreserved(t *testing.T) {
	store := NewInMemoryConsentStore()
	provider := "microsoft"

	tenants := []TenantInfo{
		{TenantID: "t1", DisplayName: "Alpha Corp", Domain: "alpha.com", HasAccess: true},
		{TenantID: "t2", DisplayName: "Beta Corp", Domain: "beta.com", HasAccess: true},
		{TenantID: "t3", DisplayName: "Gamma Corp", Domain: "gamma.com", HasAccess: false},
	}

	err := store.StoreConsent(provider, &ConsentStatus{
		Provider:          provider,
		HasAdminConsent:   true,
		AccessibleTenants: tenants,
	})
	require.NoError(t, err)

	got, err := store.GetConsent(provider)
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Len(t, got.AccessibleTenants, 3)

	for i, want := range tenants {
		assert.Equal(t, want.TenantID, got.AccessibleTenants[i].TenantID)
		assert.Equal(t, want.DisplayName, got.AccessibleTenants[i].DisplayName)
		assert.Equal(t, want.Domain, got.AccessibleTenants[i].Domain)
		assert.Equal(t, want.HasAccess, got.AccessibleTenants[i].HasAccess)
	}
}
