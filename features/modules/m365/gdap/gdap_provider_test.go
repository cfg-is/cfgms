// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gdap

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
)

// mockCredentialStore implements auth.CredentialStore for testing
type mockCredentialStore struct {
	tokens map[string]*auth.AccessToken
}

func newMockCredentialStore() *mockCredentialStore {
	return &mockCredentialStore{
		tokens: make(map[string]*auth.AccessToken),
	}
}

func (m *mockCredentialStore) StoreToken(tenantID string, token *auth.AccessToken) error {
	m.tokens[tenantID] = token
	return nil
}

func (m *mockCredentialStore) GetToken(tenantID string) (*auth.AccessToken, error) {
	if token, exists := m.tokens[tenantID]; exists {
		return token, nil
	}
	return nil, auth.ErrTokenNotFound
}

func (m *mockCredentialStore) DeleteToken(tenantID string) error {
	delete(m.tokens, tenantID)
	return nil
}

func (m *mockCredentialStore) StoreDelegatedToken(tenantID, userID string, token *auth.AccessToken) error {
	key := tenantID + ":" + userID
	m.tokens[key] = token
	return nil
}

func (m *mockCredentialStore) GetDelegatedToken(tenantID, userID string) (*auth.AccessToken, error) {
	key := tenantID + ":" + userID
	if token, exists := m.tokens[key]; exists {
		return token, nil
	}
	return nil, auth.ErrTokenNotFound
}

func (m *mockCredentialStore) DeleteDelegatedToken(tenantID, userID string) error {
	key := tenantID + ":" + userID
	delete(m.tokens, key)
	return nil
}

func (m *mockCredentialStore) StoreUserContext(tenantID, userID string, userContext *auth.UserContext) error {
	return nil // Not used in this test
}

func (m *mockCredentialStore) GetUserContext(tenantID, userID string) (*auth.UserContext, error) {
	return nil, auth.ErrTokenNotFound // Not used in this test
}

func (m *mockCredentialStore) DeleteUserContext(tenantID, userID string) error {
	return nil // Not used in this test
}

// Add missing GetConfig method for full auth.CredentialStore compatibility
func (m *mockCredentialStore) GetConfig(tenantID string) (*auth.OAuth2Config, error) {
	return nil, auth.ErrTokenNotFound
}

func (m *mockCredentialStore) StoreConfig(tenantID string, config *auth.OAuth2Config) error {
	return nil
}

func (m *mockCredentialStore) DeleteConfig(tenantID string) error {
	return nil
}

// IsAvailable checks if the credential store is available
func (m *mockCredentialStore) IsAvailable() bool {
	return true
}

func TestGDAPConfig(t *testing.T) {
	credStore := newMockCredentialStore()
	httpClient := &http.Client{}
	partnerTenantID := "partner-tenant-123"

	provider := NewGDAPProvider(credStore, httpClient, partnerTenantID)

	t.Run("ValidateGDAPConfigSuccess", func(t *testing.T) {
		config := &GDAPConfig{
			ClientID:        "test-client-id",
			ClientSecret:    "test-client-secret",
			PartnerTenantID: "test-partner-tenant",
			PartnerCenterScopes: []string{
				"https://api.partnercenter.microsoft.com/user_impersonation",
			},
			ValidateGDAPRelationships: true,
			EnforceRoleBasedAccess:    true,
		}

		err := provider.ValidateGDAPConfig(config)
		assert.NoError(t, err)
	})

	t.Run("ValidateGDAPConfigMissingClientID", func(t *testing.T) {
		config := &GDAPConfig{
			ClientSecret:    "test-client-secret",
			PartnerTenantID: "test-partner-tenant",
		}

		err := provider.ValidateGDAPConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "client_id is required")
	})

	t.Run("ValidateGDAPConfigMissingPartnerScope", func(t *testing.T) {
		config := &GDAPConfig{
			ClientID:            "test-client-id",
			ClientSecret:        "test-client-secret",
			PartnerTenantID:     "test-partner-tenant",
			PartnerCenterScopes: []string{"some.other.scope"},
		}

		err := provider.ValidateGDAPConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required Partner Center scope missing")
	})
}

func TestGDAPClientConfig(t *testing.T) {
	t.Run("ValidateGDAPClientConfigSuccess", func(t *testing.T) {
		config := &GDAPClientConfig{
			PartnerTenantID:     "test-partner-tenant",
			PartnerClientID:     "test-client-id",
			PartnerClientSecret: "test-client-secret",
			PartnerCenterScopes: []string{
				"https://api.partnercenter.microsoft.com/user_impersonation",
			},
		}

		err := ValidateGDAPClientConfig(config)
		assert.NoError(t, err)
	})

	t.Run("ValidateGDAPClientConfigMissingTenant", func(t *testing.T) {
		config := &GDAPClientConfig{
			PartnerClientID:     "test-client-id",
			PartnerClientSecret: "test-client-secret",
		}

		err := ValidateGDAPClientConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partner_tenant_id is required")
	})

	t.Run("ValidateGDAPClientConfigMissingScope", func(t *testing.T) {
		config := &GDAPClientConfig{
			PartnerTenantID:     "test-partner-tenant",
			PartnerClientID:     "test-client-id",
			PartnerClientSecret: "test-client-secret",
			PartnerCenterScopes: []string{"some.other.scope"},
		}

		err := ValidateGDAPClientConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required Partner Center scope missing")
	})
}

func TestPartnerAccessValidation(t *testing.T) {
	validation := &PartnerAccessValidation{
		CustomerTenantID:    "test-tenant",
		PartnerTenantID:     "partner-tenant",
		HasAccess:           true,
		ActiveRelationships: []string{"rel-123", "rel-456"},
		AvailableRoles:      []string{"Global Administrator", "User Administrator"},
		ValidatedAt:         time.Now(),
	}

	assert.Equal(t, "test-tenant", validation.CustomerTenantID)
	assert.True(t, validation.HasAccess)
	assert.Len(t, validation.ActiveRelationships, 2)
	assert.Contains(t, validation.AvailableRoles, "Global Administrator")
}

func TestCustomerInfo(t *testing.T) {
	validation := &PartnerAccessValidation{
		HasAccess: true,
	}

	customerInfo := &CustomerInfo{
		TenantID:     "customer-tenant-id",
		CompanyName:  "Test Company",
		Domain:       "testcompany.com",
		Country:      "US",
		Region:       "WA",
		City:         "Seattle",
		AccessMethod: "gdap",
		Validation:   validation,
	}

	assert.Equal(t, "customer-tenant-id", customerInfo.TenantID)
	assert.Equal(t, "gdap", customerInfo.AccessMethod)
	assert.True(t, customerInfo.Validation.HasAccess)
}
