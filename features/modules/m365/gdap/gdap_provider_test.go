// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gdap

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGDAPConfig(t *testing.T) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	partnerTenantID := "partner-tenant-123"

	// ValidateGDAPConfig only inspects GDAPConfig fields; it never reads the
	// credential store, so nil is safe here.
	provider := NewGDAPProvider(nil, httpClient, partnerTenantID)

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
