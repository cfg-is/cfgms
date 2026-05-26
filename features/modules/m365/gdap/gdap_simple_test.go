// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gdap

import (
	"net/http"
	"os"
	"testing"

	"github.com/cfgis/cfgms/features/modules/m365/auth"
	saas "github.com/cfgis/cfgms/features/saas"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGDAPTypes tests the GDAP data structures and basic functionality
func TestGDAPTypes(t *testing.T) {
	t.Run("GDAPRelationshipStatus", func(t *testing.T) {
		// Test status constants
		assert.Equal(t, GDAPRelationshipStatus("pending"), GDAPStatusPending)
		assert.Equal(t, GDAPRelationshipStatus("active"), GDAPStatusActive)
		assert.Equal(t, GDAPRelationshipStatus("expired"), GDAPStatusExpired)
		assert.Equal(t, GDAPRelationshipStatus("terminated"), GDAPStatusTerminated)
	})

	t.Run("GDAPRole", func(t *testing.T) {
		role := GDAPRole{
			RoleDefinitionID: "role-123",
			RoleName:         "Global Administrator",
			RoleDescription:  "Global Admin Role",
		}

		assert.Equal(t, "role-123", role.RoleDefinitionID)
		assert.Equal(t, "Global Administrator", role.RoleName)
		assert.Equal(t, "Global Admin Role", role.RoleDescription)
	})

	t.Run("GDAPConfig", func(t *testing.T) {
		config := &GDAPConfig{
			ClientID:                  "test-client-id",
			ClientSecret:              "test-client-secret",
			PartnerTenantID:           "test-partner-tenant",
			PartnerCenterScopes:       []string{"https://api.partnercenter.microsoft.com/user_impersonation"},
			GraphScopes:               []string{"User.Read", "Directory.Read.All"},
			ValidateGDAPRelationships: true,
			EnforceRoleBasedAccess:    true,
			RequireActiveRelationship: true,
		}

		assert.Equal(t, "test-client-id", config.ClientID)
		assert.True(t, config.ValidateGDAPRelationships)
		assert.Contains(t, config.PartnerCenterScopes, "https://api.partnercenter.microsoft.com/user_impersonation")
		assert.Contains(t, config.GraphScopes, "User.Read")
	})
}

func TestGDAPClientConfigValidation(t *testing.T) {
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
			PartnerCenterScopes: []string{
				"https://api.partnercenter.microsoft.com/user_impersonation",
			},
		}

		err := ValidateGDAPClientConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partner_tenant_id is required")
	})

	t.Run("ValidateGDAPClientConfigMissingClientID", func(t *testing.T) {
		config := &GDAPClientConfig{
			PartnerTenantID:     "test-partner-tenant",
			PartnerClientSecret: "test-client-secret",
			PartnerCenterScopes: []string{
				"https://api.partnercenter.microsoft.com/user_impersonation",
			},
		}

		err := ValidateGDAPClientConfig(config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "partner_client_id is required")
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

func TestPartnerAccessValidationStruct(t *testing.T) {
	validation := &PartnerAccessValidation{
		CustomerTenantID:    "test-tenant",
		PartnerTenantID:     "partner-tenant",
		HasAccess:           true,
		ActiveRelationships: []string{"rel-123", "rel-456"},
		AvailableRoles:      []string{"Global Administrator", "User Administrator"},
	}

	assert.Equal(t, "test-tenant", validation.CustomerTenantID)
	assert.True(t, validation.HasAccess)
	assert.Len(t, validation.ActiveRelationships, 2)
	assert.Contains(t, validation.AvailableRoles, "Global Administrator")
}

func TestCustomerInfoStruct(t *testing.T) {
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

func TestGDAPRoleRequirements(t *testing.T) {
	// This tests the standalone role requirement logic
	// without needing a full provider
	roleMap := map[string]map[string][]string{
		"users": {
			"create": {"User Administrator", "Global Administrator"},
			"read":   {"User Administrator", "Global Reader", "Directory Readers"},
			"update": {"User Administrator", "Global Administrator"},
			"delete": {"User Administrator", "Global Administrator"},
			"list":   {"User Administrator", "Global Reader", "Directory Readers"},
		},
		"groups": {
			"create": {"Groups Administrator", "Global Administrator"},
			"read":   {"Groups Administrator", "Global Reader", "Directory Readers"},
			"update": {"Groups Administrator", "Global Administrator"},
			"delete": {"Groups Administrator", "Global Administrator"},
			"list":   {"Groups Administrator", "Global Reader", "Directory Readers"},
		},
		"conditional_access": {
			"create": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"read":   {"Conditional Access Administrator", "Security Administrator", "Security Reader", "Global Reader"},
			"update": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"delete": {"Conditional Access Administrator", "Security Administrator", "Global Administrator"},
			"list":   {"Conditional Access Administrator", "Security Administrator", "Security Reader", "Global Reader"},
		},
	}

	t.Run("UserOperations", func(t *testing.T) {
		roles := roleMap["users"]["create"]
		assert.Contains(t, roles, "User Administrator")
		assert.Contains(t, roles, "Global Administrator")

		roles = roleMap["users"]["read"]
		assert.Contains(t, roles, "Directory Readers")
	})

	t.Run("ConditionalAccessOperations", func(t *testing.T) {
		roles := roleMap["conditional_access"]["create"]
		assert.Contains(t, roles, "Conditional Access Administrator")
		assert.Contains(t, roles, "Security Administrator")

		roles = roleMap["conditional_access"]["read"]
		assert.Contains(t, roles, "Security Reader")
	})

	t.Run("UnknownResourceDefault", func(t *testing.T) {
		// Verify the production method returns ["Global Administrator"] for unmapped resources.
		provider := NewGDAPProvider(nil, &http.Client{}, "partner-tenant")
		roles := provider.GetGDAPRoleRequirements("unknown_resource", "read")
		assert.Equal(t, []string{"Global Administrator"}, roles)
	})
}

func TestGDAPProviderCreation(t *testing.T) {
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}

	tmpDir := t.TempDir()
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{"secrets_dir": tmpDir})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	credStore := saas.NewSecretStoreCredentialStore(store)
	var _ auth.CredentialStore = credStore

	httpClient := &http.Client{}
	partnerTenantID := "test-partner-tenant"

	gdapProvider := NewGDAPProvider(credStore, httpClient, partnerTenantID)
	assert.NotNil(t, gdapProvider)
	assert.Equal(t, partnerTenantID, gdapProvider.partnerTenantID)
	assert.NotNil(t, gdapProvider.gdapClient)

	// Smoke-test: provider info is populated by the embedded MicrosoftMultiTenantProvider.
	info := gdapProvider.GetInfo()
	assert.NotEmpty(t, info.Name)
}

// TestGDAPImplementationComplete validates that all required types and functions are implemented
func TestGDAPImplementationComplete(t *testing.T) {
	t.Run("RequiredTypesExist", func(t *testing.T) {
		// Validate that all required types are defined
		_ = GDAPStatusActive
		var _ = GDAPRole{}
		var _ = GDAPRelationship{}
		var _ = GDAPConfig{}
		var _ = GDAPMetrics{}
		var _ = PartnerAccessValidation{}
		var _ = CustomerInfo{}
		var _ = GDAPClientConfig{}

		// Compile-time guard: the test fails to build if any type is removed.
	})

	t.Run("RequiredFunctionsExist", func(t *testing.T) {
		// Validate that key functions are defined

		// NewGDAPClient function exists (we test by calling it with nil - it should handle gracefully)
		client := NewGDAPClient(nil, "test-tenant")
		assert.NotNil(t, client)
		assert.Equal(t, "test-tenant", client.partnerTenantID)

		// ValidateGDAPClientConfig function exists
		config := &GDAPClientConfig{
			PartnerTenantID:     "test",
			PartnerClientID:     "test",
			PartnerClientSecret: "test",
			PartnerCenterScopes: []string{"https://api.partnercenter.microsoft.com/user_impersonation"},
		}
		err := ValidateGDAPClientConfig(config)
		assert.NoError(t, err)
	})
}
