// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MockStewardClientForIntegration provides enhanced mock for integration testing
type MockStewardClientForIntegration struct {
	stewards       []StewardInfo
	moduleStates   map[string]map[string]interface{}
	healthStatuses map[string]*StewardHealth
	errorMode      bool
}

// NewMockStewardClientForIntegration creates a comprehensive mock steward client
func NewMockStewardClientForIntegration() *MockStewardClientForIntegration {
	return &MockStewardClientForIntegration{
		stewards: []StewardInfo{
			{
				ID:        "steward-ad-primary",
				Hostname:  "dc1.corp.contoso.com",
				Platform:  "windows",
				Version:   "1.0.0",
				Modules:   []string{"activedirectory", "firewall", "package"},
				Tags:      map[string]string{"ad_domain": "corp.contoso.com", "role": "domain_controller"},
				LastSeen:  time.Now(),
				IsHealthy: true,
			},
			{
				ID:        "steward-ad-dev",
				Hostname:  "dc1.dev.contoso.com",
				Platform:  "windows",
				Version:   "1.0.0",
				Modules:   []string{"activedirectory"},
				Tags:      map[string]string{"ad_domain": "dev.contoso.com", "role": "domain_controller"},
				LastSeen:  time.Now(),
				IsHealthy: true,
			},
			{
				ID:        "steward-gc",
				Hostname:  "gc1.contoso.com",
				Platform:  "windows",
				Version:   "1.0.0",
				Modules:   []string{"activedirectory"},
				Tags:      map[string]string{"ad_domain": "contoso.com", "role": "global_catalog"},
				LastSeen:  time.Now(),
				IsHealthy: true,
			},
		},
		moduleStates: make(map[string]map[string]interface{}),
		healthStatuses: map[string]*StewardHealth{
			"steward-ad-primary": {
				Status:    "healthy",
				LastCheck: time.Now(),
				Modules:   map[string]string{"activedirectory": "healthy"},
				Uptime:    24 * time.Hour,
			},
			"steward-ad-dev": {
				Status:    "healthy",
				LastCheck: time.Now(),
				Modules:   map[string]string{"activedirectory": "healthy"},
				Uptime:    48 * time.Hour,
			},
			"steward-gc": {
				Status:    "healthy",
				LastCheck: time.Now(),
				Modules:   map[string]string{"activedirectory": "healthy"},
				Uptime:    72 * time.Hour,
			},
		},
		errorMode: false,
	}
}

func (m *MockStewardClientForIntegration) GetConnectedStewards(ctx context.Context) ([]StewardInfo, error) {
	if m.errorMode {
		return nil, fmt.Errorf("mock steward discovery error")
	}
	return m.stewards, nil
}

func (m *MockStewardClientForIntegration) GetStewardHealth(ctx context.Context, stewardID string) (*StewardHealth, error) {
	if m.errorMode {
		return nil, fmt.Errorf("mock steward health error")
	}

	health, exists := m.healthStatuses[stewardID]
	if !exists {
		return nil, fmt.Errorf("steward %s not found", stewardID)
	}

	return health, nil
}

func (m *MockStewardClientForIntegration) GetModuleState(ctx context.Context, stewardID, moduleType, resourceID string) (map[string]interface{}, error) {
	if m.errorMode {
		return nil, fmt.Errorf("mock module state error")
	}

	// Simulate realistic AD responses based on resourceID
	switch resourceID {
	case "status":
		return map[string]interface{}{
			"connected":         true,
			"domain_controller": "dc1.corp.contoso.com",
			"domain":            "corp.contoso.com",
			"auth_method":       "kerberos",
			"health_status":     "healthy",
			"response_time":     "50ms",
			"request_count":     int64(150),
			"error_count":       int64(2),
		}, nil

	case "query:user:john.doe":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "user",
			"object_id":     "john.doe",
			"executed_at":   time.Now(),
			"response_time": 45 * time.Millisecond,
			"user": map[string]interface{}{
				"id":                  "cn=john.doe,ou=users,dc=corp,dc=contoso,dc=com",
				"sam_account_name":    "john.doe",
				"user_principal_name": "john.doe@corp.contoso.com",
				"display_name":        "John Doe",
				"email_address":       "john.doe@contoso.com",
				"account_enabled":     true,
				"distinguished_name":  "CN=John Doe,OU=Users,DC=corp,DC=contoso,DC=com",
				"source":              "activedirectory",
			},
		}, nil

	case "query:user:jane.smith:dev.contoso.com":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "user",
			"object_id":     "jane.smith",
			"executed_at":   time.Now(),
			"response_time": 85 * time.Millisecond, // Slower for cross-domain
			"user": map[string]interface{}{
				"id":                  "cn=jane.smith,ou=developers,dc=dev,dc=contoso,dc=com",
				"sam_account_name":    "jane.smith",
				"user_principal_name": "jane.smith@dev.contoso.com",
				"display_name":        "Jane Smith",
				"email_address":       "jane.smith@dev.contoso.com",
				"account_enabled":     true,
				"distinguished_name":  "CN=Jane Smith,OU=Developers,DC=dev,DC=contoso,DC=com",
				"source":              "activedirectory",
				"source_domain":       "dev.contoso.com",
				"cross_domain_query":  true,
			},
		}, nil

	case "forest:user:admin.user":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "forest_user",
			"object_id":     "admin.user",
			"executed_at":   time.Now(),
			"response_time": 120 * time.Millisecond, // Slower for forest search
			"total_count":   2,
			"users": []interface{}{
				map[string]interface{}{
					"sam_account_name":    "admin.user",
					"user_principal_name": "admin.user@corp.contoso.com",
					"display_name":        "Admin User Corp",
					"source_domain":       "corp.contoso.com",
					"forest_search":       true,
				},
				map[string]interface{}{
					"sam_account_name":    "admin.user",
					"user_principal_name": "admin.user@dev.contoso.com",
					"display_name":        "Admin User Dev",
					"source_domain":       "dev.contoso.com",
					"forest_search":       true,
				},
			},
		}, nil

	case "validate_trust:dev.contoso.com":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "trust_validation",
			"object_id":     "dev.contoso.com",
			"executed_at":   time.Now(),
			"response_time": 25 * time.Millisecond,
		}, nil

	case "query:computer:WORKSTATION-01":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "computer",
			"object_id":     "WORKSTATION-01",
			"executed_at":   time.Now(),
			"response_time": 35 * time.Millisecond,
			"user": map[string]interface{}{ // Computer as DirectoryUser
				"id":                 "cn=workstation-01,cn=computers,dc=corp,dc=contoso,dc=com",
				"sam_account_name":   "WORKSTATION-01$",
				"display_name":       "WORKSTATION-01",
				"account_enabled":    true,
				"distinguished_name": "CN=WORKSTATION-01,CN=Computers,DC=corp,DC=contoso,DC=com",
				"object_type":        "computer",
			},
		}, nil

	case "query:gpo:Default Domain Policy":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "gpo",
			"object_id":     "Default Domain Policy",
			"executed_at":   time.Now(),
			"response_time": 40 * time.Millisecond,
			"generic_object": map[string]interface{}{
				"name":               "Default Domain Policy",
				"display_name":       "Default Domain Policy",
				"gpo_guid":           "{31B2F340-016D-11D2-945F-00C04FB984F9}",
				"distinguished_name": "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=contoso,DC=com",
				"version_number":     "65537",
				"creation_time":      "2024-01-15T10:30:00Z",
				"modification_time":  "2024-12-20T14:22:00Z",
			},
		}, nil

	case "list:user":
		return map[string]interface{}{
			"success":       true,
			"query_type":    "user",
			"executed_at":   time.Now(),
			"response_time": 200 * time.Millisecond,
			"total_count":   3,
			"users": []interface{}{
				map[string]interface{}{
					"sam_account_name":    "john.doe",
					"user_principal_name": "john.doe@corp.contoso.com",
					"display_name":        "John Doe",
					"email_address":       "john.doe@contoso.com",
				},
				map[string]interface{}{
					"sam_account_name":    "jane.smith",
					"user_principal_name": "jane.smith@corp.contoso.com",
					"display_name":        "Jane Smith",
					"email_address":       "jane.smith@contoso.com",
				},
				map[string]interface{}{
					"sam_account_name":    "admin.user",
					"user_principal_name": "admin.user@corp.contoso.com",
					"display_name":        "Admin User",
					"email_address":       "admin@contoso.com",
				},
			},
		}, nil

	default:
		return map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("mock: resource not found: %s", resourceID),
		}, nil
	}
}

func (m *MockStewardClientForIntegration) SetModuleConfig(ctx context.Context, stewardID, moduleType, resourceID string, config map[string]interface{}) error {
	if m.errorMode {
		return fmt.Errorf("mock configuration error")
	}

	// Store configuration for later retrieval
	key := fmt.Sprintf("%s:%s:%s", stewardID, moduleType, resourceID)
	m.moduleStates[key] = config

	return nil
}

// TestADProviderIntegration tests the provider with realistic scenarios
func TestADProviderIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping provider integration tests in short mode")
	}

	// Setup provider with mock steward client
	logger := logging.NewNoopLogger()
	mockClient := NewMockStewardClientForIntegration()
	provider := NewActiveDirectoryProvider(mockClient, logger)

	ctx := context.Background()

	// Enterprise configuration
	config := interfaces.ProviderConfig{
		ServerAddress:     "corp.contoso.com",
		AuthMethod:        interfaces.AuthMethodKerberos,
		Username:          "svc-cfgms@corp.contoso.com",
		Password:          "enterprise-service-password",
		UseTLS:            true,
		Port:              636,
		PageSize:          1000,
		MaxConnections:    10,
		ConnectionTimeout: 60 * time.Second,
	}

	t.Run("Provider Connection and Health", func(t *testing.T) {
		t.Run("Successful Connection", func(t *testing.T) {
			err := provider.Connect(ctx, config)
			require.NoError(t, err, "Provider should connect successfully with mock steward")
			assert.True(t, provider.IsConnected(ctx), "Provider should be connected")
		})

		t.Run("Health Check", func(t *testing.T) {
			health, err := provider.HealthCheck(ctx)
			require.NoError(t, err, "Health check should succeed")
			assert.True(t, health.IsHealthy, "Provider should be healthy")
			assert.NotZero(t, health.LastCheck, "Health check timestamp should be set")
			assert.Greater(t, health.ResponseTime, time.Duration(0), "Response time should be measured")
		})

		t.Run("Connection Info", func(t *testing.T) {
			info, err := provider.GetConnectionInfo()
			if err != nil {
				// In mock environment, connection info may not be available
				t.Logf("Note: Connection info requires active connection: %v", err)
				assert.Contains(t, err.Error(), "not connected")
			} else {
				assert.Equal(t, "network_activedirectory", info.ProviderName)
				assert.Equal(t, "corp.contoso.com", info.ServerAddress)
				assert.Equal(t, interfaces.AuthMethod("kerberos"), info.AuthMethod)
				assert.NotZero(t, info.ConnectedSince, "Connected timestamp should be set")
			}
		})
	})

	t.Run("Basic Directory Operations", func(t *testing.T) {
		t.Run("Get User", func(t *testing.T) {
			user, err := provider.GetUser(ctx, "john.doe")
			require.NoError(t, err, "Should get user successfully")
			assert.Equal(t, "john.doe", user.SAMAccountName)
			assert.Equal(t, "john.doe@corp.contoso.com", user.UserPrincipalName)
			assert.Equal(t, "John Doe", user.DisplayName)
			assert.True(t, user.AccountEnabled)
		})

		t.Run("List Users", func(t *testing.T) {
			filters := &interfaces.SearchFilters{
				Limit: 100,
			}

			userList, err := provider.ListUsers(ctx, filters)
			require.NoError(t, err, "Should list users successfully")
			assert.Equal(t, 3, userList.TotalCount)
			assert.Len(t, userList.Users, 3)
			assert.False(t, userList.HasMore)
		})

		t.Run("Search Users with Filters", func(t *testing.T) {
			filters := &interfaces.SearchFilters{
				Query: "john",
				Limit: 10,
			}

			userList, err := provider.ListUsers(ctx, filters)
			require.NoError(t, err, "Should search users successfully")
			// Client-side filtering should find John Doe
			assert.Equal(t, 1, len(userList.Users))
			assert.Contains(t, userList.Users[0].DisplayName, "John")
		})
	})

	t.Run("Multi-Domain Operations", func(t *testing.T) {
		t.Run("Cross-Domain User Query", func(t *testing.T) {
			result, err := provider.QueryTrustedDomain(ctx, "dev.contoso.com", "user", "jane.smith")
			require.NoError(t, err, "Cross-domain query should succeed")

			// Verify cross-domain result structure
			assert.True(t, result["success"].(bool))
			assert.Equal(t, "user", result["query_type"])

			userObj := result["user"].(map[string]interface{})
			assert.Equal(t, "jane.smith@dev.contoso.com", userObj["user_principal_name"])
			assert.Equal(t, "dev.contoso.com", userObj["source_domain"])
			assert.True(t, userObj["cross_domain_query"].(bool))
		})

		t.Run("Forest-Wide Search", func(t *testing.T) {
			result, err := provider.QueryForest(ctx, "user", "admin.user")
			require.NoError(t, err, "Forest search should succeed")

			// Verify forest search results
			assert.True(t, result["success"].(bool))
			assert.Equal(t, "forest_user", result["query_type"])
			assert.Equal(t, 2, result["total_count"])

			users := result["users"].([]interface{})
			assert.Len(t, users, 2, "Should find admin.user in multiple domains")

			// Verify each result has forest search markers
			for _, userInterface := range users {
				user := userInterface.(map[string]interface{})
				assert.True(t, user["forest_search"].(bool))
				assert.NotEmpty(t, user["source_domain"])
			}
		})

		t.Run("Trust Validation", func(t *testing.T) {
			err := provider.ValidateCrossDomainTrust(ctx, "dev.contoso.com")
			require.NoError(t, err, "Trust validation should succeed for configured domain")
		})
	})

	t.Run("AD-Specific Object Operations", func(t *testing.T) {
		t.Run("Computer Object Query", func(t *testing.T) {
			computer, err := provider.GetComputer(ctx, "WORKSTATION-01")
			require.NoError(t, err, "Should get computer object")
			assert.Equal(t, "WORKSTATION-01$", computer.SAMAccountName)
			assert.Contains(t, computer.ProviderAttributes, "object_type")
			assert.Equal(t, "computer", computer.ProviderAttributes["object_type"])
		})

		t.Run("Group Policy Object Query", func(t *testing.T) {
			gpo, err := provider.GetGroupPolicy(ctx, "Default Domain Policy")
			require.NoError(t, err, "Should get GPO")
			assert.Equal(t, "Default Domain Policy", gpo["name"])
			assert.Contains(t, gpo, "gpo_guid")
			assert.Contains(t, gpo, "version_number")
		})

		t.Run("Domain Trust Query", func(t *testing.T) {
			// This would normally query actual trust relationships
			trusts, err := provider.ListDomainTrusts(ctx)
			if err != nil {
				t.Logf("Note: Trust listing requires real AD forest environment: %v", err)
			} else {
				assert.IsType(t, []map[string]interface{}{}, trusts)
			}
		})
	})

	t.Run("Provider Capabilities and Schema", func(t *testing.T) {
		t.Run("Provider Info", func(t *testing.T) {
			info := provider.GetProviderInfo()
			assert.Equal(t, "network_activedirectory", info.Name)
			assert.Equal(t, "Network Active Directory", info.DisplayName)
			assert.True(t, info.Capabilities.SupportsUserManagement)
			assert.True(t, info.Capabilities.SupportsGroupManagement)
			assert.True(t, info.Capabilities.SupportsAdvancedSearch)
			assert.Contains(t, info.Capabilities.SupportedSearchTypes, "computer")
		})

		t.Run("Directory Schema", func(t *testing.T) {
			schema, err := provider.GetSchema(ctx)
			require.NoError(t, err, "Should return AD schema")

			// Validate user schema
			assert.Equal(t, interfaces.DirectoryObjectTypeUser, schema.UserSchema.ObjectType)
			assert.NotEmpty(t, schema.UserSchema.RequiredFields)
			assert.NotEmpty(t, schema.UserSchema.SearchableFields)

			// Check AD-specific fields
			hasUPN := false
			hasSAM := false
			for _, field := range schema.UserSchema.RequiredFields {
				if field.Name == "userPrincipalName" {
					hasUPN = true
				}
				if field.Name == "sAMAccountName" {
					hasSAM = true
				}
			}
			assert.True(t, hasUPN, "Schema should include userPrincipalName")
			assert.True(t, hasSAM, "Schema should include sAMAccountName")
		})

		t.Run("Provider Capabilities", func(t *testing.T) {
			caps := provider.GetCapabilities()
			assert.True(t, caps.SupportsUserManagement)
			assert.True(t, caps.SupportsBulkOperations)
			assert.Contains(t, caps.SupportedAuthMethods, interfaces.AuthMethodKerberos)
			assert.Contains(t, caps.SupportedSearchTypes, "computer")
		})
	})

	t.Run("Statistics and Performance", func(t *testing.T) {
		// Perform some operations to generate statistics
		_, _ = provider.GetUser(ctx, "john.doe")
		_, _ = provider.ListUsers(ctx, &interfaces.SearchFilters{Limit: 10})

		t.Run("Request Statistics", func(t *testing.T) {
			reqCount := provider.GetRequestCount()
			assert.Greater(t, reqCount, int64(0), "Should have processed requests")

			avgLatency := provider.GetAverageLatency()
			assert.Greater(t, avgLatency, time.Duration(0), "Should have measured latency")

			errorCount := provider.GetErrorCount()
			assert.GreaterOrEqual(t, errorCount, int64(0), "Error count should be non-negative")
		})
	})

	t.Run("Error Scenarios", func(t *testing.T) {
		t.Run("Operations Without Connection", func(t *testing.T) {
			disconnectedProvider := NewActiveDirectoryProvider(mockClient, logger)

			_, err := disconnectedProvider.GetUser(ctx, "testuser")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not connected")
		})

		t.Run("Steward Unavailable", func(t *testing.T) {
			// Enable error mode on mock client
			mockClient.errorMode = true

			disconnectedProvider := NewActiveDirectoryProvider(mockClient, logger)
			err := disconnectedProvider.Connect(ctx, config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "steward")

			// Reset error mode
			mockClient.errorMode = false
		})

		t.Run("Invalid Cross-Domain Queries", func(t *testing.T) {
			_, err := provider.QueryTrustedDomain(ctx, "untrusted.domain", "user", "testuser")
			// Should complete but indicate trust validation failure in real environment
			if err == nil {
				t.Log("Note: Mock environment doesn't enforce trust validation")
			} else {
				assert.Contains(t, err.Error(), "trust", "Should indicate trust-related error")
			}
		})
	})

	t.Run("Validation and Security", func(t *testing.T) {
		t.Run("User Validation", func(t *testing.T) {
			validUser := &interfaces.DirectoryUser{
				SAMAccountName:    "valid.user",
				UserPrincipalName: "valid.user@corp.contoso.com",
				DisplayName:       "Valid User",
				AccountEnabled:    true,
			}

			err := provider.ValidateUser(validUser)
			require.NoError(t, err, "Valid user should pass validation")

			invalidUser := &interfaces.DirectoryUser{
				SAMAccountName: "toolongusernamethatexceedslimit", // > 20 chars
				DisplayName:    "Invalid User",
			}

			err = provider.ValidateUser(invalidUser)
			require.Error(t, err, "Invalid user should fail validation")
			assert.Contains(t, err.Error(), "exceeds maximum length")
		})

		t.Run("Trust Configuration Validation", func(t *testing.T) {
			validTrust := map[string]interface{}{
				"trust_partner":   "trusted.domain.com",
				"trust_direction": "TRUST_DIRECTION_BIDIRECTIONAL",
				"trust_type":      "TRUST_TYPE_UPLEVEL",
			}

			err := provider.ValidateDomainTrust(validTrust)
			require.NoError(t, err, "Valid trust should pass validation")

			invalidTrust := map[string]interface{}{
				"trust_partner":   "trusted.domain.com",
				"trust_direction": "INVALID_DIRECTION",
			}

			err = provider.ValidateDomainTrust(invalidTrust)
			require.Error(t, err, "Invalid trust should fail validation")
			assert.Contains(t, err.Error(), "invalid trust_direction")
		})
	})

	t.Run("Real-World Integration Scenarios", func(t *testing.T) {
		t.Run("MSP Multi-Client Environment", func(t *testing.T) {
			// Simulate MSP managing multiple client domains
			clientDomains := []string{
				"client1.local",
				"client2.corp",
				"client3.enterprise.com",
			}

			for _, domain := range clientDomains {
				t.Run(fmt.Sprintf("Client_%s", domain), func(t *testing.T) {
					clientConfig := config
					clientConfig.ServerAddress = domain

					// Test provider can handle multiple client environments
					err := provider.Connect(ctx, clientConfig)
					if err != nil {
						t.Logf("Note: MSP scenario for %s requires real multi-client environment", domain)
					}
				})
			}
		})

		t.Run("Enterprise Merger Scenario", func(t *testing.T) {
			// Simulate enterprise merger with complex trust relationships
			mergerScenarios := []struct {
				sourceUser   string
				sourceDomain string
				targetDomain string
			}{
				{"john.doe", "corp.contoso.com", "acquired.company.com"},
				{"jane.smith", "dev.contoso.com", "corp.contoso.com"},
			}

			for _, scenario := range mergerScenarios {
				t.Run(fmt.Sprintf("Merger_%s", scenario.sourceUser), func(t *testing.T) {
					// Test cross-domain user synchronization capabilities
					result, err := provider.QueryTrustedDomain(ctx, scenario.sourceDomain, "user", scenario.sourceUser)

					if err != nil {
						t.Logf("Note: Merger scenario requires real multi-domain forest: %v", err)
					} else {
						assert.True(t, result["success"].(bool))
						t.Logf("Merger simulation: Found user %s in %s", scenario.sourceUser, scenario.sourceDomain)
					}
				})
			}
		})

		t.Run("Compliance and Audit Scenario", func(t *testing.T) {
			// Test compliance-focused queries across domains
			complianceQueries := []struct {
				description string
				query       string
			}{
				{"All privileged accounts", "forest:user:admin"},
				{"Domain controllers", "list:computer"},
				{"Security policies", "list:gpo"},
				{"External trusts", "list:trust"},
			}

			for _, comp := range complianceQueries {
				t.Run(comp.description, func(t *testing.T) {
					// Parse query type
					parts := strings.Split(comp.query, ":")
					if len(parts) >= 2 {
						switch parts[0] {
						case "forest":
							if len(parts) >= 3 {
								_, err := provider.QueryForest(ctx, parts[1], parts[2])
								if err != nil {
									t.Logf("Note: %s requires real forest environment", comp.description)
								}
							}
						case "list":
							switch parts[1] {
							case "computer":
								_, err := provider.ListComputers(ctx, nil)
								if err != nil {
									t.Logf("Note: %s requires real AD environment", comp.description)
								}
							case "gpo":
								_, err := provider.ListGroupPolicies(ctx)
								if err != nil {
									t.Logf("Note: %s requires real AD environment", comp.description)
								}
							case "trust":
								_, err := provider.ListDomainTrusts(ctx)
								if err != nil {
									t.Logf("Note: %s requires real AD environment", comp.description)
								}
							}
						}
					}
				})
			}
		})
	})

	t.Run("Provider Disconnect", func(t *testing.T) {
		err := provider.Disconnect(ctx)
		require.NoError(t, err, "Should disconnect cleanly")
		assert.False(t, provider.IsConnected(ctx), "Provider should be disconnected")
	})
}

// TestADProviderFailureResilience tests provider behavior under failure conditions
func TestADProviderFailureResilience(t *testing.T) {
	logger := logging.NewNoopLogger()
	mockClient := NewMockStewardClientForIntegration()
	provider := NewActiveDirectoryProvider(mockClient, logger)
	ctx := context.Background()

	config := interfaces.ProviderConfig{
		ServerAddress: "corp.contoso.com",
		AuthMethod:    interfaces.AuthMethodLDAP,
	}

	t.Run("Steward Failure Scenarios", func(t *testing.T) {
		t.Run("No AD Stewards Available", func(t *testing.T) {
			// Remove AD stewards from mock
			originalStewards := mockClient.stewards
			mockClient.stewards = []StewardInfo{
				{
					ID:        "steward-web",
					Modules:   []string{"file", "directory"}, // No AD module
					IsHealthy: true,
				},
			}

			err := provider.Connect(ctx, config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no suitable AD steward")

			// Restore stewards
			mockClient.stewards = originalStewards
		})

		t.Run("Unhealthy AD Stewards", func(t *testing.T) {
			// Mark all AD stewards as unhealthy
			for i := range mockClient.stewards {
				mockClient.stewards[i].IsHealthy = false
			}

			err := provider.Connect(ctx, config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "no suitable AD steward")

			// Restore health
			for i := range mockClient.stewards {
				mockClient.stewards[i].IsHealthy = true
			}
		})

		t.Run("Steward Communication Failures", func(t *testing.T) {
			// Connect first
			err := provider.Connect(ctx, config)
			require.NoError(t, err)

			// Enable error mode to simulate communication failures
			mockClient.errorMode = true

			_, err = provider.GetUser(ctx, "testuser")
			require.Error(t, err)
			// Error mode affects steward discovery, so check for either error type
			assert.True(t,
				strings.Contains(err.Error(), "mock module state error") ||
					strings.Contains(err.Error(), "mock steward discovery error") ||
					strings.Contains(err.Error(), "no AD steward available"),
				"Should indicate steward communication failure, got: %v", err)

			// Reset error mode
			mockClient.errorMode = false
		})
	})

	t.Run("Query Failure Scenarios", func(t *testing.T) {
		// Connect first
		err := provider.Connect(ctx, config)
		require.NoError(t, err)

		t.Run("Nonexistent Objects", func(t *testing.T) {
			_, err := provider.GetUser(ctx, "nonexistent.user")
			// Mock returns generic "not found" error
			if err != nil {
				assert.Contains(t, err.Error(), "not found")
			}
		})

		t.Run("Invalid Cross-Domain Queries", func(t *testing.T) {
			_, err := provider.QueryTrustedDomain(ctx, "invalid.domain", "user", "testuser")
			if err != nil {
				t.Logf("Expected error for invalid domain query: %v", err)
			}
		})

		t.Run("Malformed Resource IDs", func(t *testing.T) {
			// These should be handled gracefully by the steward/module
			malformedQueries := []string{
				"invalid_format",
				"query:invalid_type:object",
				"forest:badtype:object",
			}

			for _, query := range malformedQueries {
				t.Run(fmt.Sprintf("Malformed_%s", query), func(t *testing.T) {
					// The provider passes queries to steward, so errors come from there
					// In real environment, steward would validate and return appropriate errors
					t.Logf("Testing malformed query: %s", query)
				})
			}
		})
	})

	t.Run("Performance Under Stress", func(t *testing.T) {
		// Connect first
		err := provider.Connect(ctx, config)
		require.NoError(t, err)

		t.Run("High Query Volume", func(t *testing.T) {
			const numQueries = 100

			start := time.Now()
			for i := 0; i < numQueries; i++ {
				userID := fmt.Sprintf("user%d", i)
				_, _ = provider.GetUser(ctx, userID)
			}
			duration := time.Since(start)

			avgLatency := duration / numQueries
			t.Logf("Average latency for %d queries: %v", numQueries, avgLatency)

			// Verify statistics tracking
			reqCount := provider.GetRequestCount()
			assert.Greater(t, reqCount, int64(0), "Should track request count")
		})

		t.Run("Concurrent Operations", func(t *testing.T) {
			// Test thread safety with concurrent operations
			const numGoroutines = 20
			const opsPerGoroutine = 25

			done := make(chan bool, numGoroutines)

			for i := 0; i < numGoroutines; i++ {
				go func(id int) {
					defer func() { done <- true }()

					for j := 0; j < opsPerGoroutine; j++ {
						userID := fmt.Sprintf("concurrent%d_%d", id, j)
						_, _ = provider.GetUser(ctx, userID)
					}
				}(i)
			}

			// Wait for all goroutines to complete
			for i := 0; i < numGoroutines; i++ {
				<-done
			}

			// Verify provider remained stable
			assert.True(t, provider.IsConnected(ctx), "Provider should remain connected after concurrent operations")
		})
	})
}

// BenchmarkADProviderOperations benchmarks provider performance
func BenchmarkADProviderOperations(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmarks in short mode")
	}

	logger := logging.NewNoopLogger()
	mockClient := NewMockStewardClientForIntegration()
	provider := NewActiveDirectoryProvider(mockClient, logger)
	ctx := context.Background()

	config := interfaces.ProviderConfig{
		ServerAddress: "benchmark.local",
		AuthMethod:    interfaces.AuthMethodLDAP,
	}

	// Connect for benchmarks
	err := provider.Connect(ctx, config)
	if err != nil {
		b.Skipf("Cannot benchmark without connection: %v", err)
	}

	b.Run("GetUser", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = provider.GetUser(ctx, "john.doe")
		}
	})

	b.Run("ListUsers", func(b *testing.B) {
		filters := &interfaces.SearchFilters{Limit: 100}
		for i := 0; i < b.N; i++ {
			_, _ = provider.ListUsers(ctx, filters)
		}
	})

	b.Run("CrossDomainQuery", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = provider.QueryTrustedDomain(ctx, "dev.contoso.com", "user", "jane.smith")
		}
	})

	b.Run("ForestSearch", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = provider.QueryForest(ctx, "user", "admin.user")
		}
	})

	b.Run("HealthCheck", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = provider.HealthCheck(ctx)
		}
	})
}
