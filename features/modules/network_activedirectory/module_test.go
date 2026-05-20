// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestADModuleConfig(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := &ADModuleConfig{
			Domain:            "example.com",
			AuthMethod:        "simple",
			OperationType:     "read",
			ObjectTypes:       []string{"user", "group"},
			Username:          "service-account",
			PasswordSecretKey: "ad/example.com/svc_password",
		}

		err := config.Validate()
		assert.NoError(t, err)

		// Test AsMap
		configMap := config.AsMap()
		assert.Equal(t, "example.com", configMap["domain"])
		assert.Equal(t, "simple", configMap["auth_method"])
		assert.Equal(t, "read", configMap["operation_type"])
		assert.Equal(t, []string{"user", "group"}, configMap["object_types"])
		assert.Equal(t, "service-account", configMap["username"])

		// Test managed fields
		fields := config.GetManagedFields()
		assert.Contains(t, fields, "domain")
		assert.Contains(t, fields, "auth_method")
	})

	t.Run("missing required fields", func(t *testing.T) {
		config := &ADModuleConfig{}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "domain is required")
	})

	t.Run("invalid auth method", func(t *testing.T) {
		config := &ADModuleConfig{
			Domain:        "example.com",
			AuthMethod:    "invalid",
			OperationType: "read",
			ObjectTypes:   []string{"user"},
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid auth_method")
	})

	t.Run("invalid operation type", func(t *testing.T) {
		config := &ADModuleConfig{
			Domain:        "example.com",
			AuthMethod:    "simple",
			OperationType: "invalid",
			ObjectTypes:   []string{"user"},
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid operation_type")
	})

	t.Run("invalid object type", func(t *testing.T) {
		config := &ADModuleConfig{
			Domain:        "example.com",
			AuthMethod:    "simple",
			OperationType: "read",
			ObjectTypes:   []string{"invalid"},
		}

		err := config.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid object_type")
	})

	t.Run("YAML serialization", func(t *testing.T) {
		config := &ADModuleConfig{
			Domain:            "example.com",
			AuthMethod:        "simple",
			OperationType:     "read",
			ObjectTypes:       []string{"user", "group"},
			Username:          "service-account",
			PasswordSecretKey: "ad/example.com/svc_password",
		}

		// Test ToYAML — password_secret_key is serialized; no plaintext password exists
		yamlData, err := config.ToYAML()
		require.NoError(t, err)
		yamlStr := string(yamlData)
		assert.Contains(t, yamlStr, "domain: example.com")
		assert.Contains(t, yamlStr, "password_secret_key: ad/example.com/svc_password")
		assert.NotContains(t, yamlStr, "password:")

		// Test FromYAML
		newConfig := &ADModuleConfig{}
		err = newConfig.FromYAML(yamlData)
		require.NoError(t, err)
		assert.Equal(t, "example.com", newConfig.Domain)
		assert.Equal(t, "simple", newConfig.AuthMethod)
		assert.Equal(t, "ad/example.com/svc_password", newConfig.PasswordSecretKey)
	})
}

func TestADModuleBasics(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger)

	t.Run("module creation", func(t *testing.T) {
		assert.NotNil(t, module)

		// Test capabilities
		adModule := module.(*activeDirectoryModule)
		capabilities := adModule.GetCapabilities()

		assert.True(t, capabilities["supports_read"].(bool))
		assert.True(t, capabilities["supports_write"].(bool))
		assert.False(t, capabilities["supports_monitor"].(bool))
		assert.Contains(t, capabilities["object_types"], "user")
		assert.Contains(t, capabilities["auth_methods"], "simple")
	})

	t.Run("get without configuration", func(t *testing.T) {
		ctx := context.Background()

		// Should fail because not configured
		_, err := module.Get(ctx, "query:user:test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not connected")
	})

	t.Run("invalid resource ID format", func(t *testing.T) {
		ctx := context.Background()

		_, err := module.Get(ctx, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported operation")
	})

	t.Run("query with insufficient parts", func(t *testing.T) {
		ctx := context.Background()

		_, err := module.Get(ctx, "query:user")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "query requires format")
	})
}

func TestDNParsing(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	t.Run("extract OU from DN", func(t *testing.T) {
		testCases := []struct {
			dn       string
			expected string
		}{
			{
				dn:       "CN=John Doe,OU=Users,OU=IT,DC=example,DC=com",
				expected: "Users",
			},
			{
				dn:       "CN=Administrators,CN=Builtin,DC=example,DC=com",
				expected: "",
			},
			{
				dn:       "OU=IT,OU=Departments,DC=example,DC=com",
				expected: "Departments",
			},
			{
				dn:       "CN=Test",
				expected: "",
			},
			{
				dn:       "",
				expected: "",
			},
		}

		for _, tc := range testCases {
			result := module.extractOUFromDN(tc.dn)
			assert.Equal(t, tc.expected, result, "DN: %s", tc.dn)
		}
	})

	t.Run("extract parent OU from DN", func(t *testing.T) {
		testCases := []struct {
			dn       string
			expected string
		}{
			{
				dn:       "OU=Users,OU=IT,DC=example,DC=com",
				expected: "OU=IT,DC=example,DC=com",
			},
			{
				dn:       "OU=IT,DC=example,DC=com",
				expected: "",
			},
			{
				dn:       "CN=Test,OU=Users,DC=example,DC=com",
				expected: "OU=Users,DC=example,DC=com",
			},
			{
				dn:       "",
				expected: "",
			},
		}

		for _, tc := range testCases {
			result := module.extractParentOUFromDN(tc.dn)
			assert.Equal(t, tc.expected, result, "DN: %s", tc.dn)
		}
	})

	t.Run("extract domain from DN", func(t *testing.T) {
		testCases := []struct {
			dn       string
			expected string
		}{
			{
				dn:       "CN=John Doe,OU=Users,DC=example,DC=com",
				expected: "example.com",
			},
			{
				dn:       "OU=IT,DC=subdomain,DC=example,DC=org",
				expected: "subdomain.example.org",
			},
			{
				dn:       "CN=Test",
				expected: "",
			},
			{
				dn:       "",
				expected: "",
			},
		}

		for _, tc := range testCases {
			result := module.extractDomainFromDN(tc.dn)
			assert.Equal(t, tc.expected, result, "DN: %s", tc.dn)
		}
	})
}

func TestADQueryResult(t *testing.T) {
	t.Run("basic query result structure", func(t *testing.T) {
		result := &ADQueryResult{
			QueryType:    "user",
			ObjectID:     "john.doe",
			Success:      true,
			ExecutedAt:   time.Now(),
			ResponseTime: 100 * time.Millisecond,
			TotalCount:   1,
			HasMore:      false,
		}

		assert.Equal(t, "user", result.QueryType)
		assert.Equal(t, "john.doe", result.ObjectID)
		assert.True(t, result.Success)
		assert.Equal(t, 1, result.TotalCount)
		assert.False(t, result.HasMore)
		assert.Equal(t, 100*time.Millisecond, result.ResponseTime)
	})

	t.Run("error result structure", func(t *testing.T) {
		result := &ADQueryResult{
			QueryType:    "user",
			ObjectID:     "nonexistent",
			Success:      false,
			ExecutedAt:   time.Now(),
			ResponseTime: 50 * time.Millisecond,
			Error:        "object not found",
			ErrorCode:    "NOT_FOUND",
		}

		assert.False(t, result.Success)
		assert.Equal(t, "object not found", result.Error)
		assert.Equal(t, "NOT_FOUND", result.ErrorCode)
	})
}

func TestLDAPEntryToDirectoryComputer(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	t.Run("objectClass=computer maps to DirectoryComputer not user type", func(t *testing.T) {
		entry := ldap.NewEntry("CN=WORKSTATION01,OU=Computers,DC=example,DC=com", map[string][]string{
			"objectGUID":             {"test-guid-001"},
			"objectClass":            {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":         {"WORKSTATION01$"},
			"dNSHostName":            {"workstation01.example.com"},
			"displayName":            {"WORKSTATION01"},
			"distinguishedName":      {"CN=WORKSTATION01,OU=Computers,DC=example,DC=com"},
			"operatingSystem":        {"Windows 11 Pro"},
			"operatingSystemVersion": {"10.0 (22000)"},
			"userAccountControl":     {"4096"}, // WORKSTATION_TRUST_ACCOUNT, enabled
		})

		computer := module.ldapEntryToDirectoryComputer(entry)

		require.NotNil(t, computer)
		assert.Equal(t, "test-guid-001", computer.ID)
		assert.Equal(t, "WORKSTATION01", computer.Name)
		assert.Equal(t, "WORKSTATION01$", computer.SAMAccountName)
		assert.Equal(t, "workstation01.example.com", computer.DNSHostName)
		assert.Equal(t, "CN=WORKSTATION01,OU=Computers,DC=example,DC=com", computer.DN)
		assert.Equal(t, "Windows 11 Pro", computer.OperatingSystem)
		assert.Equal(t, "10.0 (22000)", computer.OperatingSystemVersion)
		assert.True(t, computer.Enabled)
		assert.Equal(t, "activedirectory", computer.Source)
		assert.NotNil(t, computer.ProviderAttributes)
	})

	t.Run("computer with lastLogonTimestamp is parsed to time.Time", func(t *testing.T) {
		// Windows FILETIME for 2024-01-01T00:00:00Z = 133486560000000000
		entry := ldap.NewEntry("CN=SERVER01,OU=Servers,DC=example,DC=com", map[string][]string{
			"objectGUID":         {"test-guid-002"},
			"objectClass":        {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":     {"SERVER01$"},
			"distinguishedName":  {"CN=SERVER01,OU=Servers,DC=example,DC=com"},
			"lastLogonTimestamp": {"133486560000000000"},
		})

		computer := module.ldapEntryToDirectoryComputer(entry)

		require.NotNil(t, computer)
		require.NotNil(t, computer.LastLogon)
		assert.Equal(t, 2024, computer.LastLogon.Year())
	})

	t.Run("disabled computer account has Enabled=false", func(t *testing.T) {
		// userAccountControl with ACCOUNTDISABLE (0x2) set: 4096 | 2 = 4098
		entry := ldap.NewEntry("CN=DISABLED01,OU=Computers,DC=example,DC=com", map[string][]string{
			"objectGUID":         {"test-guid-003"},
			"objectClass":        {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":     {"DISABLED01$"},
			"distinguishedName":  {"CN=DISABLED01,OU=Computers,DC=example,DC=com"},
			"userAccountControl": {"4098"},
		})

		computer := module.ldapEntryToDirectoryComputer(entry)

		require.NotNil(t, computer)
		assert.False(t, computer.Enabled)
	})

	t.Run("computer timestamps are parsed correctly", func(t *testing.T) {
		entry := ldap.NewEntry("CN=TS01,OU=Computers,DC=example,DC=com", map[string][]string{
			"objectGUID":        {"test-guid-004"},
			"objectClass":       {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":    {"TS01$"},
			"distinguishedName": {"CN=TS01,OU=Computers,DC=example,DC=com"},
			"whenCreated":       {"20240101120000.0Z"},
			"whenChanged":       {"20240601120000.0Z"},
		})

		computer := module.ldapEntryToDirectoryComputer(entry)

		require.NotNil(t, computer)
		require.NotNil(t, computer.Created)
		require.NotNil(t, computer.Modified)
		assert.Equal(t, 2024, computer.Created.Year())
		assert.Equal(t, 6, int(computer.Modified.Month()))
	})

	t.Run("OU is extracted from distinguished name", func(t *testing.T) {
		entry := ldap.NewEntry("CN=PC01,OU=Workstations,OU=IT,DC=example,DC=com", map[string][]string{
			"objectGUID":        {"test-guid-005"},
			"objectClass":       {"top", "person", "organizationalPerson", "user", "computer"},
			"sAMAccountName":    {"PC01$"},
			"distinguishedName": {"CN=PC01,OU=Workstations,OU=IT,DC=example,DC=com"},
		})

		computer := module.ldapEntryToDirectoryComputer(entry)

		require.NotNil(t, computer)
		assert.Equal(t, "Workstations", computer.OU)
	})
}

func TestLDAPEntryToDirectoryUser_NoRegression(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	t.Run("user objectClass still maps to DirectoryUser", func(t *testing.T) {
		entry := ldap.NewEntry("CN=John Doe,OU=Users,DC=example,DC=com", map[string][]string{
			"objectGUID":         {"user-guid-001"},
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"sAMAccountName":     {"john.doe"},
			"userPrincipalName":  {"john.doe@example.com"},
			"displayName":        {"John Doe"},
			"mail":               {"john.doe@example.com"},
			"distinguishedName":  {"CN=John Doe,OU=Users,DC=example,DC=com"},
			"userAccountControl": {"512"}, // Normal enabled account
		})

		user := module.ldapEntryToDirectoryUser(entry)

		require.NotNil(t, user)
		assert.Equal(t, "john.doe", user.SAMAccountName)
		assert.Equal(t, "john.doe@example.com", user.UserPrincipalName)
		assert.Equal(t, "John Doe", user.DisplayName)
		assert.True(t, user.AccountEnabled)
		assert.Equal(t, "activedirectory", user.Source)
	})

	t.Run("ADQueryResult Computer field is set for computer query", func(t *testing.T) {
		result := &ADQueryResult{
			QueryType: "computer",
			ObjectID:  "WORKSTATION01$",
			Success:   true,
		}

		// Verify the Computer field exists on the result type (not User)
		assert.Nil(t, result.Computer)
		assert.Nil(t, result.User)

		// Set up a computer result
		result.Computer = &interfaces.DirectoryComputer{
			ID:             "guid-001",
			Name:           "WORKSTATION01",
			SAMAccountName: "WORKSTATION01$",
			Source:         "activedirectory",
		}

		assert.NotNil(t, result.Computer)
		assert.Equal(t, "WORKSTATION01$", result.Computer.SAMAccountName)
		// Confirm user is not populated for computer results
		assert.Nil(t, result.User)
	})
}

func TestADConnectionStatus(t *testing.T) {
	t.Run("connection status structure", func(t *testing.T) {
		status := &ADConnectionStatus{
			Connected:        true,
			DomainController: "dc01.example.com",
			Domain:           "example.com",
			AuthMethod:       "simple",
			ConnectedSince:   time.Now().Add(-1 * time.Hour),
			LastHealthCheck:  time.Now(),
			HealthStatus:     "healthy",
			ResponseTime:     50 * time.Millisecond,
			ErrorCount:       0,
			RequestCount:     100,
		}

		assert.True(t, status.Connected)
		assert.Equal(t, "dc01.example.com", status.DomainController)
		assert.Equal(t, "example.com", status.Domain)
		assert.Equal(t, "simple", status.AuthMethod)
		assert.Equal(t, "healthy", status.HealthStatus)
		assert.Equal(t, int64(0), status.ErrorCount)
		assert.Equal(t, int64(100), status.RequestCount)
	})
}
