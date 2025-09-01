package activedirectory

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestADModuleConfig(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		config := &ADModuleConfig{
			Domain:        "example.com",
			AuthMethod:    "simple",
			OperationType: "read",
			ObjectTypes:   []string{"user", "group"},
			Username:      "service-account",
			Password:      "password123",
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
			Domain:        "example.com",
			AuthMethod:    "simple",
			OperationType: "read",
			ObjectTypes:   []string{"user", "group"},
			Username:      "service-account",
			Password:      "secret123",
		}
		
		// Test ToYAML (should redact password)
		yamlData, err := config.ToYAML()
		require.NoError(t, err)
		yamlStr := string(yamlData)
		assert.Contains(t, yamlStr, "domain: example.com")
		assert.Contains(t, yamlStr, "[REDACTED]")
		assert.NotContains(t, yamlStr, "secret123")
		
		// Test FromYAML
		newConfig := &ADModuleConfig{}
		err = newConfig.FromYAML(yamlData)
		require.NoError(t, err)
		assert.Equal(t, "example.com", newConfig.Domain)
		assert.Equal(t, "simple", newConfig.AuthMethod)
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

func TestADConnectionStatus(t *testing.T) {
	t.Run("connection status structure", func(t *testing.T) {
		status := &ADConnectionStatus{
			Connected:        true,
			DomainController: "dc01.example.com",
			Domain:          "example.com",
			AuthMethod:      "simple",
			ConnectedSince:  time.Now().Add(-1 * time.Hour),
			LastHealthCheck: time.Now(),
			HealthStatus:    "healthy",
			ResponseTime:    50 * time.Millisecond,
			ErrorCount:      0,
			RequestCount:    100,
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