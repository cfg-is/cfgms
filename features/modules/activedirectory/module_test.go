package activedirectory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestActiveDirectoryModule_New(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger)
	assert.NotNil(t, module)

	// Test with nil logger
	moduleWithNilLogger := New(nil)
	assert.NotNil(t, moduleWithNilLogger)
}

func TestActiveDirectoryModule_GetCapabilities(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	capabilities := module.GetCapabilities()
	assert.NotNil(t, capabilities)

	// Check key capabilities
	assert.Equal(t, true, capabilities["supports_read"])
	assert.Equal(t, true, capabilities["supports_write"])
	assert.Equal(t, false, capabilities["supports_monitor"])
	assert.Equal(t, true, capabilities["supports_bulk"])
	assert.Equal(t, true, capabilities["system_context"])
	assert.Equal(t, true, capabilities["credential_free"])

	// Check object types
	objectTypes, ok := capabilities["object_types"].([]string)
	assert.True(t, ok)
	assert.Contains(t, objectTypes, "user")
	assert.Contains(t, objectTypes, "group")
	assert.Contains(t, objectTypes, "computer")
	assert.Contains(t, objectTypes, "organizational_unit")

	// Check auth methods
	authMethods, ok := capabilities["auth_methods"].([]string)
	assert.True(t, ok)
	assert.Contains(t, authMethods, "system_context")

	// Check platforms
	platforms, ok := capabilities["platforms"].([]string)
	assert.True(t, ok)
	assert.Contains(t, platforms, "windows")
}

func TestADModuleConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      *ADModuleConfig
		expectError bool
	}{
		{
			name: "valid config",
			config: &ADModuleConfig{
				OperationType:  "read",
				ObjectTypes:    []string{"user", "group"},
				PageSize:       100,
				RequestTimeout: 30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "missing operation type",
			config: &ADModuleConfig{
				ObjectTypes: []string{"user"},
			},
			expectError: true,
		},
		{
			name: "missing object types",
			config: &ADModuleConfig{
				OperationType: "read",
				ObjectTypes:   []string{},
			},
			expectError: true,
		},
		{
			name: "negative page size",
			config: &ADModuleConfig{
				OperationType: "read",
				ObjectTypes:   []string{"user"},
				PageSize:      -1,
			},
			expectError: true,
		},
		{
			name: "negative timeout",
			config: &ADModuleConfig{
				OperationType:  "read",
				ObjectTypes:    []string{"user"},
				RequestTimeout: -1 * time.Second,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestADModuleConfig_AsMap(t *testing.T) {
	config := &ADModuleConfig{
		OperationType:       "read",
		ObjectTypes:         []string{"user", "group"},
		SearchBase:          "DC=example,DC=com",
		PageSize:            100,
		RequestTimeout:      30 * time.Second,
		EnableDNACollection: true,
	}

	configMap := config.AsMap()
	assert.Equal(t, "read", configMap["operation_type"])
	assert.Equal(t, []string{"user", "group"}, configMap["object_types"])
	assert.Equal(t, "DC=example,DC=com", configMap["search_base"])
	assert.Equal(t, 100, configMap["page_size"])
	assert.Equal(t, 30*time.Second, configMap["request_timeout"])
	assert.Equal(t, true, configMap["enable_dna_collection"])
}

func TestADModuleConfig_YAML(t *testing.T) {
	config := &ADModuleConfig{
		OperationType:  "read",
		ObjectTypes:    []string{"user"},
		PageSize:       100,
		RequestTimeout: 30 * time.Second,
	}

	// Test ToYAML
	yamlData, err := config.ToYAML()
	assert.NoError(t, err)
	assert.NotEmpty(t, yamlData)

	// Test FromYAML
	newConfig := &ADModuleConfig{}
	err = newConfig.FromYAML(yamlData)
	assert.NoError(t, err)
	assert.Equal(t, config.OperationType, newConfig.OperationType)
	assert.Equal(t, config.ObjectTypes, newConfig.ObjectTypes)
	assert.Equal(t, config.PageSize, newConfig.PageSize)
	assert.Equal(t, config.RequestTimeout, newConfig.RequestTimeout)
}

func TestADSystemStatus_AsMap(t *testing.T) {
	now := time.Now()
	status := &ADSystemStatus{
		SystemContext:      true,
		Hostname:           "TEST-DC01",
		Domain:             "example.com",
		DomainController:   "dc01.example.com",
		ForestRoot:         "example.com",
		HealthStatus:       "healthy",
		RequestCount:       10,
		ErrorCount:         0,
		LastHealthCheck:    now,
		DNACollectionCount: 5,
		LastDNACollection:  now,
	}

	statusMap := status.AsMap()
	assert.Equal(t, true, statusMap["system_context"])
	assert.Equal(t, "TEST-DC01", statusMap["hostname"])
	assert.Equal(t, "example.com", statusMap["domain"])
	assert.Equal(t, "dc01.example.com", statusMap["domain_controller"])
	assert.Equal(t, "example.com", statusMap["forest_root"])
	assert.Equal(t, "healthy", statusMap["health_status"])
	assert.Equal(t, int64(10), statusMap["request_count"])
	assert.Equal(t, int64(0), statusMap["error_count"])
	assert.Equal(t, now, statusMap["last_health_check"])
	assert.Equal(t, int64(5), statusMap["dna_collection_count"])
	assert.Equal(t, now, statusMap["last_dna_collection"])
}

func TestADQueryResult_AsMap(t *testing.T) {
	now := time.Now()
	result := &ADQueryResult{
		QueryType:    "user",
		ObjectID:     "testuser",
		ExecutedAt:   now,
		ResponseTime: 100 * time.Millisecond,
		Success:      true,
		TotalCount:   1,
	}

	resultMap := result.AsMap()
	assert.Equal(t, "user", resultMap["query_type"])
	assert.Equal(t, "testuser", resultMap["object_id"])
	assert.Equal(t, now, resultMap["executed_at"])
	assert.Equal(t, 100*time.Millisecond, resultMap["response_time"])
	assert.Equal(t, true, resultMap["success"])
	assert.Equal(t, 1, resultMap["total_count"])
}

func TestADDirectoryDNA_AsMap(t *testing.T) {
	now := time.Now()
	dnaData := map[string]interface{}{
		"domain_info": map[string]interface{}{
			"domain_name": "example.com",
		},
		"statistics": map[string]interface{}{
			"total_users": 100,
		},
	}

	dna := &ADDirectoryDNA{
		CollectionTime: now,
		Success:        true,
		Source:         "activedirectory_system",
		DNA:            dnaData,
	}

	dnaMap := dna.AsMap()
	assert.Equal(t, now, dnaMap["collection_time"])
	assert.Equal(t, true, dnaMap["success"])
	assert.Equal(t, "activedirectory_system", dnaMap["source"])
	assert.Equal(t, dnaData, dnaMap["dna"])
}

func TestActiveDirectoryModule_Set_ValidConfig(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	config := &ADModuleConfig{
		OperationType:       "read",
		ObjectTypes:         []string{"user", "group"},
		PageSize:            50,
		RequestTimeout:      15 * time.Second,
		EnableDNACollection: true,
	}

	ctx := context.Background()

	// This test will fail on non-Windows systems or systems without AD access
	// but it validates the configuration logic
	err := module.Set(ctx, "config", config)

	// On non-AD systems, we expect failure during verification, not config validation
	if err != nil {
		// Should fail at system verification, not config validation
		assert.Contains(t, err.Error(), "failed to verify system AD access")
	} else {
		// If it succeeds, verify config was stored
		module.configMux.RLock()
		storedConfig := module.config
		module.configMux.RUnlock()

		assert.Equal(t, config.OperationType, storedConfig.OperationType)
		assert.Equal(t, config.ObjectTypes, storedConfig.ObjectTypes)
		assert.Equal(t, config.PageSize, storedConfig.PageSize)
		assert.Equal(t, config.RequestTimeout, storedConfig.RequestTimeout)
		assert.Equal(t, config.EnableDNACollection, storedConfig.EnableDNACollection)
	}
}

func TestActiveDirectoryModule_Set_InvalidConfig(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	invalidConfig := &ADModuleConfig{
		// Missing required fields
	}

	ctx := context.Background()
	err := module.Set(ctx, "config", invalidConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid AD configuration")
}

func TestActiveDirectoryModule_Get_InvalidResourceID(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()

	// Test empty resource ID
	_, err := module.Get(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported operation")

	// Test invalid query format
	_, err = module.Get(ctx, "query:user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "query requires format 'query:type:id'")

	// Test invalid list format
	_, err = module.Get(ctx, "list")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "list requires format 'list:type'")

	// Test unsupported operation
	_, err = module.Get(ctx, "invalid_operation")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported operation")
}

func TestActiveDirectoryModule_Test_NotConfigured(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()
	config := &ADModuleConfig{
		OperationType: "read",
		ObjectTypes:   []string{"user"},
	}

	// Test when module is not configured
	matches, err := module.Test(ctx, "test", config)
	assert.Error(t, err)
	assert.False(t, matches)
	assert.Contains(t, err.Error(), "module not configured")
}

func TestActiveDirectoryModule_ConvertPSObjectToDirectoryUser(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	psObj := map[string]interface{}{
		"id":                  "CN=testuser,CN=Users,DC=example,DC=com",
		"sam_account_name":    "testuser",
		"user_principal_name": "testuser@example.com",
		"display_name":        "Test User",
		"email_address":       "testuser@example.com",
		"account_enabled":     true,
		"distinguished_name":  "CN=testuser,CN=Users,DC=example,DC=com",
		"object_guid":         "12345678-1234-1234-1234-123456789012",
		"when_created":        "2023-01-01T12:00:00Z",
		"when_changed":        "2023-01-02T12:00:00Z",
		"member_of":           []interface{}{"CN=Domain Users,CN=Users,DC=example,DC=com"},
		"object_type":         "user",
	}

	user := module.convertPSObjectToDirectoryUser(psObj)

	assert.Equal(t, "CN=testuser,CN=Users,DC=example,DC=com", user.ID)
	assert.Equal(t, "testuser", user.SAMAccountName)
	assert.Equal(t, "testuser@example.com", user.UserPrincipalName)
	assert.Equal(t, "Test User", user.DisplayName)
	assert.Equal(t, "testuser@example.com", user.EmailAddress)
	assert.Equal(t, true, user.AccountEnabled)
	assert.Equal(t, "CN=testuser,CN=Users,DC=example,DC=com", user.DistinguishedName)
	assert.Equal(t, "activedirectory_system", user.Source)

	// Check provider attributes
	assert.NotNil(t, user.ProviderAttributes)
	assert.Equal(t, "12345678-1234-1234-1234-123456789012", user.ProviderAttributes["object_guid"])
	assert.Equal(t, "user", user.ProviderAttributes["object_type"])

	// Check groups
	assert.Len(t, user.Groups, 1)
	assert.Equal(t, "CN=Domain Users,CN=Users,DC=example,DC=com", user.Groups[0])

	// Check timestamps
	expectedCreated := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	expectedChanged := time.Date(2023, 1, 2, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, expectedCreated, *user.Created)
	assert.Equal(t, expectedChanged, *user.Modified)
}

func TestActiveDirectoryModule_ConvertPSObjectToDirectoryGroup(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	psObj := map[string]interface{}{
		"id":                 "CN=testgroup,CN=Users,DC=example,DC=com",
		"sam_account_name":   "testgroup",
		"display_name":       "Test Group",
		"description":        "Test group description",
		"distinguished_name": "CN=testgroup,CN=Users,DC=example,DC=com",
		"object_guid":        "87654321-4321-4321-4321-210987654321",
		"group_scope":        "Global",
		"group_category":     "Security",
		"members":            []interface{}{"CN=testuser,CN=Users,DC=example,DC=com"},
	}

	group := module.convertPSObjectToDirectoryGroup(psObj)

	assert.Equal(t, "CN=testgroup,CN=Users,DC=example,DC=com", group.ID)
	assert.Equal(t, "Test Group", group.Name)
	assert.Equal(t, "Test Group", group.DisplayName)
	assert.Equal(t, "Test group description", group.Description)
	assert.Equal(t, "CN=testgroup,CN=Users,DC=example,DC=com", group.DistinguishedName)
	assert.Equal(t, "activedirectory_system", group.Source)

	// Check provider attributes
	assert.NotNil(t, group.ProviderAttributes)
	assert.Equal(t, "testgroup", group.ProviderAttributes["sam_account_name"])
	assert.Equal(t, "87654321-4321-4321-4321-210987654321", group.ProviderAttributes["object_guid"])
	assert.Equal(t, "Global", group.ProviderAttributes["group_scope"])
	assert.Equal(t, "Security", group.ProviderAttributes["group_category"])

	// Check members
	assert.Len(t, group.Members, 1)
	assert.Equal(t, "CN=testuser,CN=Users,DC=example,DC=com", group.Members[0])
}

func TestActiveDirectoryModule_ConvertPSObjectToOrganizationalUnit(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	psObj := map[string]interface{}{
		"id":                 "OU=testou,DC=example,DC=com",
		"name":               "testou",
		"display_name":       "Test OU",
		"description":        "Test organizational unit",
		"distinguished_name": "OU=testou,DC=example,DC=com",
		"object_guid":        "11111111-2222-3333-4444-555555555555",
		"managed_by":         "CN=admin,CN=Users,DC=example,DC=com",
	}

	ou := module.convertPSObjectToOrganizationalUnit(psObj)

	assert.Equal(t, "OU=testou,DC=example,DC=com", ou.ID)
	assert.Equal(t, "testou", ou.Name)
	assert.Equal(t, "Test OU", ou.DisplayName)
	assert.Equal(t, "Test organizational unit", ou.Description)
	assert.Equal(t, "OU=testou,DC=example,DC=com", ou.DistinguishedName)
	assert.Equal(t, "activedirectory_system", ou.Source)

	// Check provider attributes
	assert.NotNil(t, ou.ProviderAttributes)
	assert.Equal(t, "11111111-2222-3333-4444-555555555555", ou.ProviderAttributes["object_guid"])
	assert.Equal(t, "CN=admin,CN=Users,DC=example,DC=com", ou.ProviderAttributes["managed_by"])
}

func TestActiveDirectoryModule_UpdateStats(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	// Test request count update
	module.updateStats(true)
	module.stats.RLock()
	assert.Equal(t, int64(1), module.stats.requestCount)
	assert.Equal(t, int64(0), module.stats.errorCount)
	assert.False(t, module.stats.lastRequest.IsZero())
	module.stats.RUnlock()

	// Test error count update
	module.updateStats(false)
	module.stats.RLock()
	assert.Equal(t, int64(1), module.stats.requestCount)
	assert.Equal(t, int64(1), module.stats.errorCount)
	module.stats.RUnlock()
}

func TestActiveDirectoryModule_ExtractStatInt(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	data := map[string]interface{}{
		"statistics": map[string]interface{}{
			"total_users":  float64(100),
			"total_groups": float64(50),
		},
		"simple_value": float64(42),
	}

	// Test nested extraction
	totalUsers := module.extractStatInt(data, "statistics", "total_users")
	assert.Equal(t, 100, totalUsers)

	totalGroups := module.extractStatInt(data, "statistics", "total_groups")
	assert.Equal(t, 50, totalGroups)

	// Test simple extraction
	simpleValue := module.extractStatInt(data, "simple_value")
	assert.Equal(t, 42, simpleValue)

	// Test non-existent key
	nonExistent := module.extractStatInt(data, "non_existent")
	assert.Equal(t, 0, nonExistent)

	// Test invalid path
	invalid := module.extractStatInt(data, "statistics", "non_existent")
	assert.Equal(t, 0, invalid)
}

func TestActiveDirectoryModule_GetHostname(t *testing.T) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	hostname := module.getHostname()
	assert.NotEmpty(t, hostname)
	// On non-Windows systems this might return "unknown" but should not panic
}

// Integration test functions that would run on actual Windows AD systems
// These are marked as skipped in non-AD environments

func TestActiveDirectoryModule_Integration_SystemAccess(t *testing.T) {
	t.Skip("Integration test - requires Windows AD environment")

	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()
	err := module.verifySystemAccess(ctx)
	assert.NoError(t, err)
}

func TestActiveDirectoryModule_Integration_GetSystemStatus(t *testing.T) {
	t.Skip("Integration test - requires Windows AD environment")

	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()
	status, err := module.getSystemStatus(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, status)

	statusObj := status.(*ADSystemStatus)
	assert.True(t, statusObj.SystemContext)
	assert.NotEmpty(t, statusObj.Hostname)
	assert.Equal(t, "healthy", statusObj.HealthStatus)
}

func TestActiveDirectoryModule_Integration_QueryADObject(t *testing.T) {
	t.Skip("Integration test - requires Windows AD environment")

	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()

	// Test user query
	result, err := module.queryADObjectSystem(ctx, "user", "Administrator")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	queryResult := result.(*ADQueryResult)
	assert.True(t, queryResult.Success)
	assert.NotNil(t, queryResult.User)
	assert.Equal(t, "user", queryResult.QueryType)
}

func TestActiveDirectoryModule_Integration_ListADObjects(t *testing.T) {
	t.Skip("Integration test - requires Windows AD environment")

	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	// Configure module first
	config := &ADModuleConfig{
		OperationType:  "read",
		ObjectTypes:    []string{"user"},
		PageSize:       10,
		RequestTimeout: 30 * time.Second,
	}

	module.configMux.Lock()
	module.config = config
	module.configMux.Unlock()

	ctx := context.Background()

	// Test user listing
	result, err := module.listADObjectsSystem(ctx, "user")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	queryResult := result.(*ADQueryResult)
	assert.True(t, queryResult.Success)
	assert.Greater(t, queryResult.TotalCount, 0)
	assert.NotNil(t, queryResult.Users)
}

func TestActiveDirectoryModule_Integration_CollectDirectoryDNA(t *testing.T) {
	t.Skip("Integration test - requires Windows AD environment")

	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	ctx := context.Background()

	dna, err := module.collectDirectoryDNA(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, dna)

	dnaResult := dna.(*ADDirectoryDNA)
	assert.True(t, dnaResult.Success)
	assert.Equal(t, "activedirectory_system", dnaResult.Source)
	assert.NotNil(t, dnaResult.DNA)

	// Check DNA structure
	assert.Contains(t, dnaResult.DNA, "domain_info")
	assert.Contains(t, dnaResult.DNA, "statistics")
}

// Benchmark tests for performance validation

func BenchmarkActiveDirectoryModule_ConvertPSObjectToDirectoryUser(b *testing.B) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	psObj := map[string]interface{}{
		"id":                  "CN=testuser,CN=Users,DC=example,DC=com",
		"sam_account_name":    "testuser",
		"user_principal_name": "testuser@example.com",
		"display_name":        "Test User",
		"email_address":       "testuser@example.com",
		"account_enabled":     true,
		"distinguished_name":  "CN=testuser,CN=Users,DC=example,DC=com",
		"object_guid":         "12345678-1234-1234-1234-123456789012",
		"when_created":        "2023-01-01T12:00:00Z",
		"when_changed":        "2023-01-02T12:00:00Z",
		"member_of":           []interface{}{"CN=Domain Users,CN=Users,DC=example,DC=com"},
	}

	for i := 0; i < b.N; i++ {
		user := module.convertPSObjectToDirectoryUser(psObj)
		_ = user
	}
}

func BenchmarkActiveDirectoryModule_ExtractStatInt(b *testing.B) {
	logger := logging.NewNoopLogger()
	module := New(logger).(*activeDirectoryModule)

	data := map[string]interface{}{
		"statistics": map[string]interface{}{
			"total_users": float64(100),
		},
	}

	for i := 0; i < b.N; i++ {
		result := module.extractStatInt(data, "statistics", "total_users")
		_ = result
	}
}
