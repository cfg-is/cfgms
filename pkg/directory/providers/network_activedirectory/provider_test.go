package network_activedirectory

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockStewardClient implements StewardClient for testing
type MockStewardClient struct {
	stewards       []StewardInfo
	moduleStates   map[string]map[string]interface{} // stewardID -> resourceID -> state
	moduleConfigs  map[string]map[string]interface{} // stewardID -> resourceID -> config
	shouldError    bool
	errorMessage   string
}

func NewMockStewardClient() *MockStewardClient {
	return &MockStewardClient{
		stewards:      []StewardInfo{},
		moduleStates:  make(map[string]map[string]interface{}),
		moduleConfigs: make(map[string]map[string]interface{}),
	}
}

func (m *MockStewardClient) GetModuleState(ctx context.Context, stewardID, moduleType, resourceID string) (map[string]interface{}, error) {
	if m.shouldError {
		return nil, fmt.Errorf(m.errorMessage)
	}
	
	key := stewardID + ":" + resourceID
	if state, exists := m.moduleStates[key]; exists {
		return state, nil
	}
	
	// Return default state for different resource types
	switch resourceID {
	case "status":
		return map[string]interface{}{
			"connected":         true,
			"domain_controller": "dc01.example.com",
			"domain":           "example.com",
			"health_status":    "healthy",
			"request_count":    int64(10),
			"error_count":      int64(0),
		}, nil
	default:
		if strings.HasPrefix(resourceID, "query:user:") {
			userID := strings.TrimPrefix(resourceID, "query:user:")
			return map[string]interface{}{
				"query_type":    "user",
				"object_id":     userID,
				"success":       true,
				"executed_at":   time.Now(),
				"response_time": 100 * time.Millisecond,
				"user": map[string]interface{}{
					"id":                   "user-guid-123",
					"user_principal_name":  userID + "@example.com",
					"sam_account_name":     userID,
					"display_name":         "Test User",
					"email_address":        userID + "@example.com",
					"account_enabled":      true,
					"distinguished_name":   "CN=" + userID + ",OU=Users,DC=example,DC=com",
					"source":              "activedirectory",
				},
			}, nil
		}
		return map[string]interface{}{}, nil
	}
}

func (m *MockStewardClient) SetModuleConfig(ctx context.Context, stewardID, moduleType, resourceID string, config map[string]interface{}) error {
	if m.shouldError {
		return fmt.Errorf(m.errorMessage)
	}
	
	key := stewardID + ":" + resourceID
	m.moduleConfigs[key] = config
	return nil
}

func (m *MockStewardClient) GetConnectedStewards(ctx context.Context) ([]StewardInfo, error) {
	if m.shouldError {
		return nil, fmt.Errorf(m.errorMessage)
	}
	return m.stewards, nil
}

func (m *MockStewardClient) GetStewardHealth(ctx context.Context, stewardID string) (*StewardHealth, error) {
	if m.shouldError {
		return nil, fmt.Errorf(m.errorMessage)
	}
	
	return &StewardHealth{
		Status:    "healthy",
		LastCheck: time.Now(),
		Modules: map[string]string{
			"activedirectory": "healthy",
		},
		Uptime:      24 * time.Hour,
		CPUUsage:    25.5,
		MemoryUsage: 512.0,
	}, nil
}

func (m *MockStewardClient) AddSteward(steward StewardInfo) {
	m.stewards = append(m.stewards, steward)
}

func (m *MockStewardClient) SetModuleState(stewardID, resourceID string, state map[string]interface{}) {
	key := stewardID + ":" + resourceID
	m.moduleStates[key] = state
}

func (m *MockStewardClient) SetError(shouldError bool, message string) {
	m.shouldError = shouldError
	m.errorMessage = message
}

func TestActiveDirectoryProviderInfo(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	info := provider.GetProviderInfo()
	
	assert.Equal(t, "network_activedirectory", info.Name)
	assert.Equal(t, "Network Active Directory", info.DisplayName)
	assert.Equal(t, "1.0.0", info.Version)
	assert.True(t, info.Capabilities.SupportsUserManagement)
	assert.True(t, info.Capabilities.SupportsGroupManagement)
	assert.True(t, info.Capabilities.SupportsOUManagement)
	assert.Contains(t, info.Capabilities.SupportedAuthMethods, interfaces.AuthMethodKerberos)
	assert.Contains(t, info.Capabilities.SupportedAuthMethods, interfaces.AuthMethodLDAP)
}

func TestActiveDirectoryProviderConnection(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	// Add a mock steward with AD module
	client.AddSteward(StewardInfo{
		ID:       "steward-dc01",
		Hostname: "dc01.example.com",
		Platform: "windows",
		Modules:  []string{"activedirectory"},
		Tags: map[string]string{
			"ad_domain": "example.com",
		},
		LastSeen:  time.Now(),
		IsHealthy: true,
	})
	
	ctx := context.Background()
	
	t.Run("successful connection", func(t *testing.T) {
		config := interfaces.ProviderConfig{
			ServerAddress: "example.com",
			AuthMethod:    interfaces.AuthMethodLDAP,
			Username:      "service-account",
			Password:      "password123",
			Port:          389,
			UseTLS:        false,
		}
		
		err := provider.Connect(ctx, config)
		require.NoError(t, err)
		assert.True(t, provider.IsConnected(ctx))
	})
	
	t.Run("health check", func(t *testing.T) {
		health, err := provider.HealthCheck(ctx)
		require.NoError(t, err)
		assert.True(t, health.IsHealthy)
		assert.NotZero(t, health.LastCheck)
		assert.Contains(t, health.Details, "steward_id")
	})
	
	t.Run("connection info", func(t *testing.T) {
		info, err := provider.GetConnectionInfo()
		require.NoError(t, err)
		assert.Equal(t, "network_activedirectory", info.ProviderName)
		assert.Equal(t, "example.com", info.ServerAddress)
		assert.Equal(t, interfaces.AuthMethodLDAP, info.AuthMethod)
	})
	
	t.Run("disconnect", func(t *testing.T) {
		err := provider.Disconnect(ctx)
		require.NoError(t, err)
		assert.False(t, provider.IsConnected(ctx))
	})
}

func TestActiveDirectoryProviderOperations(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	// Add a mock steward with AD module
	client.AddSteward(StewardInfo{
		ID:       "steward-dc01",
		Hostname: "dc01.example.com",
		Platform: "windows",
		Modules:  []string{"activedirectory"},
		Tags: map[string]string{
			"ad_domain": "example.com",
		},
		LastSeen:  time.Now(),
		IsHealthy: true,
	})
	
	// Connect provider
	config := interfaces.ProviderConfig{
		ServerAddress: "example.com",
		AuthMethod:    interfaces.AuthMethodLDAP,
		Username:      "service-account",
		Password:      "password123",
	}
	
	ctx := context.Background()
	err := provider.Connect(ctx, config)
	require.NoError(t, err)
	
	t.Run("get user", func(t *testing.T) {
		user, err := provider.GetUser(ctx, "john.doe")
		require.NoError(t, err)
		assert.Equal(t, "user-guid-123", user.ID)
		assert.Equal(t, "john.doe@example.com", user.UserPrincipalName)
		assert.Equal(t, "john.doe", user.SAMAccountName)
		assert.Equal(t, "Test User", user.DisplayName)
		assert.True(t, user.AccountEnabled)
	})
	
	t.Run("get user not found", func(t *testing.T) {
		client.SetModuleState("steward-dc01", "query:user:nonexistent", map[string]interface{}{
			"query_type": "user",
			"object_id":  "nonexistent",
			"success":    false,
			"error":      "object not found",
		})
		
		user, err := provider.GetUser(ctx, "nonexistent")
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "not found")
	})
	
	t.Run("list users", func(t *testing.T) {
		// Set up mock response for list operation
		client.SetModuleState("steward-dc01", "list:user", map[string]interface{}{
			"query_type":   "list_user",
			"success":      true,
			"total_count":  2,
			"has_more":     false,
			"executed_at":  time.Now(),
			"response_time": 200 * time.Millisecond,
			"users": []map[string]interface{}{
				{
					"id":                  "user1-guid",
					"user_principal_name": "user1@example.com",
					"display_name":        "User One",
					"account_enabled":     true,
				},
				{
					"id":                  "user2-guid",
					"user_principal_name": "user2@example.com",
					"display_name":        "User Two",
					"account_enabled":     true,
				},
			},
		})
		
		userList, err := provider.ListUsers(ctx, &interfaces.SearchFilters{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, userList.Users, 2)
		assert.Equal(t, 2, userList.TotalCount)
		assert.False(t, userList.HasMore)
	})
}

func TestActiveDirectoryProviderValidation(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	t.Run("validate user - valid", func(t *testing.T) {
		user := &interfaces.DirectoryUser{
			SAMAccountName:    "john.doe",
			UserPrincipalName: "john.doe@example.com",
			DisplayName:       "John Doe",
			EmailAddress:      "john.doe@example.com",
		}
		
		err := provider.ValidateUser(user)
		assert.NoError(t, err)
	})
	
	t.Run("validate user - missing required fields", func(t *testing.T) {
		user := &interfaces.DirectoryUser{
			EmailAddress: "test@example.com",
		}
		
		err := provider.ValidateUser(user)
		assert.Error(t, err)
		// The validation should fail on either missing SAM/UPN or displayName
		assert.True(t, strings.Contains(err.Error(), "sAMAccountName or userPrincipalName is required") || 
					strings.Contains(err.Error(), "displayName is required"))
	})
	
	t.Run("validate user - invalid UPN format", func(t *testing.T) {
		user := &interfaces.DirectoryUser{
			SAMAccountName:    "john.doe",
			UserPrincipalName: "invalid-upn",
			DisplayName:       "John Doe",
		}
		
		err := provider.ValidateUser(user)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user@domain format")
	})
	
	t.Run("validate group - valid", func(t *testing.T) {
		group := &interfaces.DirectoryGroup{
			Name:        "TestGroup",
			DisplayName: "Test Group",
			Description: "A test group",
			GroupType:   interfaces.GroupTypeSecurity,
			GroupScope:  interfaces.GroupScopeGlobal,
		}
		
		err := provider.ValidateGroup(group)
		assert.NoError(t, err)
	})
	
	t.Run("validate group - missing required fields", func(t *testing.T) {
		group := &interfaces.DirectoryGroup{
			Description: "A test group",
		}
		
		err := provider.ValidateGroup(group)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "group name is required")
	})
	
	t.Run("validate group - invalid type", func(t *testing.T) {
		group := &interfaces.DirectoryGroup{
			Name:        "TestGroup",
			DisplayName: "Test Group",
			GroupType:   "invalid",
		}
		
		err := provider.ValidateGroup(group)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid group type")
	})
}

func TestActiveDirectoryProviderStewardDiscovery(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	ctx := context.Background()
	
	t.Run("find AD steward by domain tag", func(t *testing.T) {
		client.AddSteward(StewardInfo{
			ID:       "steward-dc01",
			Hostname: "dc01.example.com",
			Platform: "windows",
			Modules:  []string{"activedirectory"},
			Tags: map[string]string{
				"ad_domain": "example.com",
			},
			IsHealthy: true,
		})
		
		stewardID, err := provider.findADSteward(ctx, "example.com")
		require.NoError(t, err)
		assert.Equal(t, "steward-dc01", stewardID)
	})
	
	t.Run("find AD steward by hostname", func(t *testing.T) {
		client = NewMockStewardClient()
		provider = NewActiveDirectoryProvider(client, logger)
		client.AddSteward(StewardInfo{
			ID:       "steward-dc02",
			Hostname: "dc02.testdomain.com",
			Platform: "windows",
			Modules:  []string{"activedirectory"},
			IsHealthy: true,
		})
		
		stewardID, err := provider.findADSteward(ctx, "testdomain.com")
		require.NoError(t, err)
		assert.Equal(t, "steward-dc02", stewardID)
	})
	
	t.Run("no suitable steward found", func(t *testing.T) {
		client = NewMockStewardClient()
		provider = NewActiveDirectoryProvider(client, logger)
		client.AddSteward(StewardInfo{
			ID:       "steward-web01",
			Hostname: "web01.example.com",
			Platform: "linux",
			Modules:  []string{"file", "package"}, // No activedirectory module
			IsHealthy: true,
		})
		
		stewardID, err := provider.findADSteward(ctx, "example.com")
		assert.Error(t, err)
		assert.Equal(t, "", stewardID)
		assert.Contains(t, err.Error(), "no suitable AD steward found")
	})
	
	t.Run("steward not healthy", func(t *testing.T) {
		client = NewMockStewardClient()
		provider = NewActiveDirectoryProvider(client, logger)
		client.AddSteward(StewardInfo{
			ID:       "steward-dc01",
			Hostname: "dc01.example.com",
			Platform: "windows",
			Modules:  []string{"activedirectory"},
			IsHealthy: false, // Not healthy
		})
		
		stewardID, err := provider.findADSteward(ctx, "example.com")
		assert.Error(t, err)
		assert.Equal(t, "", stewardID)
	})
}

func TestActiveDirectoryProviderStatistics(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	// Add steward and connect
	client.AddSteward(StewardInfo{
		ID:       "steward-dc01",
		Hostname: "dc01.example.com",
		Platform: "windows",
		Modules:  []string{"activedirectory"},
		Tags: map[string]string{
			"ad_domain": "example.com",
		},
		IsHealthy: true,
	})
	
	config := interfaces.ProviderConfig{
		ServerAddress: "example.com",
		AuthMethod:    interfaces.AuthMethodLDAP,
		Username:      "service-account",
		Password:      "password123",
	}
	
	ctx := context.Background()
	err := provider.Connect(ctx, config)
	require.NoError(t, err)
	
	t.Run("initial statistics", func(t *testing.T) {
		assert.Equal(t, int64(0), provider.GetRequestCount())
		assert.Equal(t, int64(0), provider.GetErrorCount())
		assert.Equal(t, time.Duration(0), provider.GetAverageLatency())
	})
	
	t.Run("statistics after operations", func(t *testing.T) {
		// Perform some operations
		_, _ = provider.GetUser(ctx, "john.doe")
		_, _ = provider.ListUsers(ctx, nil)
		
		// Check that stats are updated
		assert.Greater(t, provider.GetRequestCount(), int64(0))
		assert.GreaterOrEqual(t, provider.GetErrorCount(), int64(0))
	})
}

func TestActiveDirectoryProviderErrors(t *testing.T) {
	client := NewMockStewardClient()
	logger := logging.NewNoopLogger()
	provider := NewActiveDirectoryProvider(client, logger)
	
	ctx := context.Background()
	
	t.Run("operations without connection", func(t *testing.T) {
		_, err := provider.GetUser(ctx, "john.doe")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not connected")
		
		_, err = provider.ListUsers(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not connected")
	})
	
	t.Run("connection with no stewards", func(t *testing.T) {
		config := interfaces.ProviderConfig{
			ServerAddress: "example.com",
			AuthMethod:    interfaces.AuthMethodLDAP,
		}
		
		err := provider.Connect(ctx, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no suitable AD steward found")
	})
	
	t.Run("steward client errors", func(t *testing.T) {
		client.SetError(true, "steward communication failed")
		
		config := interfaces.ProviderConfig{
			ServerAddress: "example.com",
			AuthMethod:    interfaces.AuthMethodLDAP,
		}
		
		err := provider.Connect(ctx, config)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "steward communication failed")
	})
}