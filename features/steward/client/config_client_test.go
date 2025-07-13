package client

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/steward/config"
)

// mockConfigClient implements the ConfigurationServiceClient interface for testing
type mockConfigClient struct {
	configurations map[string]*config.StewardConfig
	responses      map[string]*controllerpb.ConfigResponse
	statusResponses map[string]*commonpb.Status
	validationResponses map[string]*controllerpb.ConfigValidationResponse
}

func newMockConfigClient() *mockConfigClient {
	return &mockConfigClient{
		configurations: make(map[string]*config.StewardConfig),
		responses:      make(map[string]*controllerpb.ConfigResponse),
		statusResponses: make(map[string]*commonpb.Status),
		validationResponses: make(map[string]*controllerpb.ConfigValidationResponse),
	}
}

func (m *mockConfigClient) GetConfiguration(ctx context.Context, in *controllerpb.ConfigRequest, opts ...grpc.CallOption) (*controllerpb.ConfigResponse, error) {
	key := in.StewardId
	if resp, exists := m.responses[key]; exists {
		return resp, nil
	}
	
	// Return not found
	return &controllerpb.ConfigResponse{
		Status: &commonpb.Status{
			Code:    commonpb.Status_NOT_FOUND,
			Message: "No configuration found for steward",
		},
	}, nil
}

func (m *mockConfigClient) ReportConfigStatus(ctx context.Context, in *controllerpb.ConfigStatusReport, opts ...grpc.CallOption) (*commonpb.Status, error) {
	key := in.StewardId
	if resp, exists := m.statusResponses[key]; exists {
		return resp, nil
	}
	
	// Return success by default
	return &commonpb.Status{
		Code:    commonpb.Status_OK,
		Message: "Status report processed successfully",
	}, nil
}

func (m *mockConfigClient) ValidateConfig(ctx context.Context, in *controllerpb.ConfigValidationRequest, opts ...grpc.CallOption) (*controllerpb.ConfigValidationResponse, error) {
	key := in.Version
	if resp, exists := m.validationResponses[key]; exists {
		return resp, nil
	}
	
	// Return success by default
	return &controllerpb.ConfigValidationResponse{
		Status: &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "Configuration is valid",
		},
	}, nil
}

func (m *mockConfigClient) StreamConfigurationUpdates(ctx context.Context, in *controllerpb.ConfigStreamRequest, opts ...grpc.CallOption) (controllerpb.ConfigurationService_StreamConfigurationUpdatesClient, error) {
	// Return a mock stream client
	return &mockConfigStreamClient{}, nil
}

// mockConfigStreamClient implements the streaming interface
type mockConfigStreamClient struct{}

func (m *mockConfigStreamClient) Recv() (*controllerpb.ConfigurationUpdate, error) {
	// For testing purposes, just return EOF to end the stream
	return nil, context.Canceled
}

func (m *mockConfigStreamClient) Header() (metadata.MD, error) {
	return nil, nil
}

func (m *mockConfigStreamClient) Trailer() metadata.MD {
	return nil
}

func (m *mockConfigStreamClient) CloseSend() error {
	return nil
}

func (m *mockConfigStreamClient) Context() context.Context {
	return context.Background()
}

func (m *mockConfigStreamClient) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockConfigStreamClient) RecvMsg(msg interface{}) error {
	return nil
}

func (m *mockConfigClient) setConfigurationResponse(stewardID string, config *config.StewardConfig, version string) {
	configData, _ := json.Marshal(config)
	m.responses[stewardID] = &controllerpb.ConfigResponse{
		Status: &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "Configuration retrieved successfully",
		},
		Config:  configData,
		Version: version,
	}
}

func (m *mockConfigClient) setStatusResponse(stewardID string, status *commonpb.Status) {
	m.statusResponses[stewardID] = status
}

func (m *mockConfigClient) setValidationResponse(version string, response *controllerpb.ConfigValidationResponse) {
	m.validationResponses[version] = response
}

func createTestClient() *Client {
	return &Client{
		connected:    true,
		stewardID:    "test-steward",
		configClient: newMockConfigClient(),
		logger:       &mockLogger{},
	}
}

// mockLogger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}
func (m *mockLogger) Fatal(msg string, fields ...interface{}) {}
func (m *mockLogger) DebugCtx(ctx context.Context, msg string, fields ...interface{}) {}
func (m *mockLogger) InfoCtx(ctx context.Context, msg string, fields ...interface{})  {}
func (m *mockLogger) WarnCtx(ctx context.Context, msg string, fields ...interface{})  {}
func (m *mockLogger) ErrorCtx(ctx context.Context, msg string, fields ...interface{}) {}
func (m *mockLogger) FatalCtx(ctx context.Context, msg string, fields ...interface{}) {}

func createTestStewardConfig() *config.StewardConfig {
	return &config.StewardConfig{
		Steward: config.StewardSettings{
			ID:   "test-steward",
			Mode: config.ModeController,
			Logging: config.LoggingConfig{
				Level:  "info",
				Format: "text",
			},
			ErrorHandling: config.ErrorHandlingConfig{
				ModuleLoadFailure:  config.ActionContinue,
				ResourceFailure:    config.ActionWarn,
				ConfigurationError: config.ActionFail,
			},
		},
		Resources: []config.ResourceConfig{
			{
				Name:   "test-directory",
				Module: "directory",
				Config: map[string]interface{}{
					"path":        "/tmp/test",
					"permissions": "755",
				},
			},
			{
				Name:   "test-file",
				Module: "file",
				Config: map[string]interface{}{
					"path":    "/tmp/test/test.txt",
					"content": "Hello World",
				},
			},
		},
	}
}

func TestClient_GetConfiguration(t *testing.T) {
	client := createTestClient()
	mockClient := client.configClient.(*mockConfigClient)

	testConfig := createTestStewardConfig()
	testVersion := "v1"

	t.Run("successful configuration retrieval", func(t *testing.T) {
		mockClient.setConfigurationResponse("test-steward", testConfig, testVersion)

		retrievedConfig, version, err := client.GetConfiguration(context.Background(), nil)
		require.NoError(t, err)
		assert.Equal(t, testVersion, version)
		assert.NotNil(t, retrievedConfig)
		assert.Equal(t, testConfig.Steward.ID, retrievedConfig.Steward.ID)
		assert.Len(t, retrievedConfig.Resources, 2)
	})

	t.Run("configuration not found", func(t *testing.T) {
		// Clear responses to simulate not found
		mockClient.responses = make(map[string]*controllerpb.ConfigResponse)

		_, _, err := client.GetConfiguration(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "No configuration found for steward")
	})

	t.Run("configuration with module filtering", func(t *testing.T) {
		mockClient.setConfigurationResponse("test-steward", testConfig, testVersion)

		retrievedConfig, version, err := client.GetConfiguration(context.Background(), []string{"directory"})
		require.NoError(t, err)
		assert.Equal(t, testVersion, version)
		assert.NotNil(t, retrievedConfig)
		// Note: The mock doesn't actually filter, but the client request should include modules
		assert.Len(t, retrievedConfig.Resources, 2) // Mock returns full config
	})

	t.Run("not connected", func(t *testing.T) {
		client.connected = false
		_, _, err := client.GetConfiguration(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not connected to controller")
		
		// Reset for other tests
		client.connected = true
	})

	t.Run("not registered", func(t *testing.T) {
		originalID := client.stewardID
		client.stewardID = ""
		
		_, _, err := client.GetConfiguration(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not registered with controller")
		
		// Reset for other tests
		client.stewardID = originalID
	})
}

func TestClient_ReportConfigurationStatus(t *testing.T) {
	client := createTestClient()
	mockClient := client.configClient.(*mockConfigClient)

	configVersion := "v1"
	moduleStatuses := map[string]*controllerpb.ModuleStatus{
		"directory": {
			Name:      "directory",
			Status:    &commonpb.Status{Code: commonpb.Status_OK, Message: "Directory created successfully"},
			Message:   "Directory created successfully",
			Timestamp: timestamppb.Now(),
		},
		"file": {
			Name:      "file",
			Status:    &commonpb.Status{Code: commonpb.Status_OK, Message: "File created successfully"},
			Message:   "File created successfully",
			Timestamp: timestamppb.Now(),
		},
	}

	t.Run("successful status report", func(t *testing.T) {
		mockClient.setStatusResponse("test-steward", &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "Status report processed successfully",
		})

		err := client.ReportConfigurationStatus(context.Background(), configVersion, commonpb.Status_OK, "Configuration applied successfully", moduleStatuses)
		require.NoError(t, err)
	})

	t.Run("error status report", func(t *testing.T) {
		mockClient.setStatusResponse("test-steward", &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "Status report processed successfully",
		})

		errorModuleStatuses := map[string]*controllerpb.ModuleStatus{
			"directory": {
				Name:      "directory",
				Status:    &commonpb.Status{Code: commonpb.Status_ERROR, Message: "Permission denied"},
				Message:   "Permission denied",
				Timestamp: timestamppb.Now(),
			},
		}

		err := client.ReportConfigurationStatus(context.Background(), configVersion, commonpb.Status_ERROR, "Configuration failed", errorModuleStatuses)
		require.NoError(t, err)
	})

	t.Run("status report rejected", func(t *testing.T) {
		mockClient.setStatusResponse("test-steward", &commonpb.Status{
			Code:    commonpb.Status_ERROR,
			Message: "Status report rejected",
		})

		err := client.ReportConfigurationStatus(context.Background(), configVersion, commonpb.Status_OK, "Configuration applied successfully", moduleStatuses)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Status report rejected")
	})

	t.Run("not connected", func(t *testing.T) {
		client.connected = false
		err := client.ReportConfigurationStatus(context.Background(), configVersion, commonpb.Status_OK, "Configuration applied successfully", moduleStatuses)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not connected to controller")
		
		// Reset for other tests
		client.connected = true
	})

	t.Run("not registered", func(t *testing.T) {
		originalID := client.stewardID
		client.stewardID = ""
		
		err := client.ReportConfigurationStatus(context.Background(), configVersion, commonpb.Status_OK, "Configuration applied successfully", moduleStatuses)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not registered with controller")
		
		// Reset for other tests
		client.stewardID = originalID
	})
}

func TestClient_ValidateConfiguration(t *testing.T) {
	client := createTestClient()
	mockClient := client.configClient.(*mockConfigClient)

	testConfig := createTestStewardConfig()
	testVersion := "v1"

	t.Run("successful validation", func(t *testing.T) {
		mockClient.setValidationResponse(testVersion, &controllerpb.ConfigValidationResponse{
			Status: &commonpb.Status{
				Code:    commonpb.Status_OK,
				Message: "Configuration is valid",
			},
		})

		errors, err := client.ValidateConfiguration(context.Background(), testConfig, testVersion)
		require.NoError(t, err)
		assert.Empty(t, errors)
	})

	t.Run("validation failure", func(t *testing.T) {
		mockClient.setValidationResponse(testVersion, &controllerpb.ConfigValidationResponse{
			Status: &commonpb.Status{
				Code:    commonpb.Status_ERROR,
				Message: "Configuration validation failed",
			},
			Errors: []*controllerpb.ValidationError{
				{
					Field:   "steward.id",
					Message: "ID is required",
				},
				{
					Field:   "resources[0].config",
					Message: "Config is required",
				},
			},
		})

		errors, err := client.ValidateConfiguration(context.Background(), testConfig, testVersion)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Configuration validation failed")
		assert.Len(t, errors, 2)
		assert.Contains(t, errors[0], "steward.id")
		assert.Contains(t, errors[1], "resources[0].config")
	})

	t.Run("not connected", func(t *testing.T) {
		client.connected = false
		_, err := client.ValidateConfiguration(context.Background(), testConfig, testVersion)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not connected to controller")
		
		// Reset for other tests
		client.connected = true
	})

	t.Run("marshal error", func(t *testing.T) {
		// Create a config that can't be marshaled
		invalidConfig := &config.StewardConfig{
			Steward: config.StewardSettings{
				ID: "test",
			},
			Resources: []config.ResourceConfig{
				{
					Name:   "test",
					Module: "test",
					Config: map[string]interface{}{
						"invalid": make(chan int), // channels can't be marshaled
					},
				},
			},
		}

		_, err := client.ValidateConfiguration(context.Background(), invalidConfig, testVersion)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to marshal configuration")
	})
}

func TestClient_ConfigurationMethods_Integration(t *testing.T) {
	client := createTestClient()
	mockClient := client.configClient.(*mockConfigClient)

	testConfig := createTestStewardConfig()
	testVersion := "v1"

	// Setup mock responses
	mockClient.setConfigurationResponse("test-steward", testConfig, testVersion)
	mockClient.setValidationResponse(testVersion, &controllerpb.ConfigValidationResponse{
		Status: &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "Configuration is valid",
		},
	})
	mockClient.setStatusResponse("test-steward", &commonpb.Status{
		Code:    commonpb.Status_OK,
		Message: "Status report processed successfully",
	})

	// Test typical workflow
	t.Run("full configuration workflow", func(t *testing.T) {
		// 1. Get configuration
		retrievedConfig, version, err := client.GetConfiguration(context.Background(), nil)
		require.NoError(t, err)
		assert.Equal(t, testVersion, version)
		assert.NotNil(t, retrievedConfig)

		// 2. Validate configuration
		errors, err := client.ValidateConfiguration(context.Background(), retrievedConfig, version)
		require.NoError(t, err)
		assert.Empty(t, errors)

		// 3. Report status
		moduleStatuses := map[string]*controllerpb.ModuleStatus{
			"directory": {
				Name:      "directory",
				Status:    &commonpb.Status{Code: commonpb.Status_OK, Message: "Success"},
				Message:   "Success",
				Timestamp: timestamppb.Now(),
			},
		}

		err = client.ReportConfigurationStatus(context.Background(), version, commonpb.Status_OK, "Applied successfully", moduleStatuses)
		require.NoError(t, err)
	})
}