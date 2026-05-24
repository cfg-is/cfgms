// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestProviderRegistry_RegisterProvider(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	// Test registering a new provider
	mockProvider := &MockProvider{name: "test"}
	err := registry.RegisterProvider("test", mockProvider)
	require.NoError(t, err)

	// Test registering duplicate provider
	err = registry.RegisterProvider("test", mockProvider)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestProviderRegistry_GetProvider(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	// Test getting non-existent provider
	_, err := registry.GetProvider("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")

	// Test getting existing provider
	mockProvider := &MockProvider{name: "test"}
	err = registry.RegisterProvider("test", mockProvider)
	require.NoError(t, err)

	provider, err := registry.GetProvider("test")
	require.NoError(t, err)
	assert.Equal(t, "test", provider.GetName())
}

func TestProviderRegistry_ListProviders(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	// Should have built-in providers
	providers := registry.ListProviders()
	assert.Greater(t, len(providers), 0)

	// Check that Microsoft provider is registered
	var foundMicrosoft bool
	for _, provider := range providers {
		if provider.Name == "microsoft" {
			foundMicrosoft = true
			assert.Contains(t, provider.Services, "users")
			assert.Contains(t, provider.SupportedAuth, AuthTypeOAuth2)
			break
		}
	}
	assert.True(t, foundMicrosoft, "Microsoft provider should be registered")
}

func TestProviderRegistry_ExecuteOperation(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	// Use a mock provider so the test is build-tag-neutral; the builtin provider
	// gate is verified by TestDefaultBuildProvidersReturnErrNotImplemented.
	mockProvider := &MockProvider{name: "test-exec"}
	err := registry.RegisterProvider("test-exec", mockProvider)
	require.NoError(t, err)

	config := &APIConfig{
		Provider:  "test-exec",
		Service:   "test",
		Operation: "list",
		Parameters: map[string]interface{}{
			"top": 10,
		},
	}

	ctx := context.Background()
	response, err := registry.ExecuteOperation(ctx, config)
	require.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, 200, response.StatusCode)
}

func TestProviderRegistry_ExecuteOperation_InvalidProvider(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	config := &APIConfig{
		Provider:  "nonexistent",
		Service:   "test",
		Operation: "test",
	}

	ctx := context.Background()
	_, err := registry.ExecuteOperation(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestProviderRegistry_ExecuteOperation_InvalidConfig(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	config := &APIConfig{
		Provider:  "microsoft",
		Service:   "invalid_service",
		Operation: "test",
	}

	ctx := context.Background()
	_, err := registry.ExecuteOperation(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestMicrosoftProvider(t *testing.T) {
	provider := &MicrosoftProvider{}

	assert.Equal(t, "microsoft", provider.GetName())

	services := provider.GetServices()
	assert.Contains(t, services, "users")
	assert.Contains(t, services, "groups")
	assert.Contains(t, services, "teams")

	userOps := provider.GetOperations("users")
	assert.Contains(t, userOps, "list")
	assert.Contains(t, userOps, "create")
	assert.Contains(t, userOps, "assign_license")

	authMethods := provider.GetAuthenticationMethods()
	assert.Contains(t, authMethods, AuthTypeOAuth2)
	assert.Contains(t, authMethods, AuthTypeBearer)

	// Test valid config
	validConfig := &APIConfig{
		Provider:  "microsoft",
		Service:   "users",
		Operation: "list",
	}
	err := provider.ValidateConfig(validConfig)
	assert.NoError(t, err)

	// Test invalid config
	invalidConfig := &APIConfig{
		Provider:  "microsoft",
		Service:   "invalid",
		Operation: "list",
	}
	err = provider.ValidateConfig(invalidConfig)
	assert.Error(t, err)
}

func TestGoogleProvider(t *testing.T) {
	provider := &GoogleProvider{}

	assert.Equal(t, "google", provider.GetName())

	services := provider.GetServices()
	assert.Contains(t, services, "admin")
	assert.Contains(t, services, "workspace")

	adminOps := provider.GetOperations("admin")
	assert.Contains(t, adminOps, "list_users")
	assert.Contains(t, adminOps, "create_user")

	authMethods := provider.GetAuthenticationMethods()
	assert.Contains(t, authMethods, AuthTypeOAuth2)
	assert.Contains(t, authMethods, AuthTypeAPIKey)
}

func TestSalesforceProvider(t *testing.T) {
	provider := &SalesforceProvider{}

	assert.Equal(t, "salesforce", provider.GetName())

	services := provider.GetServices()
	assert.Contains(t, services, "sobjects")
	assert.Contains(t, services, "query")

	sobjectOps := provider.GetOperations("sobjects")
	assert.Contains(t, sobjectOps, "create")
	assert.Contains(t, sobjectOps, "describe")

	authMethods := provider.GetAuthenticationMethods()
	assert.Contains(t, authMethods, AuthTypeOAuth2)
	assert.Contains(t, authMethods, AuthTypeBearer)
}

func TestConnectWiseProvider(t *testing.T) {
	provider := &ConnectWiseProvider{}

	assert.Equal(t, "connectwise", provider.GetName())

	services := provider.GetServices()
	assert.Contains(t, services, "manage")
	assert.Contains(t, services, "automate")

	manageOps := provider.GetOperations("manage")
	assert.Contains(t, manageOps, "companies")
	assert.Contains(t, manageOps, "tickets")

	authMethods := provider.GetAuthenticationMethods()
	assert.Contains(t, authMethods, AuthTypeAPIKey)
	assert.Contains(t, authMethods, AuthTypeBasic)
}

func TestEngine_ExecuteAPIStep_WithProviderRegistry(t *testing.T) {
	// Create engine and register a succeeding mock provider to test engine plumbing.
	// The builtin providers return ErrProviderNotImplemented in default builds;
	// this test exercises the engine's variable-storage path, not the provider stubs.
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger, nil)

	const providerName = "test-api-provider"
	err := engine.providerRegistry.RegisterProvider(providerName, &MockProvider{name: providerName})
	require.NoError(t, err)

	workflow := Workflow{
		Name: "api-provider-test",
		Steps: []Step{
			{
				Name: "test-api-call",
				Type: StepTypeAPI,
				API: &APIConfig{
					Provider:  providerName,
					Service:   "test",
					Operation: "list",
					Parameters: map[string]interface{}{
						"top": 10,
					},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)

	// Wait for execution to complete
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	finalExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExecution.GetStatus())

	// Check that API response was stored correctly
	assert.True(t, finalExecution.Variables["test-api-call_api_success"].(bool))
	assert.Equal(t, 200, finalExecution.Variables["test-api-call_api_status"])
	assert.NotNil(t, finalExecution.Variables["test-api-call_api_response"])
}

// TestProviderNoPayloadLogging verifies that config.Parameters and config.Auth credential
// values never appear in log output at any level in either build.
func TestProviderNoPayloadLogging(t *testing.T) {
	logger := pkgtesting.NewMockLogger(true)
	registry := NewProviderRegistry(logger)

	// Register a succeeding mock so the completion-log path is exercised.
	const providerName = "test-log-provider"
	err := registry.RegisterProvider(providerName, &MockProvider{name: providerName})
	require.NoError(t, err)

	const sensitiveParam = "super-secret-param-value-7f3x"
	const sensitiveCredential = "super-secret-bearer-token-9z2q"

	config := &APIConfig{
		Provider:  providerName,
		Service:   "test",
		Operation: "test",
		Parameters: map[string]interface{}{
			"secret_key": sensitiveParam,
		},
		Auth: &AuthConfig{
			Type:        AuthTypeBearer,
			BearerToken: sensitiveCredential,
		},
	}

	_, execErr := registry.ExecuteOperation(context.Background(), config)
	require.NoError(t, execErr)

	for _, level := range []string{"debug", "info", "warn", "error", "fatal"} {
		for _, entry := range logger.GetLogs(level) {
			assert.NotContains(t, entry.Message, sensitiveParam,
				"level=%s message contains sensitive parameter value", level)
			assert.NotContains(t, entry.Message, sensitiveCredential,
				"level=%s message contains sensitive credential value", level)
			for _, kv := range entry.Data {
				s := fmt.Sprintf("%v", kv)
				assert.NotContains(t, s, sensitiveParam,
					"level=%s log data contains sensitive parameter value", level)
				assert.NotContains(t, s, sensitiveCredential,
					"level=%s log data contains sensitive credential value", level)
			}
		}
	}
}

// MockProvider is a test implementation of APIProvider
type MockProvider struct {
	name string
}

func (m *MockProvider) GetName() string {
	return m.name
}

func (m *MockProvider) GetServices() []string {
	return []string{"test"}
}

func (m *MockProvider) GetOperations(service string) []string {
	return []string{"test"}
}

func (m *MockProvider) ValidateConfig(config *APIConfig) error {
	return nil
}

func (m *MockProvider) ExecuteOperation(ctx context.Context, config *APIConfig) (*APIResponse, error) {
	return &APIResponse{
		Success:    true,
		Data:       map[string]interface{}{"mock": "response"},
		StatusCode: 200,
	}, nil
}

func (m *MockProvider) GetAuthenticationMethods() []AuthType {
	return []AuthType{AuthTypeAPIKey}
}

func (m *MockProvider) RefreshToken(ctx context.Context, config *APIConfig) error {
	return nil
}
