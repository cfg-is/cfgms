// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// IntegrationTestSuite provides integration testing for the complete trigger system
type IntegrationTestSuite struct {
	manager         *TriggerManagerImpl
	scheduler       *CronScheduler
	webhookHandler  *HTTPWebhookHandler
	siemProcessor   *SIEMProcessor
	apiHandler      *APIHandler
	workflowTrigger *TestWorkflowTrigger
	storage         *TestStorageProvider
	router          *mux.Router
	server          *httptest.Server
}

// TestStorageProvider implements a simple in-memory storage for testing
type TestStorageProvider struct {
	data  map[string][]byte
	mutex sync.RWMutex
}

func NewTestStorageProvider() *TestStorageProvider {
	return &TestStorageProvider{
		data: make(map[string][]byte),
	}
}

func (t *TestStorageProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	return nil
}

func (t *TestStorageProvider) Available() (bool, error) {
	return true, nil
}

func (t *TestStorageProvider) Store(ctx context.Context, key string, data []byte) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.data[key] = data
	return nil
}

func (t *TestStorageProvider) Retrieve(ctx context.Context, key string) ([]byte, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	data, exists := t.data[key]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", key)
	}
	return data, nil
}

func (t *TestStorageProvider) Delete(ctx context.Context, key string) error {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	delete(t.data, key)
	return nil
}

func (t *TestStorageProvider) List(ctx context.Context, prefix string) ([]string, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	keys := make([]string, 0)
	for key := range t.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (t *TestStorageProvider) Exists(ctx context.Context, key string) (bool, error) {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	_, exists := t.data[key]
	return exists, nil
}

func (t *TestStorageProvider) Close() error {
	return nil
}

// Additional methods required by StorageProvider interface
func (t *TestStorageProvider) Name() string {
	return "test"
}

func (t *TestStorageProvider) Description() string {
	return "Test storage provider for integration tests"
}

func (t *TestStorageProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) CreateRegistrationTokenStore(config map[string]interface{}) (interfaces.RegistrationTokenStore, error) {
	return nil, fmt.Errorf("not implemented in test provider")
}

func (t *TestStorageProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		MaxBatchSize:          100,
		MaxConfigSize:         1024,
		MaxAuditRetentionDays: 30,
	}
}

func (t *TestStorageProvider) GetVersion() string {
	return "1.0.0-test"
}

// TestWorkflowTrigger implements a test workflow trigger that records executions
type TestWorkflowTrigger struct {
	executions []WorkflowExecution
	mutex      sync.RWMutex
	failNext   bool
}

func NewTestWorkflowTrigger() *TestWorkflowTrigger {
	return &TestWorkflowTrigger{
		executions: make([]WorkflowExecution, 0),
	}
}

func (t *TestWorkflowTrigger) TriggerWorkflow(ctx context.Context, trigger *Trigger, data map[string]interface{}) (*WorkflowExecution, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.failNext {
		t.failNext = false
		return nil, fmt.Errorf("simulated workflow execution failure")
	}

	execution := WorkflowExecution{
		ID:           fmt.Sprintf("exec-%d", len(t.executions)+1),
		WorkflowName: trigger.WorkflowName,
		Status:       "running",
		StartTime:    time.Now(),
	}

	t.executions = append(t.executions, execution)
	return &execution, nil
}

func (t *TestWorkflowTrigger) ValidateTrigger(ctx context.Context, trigger *Trigger) error {
	if trigger.WorkflowName == "" {
		return fmt.Errorf("workflow name cannot be empty")
	}
	return nil
}

func (t *TestWorkflowTrigger) GetExecutions() []WorkflowExecution {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return append([]WorkflowExecution{}, t.executions...)
}

func (t *TestWorkflowTrigger) SetFailNext(fail bool) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	t.failNext = fail
}

func setupIntegrationTest(t *testing.T) *IntegrationTestSuite {
	// Create components
	storage := NewTestStorageProvider()
	workflowTrigger := NewTestWorkflowTrigger()

	// Create manager first (we'll create scheduler separately)
	manager := NewTriggerManager(
		storage,
		nil, // scheduler will be set later
		nil, // webhook handler will be set later
		nil, // siem integration will be set later
		workflowTrigger,
	)

	// Create scheduler
	scheduler := NewCronScheduler(manager, workflowTrigger)
	// Set a faster tick interval for integration tests
	scheduler.SetTickerInterval(100 * time.Millisecond)

	// Create webhook handler
	webhookHandler := NewHTTPWebhookHandler(manager, workflowTrigger, "localhost", 0)

	// Create SIEM processor
	siemProcessor := NewSIEMProcessor(manager, workflowTrigger)

	// Update manager with all components
	manager.scheduler = scheduler
	manager.webhookHandler = webhookHandler
	manager.siemIntegration = siemProcessor

	// Create API handler
	apiHandler := NewAPIHandler(manager)

	// Set up router
	router := mux.NewRouter()
	router.Use(TriggerAPIMiddleware)
	apiHandler.RegisterRoutes(router)

	// Create test server
	server := httptest.NewServer(router)

	return &IntegrationTestSuite{
		manager:         manager,
		scheduler:       scheduler,
		webhookHandler:  webhookHandler,
		siemProcessor:   siemProcessor,
		apiHandler:      apiHandler,
		workflowTrigger: workflowTrigger,
		storage:         storage,
		router:          router,
		server:          server,
	}
}

// makeRequest makes an HTTP request with the integration tenant header
func (suite *IntegrationTestSuite) makeRequest(method, path, contentType string, body []byte) (*http.Response, error) {
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequest(method, suite.server.URL+path, bytes.NewReader(body))
	} else {
		req, err = http.NewRequest(method, suite.server.URL+path, nil)
	}

	if err != nil {
		return nil, err
	}

	// Set tenant header for integration tests
	req.Header.Set("X-Tenant-ID", "integration-tenant")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	client := &http.Client{}
	return client.Do(req)
}

func (suite *IntegrationTestSuite) cleanup() {
	if suite.server != nil {
		suite.server.Close()
	}
}

func TestTriggerSystem_FullIntegration(t *testing.T) {
	suite := setupIntegrationTest(t)
	defer suite.cleanup()

	// Create tenant-aware context for integration tests to work with tenant isolation
	ctx := context.WithValue(context.Background(), TenantIDContextKey, "integration-tenant")

	// Start the system
	err := suite.manager.Start(ctx)
	require.NoError(t, err)
	defer func() { _ = suite.manager.Stop(ctx) }()

	t.Run("Schedule Trigger End-to-End", func(t *testing.T) {
		// Create a schedule trigger via API
		trigger := Trigger{
			ID:           "schedule-integration-1",
			Name:         "Integration Test Schedule",
			Type:         TriggerTypeSchedule,
			Status:       TriggerStatusActive,
			TenantID:     "integration-tenant",
			WorkflowName: "integration-workflow",
			Schedule: &ScheduleConfig{
				CronExpression: "*/1 * * * * *", // Every second for quick testing
				Enabled:        true,
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		triggerJSON, _ := json.Marshal(trigger)
		resp, err := suite.makeRequest("POST", "/triggers", "application/json", triggerJSON)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		// Wait for scheduler to execute the trigger
		time.Sleep(2 * time.Second)

		// Check that workflow was executed
		executions := suite.workflowTrigger.GetExecutions()
		assert.Greater(t, len(executions), 0, "Expected at least one workflow execution")

		// Verify trigger is stored
		storedTrigger, err := suite.manager.GetTrigger(ctx, trigger.ID)
		require.NoError(t, err)
		assert.Equal(t, trigger.Name, storedTrigger.Name)

		// Clean up
		err = suite.manager.DeleteTrigger(ctx, trigger.ID)
		require.NoError(t, err)
	})

	t.Run("Webhook Trigger End-to-End", func(t *testing.T) {
		// Create a webhook trigger
		trigger := &Trigger{
			ID:           "webhook-integration-1",
			Name:         "Integration Test Webhook",
			Type:         TriggerTypeWebhook,
			Status:       TriggerStatusActive,
			TenantID:     "integration-tenant",
			WorkflowName: "webhook-workflow",
			Webhook: &WebhookConfig{
				Path:    "/webhook/integration",
				Method:  []string{"POST"},
				Enabled: true,
				Authentication: &WebhookAuth{
					Type:   WebhookAuthAPIKey,
					APIKey: "integration-test-key",
				},
			},
		}

		err := suite.manager.CreateTrigger(ctx, trigger)
		require.NoError(t, err)

		// Test webhook execution
		initialExecutions := len(suite.workflowTrigger.GetExecutions())

		// Simulate webhook call
		payload := []byte(`{"event": "integration_test", "data": "webhook_payload"}`)
		headers := map[string]string{
			"X-API-Key":    "integration-test-key",
			"Content-Type": "application/json",
		}

		execution, err := suite.webhookHandler.HandleWebhook(ctx, trigger.ID, payload, headers)
		require.NoError(t, err)
		assert.NotNil(t, execution)
		assert.Equal(t, trigger.ID, execution.TriggerID)

		// Wait for async execution
		time.Sleep(100 * time.Millisecond)

		// Verify workflow was triggered
		finalExecutions := suite.workflowTrigger.GetExecutions()
		assert.Greater(t, len(finalExecutions), initialExecutions, "Expected workflow execution from webhook")

		// Clean up
		err = suite.manager.DeleteTrigger(ctx, trigger.ID)
		require.NoError(t, err)
	})

	t.Run("SIEM Trigger End-to-End", func(t *testing.T) {
		// Create a SIEM trigger
		trigger := &Trigger{
			ID:           "siem-integration-1",
			Name:         "Integration Test SIEM",
			Type:         TriggerTypeSIEM,
			Status:       TriggerStatusActive,
			TenantID:     "integration-tenant",
			WorkflowName: "siem-workflow",
			SIEM: &SIEMConfig{
				EventTypes: []string{"auth_failure"},
				Conditions: []*SIEMCondition{
					{
						Field:    "level",
						Operator: SIEMOperatorEquals,
						Value:    "error",
					},
				},
				Threshold: &SIEMThreshold{
					Count: 2, // Trigger after 2 matching events
				},
				WindowSize: 1 * time.Minute,
				Enabled:    true,
			},
		}

		err := suite.manager.CreateTrigger(ctx, trigger)
		require.NoError(t, err)

		initialExecutions := len(suite.workflowTrigger.GetExecutions())

		// Send log entries that should trigger the SIEM rule
		logEntry1 := map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339),
			"level":     "error",
			"message":   "Authentication failed for user",
			"source":    "auth-service",
			"tenant_id": "integration-tenant",
			"fields": map[string]interface{}{
				"event_type": "auth_failure",
				"user_id":    "user-123",
				"ip_address": "192.168.1.100",
			},
		}

		logEntry2 := map[string]interface{}{
			"timestamp": time.Now().Format(time.RFC3339),
			"level":     "error",
			"message":   "Another authentication failure",
			"source":    "auth-service",
			"tenant_id": "integration-tenant",
			"fields": map[string]interface{}{
				"event_type": "auth_failure",
				"user_id":    "user-456",
				"ip_address": "192.168.1.101",
			},
		}

		// Process log entries
		err = suite.siemProcessor.ProcessLogEntry(ctx, logEntry1)
		require.NoError(t, err)

		err = suite.siemProcessor.ProcessLogEntry(ctx, logEntry2)
		require.NoError(t, err)

		// Wait for SIEM processing and threshold evaluation
		time.Sleep(200 * time.Millisecond)

		// Verify workflow was triggered when threshold was met
		finalExecutions := suite.workflowTrigger.GetExecutions()
		assert.Greater(t, len(finalExecutions), initialExecutions, "Expected workflow execution from SIEM trigger")

		// Clean up
		err = suite.manager.DeleteTrigger(ctx, trigger.ID)
		require.NoError(t, err)
	})

	t.Run("API Integration - CRUD Operations", func(t *testing.T) {
		triggerData := map[string]interface{}{
			"id":            "api-integration-1",
			"name":          "API Integration Test",
			"type":          "manual",
			"status":        "active",
			"tenant_id":     "integration-tenant",
			"workflow_name": "api-workflow",
		}

		// CREATE via API
		triggerJSON, _ := json.Marshal(triggerData)
		resp, err := suite.makeRequest("POST", "/triggers", "application/json", triggerJSON)
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, resp.StatusCode)

		// READ via API
		resp, err = suite.makeRequest("GET", "/triggers/api-integration-1", "", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var retrievedTrigger Trigger
		err = json.NewDecoder(resp.Body).Decode(&retrievedTrigger)
		require.NoError(t, err)
		assert.Equal(t, "api-integration-1", retrievedTrigger.ID)
		assert.Equal(t, "API Integration Test", retrievedTrigger.Name)

		// UPDATE via API
		updatedData := triggerData
		updatedData["name"] = "Updated API Integration Test"
		updatedJSON, _ := json.Marshal(updatedData)

		resp, err = suite.makeRequest("PUT", "/triggers/api-integration-1", "application/json", updatedJSON)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Verify update
		resp, err = suite.makeRequest("GET", "/triggers/api-integration-1", "", nil)
		require.NoError(t, err)
		err = json.NewDecoder(resp.Body).Decode(&retrievedTrigger)
		require.NoError(t, err)
		assert.Equal(t, "Updated API Integration Test", retrievedTrigger.Name)

		// EXECUTE via API
		executeData := map[string]interface{}{
			"manual_execution": true,
			"user_id":          "integration-user",
		}
		executeJSON, _ := json.Marshal(executeData)

		resp, err = suite.makeRequest("POST", "/triggers/api-integration-1/execute", "application/json", executeJSON)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var execution TriggerExecution
		err = json.NewDecoder(resp.Body).Decode(&execution)
		require.NoError(t, err)
		assert.Equal(t, "api-integration-1", execution.TriggerID)

		// DELETE via API
		resp, err = suite.makeRequest("DELETE", "/triggers/api-integration-1", "", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)

		// Verify deletion
		resp, err = suite.makeRequest("GET", "/triggers/api-integration-1", "", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Error Handling and Recovery", func(t *testing.T) {
		// Test workflow execution failure handling
		trigger := &Trigger{
			ID:           "error-handling-1",
			Name:         "Error Handling Test",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			TenantID:     "integration-tenant",
			WorkflowName: "failing-workflow",
		}

		err := suite.manager.CreateTrigger(ctx, trigger)
		require.NoError(t, err)

		// Configure workflow trigger to fail next execution
		suite.workflowTrigger.SetFailNext(true)

		// Execute trigger
		execution, err := suite.manager.ExecuteTrigger(ctx, trigger.ID, map[string]interface{}{
			"test": "data",
		})

		// Should return execution with error status, not fail the operation
		require.NoError(t, err)
		assert.NotNil(t, execution)
		assert.Equal(t, TriggerExecutionStatusFailed, execution.Status)
		assert.NotEmpty(t, execution.Error)

		// Clean up
		err = suite.manager.DeleteTrigger(ctx, trigger.ID)
		require.NoError(t, err)
	})

	t.Run("Concurrent Operations", func(t *testing.T) {
		// Test concurrent trigger creation and execution
		var wg sync.WaitGroup
		triggerIDs := make([]string, 10)

		// Create multiple triggers concurrently
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				triggerID := fmt.Sprintf("concurrent-trigger-%d", index)
				triggerIDs[index] = triggerID

				trigger := &Trigger{
					ID:           triggerID,
					Name:         fmt.Sprintf("Concurrent Test %d", index),
					Type:         TriggerTypeManual,
					Status:       TriggerStatusActive,
					TenantID:     "integration-tenant",
					WorkflowName: fmt.Sprintf("concurrent-workflow-%d", index),
				}

				err := suite.manager.CreateTrigger(ctx, trigger)
				assert.NoError(t, err)
			}(i)
		}

		wg.Wait()

		// Execute all triggers concurrently
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				execution, err := suite.manager.ExecuteTrigger(ctx, triggerIDs[index], map[string]interface{}{
					"concurrent": true,
					"index":      index,
				})

				if assert.NoError(t, err) {
					assert.NotNil(t, execution)
					if execution != nil {
						assert.Equal(t, triggerIDs[index], execution.TriggerID)
					}
				}
			}(i)
		}

		wg.Wait()

		// Clean up
		for _, triggerID := range triggerIDs {
			err := suite.manager.DeleteTrigger(ctx, triggerID)
			assert.NoError(t, err)
		}
	})

	t.Run("Storage Persistence", func(t *testing.T) {
		// Create trigger
		trigger := &Trigger{
			ID:           "persistence-test-1",
			Name:         "Persistence Test",
			Type:         TriggerTypeSchedule,
			Status:       TriggerStatusActive,
			TenantID:     "integration-tenant",
			WorkflowName: "persistence-workflow",
			Schedule: &ScheduleConfig{
				CronExpression: "0 0 * * *",
				Enabled:        true,
			},
		}

		err := suite.manager.CreateTrigger(ctx, trigger)
		require.NoError(t, err)

		// Verify it's stored
		exists, err := suite.storage.Exists(ctx, "triggers/persistence-test-1")
		require.NoError(t, err)
		assert.True(t, exists)

		// Retrieve from storage directly
		data, err := suite.storage.Retrieve(ctx, "triggers/persistence-test-1")
		require.NoError(t, err)

		var storedTrigger Trigger
		err = json.Unmarshal(data, &storedTrigger)
		require.NoError(t, err)
		assert.Equal(t, trigger.ID, storedTrigger.ID)
		assert.Equal(t, trigger.Name, storedTrigger.Name)

		// Update trigger
		trigger.Name = "Updated Persistence Test"
		err = suite.manager.UpdateTrigger(ctx, trigger)
		require.NoError(t, err)

		// Verify update is persisted
		data, err = suite.storage.Retrieve(ctx, "triggers/persistence-test-1")
		require.NoError(t, err)
		err = json.Unmarshal(data, &storedTrigger)
		require.NoError(t, err)
		assert.Equal(t, "Updated Persistence Test", storedTrigger.Name)

		// Delete trigger
		err = suite.manager.DeleteTrigger(ctx, trigger.ID)
		require.NoError(t, err)

		// Verify deletion from storage
		exists, err = suite.storage.Exists(ctx, "triggers/persistence-test-1")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}
