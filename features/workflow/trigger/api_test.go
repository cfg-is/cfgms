// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestTriggerRouter wires handler onto a /triggers-prefixed subrouter, matching
// how server.go registers it: api.PathPrefix("/triggers").Subrouter().
func newTestTriggerRouter(handler *APIHandler) *mux.Router {
	router := mux.NewRouter()
	sub := router.PathPrefix("/triggers").Subrouter()
	handler.RegisterRoutes(sub)
	return router
}

// newRealTriggerManager builds a fully-wired TriggerManagerImpl backed by real
// CFGMS test components (in-memory storage provider + workflow trigger). CFGMS
// mandates real-component testing, so the API handler is exercised against the
// genuine manager rather than a mock of the TriggerManager interface.
func newRealTriggerManager() *TriggerManagerImpl {
	return NewControllerTriggerManager(NewTestStorageProvider(), NewTestWorkflowTrigger())
}

// newRealTriggerManagerWithWorkflow is like newRealTriggerManager but also returns
// the underlying TestWorkflowTrigger so tests can drive workflow-execution outcomes.
func newRealTriggerManagerWithWorkflow() (*TriggerManagerImpl, *TestWorkflowTrigger) {
	wf := NewTestWorkflowTrigger()
	return NewControllerTriggerManager(NewTestStorageProvider(), wf), wf
}

// seedTrigger creates a trigger through the real manager path (validation,
// handler registration, storage persistence). The API test router carries no
// tenant middleware, so triggers are created with the empty-tenant context to
// match the tenant the handler will extract from inbound requests.
func seedTrigger(t *testing.T, mgr *TriggerManagerImpl, trigger *Trigger) {
	t.Helper()
	require.NoError(t, mgr.CreateTrigger(context.Background(), trigger))
}

func TestAPIHandler_NewAPIHandler(t *testing.T) {
	mgr := newRealTriggerManager()

	handler := NewAPIHandler(mgr)

	assert.NotNil(t, handler)
	assert.Equal(t, mgr, handler.triggerManager)
	assert.NotNil(t, handler.logger)
}

func TestAPIHandler_RegisterRoutes(t *testing.T) {
	handler := NewAPIHandler(newRealTriggerManager())
	router := newTestTriggerRouter(handler)

	// Test that routes are registered by attempting to match them
	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/triggers"},
		{"GET", "/triggers"},
		{"GET", "/triggers/test-id"},
		{"PUT", "/triggers/test-id"},
		{"DELETE", "/triggers/test-id"},
		{"POST", "/triggers/test-id/enable"},
		{"POST", "/triggers/test-id/disable"},
		{"POST", "/triggers/test-id/execute"},
		{"GET", "/triggers/test-id/executions"},
		{"GET", "/triggers/health"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s %s", tt.method, tt.path), func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			var match mux.RouteMatch
			matched := router.Match(req, &match)
			assert.True(t, matched, "Route should be registered")
		})
	}
}

func TestAPIHandler_HandleCreateTrigger(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name: "successful trigger creation",
			requestBody: Trigger{
				ID:           "test-1",
				Name:         "Test Trigger",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
				Schedule: &ScheduleConfig{
					CronExpression: "0 2 * * *",
					Enabled:        true,
				},
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "invalid JSON payload",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON payload",
		},
		{
			// A schedule trigger with no schedule configuration fails real
			// validation inside the manager, which the handler maps to 500.
			name: "trigger validation failure",
			requestBody: Trigger{
				ID:           "test-2",
				Name:         "Test Trigger",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to create trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAPIHandler(newRealTriggerManager())
			router := newTestTriggerRouter(handler)

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				_ = json.NewEncoder(&body).Encode(tt.requestBody)
			}

			req, err := http.NewRequest("POST", "/triggers", &body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			} else {
				var trigger Trigger
				err := json.Unmarshal(rr.Body.Bytes(), &trigger)
				require.NoError(t, err)
				assert.NotEmpty(t, trigger.ID)
			}
		})
	}
}

func TestAPIHandler_HandleListTriggers(t *testing.T) {
	// seedListTriggers populates a real manager with one schedule and one manual
	// trigger so list/filter behaviour is exercised against real manager state.
	seedListTriggers := func(t *testing.T, mgr *TriggerManagerImpl) {
		t.Helper()
		seedTrigger(t, mgr, &Trigger{
			ID:           "trigger-1",
			Name:         "Test Trigger 1",
			Type:         TriggerTypeSchedule,
			WorkflowName: "workflow-1",
			Schedule:     &ScheduleConfig{CronExpression: "0 2 * * *", Enabled: true},
		})
		seedTrigger(t, mgr, &Trigger{
			ID:           "trigger-2",
			Name:         "Test Trigger 2",
			Type:         TriggerTypeManual,
			WorkflowName: "workflow-2",
		})
	}

	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		expectedCount  int
		expectedError  string
	}{
		{
			name:           "list all triggers",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:           "list with type filter",
			queryParams:    "?type=schedule",
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:           "list with limit",
			queryParams:    "?limit=1",
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:           "invalid query parameter",
			queryParams:    "?limit=invalid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid query parameters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newRealTriggerManager()
			seedListTriggers(t, mgr)
			handler := NewAPIHandler(mgr)
			router := newTestTriggerRouter(handler)

			req, err := http.NewRequest("GET", "/triggers"+tt.queryParams, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			} else {
				var response map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, float64(tt.expectedCount), response["count"])
			}
		})
	}
}

func TestAPIHandler_HandleGetTrigger(t *testing.T) {
	tests := []struct {
		name           string
		triggerID      string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "get existing trigger",
			triggerID:      "test-1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "get non-existent trigger",
			triggerID:      "non-existent",
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newRealTriggerManager()
			seedTrigger(t, mgr, &Trigger{
				ID:           "test-1",
				Name:         "Test Trigger",
				Type:         TriggerTypeManual,
				WorkflowName: "test-workflow",
			})
			handler := NewAPIHandler(mgr)
			router := newTestTriggerRouter(handler)

			req, err := http.NewRequest("GET", "/triggers/"+tt.triggerID, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			} else {
				var trigger Trigger
				err := json.Unmarshal(rr.Body.Bytes(), &trigger)
				require.NoError(t, err)
				assert.Equal(t, "test-1", trigger.ID)
			}
		})
	}
}

func TestAPIHandler_HandleUpdateTrigger(t *testing.T) {
	tests := []struct {
		name           string
		triggerID      string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "successful update",
			triggerID: "test-1",
			requestBody: Trigger{
				ID:           "test-1",
				Name:         "Updated Test Trigger",
				Type:         TriggerTypeManual,
				WorkflowName: "updated-workflow",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid JSON payload",
			triggerID:      "test-1",
			requestBody:    "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON payload",
		},
		{
			name:      "update non-existent trigger",
			triggerID: "non-existent",
			requestBody: Trigger{
				Name:         "Ghost",
				Type:         TriggerTypeManual,
				WorkflowName: "ghost-workflow",
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
		{
			// Updating an existing trigger with an invalid schedule config fails
			// real validation, which the handler maps to 500.
			name:      "update validation failure",
			triggerID: "test-1",
			requestBody: Trigger{
				ID:           "test-1",
				Name:         "Bad Update",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to update trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newRealTriggerManager()
			seedTrigger(t, mgr, &Trigger{
				ID:           "test-1",
				Name:         "Test Trigger",
				Type:         TriggerTypeManual,
				WorkflowName: "test-workflow",
			})
			handler := NewAPIHandler(mgr)
			router := newTestTriggerRouter(handler)

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				_ = json.NewEncoder(&body).Encode(tt.requestBody)
			}

			req, err := http.NewRequest("PUT", "/triggers/"+tt.triggerID, &body)
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			}
		})
	}
}

func TestAPIHandler_HandleDeleteTrigger(t *testing.T) {
	tests := []struct {
		name           string
		triggerID      string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "successful deletion",
			triggerID:      "test-1",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "delete non-existent trigger",
			triggerID:      "non-existent",
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newRealTriggerManager()
			seedTrigger(t, mgr, &Trigger{
				ID:           "test-1",
				Name:         "Test Trigger",
				Type:         TriggerTypeManual,
				WorkflowName: "test-workflow",
			})
			handler := NewAPIHandler(mgr)
			router := newTestTriggerRouter(handler)

			req, err := http.NewRequest("DELETE", "/triggers/"+tt.triggerID, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			}
		})
	}
}

func TestAPIHandler_HandleEnableDisableTrigger(t *testing.T) {
	tests := []struct {
		name                  string
		endpoint              string
		triggerID             string
		seededStatus          TriggerStatus
		expectedStatus        int
		expectedError         string
		expectedTriggerStatus string
	}{
		{
			name:                  "enable trigger success",
			endpoint:              "enable",
			triggerID:             "test-1",
			seededStatus:          TriggerStatusInactive,
			expectedStatus:        http.StatusOK,
			expectedTriggerStatus: "active",
		},
		{
			name:                  "disable trigger success",
			endpoint:              "disable",
			triggerID:             "test-1",
			seededStatus:          TriggerStatusActive,
			expectedStatus:        http.StatusOK,
			expectedTriggerStatus: "inactive",
		},
		{
			name:           "enable non-existent trigger",
			endpoint:       "enable",
			triggerID:      "non-existent",
			seededStatus:   TriggerStatusActive,
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := newRealTriggerManager()
			seedTrigger(t, mgr, &Trigger{
				ID:           "test-1",
				Name:         "Test Trigger",
				Type:         TriggerTypeManual,
				Status:       tt.seededStatus,
				WorkflowName: "test-workflow",
			})
			handler := NewAPIHandler(mgr)
			router := newTestTriggerRouter(handler)

			url := fmt.Sprintf("/triggers/%s/%s", tt.triggerID, tt.endpoint)
			req, err := http.NewRequest("POST", url, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				var errorResponse map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse["error"], tt.expectedError)
			} else {
				var response map[string]interface{}
				err := json.Unmarshal(rr.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedTriggerStatus, response["status"])
			}
		})
	}
}

func TestAPIHandler_HandleExecuteTrigger(t *testing.T) {
	t.Run("successful execution", func(t *testing.T) {
		mgr := newRealTriggerManager()
		seedTrigger(t, mgr, &Trigger{
			ID:           "test-1",
			Name:         "Test Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			WorkflowName: "test-workflow",
		})
		handler := NewAPIHandler(mgr)
		router := newTestTriggerRouter(handler)

		body := mustJSON(t, map[string]interface{}{"manual_execution": true, "user_id": "user-123"})
		req, err := http.NewRequest("POST", "/triggers/test-1/execute", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)

		var execution TriggerExecution
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &execution))
		assert.Equal(t, "test-1", execution.TriggerID)
		assert.Equal(t, TriggerExecutionStatusSuccess, execution.Status)
		assert.NotEmpty(t, execution.WorkflowExecutionID)
	})

	t.Run("execution with empty data", func(t *testing.T) {
		mgr := newRealTriggerManager()
		seedTrigger(t, mgr, &Trigger{
			ID:           "test-1",
			Name:         "Test Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			WorkflowName: "test-workflow",
		})
		handler := NewAPIHandler(mgr)
		router := newTestTriggerRouter(handler)

		body := mustJSON(t, map[string]interface{}{})
		req, err := http.NewRequest("POST", "/triggers/test-1/execute", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var execution TriggerExecution
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &execution))
		assert.Equal(t, "test-1", execution.TriggerID)
	})

	t.Run("execute non-existent trigger", func(t *testing.T) {
		handler := NewAPIHandler(newRealTriggerManager())
		router := newTestTriggerRouter(handler)

		body := mustJSON(t, map[string]interface{}{"test": "data"})
		req, err := http.NewRequest("POST", "/triggers/non-existent/execute", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		var errorResponse map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errorResponse))
		assert.Contains(t, errorResponse["error"], "Trigger not found")
	})

	t.Run("workflow failure returns failed execution", func(t *testing.T) {
		// A workflow-execution failure is not an API error: the manager records
		// the failed execution and returns 200 with a failed status. This is the
		// real manager contract, verified with the real TestWorkflowTrigger.
		mgr, wf := newRealTriggerManagerWithWorkflow()
		seedTrigger(t, mgr, &Trigger{
			ID:           "test-1",
			Name:         "Test Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			WorkflowName: "failing-workflow",
		})
		wf.SetFailNext(true)

		handler := NewAPIHandler(mgr)
		router := newTestTriggerRouter(handler)

		body := mustJSON(t, map[string]interface{}{"test": "data"})
		req, err := http.NewRequest("POST", "/triggers/test-1/execute", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var execution TriggerExecution
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &execution))
		assert.Equal(t, TriggerExecutionStatusFailed, execution.Status)
		assert.NotEmpty(t, execution.Error)
	})
}

func TestAPIHandler_HandleGetTriggerExecutions(t *testing.T) {
	t.Run("get executions success", func(t *testing.T) {
		mgr := newRealTriggerManager()
		seedTrigger(t, mgr, &Trigger{
			ID:           "test-1",
			Name:         "Test Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			WorkflowName: "test-workflow",
		})
		_, err := mgr.ExecuteTrigger(context.Background(), "test-1", map[string]interface{}{"run": 1})
		require.NoError(t, err)

		handler := NewAPIHandler(mgr)
		router := newTestTriggerRouter(handler)

		req, err := http.NewRequest("GET", "/triggers/test-1/executions", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
		assert.Equal(t, float64(1), response["count"])
	})

	t.Run("get executions with limit", func(t *testing.T) {
		mgr := newRealTriggerManager()
		seedTrigger(t, mgr, &Trigger{
			ID:           "test-1",
			Name:         "Test Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			WorkflowName: "test-workflow",
		})
		_, err := mgr.ExecuteTrigger(context.Background(), "test-1", map[string]interface{}{"run": 1})
		require.NoError(t, err)
		_, err = mgr.ExecuteTrigger(context.Background(), "test-1", map[string]interface{}{"run": 2})
		require.NoError(t, err)

		handler := NewAPIHandler(mgr)
		router := newTestTriggerRouter(handler)

		req, err := http.NewRequest("GET", "/triggers/test-1/executions?limit=1", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		var response map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
		assert.Equal(t, float64(1), response["count"])
	})

	t.Run("invalid limit parameter", func(t *testing.T) {
		mgr := newRealTriggerManager()
		seedTrigger(t, mgr, &Trigger{
			ID:           "test-1",
			Name:         "Test Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			WorkflowName: "test-workflow",
		})
		handler := NewAPIHandler(mgr)
		router := newTestTriggerRouter(handler)

		req, err := http.NewRequest("GET", "/triggers/test-1/executions?limit=invalid", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		var errorResponse map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errorResponse))
		assert.Contains(t, errorResponse["error"], "Invalid limit parameter")
	})

	t.Run("executions for non-existent trigger", func(t *testing.T) {
		handler := NewAPIHandler(newRealTriggerManager())
		router := newTestTriggerRouter(handler)

		req, err := http.NewRequest("GET", "/triggers/non-existent/executions", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		var errorResponse map[string]interface{}
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &errorResponse))
		assert.Contains(t, errorResponse["error"], "Trigger not found")
	})
}

func TestAPIHandler_HandleHealthCheck(t *testing.T) {
	handler := NewAPIHandler(newRealTriggerManager())
	router := newTestTriggerRouter(handler)

	req, err := http.NewRequest("GET", "/triggers/health", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response map[string]interface{}
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response["status"])
	assert.NotEmpty(t, response["timestamp"])
}

func TestAPIHandler_ParseFilterFromQuery(t *testing.T) {
	handler := NewAPIHandler(newRealTriggerManager())

	tests := []struct {
		name           string
		queryParams    string
		expectedFilter *TriggerFilter
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "empty query",
			queryParams:    "",
			expectedFilter: &TriggerFilter{},
			expectError:    false,
		},
		{
			name:        "type filter",
			queryParams: "type=webhook",
			expectedFilter: &TriggerFilter{
				Type: TriggerTypeWebhook,
			},
			expectError: false,
		},
		{
			name:        "status filter",
			queryParams: "status=active",
			expectedFilter: &TriggerFilter{
				Status: TriggerStatusActive,
			},
			expectError: false,
		},
		{
			name:        "tenant filter",
			queryParams: "tenant_id=tenant-123",
			expectedFilter: &TriggerFilter{
				TenantID: "tenant-123",
			},
			expectError: false,
		},
		{
			name:        "limit filter",
			queryParams: "limit=10",
			expectedFilter: &TriggerFilter{
				Limit: 10,
			},
			expectError: false,
		},
		{
			name:        "offset filter",
			queryParams: "offset=5",
			expectedFilter: &TriggerFilter{
				Offset: 5,
			},
			expectError: false,
		},
		{
			name:        "tags filter",
			queryParams: "tags=security,monitoring",
			expectedFilter: &TriggerFilter{
				Tags: []string{"security", "monitoring"},
			},
			expectError: false,
		},
		{
			name:        "multiple filters",
			queryParams: "type=schedule&status=active&limit=5",
			expectedFilter: &TriggerFilter{
				Type:   TriggerTypeSchedule,
				Status: TriggerStatusActive,
				Limit:  5,
			},
			expectError: false,
		},
		{
			name:        "invalid limit",
			queryParams: "limit=invalid",
			expectError: true,
			errorMsg:    "invalid limit parameter",
		},
		{
			name:        "invalid offset",
			queryParams: "offset=invalid",
			expectError: true,
			errorMsg:    "invalid offset parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/triggers?"+tt.queryParams, nil)
			require.NoError(t, err)

			filter, err := handler.parseFilterFromQuery(req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedFilter.Type, filter.Type)
				assert.Equal(t, tt.expectedFilter.Status, filter.Status)
				assert.Equal(t, tt.expectedFilter.TenantID, filter.TenantID)
				assert.Equal(t, tt.expectedFilter.Limit, filter.Limit)
				assert.Equal(t, tt.expectedFilter.Offset, filter.Offset)
				assert.Equal(t, tt.expectedFilter.Tags, filter.Tags)
			}
		})
	}
}

// TestAPIHandler_HandleListTriggers_EmptyReturnsArrayNotNull verifies that when the trigger
// manager holds no triggers for a tenant, the API serializes the list as [] rather than null.
// A nil slice marshals as JSON null, which crashes client-side .map() calls.
// The fix is in TriggerManagerImpl.ListTriggers (source level), not in the handler.
func TestAPIHandler_HandleListTriggers_EmptyReturnsArrayNotNull(t *testing.T) {
	// Use a real TriggerManagerImpl with no triggers seeded — this is what exercises the
	// source-level fix in manager.go. If the fix is absent, ListTriggers returns a nil
	// slice and the JSON will contain "triggers": null.
	mgr := NewControllerTriggerManager(nil, nil)
	handler := NewAPIHandler(mgr)
	router := newTestTriggerRouter(handler)

	req, err := http.NewRequest("GET", "/triggers", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &raw))
	assert.Equal(t, json.RawMessage("[]"), raw["triggers"], "empty trigger list must be [] not null")
}

func TestAPIHandler_SendErrorResponse(t *testing.T) {
	handler := NewAPIHandler(newRealTriggerManager())

	tests := []struct {
		name           string
		statusCode     int
		message        string
		err            error
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "bad request error",
			statusCode:     http.StatusBadRequest,
			message:        "Invalid input",
			err:            fmt.Errorf("validation failed"),
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid input",
		},
		{
			name:           "internal server error",
			statusCode:     http.StatusInternalServerError,
			message:        "Internal error",
			err:            fmt.Errorf("database connection failed"),
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Internal error",
		},
		{
			name:           "not found error",
			statusCode:     http.StatusNotFound,
			message:        "Resource not found",
			err:            fmt.Errorf("trigger not found"),
			expectedStatus: http.StatusNotFound,
			expectedError:  "Resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()

			handler.sendErrorResponse(rr, tt.statusCode, tt.message, tt.err)

			assert.Equal(t, tt.expectedStatus, rr.Code)
			assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

			var errorResponse map[string]interface{}
			err := json.Unmarshal(rr.Body.Bytes(), &errorResponse)
			require.NoError(t, err)

			assert.Contains(t, errorResponse["error"], tt.expectedError)
			assert.NotEmpty(t, errorResponse["timestamp"])
		})
	}
}

// mustJSON marshals v to JSON, failing the test on error.
func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
