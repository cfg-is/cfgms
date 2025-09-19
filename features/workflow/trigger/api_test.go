package trigger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAPIHandler_NewAPIHandler(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}

	handler := NewAPIHandler(mockTriggerManager)

	assert.NotNil(t, handler)
	assert.Equal(t, mockTriggerManager, handler.triggerManager)
	assert.NotNil(t, handler.logger)
}

func TestAPIHandler_RegisterRoutes(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()

	handler.RegisterRoutes(router)

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
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		requestBody    interface{}
		setupMocks     func()
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
			setupMocks: func() {
				mockTriggerManager.On("CreateTrigger", mock.Anything, mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "invalid JSON payload",
			requestBody:    "invalid json",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON payload",
		},
		{
			name: "trigger manager error",
			requestBody: Trigger{
				ID:           "test-2",
				Name:         "Test Trigger",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			setupMocks: func() {
				mockTriggerManager.On("CreateTrigger", mock.Anything, mock.Anything).Return(fmt.Errorf("creation failed"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to create trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				json.NewEncoder(&body).Encode(tt.requestBody)
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
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	testTriggers := []*Trigger{
		{
			ID:           "trigger-1",
			Name:         "Test Trigger 1",
			Type:         TriggerTypeSchedule,
			Status:       TriggerStatusActive,
			WorkflowName: "workflow-1",
		},
		{
			ID:           "trigger-2",
			Name:         "Test Trigger 2",
			Type:         TriggerTypeWebhook,
			Status:       TriggerStatusActive,
			WorkflowName: "workflow-2",
		},
	}

	tests := []struct {
		name           string
		queryParams    string
		setupMocks     func()
		expectedStatus int
		expectedCount  int
		expectedError  string
	}{
		{
			name:        "list all triggers",
			queryParams: "",
			setupMocks: func() {
				mockTriggerManager.On("ListTriggers", mock.Anything, mock.Anything).Return(testTriggers, nil)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:        "list with type filter",
			queryParams: "?type=schedule",
			setupMocks: func() {
				mockTriggerManager.On("ListTriggers", mock.Anything, mock.Anything).Return([]*Trigger{testTriggers[0]}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "list with limit",
			queryParams: "?limit=1",
			setupMocks: func() {
				mockTriggerManager.On("ListTriggers", mock.Anything, mock.Anything).Return([]*Trigger{testTriggers[0]}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "invalid query parameter",
			queryParams: "?limit=invalid",
			setupMocks:  func() {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid query parameters",
		},
		{
			name:        "trigger manager error",
			queryParams: "",
			setupMocks: func() {
				mockTriggerManager.On("ListTriggers", mock.Anything, mock.Anything).Return(nil, fmt.Errorf("list failed"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to list triggers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

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
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	testTrigger := &Trigger{
		ID:           "test-1",
		Name:         "Test Trigger",
		Type:         TriggerTypeSchedule,
		Status:       TriggerStatusActive,
		WorkflowName: "test-workflow",
	}

	tests := []struct {
		name           string
		triggerID      string
		setupMocks     func()
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "get existing trigger",
			triggerID: "test-1",
			setupMocks: func() {
				mockTriggerManager.On("GetTrigger", mock.Anything, "test-1").Return(testTrigger, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "get non-existent trigger",
			triggerID: "non-existent",
			setupMocks: func() {
				mockTriggerManager.On("GetTrigger", mock.Anything, "non-existent").Return(nil, fmt.Errorf("trigger not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
		{
			name:      "trigger manager error",
			triggerID: "error-trigger",
			setupMocks: func() {
				mockTriggerManager.On("GetTrigger", mock.Anything, "error-trigger").Return(nil, fmt.Errorf("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to get trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

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
				assert.Equal(t, testTrigger.ID, trigger.ID)
			}
		})
	}
}

func TestAPIHandler_HandleUpdateTrigger(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	updatedTrigger := Trigger{
		ID:           "test-1",
		Name:         "Updated Test Trigger",
		Type:         TriggerTypeSchedule,
		Status:       TriggerStatusActive,
		WorkflowName: "updated-workflow",
	}

	tests := []struct {
		name           string
		triggerID      string
		requestBody    interface{}
		setupMocks     func()
		expectedStatus int
		expectedError  string
	}{
		{
			name:        "successful update",
			triggerID:   "test-1",
			requestBody: updatedTrigger,
			setupMocks: func() {
				mockTriggerManager.On("UpdateTrigger", mock.Anything, mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid JSON payload",
			triggerID:      "test-1",
			requestBody:    "invalid json",
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid JSON payload",
		},
		{
			name:        "trigger manager error",
			triggerID:   "test-1",
			requestBody: updatedTrigger,
			setupMocks: func() {
				mockTriggerManager.On("UpdateTrigger", mock.Anything, mock.Anything).Return(fmt.Errorf("update failed"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to update trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

			var body bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				body.WriteString(str)
			} else {
				json.NewEncoder(&body).Encode(tt.requestBody)
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
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		triggerID      string
		setupMocks     func()
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "successful deletion",
			triggerID: "test-1",
			setupMocks: func() {
				mockTriggerManager.On("DeleteTrigger", mock.Anything, "test-1").Return(nil)
			},
			expectedStatus: http.StatusNoContent,
		},
		{
			name:      "delete non-existent trigger",
			triggerID: "non-existent",
			setupMocks: func() {
				mockTriggerManager.On("DeleteTrigger", mock.Anything, "non-existent").Return(fmt.Errorf("trigger not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
		{
			name:      "trigger manager error",
			triggerID: "error-trigger",
			setupMocks: func() {
				mockTriggerManager.On("DeleteTrigger", mock.Anything, "error-trigger").Return(fmt.Errorf("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to delete trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

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
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		endpoint       string
		triggerID      string
		setupMocks     func()
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "enable trigger success",
			endpoint:  "enable",
			triggerID: "test-1",
			setupMocks: func() {
				mockTriggerManager.On("EnableTrigger", mock.Anything, "test-1").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "disable trigger success",
			endpoint:  "disable",
			triggerID: "test-1",
			setupMocks: func() {
				mockTriggerManager.On("DisableTrigger", mock.Anything, "test-1").Return(nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "enable non-existent trigger",
			endpoint:  "enable",
			triggerID: "non-existent",
			setupMocks: func() {
				mockTriggerManager.On("EnableTrigger", mock.Anything, "non-existent").Return(fmt.Errorf("trigger not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
		{
			name:      "disable with manager error",
			endpoint:  "disable",
			triggerID: "error-trigger",
			setupMocks: func() {
				mockTriggerManager.On("DisableTrigger", mock.Anything, "error-trigger").Return(fmt.Errorf("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to disable trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

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
				assert.Equal(t, "success", response["status"])
			}
		})
	}
}

func TestAPIHandler_HandleExecuteTrigger(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	executionResult := &TriggerExecution{
		ID:                  "exec-123",
		TriggerID:           "test-1",
		Status:              TriggerExecutionStatusSuccess,
		StartTime:           time.Now(),
		WorkflowExecutionID: "workflow-exec-456",
	}

	tests := []struct {
		name           string
		triggerID      string
		requestBody    map[string]interface{}
		setupMocks     func()
		expectedStatus int
		expectedError  string
	}{
		{
			name:      "successful execution",
			triggerID: "test-1",
			requestBody: map[string]interface{}{
				"manual_execution": true,
				"user_id":          "user-123",
			},
			setupMocks: func() {
				mockTriggerManager.On("ExecuteTrigger", mock.Anything, "test-1", mock.Anything).Return(executionResult, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "execution with empty data",
			triggerID: "test-1",
			requestBody: map[string]interface{}{},
			setupMocks: func() {
				mockTriggerManager.On("ExecuteTrigger", mock.Anything, "test-1", mock.Anything).Return(executionResult, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:      "execute non-existent trigger",
			triggerID: "non-existent",
			requestBody: map[string]interface{}{
				"test": "data",
			},
			setupMocks: func() {
				mockTriggerManager.On("ExecuteTrigger", mock.Anything, "non-existent", mock.Anything).Return(nil, fmt.Errorf("trigger not found"))
			},
			expectedStatus: http.StatusNotFound,
			expectedError:  "Trigger not found",
		},
		{
			name:      "execution error",
			triggerID: "error-trigger",
			requestBody: map[string]interface{}{
				"test": "data",
			},
			setupMocks: func() {
				mockTriggerManager.On("ExecuteTrigger", mock.Anything, "error-trigger", mock.Anything).Return(nil, fmt.Errorf("execution failed"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to execute trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

			var body bytes.Buffer
			json.NewEncoder(&body).Encode(tt.requestBody)

			req, err := http.NewRequest("POST", "/triggers/"+tt.triggerID+"/execute", &body)
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
				var execution TriggerExecution
				err := json.Unmarshal(rr.Body.Bytes(), &execution)
				require.NoError(t, err)
				assert.Equal(t, executionResult.ID, execution.ID)
				assert.Equal(t, executionResult.TriggerID, execution.TriggerID)
			}
		})
	}
}

func TestAPIHandler_HandleGetTriggerExecutions(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	executions := []*TriggerExecution{
		{
			ID:        "exec-1",
			TriggerID: "test-1",
			Status:    TriggerExecutionStatusSuccess,
			StartTime: time.Now().Add(-1 * time.Hour),
		},
		{
			ID:        "exec-2",
			TriggerID: "test-1",
			Status:    TriggerExecutionStatusFailed,
			StartTime: time.Now().Add(-30 * time.Minute),
		},
	}

	tests := []struct {
		name           string
		triggerID      string
		queryParams    string
		setupMocks     func()
		expectedStatus int
		expectedCount  int
		expectedError  string
	}{
		{
			name:        "get executions success",
			triggerID:   "test-1",
			queryParams: "",
			setupMocks: func() {
				mockTriggerManager.On("GetTriggerExecutions", mock.Anything, "test-1", 50).Return(executions, nil)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:        "get executions with limit",
			triggerID:   "test-1",
			queryParams: "?limit=1",
			setupMocks: func() {
				mockTriggerManager.On("GetTriggerExecutions", mock.Anything, "test-1", 1).Return([]*TriggerExecution{executions[0]}, nil)
			},
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:        "invalid limit parameter",
			triggerID:   "test-1",
			queryParams: "?limit=invalid",
			setupMocks:  func() {},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid limit parameter",
		},
		{
			name:        "trigger manager error",
			triggerID:   "error-trigger",
			queryParams: "",
			setupMocks: func() {
				mockTriggerManager.On("GetTriggerExecutions", mock.Anything, "error-trigger", 50).Return(nil, fmt.Errorf("internal error"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to get trigger executions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

			url := fmt.Sprintf("/triggers/%s/executions%s", tt.triggerID, tt.queryParams)
			req, err := http.NewRequest("GET", url, nil)
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

func TestAPIHandler_HandleHealthCheck(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

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
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)

	tests := []struct {
		name          string
		queryParams   string
		expectedFilter *TriggerFilter
		expectError   bool
		errorMsg      string
	}{
		{
			name:        "empty query",
			queryParams: "",
			expectedFilter: &TriggerFilter{},
			expectError: false,
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

func TestAPIHandler_SendErrorResponse(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)

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