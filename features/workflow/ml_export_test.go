package workflow

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

func TestMLDataExporter_ExportJSON(t *testing.T) {
	// Setup mock provider with test data
	mockProvider := &MockLoggingProvider{}
	testEntries := createTestMLLogEntries()

	mockProvider.On("QueryTimeRange", mock.Anything, mock.Anything).Return(testEntries, nil)

	exporter := NewMLDataExporter(mockProvider)

	// Create export request
	request := ExportRequest{
		StartTime:              time.Now().Add(-24 * time.Hour),
		EndTime:                time.Now(),
		Format:                 ExportFormatJSON,
		IncludeHeaders:         true,
		IncludeVariableStates:  true,
		IncludeAPIData:         true,
		IncludePerformanceData: true,
		IncludeErrorPatterns:   true,
		IncludeOnlyMLEvents:    true,
	}

	// Export data
	var buf bytes.Buffer
	result, err := exporter.ExportMLData(context.Background(), request, &buf)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, ExportFormatJSON, result.Format)
	assert.Greater(t, result.BytesExported, int64(0))
	assert.Greater(t, result.ProcessingTime, time.Duration(0))

	// Verify JSON structure
	var exportedData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &exportedData)
	assert.NoError(t, err)

	assert.Contains(t, exportedData, "export_metadata")
	assert.Contains(t, exportedData, "ml_log_entries")

	metadata := exportedData["export_metadata"].(map[string]interface{})
	assert.Contains(t, metadata, "exported_at")
	assert.Contains(t, metadata, "record_count")
	assert.Contains(t, metadata, "format")

	entries := exportedData["ml_log_entries"].([]interface{})
	assert.NotEmpty(t, entries)
}

func TestMLDataExporter_ExportCSV(t *testing.T) {
	// Setup mock provider with test data
	mockProvider := &MockLoggingProvider{}
	testEntries := createTestMLLogEntries()

	mockProvider.On("QueryTimeRange", mock.Anything, mock.Anything).Return(testEntries, nil)

	exporter := NewMLDataExporter(mockProvider)

	// Create export request
	request := ExportRequest{
		StartTime:              time.Now().Add(-24 * time.Hour),
		EndTime:                time.Now(),
		Format:                 ExportFormatCSV,
		IncludeHeaders:         true,
		IncludeVariableStates:  true,
		IncludeAPIData:         true,
		IncludePerformanceData: true,
		IncludeErrorPatterns:   true,
		IncludeOnlyMLEvents:    true,
	}

	// Export data
	var buf bytes.Buffer
	result, err := exporter.ExportMLData(context.Background(), request, &buf)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, ExportFormatCSV, result.Format)
	assert.Greater(t, result.BytesExported, int64(0))

	// Verify CSV structure
	csvData := buf.String()
	lines := strings.Split(csvData, "\n")
	assert.GreaterOrEqual(t, len(lines), 2) // Headers + at least one data row

	// Parse and verify headers
	reader := csv.NewReader(strings.NewReader(csvData))
	records, err := reader.ReadAll()
	assert.NoError(t, err)

	headers := records[0]
	assert.Contains(t, headers, "timestamp")
	assert.Contains(t, headers, "execution_id")
	assert.Contains(t, headers, "workflow_name")
	assert.Contains(t, headers, "event_type")

	// Verify data rows
	if len(records) > 1 {
		dataRow := records[1]
		assert.Len(t, dataRow, len(headers))
	}
}

func TestMLDataExporter_ExportJSONLines(t *testing.T) {
	// Setup mock provider with test data
	mockProvider := &MockLoggingProvider{}
	testEntries := createTestMLLogEntries()

	mockProvider.On("QueryTimeRange", mock.Anything, mock.Anything).Return(testEntries, nil)

	exporter := NewMLDataExporter(mockProvider)

	// Create export request
	request := ExportRequest{
		StartTime:              time.Now().Add(-24 * time.Hour),
		EndTime:                time.Now(),
		Format:                 ExportFormatJSONL,
		IncludeVariableStates:  true,
		IncludeAPIData:         true,
		IncludePerformanceData: true,
		IncludeOnlyMLEvents:    true,
	}

	// Export data
	var buf bytes.Buffer
	result, err := exporter.ExportMLData(context.Background(), request, &buf)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, ExportFormatJSONL, result.Format)
	assert.Greater(t, result.BytesExported, int64(0))

	// Verify JSONL structure (each line should be valid JSON)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.GreaterOrEqual(t, len(lines), 1)

	// First line should be metadata
	var metadata map[string]interface{}
	err = json.Unmarshal([]byte(lines[0]), &metadata)
	assert.NoError(t, err)
	assert.Contains(t, metadata, "_metadata")

	// Subsequent lines should be ML log entries
	if len(lines) > 1 {
		var mlEntry MLLogEntry
		err = json.Unmarshal([]byte(lines[1]), &mlEntry)
		assert.NoError(t, err)
		assert.NotEmpty(t, mlEntry.ExecutionID)
		assert.NotEmpty(t, mlEntry.EventType)
	}
}

func TestMLDataExporter_Filtering(t *testing.T) {
	// Setup mock provider with test data
	mockProvider := &MockLoggingProvider{}
	testEntries := createTestMLLogEntries()

	mockProvider.On("QueryTimeRange", mock.Anything, mock.Anything).Return(testEntries, nil)

	exporter := NewMLDataExporter(mockProvider)

	// Test workflow name filtering
	request := ExportRequest{
		StartTime:           time.Now().Add(-24 * time.Hour),
		EndTime:             time.Now(),
		Format:              ExportFormatJSON,
		WorkflowNames:       []string{"test-workflow-1"},
		IncludeOnlyMLEvents: true,
	}

	var buf bytes.Buffer
	result, err := exporter.ExportMLData(context.Background(), request, &buf)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Parse and verify filtered results
	var exportedData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &exportedData)
	assert.NoError(t, err)

	entries := exportedData["ml_log_entries"].([]interface{})

	// All entries should match the filter
	for _, entryInterface := range entries {
		entryBytes, _ := json.Marshal(entryInterface)
		var entry MLLogEntry
		_ = json.Unmarshal(entryBytes, &entry)

		if entry.WorkflowName != "" {
			assert.Equal(t, "test-workflow-1", entry.WorkflowName)
		}
	}
}

func TestMLDataExporter_DataSelection(t *testing.T) {
	// Setup mock provider with test data
	mockProvider := &MockLoggingProvider{}
	testEntries := createTestMLLogEntries()

	mockProvider.On("QueryTimeRange", mock.Anything, mock.Anything).Return(testEntries, nil)

	exporter := NewMLDataExporter(mockProvider)

	// Test selective data inclusion
	request := ExportRequest{
		StartTime:              time.Now().Add(-24 * time.Hour),
		EndTime:                time.Now(),
		Format:                 ExportFormatJSON,
		IncludeVariableStates:  false, // Exclude variable states
		IncludeAPIData:         true,
		IncludePerformanceData: false, // Exclude performance data
		IncludeErrorPatterns:   true,
		IncludeOnlyMLEvents:    true,
	}

	var buf bytes.Buffer
	result, err := exporter.ExportMLData(context.Background(), request, &buf)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Parse and verify data selection
	var exportedData map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &exportedData)
	assert.NoError(t, err)

	entries := exportedData["ml_log_entries"].([]interface{})

	// Verify excluded data is not present
	for _, entryInterface := range entries {
		entryBytes, _ := json.Marshal(entryInterface)
		var entry MLLogEntry
		_ = json.Unmarshal(entryBytes, &entry)

		// Variable states should be excluded
		assert.Nil(t, entry.VariableStates)
		assert.Nil(t, entry.VariableChanges)

		// Performance data should be excluded
		assert.Nil(t, entry.PerformanceMetrics)

		// API data should be included (if present)
		// Error patterns should be included (if present)
	}
}

func TestMLDataExporter_GetAvailableDataSummary(t *testing.T) {
	// Setup mock provider
	mockProvider := &MockLoggingProvider{}

	// Mock count query
	mockProvider.On("QueryCount", mock.Anything, mock.Anything).Return(int64(100), nil)

	// Mock sample entries query
	testEntries := createTestMLLogEntries()
	mockProvider.On("QueryTimeRange", mock.Anything, mock.Anything).Return(testEntries, nil)

	exporter := NewMLDataExporter(mockProvider)

	// Get data summary
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()
	summary, err := exporter.GetAvailableDataSummary(context.Background(), startTime, endTime)

	assert.NoError(t, err)
	assert.NotNil(t, summary)
	assert.Equal(t, int64(100), summary.TotalRecords)
	assert.Equal(t, startTime, summary.TimeRange.Start)
	assert.Equal(t, endTime, summary.TimeRange.End)
	assert.NotEmpty(t, summary.AvailableFields)
	assert.Contains(t, summary.AvailableFields, "timestamp")
	assert.Contains(t, summary.AvailableFields, "execution_id")
	assert.Contains(t, summary.AvailableFields, "workflow_name")
}

func TestMLDataExporter_CSVColumnDetermination(t *testing.T) {
	exporter := NewMLDataExporter(nil)

	// Create a sample ML entry
	entry := MLLogEntry{
		EventType:      "test_event",
		VariableStates: map[string]interface{}{"var1": "value1"},
		APIRequestData: &APIRequestData{
			URL:    "https://api.example.com",
			Method: "POST",
		},
		PerformanceMetrics: &PerformanceMetrics{
			CPUUsagePercent: 25.5,
		},
		ErrorPattern: &ErrorPattern{
			ErrorCode: "TEST_ERROR",
		},
	}

	request := ExportRequest{
		IncludeVariableStates:  true,
		IncludeAPIData:         true,
		IncludePerformanceData: true,
		IncludeErrorPatterns:   true,
		CustomFields:           []string{"custom_field1", "custom_field2"},
		ExcludeFields:          []string{"duration_ms"},
	}

	columns := exporter.determineCSVColumns(entry, request)

	// Verify standard columns are present
	assert.Contains(t, columns, "timestamp")
	assert.Contains(t, columns, "execution_id")
	assert.Contains(t, columns, "event_type")

	// Verify conditional columns based on inclusion flags
	assert.Contains(t, columns, "variable_states_json")
	assert.Contains(t, columns, "api_request_url")
	assert.Contains(t, columns, "cpu_usage_percent")
	assert.Contains(t, columns, "error_code")

	// Verify custom fields are included
	assert.Contains(t, columns, "custom_field1")
	assert.Contains(t, columns, "custom_field2")

	// Verify excluded fields are not present
	assert.NotContains(t, columns, "duration_ms")
}

func TestMLDataExporter_CSVRowFlattening(t *testing.T) {
	exporter := NewMLDataExporter(nil)

	// Create a test ML entry with data
	timestamp := time.Now()
	entry := MLLogEntry{
		Timestamp:    timestamp,
		ExecutionID:  "exec-123",
		WorkflowName: "test-workflow",
		StepName:     "test-step",
		EventType:    "test_event",
		StartTime:    timestamp.Add(-5 * time.Second),
		EndTime:      timestamp,
		Duration:     5 * time.Second,
		VariableStates: map[string]interface{}{
			"var1": "value1",
			"var2": 42,
		},
		APIRequestData: &APIRequestData{
			URL:    "https://api.example.com",
			Method: "POST",
		},
		APIResponseData: &APIResponseData{
			StatusCode:   200,
			ResponseTime: 150 * time.Millisecond,
		},
		PerformanceMetrics: &PerformanceMetrics{
			CPUUsagePercent:  25.5,
			MemoryUsageBytes: 1024 * 1024,
			GoRoutineCount:   10,
			GCCount:          5,
		},
		ErrorPattern: &ErrorPattern{
			ErrorCode:       "TEST_ERROR",
			ErrorMessage:    "Test error message",
			FailureCategory: "test",
			IsRecoverable:   true,
		},
	}

	columns := []string{
		"timestamp", "execution_id", "workflow_name", "step_name", "event_type",
		"start_time", "end_time", "duration_ms",
		"variable_states_json",
		"api_request_url", "api_request_method",
		"api_response_status", "api_response_time_ms",
		"cpu_usage_percent", "memory_usage_bytes", "goroutine_count", "gc_count",
		"error_code", "error_message", "error_category", "is_recoverable",
	}

	request := ExportRequest{
		IncludeVariableStates:  true,
		IncludeAPIData:         true,
		IncludePerformanceData: true,
		IncludeErrorPatterns:   true,
	}

	row := exporter.flattenEntryToCSVRow(entry, columns, request)

	// Verify row has correct length
	assert.Len(t, row, len(columns))

	// Verify specific values
	assert.Equal(t, timestamp.Format(time.RFC3339), row[0]) // timestamp
	assert.Equal(t, "exec-123", row[1])                     // execution_id
	assert.Equal(t, "test-workflow", row[2])                // workflow_name
	assert.Equal(t, "test-step", row[3])                    // step_name
	assert.Equal(t, "test_event", row[4])                   // event_type
	assert.Equal(t, "5000", row[7])                         // duration_ms
	assert.Contains(t, row[8], "var1")                      // variable_states_json should contain variable
	assert.Equal(t, "https://api.example.com", row[9])      // api_request_url
	assert.Equal(t, "POST", row[10])                        // api_request_method
	assert.Equal(t, "200", row[11])                         // api_response_status
	assert.Equal(t, "150", row[12])                         // api_response_time_ms
	assert.Equal(t, "25.50", row[13])                       // cpu_usage_percent
	assert.Equal(t, "1048576", row[14])                     // memory_usage_bytes
	assert.Equal(t, "10", row[15])                          // goroutine_count
	assert.Equal(t, "5", row[16])                           // gc_count
	assert.Equal(t, "TEST_ERROR", row[17])                  // error_code
	assert.Equal(t, "Test error message", row[18])          // error_message
	assert.Equal(t, "test", row[19])                        // error_category
	assert.Equal(t, "true", row[20])                        // is_recoverable
}

// Helper function to create test ML log entries
func createTestMLLogEntries() []interfaces.LogEntry {
	timestamp := time.Now()

	// Create test ML log entries
	mlEntries := []MLLogEntry{
		{
			Timestamp:    timestamp,
			ExecutionID:  "exec-1",
			WorkflowName: "test-workflow-1",
			StepName:     "step-1",
			EventType:    "execution_start",
			VariableStates: map[string]interface{}{
				"var1": "value1",
				"var2": 42,
			},
			PerformanceMetrics: &PerformanceMetrics{
				CPUUsagePercent:  10.5,
				MemoryUsageBytes: 1024 * 1024,
				GoRoutineCount:   5,
			},
		},
		{
			Timestamp:    timestamp.Add(time.Second),
			ExecutionID:  "exec-1",
			WorkflowName: "test-workflow-1",
			StepName:     "api-step",
			EventType:    "api_request",
			APIRequestData: &APIRequestData{
				URL:       "https://api.example.com/test",
				Method:    "POST",
				Headers:   map[string]string{"Content-Type": "application/json"},
				Body:      map[string]interface{}{"key": "value"},
				RequestID: "req-123",
			},
		},
		{
			Timestamp:    timestamp.Add(2 * time.Second),
			ExecutionID:  "exec-1",
			WorkflowName: "test-workflow-1",
			StepName:     "api-step",
			EventType:    "api_response",
			APIResponseData: &APIResponseData{
				StatusCode:   200,
				Headers:      map[string]string{"Content-Type": "application/json"},
				Body:         map[string]interface{}{"result": "success"},
				ResponseTime: 150 * time.Millisecond,
				RequestID:    "req-123",
			},
		},
	}

	// Convert to standard log entries with ML data
	logEntries := make([]interfaces.LogEntry, len(mlEntries))
	for i, mlEntry := range mlEntries {
		mlData, _ := json.Marshal(mlEntry)

		logEntries[i] = interfaces.LogEntry{
			Timestamp:   mlEntry.Timestamp,
			Level:       "INFO",
			Message:     "ML workflow event",
			ServiceName: "workflow_engine",
			Component:   "ml_logger",
			Fields: map[string]interface{}{
				"ml_event_type": mlEntry.EventType,
				"execution_id":  mlEntry.ExecutionID,
				"workflow_name": mlEntry.WorkflowName,
				"step_name":     mlEntry.StepName,
				"ml_data":       string(mlData),
			},
		}
	}

	return logEntries
}
