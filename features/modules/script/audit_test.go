package script

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestAuditLogger_LogExecution(t *testing.T) {
	logger := NewAuditLogger(10)
	ctx := context.Background()
	stewardID := "test-steward"

	// Test basic logging
	record := &AuditRecord{
		StewardID:     stewardID,
		ResourceID:    "test-script",
		ExecutionTime: time.Now(),
		Status:        StatusCompleted,
		ExitCode:      0,
		Duration:      5000,
	}

	err := logger.LogExecution(ctx, record)
	if err != nil {
		t.Fatalf("Failed to log execution: %v", err)
	}

	// Verify record was stored
	history, err := logger.GetExecutionHistory(stewardID, 10)
	if err != nil {
		t.Fatalf("Failed to get execution history: %v", err)
	}

	if len(history) != 1 {
		t.Errorf("Expected 1 record, got %d", len(history))
	}

	if history[0].ResourceID != "test-script" {
		t.Errorf("Expected resource ID 'test-script', got %s", history[0].ResourceID)
	}
}

func TestAuditLogger_MaxHistorySize(t *testing.T) {
	maxSize := 3
	logger := NewAuditLogger(maxSize)
	ctx := context.Background()
	stewardID := "test-steward"

	// Add more records than max size
	for i := 0; i < 5; i++ {
		record := &AuditRecord{
			StewardID:     stewardID,
			ResourceID:    "test-script",
			ExecutionTime: time.Now().Add(time.Duration(i) * time.Second),
			Status:        StatusCompleted,
			ExitCode:      0,
			Duration:      1000,
		}

		err := logger.LogExecution(ctx, record)
		if err != nil {
			t.Fatalf("Failed to log execution %d: %v", i, err)
		}
	}

	// Verify only max size records are kept
	history, err := logger.GetExecutionHistory(stewardID, 10)
	if err != nil {
		t.Fatalf("Failed to get execution history: %v", err)
	}

	if len(history) != maxSize {
		t.Errorf("Expected %d records, got %d", maxSize, len(history))
	}
}

func TestAuditLogger_QueryExecutions(t *testing.T) {
	logger := NewAuditLogger(100)
	ctx := context.Background()
	stewardID := "test-steward"
	baseTime := time.Now()

	// Add test records
	testRecords := []*AuditRecord{
		{
			StewardID:     stewardID,
			ResourceID:    "script-1",
			ExecutionTime: baseTime.Add(-1 * time.Hour),
			Status:        StatusCompleted,
			ExitCode:      0,
			UserID:        "user1",
		},
		{
			StewardID:     stewardID,
			ResourceID:    "script-2",
			ExecutionTime: baseTime.Add(-30 * time.Minute),
			Status:        StatusFailed,
			ExitCode:      1,
			UserID:        "user2",
		},
		{
			StewardID:     stewardID,
			ResourceID:    "script-1",
			ExecutionTime: baseTime.Add(-10 * time.Minute),
			Status:        StatusCompleted,
			ExitCode:      0,
			UserID:        "user1",
		},
	}

	for _, record := range testRecords {
		err := logger.LogExecution(ctx, record)
		if err != nil {
			t.Fatalf("Failed to log execution: %v", err)
		}
	}

	// Test query by resource ID
	query := &AuditQuery{
		StewardID:  stewardID,
		ResourceID: "script-1",
	}

	results, err := logger.QueryExecutions(query)
	if err != nil {
		t.Fatalf("Failed to query executions: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results for script-1, got %d", len(results))
	}

	// Test query by status
	query = &AuditQuery{
		StewardID: stewardID,
		Status:    StatusFailed,
	}

	results, err = logger.QueryExecutions(query)
	if err != nil {
		t.Fatalf("Failed to query executions: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 failed result, got %d", len(results))
	}

	// Test query by user ID
	query = &AuditQuery{
		StewardID: stewardID,
		UserID:    "user1",
	}

	results, err = logger.QueryExecutions(query)
	if err != nil {
		t.Fatalf("Failed to query executions: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results for user1, got %d", len(results))
	}

	// Test time range query
	startTime := baseTime.Add(-45 * time.Minute)
	endTime := baseTime.Add(-5 * time.Minute)
	query = &AuditQuery{
		StewardID: stewardID,
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	results, err = logger.QueryExecutions(query)
	if err != nil {
		t.Fatalf("Failed to query executions: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 results in time range, got %d", len(results))
	}
}

func TestAuditLogger_GetExecutionMetrics(t *testing.T) {
	logger := NewAuditLogger(100)
	ctx := context.Background()
	stewardID := "test-steward"
	since := time.Now().Add(-1 * time.Hour)

	// Add test records with different outcomes
	testRecords := []*AuditRecord{
		{
			StewardID:     stewardID,
			ExecutionTime: time.Now().Add(-50 * time.Minute),
			Status:        StatusCompleted,
			Duration:      1000,
			ScriptConfig:  ScriptAuditInfo{Shell: ShellBash},
		},
		{
			StewardID:     stewardID,
			ExecutionTime: time.Now().Add(-40 * time.Minute),
			Status:        StatusCompleted,
			Duration:      2000,
			ScriptConfig:  ScriptAuditInfo{Shell: ShellBash},
		},
		{
			StewardID:     stewardID,
			ExecutionTime: time.Now().Add(-30 * time.Minute),
			Status:        StatusFailed,
			Duration:      500,
			ScriptConfig:  ScriptAuditInfo{Shell: ShellPowerShell},
		},
		{
			StewardID:     stewardID,
			ExecutionTime: time.Now().Add(-20 * time.Minute),
			Status:        StatusCompleted,
			Duration:      3000,
			ScriptConfig:  ScriptAuditInfo{Shell: ShellPython},
		},
	}

	for _, record := range testRecords {
		err := logger.LogExecution(ctx, record)
		if err != nil {
			t.Fatalf("Failed to log execution: %v", err)
		}
	}

	// Get metrics
	metrics, err := logger.GetExecutionMetrics(stewardID, since)
	if err != nil {
		t.Fatalf("Failed to get execution metrics: %v", err)
	}

	// Verify metrics
	if metrics.TotalExecutions != 4 {
		t.Errorf("Expected 4 total executions, got %d", metrics.TotalExecutions)
	}

	if metrics.SuccessCount != 3 {
		t.Errorf("Expected 3 successful executions, got %d", metrics.SuccessCount)
	}

	if metrics.FailureCount != 1 {
		t.Errorf("Expected 1 failed execution, got %d", metrics.FailureCount)
	}

	expectedSuccessRate := 75.0 // 3/4 * 100
	if metrics.SuccessRate != expectedSuccessRate {
		t.Errorf("Expected success rate %.1f%%, got %.1f%%", expectedSuccessRate, metrics.SuccessRate)
	}

	expectedAvgDuration := int64(1625) // (1000+2000+500+3000)/4
	if metrics.AverageDuration != expectedAvgDuration {
		t.Errorf("Expected average duration %d ms, got %d ms", expectedAvgDuration, metrics.AverageDuration)
	}

	// Verify shell usage
	if metrics.ShellUsage["bash"] != 2 {
		t.Errorf("Expected 2 bash executions, got %d", metrics.ShellUsage["bash"])
	}
	if metrics.ShellUsage["powershell"] != 1 {
		t.Errorf("Expected 1 powershell execution, got %d", metrics.ShellUsage["powershell"])
	}
	if metrics.ShellUsage["python"] != 1 {
		t.Errorf("Expected 1 python execution, got %d", metrics.ShellUsage["python"])
	}
}

func TestCreateAuditRecord(t *testing.T) {
	stewardID := "test-steward"
	resourceID := "test-script"

	config := &ScriptConfig{
		Content:       "echo 'test'",
		Shell:         ShellBash,
		Timeout:       30 * time.Second,
		SigningPolicy: SigningPolicyNone,
		Description:   "Test script",
		Environment:   map[string]string{"TEST": "value"},
	}

	result := &ExecutionResult{
		ExitCode:  0,
		Stdout:    "test\n",
		Stderr:    "",
		Duration:  time.Duration(2500) * time.Millisecond,
		StartTime: time.Now().Add(-5 * time.Second),
		EndTime:   time.Now().Add(-2500 * time.Millisecond),
		PID:       12345,
	}

	record := CreateAuditRecord(stewardID, resourceID, config, result, nil)

	if record.StewardID != stewardID {
		t.Errorf("Expected steward ID %s, got %s", stewardID, record.StewardID)
	}

	if record.ResourceID != resourceID {
		t.Errorf("Expected resource ID %s, got %s", resourceID, record.ResourceID)
	}

	if record.Status != StatusCompleted {
		t.Errorf("Expected status %s, got %s", StatusCompleted, record.Status)
	}

	if record.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", record.ExitCode)
	}

	if record.Duration != 2500 {
		t.Errorf("Expected duration 2500ms, got %d ms", record.Duration)
	}

	if record.ScriptConfig.Shell != ShellBash {
		t.Errorf("Expected shell bash, got %s", record.ScriptConfig.Shell)
	}

	if record.ScriptConfig.ContentLength != len(config.Content) {
		t.Errorf("Expected content length %d, got %d", len(config.Content), record.ScriptConfig.ContentLength)
	}

	if len(record.ScriptConfig.Environment) != 1 {
		t.Errorf("Expected 1 environment variable, got %d", len(record.ScriptConfig.Environment))
	}
}

func TestCreateAuditRecord_WithError(t *testing.T) {
	stewardID := "test-steward"
	resourceID := "test-script"

	config := &ScriptConfig{
		Content: "exit 1",
		Shell:   ShellBash,
		Timeout: 30 * time.Second,
	}

	testError := fmt.Errorf("script execution failed")
	record := CreateAuditRecord(stewardID, resourceID, config, nil, testError)

	if record.Status != StatusFailed {
		t.Errorf("Expected status %s, got %s", StatusFailed, record.Status)
	}

	if record.ErrorMessage != testError.Error() {
		t.Errorf("Expected error message %s, got %s", testError.Error(), record.ErrorMessage)
	}
}

func TestAuditLogger_Pagination(t *testing.T) {
	logger := NewAuditLogger(100)
	ctx := context.Background()
	stewardID := "test-steward"

	// Add 10 test records
	for i := 0; i < 10; i++ {
		record := &AuditRecord{
			StewardID:     stewardID,
			ResourceID:    fmt.Sprintf("script-%d", i),
			ExecutionTime: time.Now().Add(time.Duration(i) * time.Minute),
			Status:        StatusCompleted,
		}

		err := logger.LogExecution(ctx, record)
		if err != nil {
			t.Fatalf("Failed to log execution %d: %v", i, err)
		}
	}

	// Test limit
	query := &AuditQuery{
		StewardID: stewardID,
		Limit:     5,
	}

	results, err := logger.QueryExecutions(query)
	if err != nil {
		t.Fatalf("Failed to query executions: %v", err)
	}

	if len(results) != 5 {
		t.Errorf("Expected 5 results with limit, got %d", len(results))
	}

	// Test offset
	query = &AuditQuery{
		StewardID: stewardID,
		Offset:    3,
		Limit:     3,
	}

	results, err = logger.QueryExecutions(query)
	if err != nil {
		t.Fatalf("Failed to query executions: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 results with offset and limit, got %d", len(results))
	}
}
