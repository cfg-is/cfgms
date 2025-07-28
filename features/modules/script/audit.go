package script

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// AuditLogger handles comprehensive audit logging for script executions
type AuditLogger struct {
	mu sync.RWMutex
	// executionHistory stores historical execution records by steward ID
	executionHistory map[string][]*AuditRecord
	// maxHistorySize limits the number of records per steward
	maxHistorySize int
}

// AuditRecord represents a complete audit trail for a script execution
type AuditRecord struct {
	// Execution metadata
	ID            string    `json:"id"`
	StewardID     string    `json:"steward_id"`
	ResourceID    string    `json:"resource_id"`
	ExecutionTime time.Time `json:"execution_time"`
	Duration      int64     `json:"duration_ms"`
	
	// Script details
	ScriptConfig  ScriptAuditInfo `json:"script_config"`
	
	// Execution results
	Status        ExecutionStatus `json:"status"`
	ExitCode      int             `json:"exit_code"`
	Stdout        string          `json:"stdout,omitempty"`
	Stderr        string          `json:"stderr,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`
	
	// Performance metrics
	Metrics       ExecutionMetrics `json:"metrics"`
	
	// Security and compliance
	SignatureValidated bool   `json:"signature_validated"`
	UserID             string `json:"user_id,omitempty"`
	TenantID           string `json:"tenant_id,omitempty"`
	
	// Context information
	CorrelationID string            `json:"correlation_id,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
}

// ScriptAuditInfo contains sanitized script configuration for audit purposes
type ScriptAuditInfo struct {
	Shell         ShellType         `json:"shell"`
	Timeout       int64             `json:"timeout_ms"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	SigningPolicy SigningPolicy     `json:"signing_policy"`
	Description   string            `json:"description,omitempty"`
	// Note: Content is not logged for security reasons - only hash
	ContentHash   string            `json:"content_hash"`
	ContentLength int               `json:"content_length"`
}

// ExecutionMetrics contains performance and resource usage metrics
type ExecutionMetrics struct {
	StartTime     time.Time `json:"start_time"`
	EndTime       time.Time `json:"end_time"`
	Duration      int64     `json:"duration_ms"`
	MemoryUsage   int64     `json:"memory_usage_bytes,omitempty"`
	CPUTime       int64     `json:"cpu_time_ms,omitempty"`
	ProcessID     int       `json:"process_id,omitempty"`
	RetryCount    int       `json:"retry_count"`
	NetworkCalls  int       `json:"network_calls,omitempty"`
}

// AuditQuery represents query parameters for audit log retrieval
type AuditQuery struct {
	StewardID     string            `json:"steward_id,omitempty"`
	ResourceID    string            `json:"resource_id,omitempty"`
	Status        ExecutionStatus   `json:"status,omitempty"`
	StartTime     *time.Time        `json:"start_time,omitempty"`
	EndTime       *time.Time        `json:"end_time,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
	TenantID      string            `json:"tenant_id,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	Limit         int               `json:"limit,omitempty"`
	Offset        int               `json:"offset,omitempty"`
}

// NewAuditLogger creates a new audit logger with the specified configuration
func NewAuditLogger(maxHistorySize int) *AuditLogger {
	if maxHistorySize <= 0 {
		maxHistorySize = 1000 // Default to 1000 records per steward
	}
	
	return &AuditLogger{
		executionHistory: make(map[string][]*AuditRecord),
		maxHistorySize:   maxHistorySize,
	}
}

// LogExecution records a script execution in the audit trail
func (al *AuditLogger) LogExecution(ctx context.Context, record *AuditRecord) error {
	if record == nil {
		return fmt.Errorf("audit record cannot be nil")
	}
	
	// Generate unique ID if not provided
	if record.ID == "" {
		record.ID = generateExecutionID(record.StewardID, record.ResourceID, record.ExecutionTime)
	}
	
	// Extract context information
	if correlationID, ok := ctx.Value("correlation_id").(string); ok {
		record.CorrelationID = correlationID
	}
	if userID, ok := ctx.Value("user_id").(string); ok {
		record.UserID = userID
	}
	if tenantID, ok := ctx.Value("tenant_id").(string); ok {
		record.TenantID = tenantID
	}
	
	al.mu.Lock()
	defer al.mu.Unlock()
	
	// Initialize history for steward if not exists
	if _, exists := al.executionHistory[record.StewardID]; !exists {
		al.executionHistory[record.StewardID] = make([]*AuditRecord, 0, al.maxHistorySize)
	}
	
	// Add the record
	al.executionHistory[record.StewardID] = append(al.executionHistory[record.StewardID], record)
	
	// Trim history if it exceeds max size
	if len(al.executionHistory[record.StewardID]) > al.maxHistorySize {
		// Remove oldest records
		al.executionHistory[record.StewardID] = al.executionHistory[record.StewardID][1:]
	}
	
	return nil
}

// QueryExecutions retrieves audit records based on query parameters
func (al *AuditLogger) QueryExecutions(query *AuditQuery) ([]*AuditRecord, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	var results []*AuditRecord
	
	// If steward ID is specified, search only that steward's history
	if query.StewardID != "" {
		if history, exists := al.executionHistory[query.StewardID]; exists {
			results = al.filterRecords(history, query)
		}
	} else {
		// Search all stewards
		for _, history := range al.executionHistory {
			filtered := al.filterRecords(history, query)
			results = append(results, filtered...)
		}
	}
	
	// Apply pagination
	if query.Offset > 0 && query.Offset < len(results) {
		results = results[query.Offset:]
	}
	if query.Limit > 0 && query.Limit < len(results) {
		results = results[:query.Limit]
	}
	
	return results, nil
}

// GetExecutionHistory returns the execution history for a specific steward
func (al *AuditLogger) GetExecutionHistory(stewardID string, limit int) ([]*AuditRecord, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	history, exists := al.executionHistory[stewardID]
	if !exists {
		return []*AuditRecord{}, nil
	}
	
	// Return most recent records first
	result := make([]*AuditRecord, len(history))
	for i, record := range history {
		result[len(history)-1-i] = record
	}
	
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	
	return result, nil
}

// GetExecutionMetrics returns aggregated metrics for a steward
func (al *AuditLogger) GetExecutionMetrics(stewardID string, since time.Time) (*AggregatedMetrics, error) {
	al.mu.RLock()
	defer al.mu.RUnlock()
	
	history, exists := al.executionHistory[stewardID]
	if !exists {
		return &AggregatedMetrics{}, nil
	}
	
	metrics := &AggregatedMetrics{
		StewardID: stewardID,
		Since:     since,
		Until:     time.Now(),
	}
	
	var totalDuration int64
	var successCount, failureCount int
	
	for _, record := range history {
		if record.ExecutionTime.Before(since) {
			continue
		}
		
		metrics.TotalExecutions++
		totalDuration += record.Duration
		
		if record.Status == StatusCompleted {
			successCount++
		} else if record.Status == StatusFailed {
			failureCount++
		}
		
		// Track shell usage
		if metrics.ShellUsage == nil {
			metrics.ShellUsage = make(map[string]int)
		}
		metrics.ShellUsage[string(record.ScriptConfig.Shell)]++
	}
	
	metrics.SuccessCount = successCount
	metrics.FailureCount = failureCount
	
	if metrics.TotalExecutions > 0 {
		metrics.AverageDuration = totalDuration / int64(metrics.TotalExecutions)
		metrics.SuccessRate = float64(successCount) / float64(metrics.TotalExecutions) * 100
	}
	
	return metrics, nil
}

// filterRecords applies query filters to a set of audit records
func (al *AuditLogger) filterRecords(records []*AuditRecord, query *AuditQuery) []*AuditRecord {
	var filtered []*AuditRecord
	
	for _, record := range records {
		if query.ResourceID != "" && record.ResourceID != query.ResourceID {
			continue
		}
		if query.Status != "" && record.Status != query.Status {
			continue
		}
		if query.StartTime != nil && record.ExecutionTime.Before(*query.StartTime) {
			continue
		}
		if query.EndTime != nil && record.ExecutionTime.After(*query.EndTime) {
			continue
		}
		if query.UserID != "" && record.UserID != query.UserID {
			continue
		}
		if query.TenantID != "" && record.TenantID != query.TenantID {
			continue
		}
		
		// Check tags filter
		if len(query.Tags) > 0 {
			tagMatch := true
			for key, value := range query.Tags {
				if record.Tags[key] != value {
					tagMatch = false
					break
				}
			}
			if !tagMatch {
				continue
			}
		}
		
		filtered = append(filtered, record)
	}
	
	return filtered
}

// AggregatedMetrics represents performance metrics for a steward
type AggregatedMetrics struct {
	StewardID        string            `json:"steward_id"`
	Since            time.Time         `json:"since"`
	Until            time.Time         `json:"until"`
	TotalExecutions  int               `json:"total_executions"`
	SuccessCount     int               `json:"success_count"`
	FailureCount     int               `json:"failure_count"`
	SuccessRate      float64           `json:"success_rate_percent"`
	AverageDuration  int64             `json:"average_duration_ms"`
	ShellUsage       map[string]int    `json:"shell_usage"`
}

// generateExecutionID creates a unique identifier for a script execution
func generateExecutionID(stewardID, resourceID string, executionTime time.Time) string {
	return fmt.Sprintf("%s-%s-%d", stewardID, resourceID, executionTime.Unix())
}

// CreateAuditRecord creates an audit record from execution state and result
func CreateAuditRecord(stewardID string, resourceID string, config *ScriptConfig, result *ExecutionResult, err error) *AuditRecord {
	record := &AuditRecord{
		StewardID:          stewardID,
		ResourceID:         resourceID,
		ExecutionTime:      time.Now(),
		ScriptConfig:       createScriptAuditInfo(config),
		SignatureValidated: config.Signature != nil,
	}
	
	if result != nil {
		record.Status = StatusCompleted
		record.ExitCode = result.ExitCode
		record.Stdout = result.Stdout
		record.Stderr = result.Stderr
		record.Duration = result.Duration.Milliseconds()
		record.Metrics = ExecutionMetrics{
			StartTime: result.StartTime,
			EndTime:   result.EndTime,
			Duration:  result.Duration.Milliseconds(),
			ProcessID: result.PID,
		}
	}
	
	if err != nil {
		record.Status = StatusFailed
		record.ErrorMessage = err.Error()
	}
	
	return record
}

// createScriptAuditInfo creates sanitized script information for audit logging
func createScriptAuditInfo(config *ScriptConfig) ScriptAuditInfo {
	// Create a sanitized copy without sensitive content
	return ScriptAuditInfo{
		Shell:         config.Shell,
		Timeout:       config.Timeout.Milliseconds(),
		WorkingDir:    config.WorkingDir,
		Environment:   config.Environment,
		SigningPolicy: config.SigningPolicy,
		Description:   config.Description,
		ContentHash:   calculateContentHash(config.Content),
		ContentLength: len(config.Content),
	}
}

// calculateContentHash creates a hash of script content for audit purposes
func calculateContentHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("sha256:%x", hash)
}