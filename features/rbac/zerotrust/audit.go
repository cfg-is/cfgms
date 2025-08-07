package zerotrust

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ZeroTrustAuditLogger provides comprehensive audit logging for zero-trust policy engine
type ZeroTrustAuditLogger struct {
	logChannel       chan *AuditLogEntry
	storage          AuditStorage
	config           *AuditConfig
	started          bool
	stopChannel      chan struct{}
	processingGroup  sync.WaitGroup
	stats           *AuditStats
	mutex           sync.RWMutex
}

// AuditStorage interface for audit log storage
type AuditStorage interface {
	Store(ctx context.Context, entry *AuditLogEntry) error
	Query(ctx context.Context, filter *AuditFilter) ([]*AuditLogEntry, error)
	GetStats() map[string]interface{}
}

// AuditConfig configures audit logging behavior
type AuditConfig struct {
	BufferSize        int           `json:"buffer_size"`
	FlushInterval     time.Duration `json:"flush_interval"`
	RetentionPeriod   time.Duration `json:"retention_period"`
	EncryptionEnabled bool          `json:"encryption_enabled"`
	CompressionLevel  int           `json:"compression_level"`
}

// AuditLogEntry represents a single audit log entry
type AuditLogEntry struct {
	ID                string                    `json:"id"`
	Timestamp         time.Time                 `json:"timestamp"`
	EventType         AuditEventType            `json:"event_type"`
	
	// Request information
	RequestID         string                    `json:"request_id"`
	SessionID         string                    `json:"session_id,omitempty"`
	SubjectID         string                    `json:"subject_id"`
	TenantID          string                    `json:"tenant_id"`
	
	// Policy evaluation details
	PoliciesEvaluated []string                  `json:"policies_evaluated,omitempty"`
	EvaluationResult  string                    `json:"evaluation_result"`
	ProcessingTime    time.Duration             `json:"processing_time"`
	
	// Compliance information
	ComplianceFrameworks []string               `json:"compliance_frameworks,omitempty"`
	ComplianceStatus     string                 `json:"compliance_status,omitempty"`
	Violations          []string                `json:"violations,omitempty"`
	
	// Context and metadata
	Environment       map[string]interface{}    `json:"environment"`
	Details           map[string]interface{}    `json:"details"`
	
	// Security tracking
	RiskLevel         string                    `json:"risk_level,omitempty"`
	ThreatIndicators  []string                  `json:"threat_indicators,omitempty"`
	
	// System information
	SourceSystem      string                    `json:"source_system"`
	Version           string                    `json:"version"`
}

// AuditFilter for querying audit logs
type AuditFilter struct {
	StartTime         time.Time                 `json:"start_time"`
	EndTime           time.Time                 `json:"end_time"`
	EventTypes        []AuditEventType          `json:"event_types,omitempty"`
	SubjectIDs        []string                  `json:"subject_ids,omitempty"`
	TenantIDs         []string                  `json:"tenant_ids,omitempty"`
	ComplianceFrameworks []string               `json:"compliance_frameworks,omitempty"`
	Limit             int                       `json:"limit"`
	Offset            int                       `json:"offset"`
}

// AuditStats tracks audit logging statistics
type AuditStats struct {
	TotalEntries      int64                     `json:"total_entries"`
	EntriesByType     map[AuditEventType]int64  `json:"entries_by_type"`
	ProcessingErrors  int64                     `json:"processing_errors"`
	StorageErrors     int64                     `json:"storage_errors"`
	AverageProcessingTime time.Duration         `json:"average_processing_time"`
	LastEntry         time.Time                 `json:"last_entry"`
	BufferUtilization float64                   `json:"buffer_utilization"`
	
	mutex            sync.RWMutex
}

// NewZeroTrustAuditLogger creates a new audit logger
func NewZeroTrustAuditLogger() *ZeroTrustAuditLogger {
	config := &AuditConfig{
		BufferSize:        1000,
		FlushInterval:     5 * time.Second,
		RetentionPeriod:   365 * 24 * time.Hour, // 1 year
		EncryptionEnabled: true,
		CompressionLevel:  1,
	}
	
	return &ZeroTrustAuditLogger{
		logChannel:      make(chan *AuditLogEntry, config.BufferSize),
		storage:         NewFileAuditStorage(), // Default file-based storage
		config:          config,
		stopChannel:     make(chan struct{}),
		stats:          NewAuditStats(),
	}
}

// Start initializes and starts the audit logger
func (z *ZeroTrustAuditLogger) Start(ctx context.Context) error {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	
	if z.started {
		return fmt.Errorf("audit logger is already started")
	}
	
	// Start background processing
	z.processingGroup.Add(1)
	go z.processingLoop(ctx)
	
	z.started = true
	return nil
}

// Stop gracefully stops the audit logger
func (z *ZeroTrustAuditLogger) Stop() error {
	z.mutex.Lock()
	defer z.mutex.Unlock()
	
	if !z.started {
		return fmt.Errorf("audit logger is not started")
	}
	
	// Signal shutdown
	close(z.stopChannel)
	
	// Wait for processing to complete
	z.processingGroup.Wait()
	
	z.started = false
	return nil
}

// LogAccessEvaluation logs a zero-trust access evaluation
func (z *ZeroTrustAuditLogger) LogAccessEvaluation(ctx context.Context, request *ZeroTrustAccessRequest, response *ZeroTrustAccessResponse, processingTime time.Duration) error {
	entry := &AuditLogEntry{
		ID:               fmt.Sprintf("audit-%d", time.Now().UnixNano()),
		Timestamp:        time.Now(),
		EventType:        AuditEventPolicyEvaluation,
		RequestID:        request.RequestID,
		SessionID:        request.SessionID,
		PoliciesEvaluated: response.PoliciesEvaluated,
		ProcessingTime:   processingTime,
		SourceSystem:     "zero-trust-policy-engine",
		Version:          "1.0.0",
	}
	
	// Safely extract SubjectID and TenantID from AccessRequest if present
	if request.AccessRequest != nil {
		entry.SubjectID = request.AccessRequest.SubjectId
		entry.TenantID = request.AccessRequest.TenantId
	}
	
	// Set evaluation result
	if response.Granted {
		entry.EvaluationResult = "granted"
		entry.EventType = AuditEventAccessGranted
	} else {
		entry.EvaluationResult = "denied"
		entry.EventType = AuditEventAccessDenied
	}
	
	// Add compliance information
	if len(response.ComplianceResults) > 0 {
		frameworks := make([]string, len(response.ComplianceResults))
		violations := make([]string, 0)
		
		for i, compResult := range response.ComplianceResults {
			frameworks[i] = string(compResult.Framework)
			violations = append(violations, compResult.ControlsViolated...)
		}
		
		entry.ComplianceFrameworks = frameworks
		entry.ComplianceStatus = string(response.ComplianceStatus)
		entry.Violations = violations
	}
	
	// Add environment context
	entry.Environment = make(map[string]interface{})
	if request.EnvironmentContext != nil {
		entry.Environment["ip_address"] = request.EnvironmentContext.IPAddress
		if request.EnvironmentContext.Location != nil {
			entry.Environment["location"] = map[string]interface{}{
				"country": request.EnvironmentContext.Location.Country,
				"city":    request.EnvironmentContext.Location.City,
			}
		}
	}
	
	// Add security context
	if request.SecurityContext != nil {
		entry.Details = map[string]interface{}{
			"authentication_method": request.SecurityContext.AuthenticationMethod,
			"mfa_verified":         request.SecurityContext.MFAVerified,
			"trust_level":          request.SecurityContext.TrustLevel,
		}
		
		if len(request.SecurityContext.ThreatIndicators) > 0 {
			indicators := make([]string, len(request.SecurityContext.ThreatIndicators))
			for i, indicator := range request.SecurityContext.ThreatIndicators {
				indicators[i] = string(indicator.Type)
			}
			entry.ThreatIndicators = indicators
		}
	}
	
	// Send to processing queue
	select {
	case z.logChannel <- entry:
		return nil
	default:
		return fmt.Errorf("audit log channel full - dropping entry")
	}
}

// LogPolicyViolation logs a policy violation
func (z *ZeroTrustAuditLogger) LogPolicyViolation(ctx context.Context, violation *ComplianceViolation) error {
	entry := &AuditLogEntry{
		ID:                   fmt.Sprintf("audit-violation-%d", time.Now().UnixNano()),
		Timestamp:            time.Now(),
		EventType:            AuditEventViolationDetected,
		ComplianceFrameworks: []string{string(violation.Framework)},
		Violations:          []string{violation.ViolationType},
		SourceSystem:        "zero-trust-policy-engine",
		Version:             "1.0.0",
		Details: map[string]interface{}{
			"violation_id":   violation.ViolationID,
			"control_id":     violation.ControlID,
			"severity":       violation.Severity,
			"description":    violation.Description,
		},
	}
	
	// Send to processing queue
	select {
	case z.logChannel <- entry:
		return nil
	default:
		return fmt.Errorf("audit log channel full - dropping entry")
	}
}

// processingLoop processes audit log entries in the background
func (z *ZeroTrustAuditLogger) processingLoop(ctx context.Context) {
	defer z.processingGroup.Done()
	
	ticker := time.NewTicker(z.config.FlushInterval)
	defer ticker.Stop()
	
	var batch []*AuditLogEntry
	
	for {
		select {
		case <-ctx.Done():
			// Flush remaining entries before shutdown
			if len(batch) > 0 {
				z.processBatch(ctx, batch)
			}
			return
			
		case <-z.stopChannel:
			// Flush remaining entries before shutdown
			if len(batch) > 0 {
				z.processBatch(ctx, batch)
			}
			return
			
		case entry := <-z.logChannel:
			batch = append(batch, entry)
			
			// Process batch when it reaches a certain size
			if len(batch) >= 100 {
				z.processBatch(ctx, batch)
				batch = make([]*AuditLogEntry, 0)
			}
			
		case <-ticker.C:
			// Process batch on timer
			if len(batch) > 0 {
				z.processBatch(ctx, batch)
				batch = make([]*AuditLogEntry, 0)
			}
			
			// Update buffer utilization
			z.updateBufferUtilization()
		}
	}
}

// processBatch processes a batch of audit log entries
func (z *ZeroTrustAuditLogger) processBatch(ctx context.Context, batch []*AuditLogEntry) {
	startTime := time.Now()
	
	for _, entry := range batch {
		if err := z.storage.Store(ctx, entry); err != nil {
			z.stats.mutex.Lock()
			z.stats.StorageErrors++
			z.stats.mutex.Unlock()
			// Log error (would use structured logging in real implementation)
			continue
		}
		
		// Update statistics
		z.stats.mutex.Lock()
		z.stats.TotalEntries++
		z.stats.EntriesByType[entry.EventType]++
		z.stats.LastEntry = entry.Timestamp
		z.stats.mutex.Unlock()
	}
	
	// Update processing time statistics
	processingTime := time.Since(startTime)
	z.stats.mutex.Lock()
	if z.stats.AverageProcessingTime == 0 {
		z.stats.AverageProcessingTime = processingTime
	} else {
		alpha := 0.1
		avgNanos := float64(z.stats.AverageProcessingTime.Nanoseconds())
		newNanos := float64(processingTime.Nanoseconds())
		z.stats.AverageProcessingTime = time.Duration(int64((1-alpha)*avgNanos + alpha*newNanos))
	}
	z.stats.mutex.Unlock()
}

// updateBufferUtilization calculates current buffer utilization
func (z *ZeroTrustAuditLogger) updateBufferUtilization() {
	z.stats.mutex.Lock()
	defer z.stats.mutex.Unlock()
	
	channelLen := len(z.logChannel)
	utilization := float64(channelLen) / float64(z.config.BufferSize)
	z.stats.BufferUtilization = utilization
}

// GetStats returns current audit logger statistics
func (z *ZeroTrustAuditLogger) GetStats() *AuditStats {
	z.stats.mutex.RLock()
	defer z.stats.mutex.RUnlock()
	
	// Return a copy to prevent external modification (without copying mutex)
	entriesByType := make(map[AuditEventType]int64)
	for k, v := range z.stats.EntriesByType {
		entriesByType[k] = v
	}
	
	return &AuditStats{
		TotalEntries:            z.stats.TotalEntries,
		EntriesByType:          entriesByType,
		ProcessingErrors:       z.stats.ProcessingErrors,
		StorageErrors:          z.stats.StorageErrors,
		AverageProcessingTime:  z.stats.AverageProcessingTime,
		LastEntry:              z.stats.LastEntry,
		BufferUtilization:      z.stats.BufferUtilization,
	}
}

// NewAuditStats creates new audit statistics
func NewAuditStats() *AuditStats {
	return &AuditStats{
		EntriesByType: make(map[AuditEventType]int64),
		LastEntry:     time.Now(),
	}
}

// FileAuditStorage provides file-based audit log storage
type FileAuditStorage struct {
	basePath    string
}

// NewFileAuditStorage creates a new file-based audit storage
func NewFileAuditStorage() *FileAuditStorage {
	return &FileAuditStorage{
		basePath: "/var/log/cfgms/audit",
	}
}

// Store stores an audit log entry to file
func (f *FileAuditStorage) Store(ctx context.Context, entry *AuditLogEntry) error {
	// This is a stub implementation
	// In a real implementation, this would:
	// 1. Serialize the entry to JSON
	// 2. Write to appropriate log file (rotating by date/size)
	// 3. Handle encryption if enabled
	// 4. Ensure atomic writes
	
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}
	
	// For now, just validate that we can serialize
	_ = data
	
	return nil
}

// Query queries audit log entries
func (f *FileAuditStorage) Query(ctx context.Context, filter *AuditFilter) ([]*AuditLogEntry, error) {
	// This is a stub implementation
	// In a real implementation, this would:
	// 1. Read from appropriate log files
	// 2. Apply filters
	// 3. Handle pagination
	// 4. Decrypt if necessary
	
	return []*AuditLogEntry{}, nil
}

// GetStats returns storage statistics
func (f *FileAuditStorage) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"storage_type": "file",
		"base_path":   f.basePath,
	}
}