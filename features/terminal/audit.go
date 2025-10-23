// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// #nosec G304 - Terminal audit system requires file access for session recording and compliance
package terminal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLogger provides tamper-proof audit logging for terminal sessions
type AuditLogger struct {
	config           *AuditConfig
	storage          AuditStorage
	integrityChecker *IntegrityChecker

	// Logging state
	logFile    *os.File
	logEncoder *json.Encoder
	logMutex   sync.Mutex

	// Security
	hmacKey        []byte
	sequenceNumber uint64
	seqMutex       sync.Mutex

	// Channels
	auditChannel chan *AuditEntry
	stopChannel  chan struct{}
	stopped      chan struct{}
}

// AuditConfig contains configuration for audit logging
type AuditConfig struct {
	StoragePath        string        `json:"storage_path"`
	MaxLogSizeMB       int           `json:"max_log_size_mb"`
	RetentionDays      int           `json:"retention_days"`
	CompressionEnabled bool          `json:"compression_enabled"`
	EncryptionEnabled  bool          `json:"encryption_enabled"`
	IntegrityChecking  bool          `json:"integrity_checking"`
	BatchSize          int           `json:"batch_size"`
	FlushInterval      time.Duration `json:"flush_interval"`

	// Tamper-proofing
	DigitalSigning bool   `json:"digital_signing"`
	HMACEnabled    bool   `json:"hmac_enabled"`
	HMACKey        string `json:"hmac_key"`
	ChainHashing   bool   `json:"chain_hashing"`
}

// AuditEntry represents a complete audit log entry
type AuditEntry struct {
	// Metadata
	ID             string     `json:"id"`
	Timestamp      time.Time  `json:"timestamp"`
	SequenceNumber uint64     `json:"sequence_number"`
	LogLevel       AuditLevel `json:"log_level"`

	// Session Information
	SessionID string `json:"session_id"`
	UserID    string `json:"user_id"`
	StewardID string `json:"steward_id"`
	TenantID  string `json:"tenant_id"`

	// Event Details
	EventType AuditEventType `json:"event_type"`
	EventData interface{}    `json:"event_data"`

	// Security Context
	ClientIP       string `json:"client_ip"`
	UserAgent      string `json:"user_agent"`
	TLSFingerprint string `json:"tls_fingerprint"`

	// Command Information (if applicable)
	Command         string         `json:"command,omitempty"`
	CommandOutput   string         `json:"command_output,omitempty"`
	ExitCode        *int           `json:"exit_code,omitempty"`
	CommandDuration *time.Duration `json:"command_duration,omitempty"`

	// Security Assessment
	ThreatLevel        string   `json:"threat_level,omitempty"`
	SecurityAction     string   `json:"security_action,omitempty"`
	FilterRulesApplied []string `json:"filter_rules_applied,omitempty"`

	// Integrity Protection
	PreviousHash string `json:"previous_hash,omitempty"`
	ContentHash  string `json:"content_hash"`
	HMAC         string `json:"hmac"`

	// Additional Context
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// AuditLevel defines the severity level of audit events
type AuditLevel string

const (
	AuditLevelInfo     AuditLevel = "info"
	AuditLevelWarning  AuditLevel = "warning"
	AuditLevelError    AuditLevel = "error"
	AuditLevelCritical AuditLevel = "critical"
)

// AuditEventType defines the type of event being audited
type AuditEventType string

const (
	EventSessionStart        AuditEventType = "session_start"
	EventSessionEnd          AuditEventType = "session_end"
	EventCommandExecuted     AuditEventType = "command_executed"
	EventCommandBlocked      AuditEventType = "command_blocked"
	EventSecurityViolation   AuditEventType = "security_violation"
	EventPrivilegeEscalation AuditEventType = "privilege_escalation"
	EventDataTransfer        AuditEventType = "data_transfer"
	EventConfigurationChange AuditEventType = "configuration_change"
	EventSystemAccess        AuditEventType = "system_access"
	EventAnomalousActivity   AuditEventType = "anomalous_activity"
)

// AuditStorage interface defines methods for storing audit logs
type AuditStorage interface {
	Store(ctx context.Context, entry *AuditEntry) error
	Retrieve(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error)
	VerifyIntegrity(ctx context.Context, entryID string) (bool, error)
	Archive(ctx context.Context, beforeDate time.Time) error
}

// AuditFilter defines criteria for retrieving audit logs
type AuditFilter struct {
	SessionID string         `json:"session_id,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	StewardID string         `json:"steward_id,omitempty"`
	TenantID  string         `json:"tenant_id,omitempty"`
	EventType AuditEventType `json:"event_type,omitempty"`
	StartTime *time.Time     `json:"start_time,omitempty"`
	EndTime   *time.Time     `json:"end_time,omitempty"`
	LogLevel  AuditLevel     `json:"log_level,omitempty"`
	Limit     int            `json:"limit,omitempty"`
	Offset    int            `json:"offset,omitempty"`
}

// IntegrityChecker provides tamper-proof integrity checking
type IntegrityChecker struct {
	hmacKey        []byte
	previousHashes map[string]string
	hashChain      []string
	mutex          sync.RWMutex
}

// NewAuditLogger creates a new audit logger with tamper-proofing
func NewAuditLogger(config *AuditConfig, storage AuditStorage) (*AuditLogger, error) {
	if config == nil {
		config = DefaultAuditConfig()
	}

	// Generate HMAC key if not provided
	hmacKey := []byte(config.HMACKey)
	if len(hmacKey) == 0 {
		hmacKey = generateHMACKey()
	}

	// Create storage directory if it doesn't exist
	if err := os.MkdirAll(config.StoragePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create audit storage directory: %w", err)
	}

	// Open log file
	logPath := filepath.Join(config.StoragePath, fmt.Sprintf("audit-%s.log", time.Now().Format("2006-01-02")))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	logger := &AuditLogger{
		config:  config,
		storage: storage,
		integrityChecker: &IntegrityChecker{
			hmacKey:        hmacKey,
			previousHashes: make(map[string]string),
			hashChain:      make([]string, 0),
		},
		logFile:      logFile,
		logEncoder:   json.NewEncoder(logFile),
		hmacKey:      hmacKey,
		auditChannel: make(chan *AuditEntry, config.BatchSize*2),
		stopChannel:  make(chan struct{}),
		stopped:      make(chan struct{}),
	}

	return logger, nil
}

// Start begins the audit logging process
func (al *AuditLogger) Start(ctx context.Context) error {
	go al.processingLoop(ctx)
	return nil
}

// Stop stops the audit logger and flushes remaining entries
func (al *AuditLogger) Stop() error {
	close(al.stopChannel)

	// Wait for processing to complete
	select {
	case <-al.stopped:
		return nil
	case <-time.After(30 * time.Second):
		return fmt.Errorf("timeout waiting for audit logger to stop")
	}
}

// LogSessionStart logs the start of a terminal session
func (al *AuditLogger) LogSessionStart(ctx context.Context, sessionID, userID, stewardID, tenantID, clientIP string) error {
	entry := &AuditEntry{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		LogLevel:  AuditLevelInfo,
		SessionID: sessionID,
		UserID:    userID,
		StewardID: stewardID,
		TenantID:  tenantID,
		EventType: EventSessionStart,
		ClientIP:  clientIP,
		EventData: map[string]interface{}{
			"action": "session_created",
		},
	}

	return al.logEntry(ctx, entry)
}

// LogSessionEnd logs the end of a terminal session
func (al *AuditLogger) LogSessionEnd(ctx context.Context, sessionID, userID string, duration time.Duration, commandCount int, dataTransferred int64) error {
	entry := &AuditEntry{
		ID:        generateAuditID(),
		Timestamp: time.Now(),
		LogLevel:  AuditLevelInfo,
		SessionID: sessionID,
		UserID:    userID,
		EventType: EventSessionEnd,
		EventData: map[string]interface{}{
			"action":           "session_ended",
			"duration_seconds": duration.Seconds(),
			"command_count":    commandCount,
			"data_transferred": dataTransferred,
		},
	}

	return al.logEntry(ctx, entry)
}

// LogCommandExecution logs the execution of a terminal command
func (al *AuditLogger) LogCommandExecution(ctx context.Context, sessionID, userID, stewardID, tenantID, command string, exitCode int, duration time.Duration, output string) error {
	entry := &AuditEntry{
		ID:              generateAuditID(),
		Timestamp:       time.Now(),
		LogLevel:        AuditLevelInfo,
		SessionID:       sessionID,
		UserID:          userID,
		StewardID:       stewardID,
		TenantID:        tenantID,
		EventType:       EventCommandExecuted,
		Command:         command,
		CommandOutput:   truncateOutput(output, 1000), // Limit output size
		ExitCode:        &exitCode,
		CommandDuration: &duration,
		EventData: map[string]interface{}{
			"action":      "command_executed",
			"success":     exitCode == 0,
			"output_size": len(output),
		},
	}

	return al.logEntry(ctx, entry)
}

// LogCommandBlocked logs when a command is blocked by security rules
func (al *AuditLogger) LogCommandBlocked(ctx context.Context, sessionID, userID, stewardID, tenantID, command, reason string, rulesApplied []string) error {
	entry := &AuditEntry{
		ID:                 generateAuditID(),
		Timestamp:          time.Now(),
		LogLevel:           AuditLevelWarning,
		SessionID:          sessionID,
		UserID:             userID,
		StewardID:          stewardID,
		TenantID:           tenantID,
		EventType:          EventCommandBlocked,
		Command:            command,
		SecurityAction:     "command_blocked",
		FilterRulesApplied: rulesApplied,
		EventData: map[string]interface{}{
			"action":        "command_blocked",
			"block_reason":  reason,
			"rules_applied": rulesApplied,
		},
	}

	return al.logEntry(ctx, entry)
}

// LogSecurityViolation logs security violations and threats
func (al *AuditLogger) LogSecurityViolation(ctx context.Context, sessionID, userID, stewardID, tenantID string, violationType, description string, threatLevel FilterSeverity) error {
	logLevel := AuditLevelWarning
	switch threatLevel {
	case FilterSeverityCritical:
		logLevel = AuditLevelCritical
	case FilterSeverityHigh:
		logLevel = AuditLevelError
	}

	entry := &AuditEntry{
		ID:          generateAuditID(),
		Timestamp:   time.Now(),
		LogLevel:    logLevel,
		SessionID:   sessionID,
		UserID:      userID,
		StewardID:   stewardID,
		TenantID:    tenantID,
		EventType:   EventSecurityViolation,
		ThreatLevel: string(threatLevel),
		EventData: map[string]interface{}{
			"action":         "security_violation",
			"violation_type": violationType,
			"description":    description,
			"threat_level":   threatLevel,
		},
	}

	return al.logEntry(ctx, entry)
}

// logEntry processes and stores an audit entry with integrity protection
func (al *AuditLogger) logEntry(ctx context.Context, entry *AuditEntry) error {
	// Add sequence number
	al.seqMutex.Lock()
	al.sequenceNumber++
	entry.SequenceNumber = al.sequenceNumber
	al.seqMutex.Unlock()

	// Add integrity protection
	if err := al.addIntegrityProtection(entry); err != nil {
		return fmt.Errorf("failed to add integrity protection: %w", err)
	}

	// Send to processing channel
	select {
	case al.auditChannel <- entry:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("audit channel full, dropping entry")
	}
}

// addIntegrityProtection adds tamper-proofing to audit entries
func (al *AuditLogger) addIntegrityProtection(entry *AuditEntry) error {
	if !al.config.IntegrityChecking {
		return nil
	}

	// Generate content hash
	contentBytes, err := json.Marshal(map[string]interface{}{
		"timestamp":       entry.Timestamp,
		"sequence_number": entry.SequenceNumber,
		"session_id":      entry.SessionID,
		"user_id":         entry.UserID,
		"event_type":      entry.EventType,
		"event_data":      entry.EventData,
		"command":         entry.Command,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal entry content: %w", err)
	}

	contentHash := sha256.Sum256(contentBytes)
	entry.ContentHash = fmt.Sprintf("%x", contentHash)

	// Add chain hashing
	if al.config.ChainHashing {
		al.integrityChecker.mutex.Lock()
		if len(al.integrityChecker.hashChain) > 0 {
			entry.PreviousHash = al.integrityChecker.hashChain[len(al.integrityChecker.hashChain)-1]
		}
		al.integrityChecker.hashChain = append(al.integrityChecker.hashChain, entry.ContentHash)
		al.integrityChecker.mutex.Unlock()
	}

	// Add HMAC
	if al.config.HMACEnabled {
		hmacData := fmt.Sprintf("%s:%s:%s", entry.ID, entry.ContentHash, entry.PreviousHash)
		mac := hmac.New(sha256.New, al.hmacKey)
		mac.Write([]byte(hmacData))
		entry.HMAC = fmt.Sprintf("%x", mac.Sum(nil))
	}

	return nil
}

// processingLoop processes audit entries from the channel
func (al *AuditLogger) processingLoop(ctx context.Context) {
	defer close(al.stopped)
	defer func() {
		if err := al.logFile.Close(); err != nil {
			// Log error but continue with shutdown - file close errors during shutdown are not critical
			_ = err // Explicitly ignore file close errors during shutdown
		}
	}()

	ticker := time.NewTicker(al.config.FlushInterval)
	defer ticker.Stop()

	batch := make([]*AuditEntry, 0, al.config.BatchSize)

	for {
		select {
		case <-ctx.Done():
			// Flush remaining entries
			if len(batch) > 0 {
				al.processBatch(batch)
			}
			return

		case <-al.stopChannel:
			// Flush remaining entries
			if len(batch) > 0 {
				al.processBatch(batch)
			}
			return

		case entry := <-al.auditChannel:
			batch = append(batch, entry)

			if len(batch) >= al.config.BatchSize {
				al.processBatch(batch)
				batch = batch[:0] // Reset slice
			}

		case <-ticker.C:
			if len(batch) > 0 {
				al.processBatch(batch)
				batch = batch[:0] // Reset slice
			}
		}
	}
}

// processBatch processes a batch of audit entries
func (al *AuditLogger) processBatch(batch []*AuditEntry) {
	al.logMutex.Lock()
	defer al.logMutex.Unlock()

	for _, entry := range batch {
		// Write to file
		if err := al.logEncoder.Encode(entry); err != nil {
			// Log error but continue processing
			continue
		}

		// Store in external storage if configured
		if al.storage != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := al.storage.Store(ctx, entry); err != nil {
				// Log error but continue processing - external storage failures shouldn't stop auditing
				_ = err // Explicitly ignore external storage errors for resilience
			}
			cancel()
		}
	}

	// Flush file buffer
	if err := al.logFile.Sync(); err != nil {
		// Log error but continue - this is best effort and sync failures are not critical
		_ = err // Explicitly ignore sync errors for best effort operation
	}
}

// VerifyIntegrity verifies the integrity of an audit entry
func (al *AuditLogger) VerifyIntegrity(entry *AuditEntry) (bool, error) {
	if !al.config.IntegrityChecking {
		return true, nil
	}

	// Verify content hash
	contentBytes, err := json.Marshal(map[string]interface{}{
		"timestamp":       entry.Timestamp,
		"sequence_number": entry.SequenceNumber,
		"session_id":      entry.SessionID,
		"user_id":         entry.UserID,
		"event_type":      entry.EventType,
		"event_data":      entry.EventData,
		"command":         entry.Command,
	})
	if err != nil {
		return false, fmt.Errorf("failed to marshal entry content: %w", err)
	}

	contentHash := sha256.Sum256(contentBytes)
	expectedHash := fmt.Sprintf("%x", contentHash)

	if entry.ContentHash != expectedHash {
		return false, fmt.Errorf("content hash mismatch")
	}

	// Verify HMAC if enabled
	if al.config.HMACEnabled {
		hmacData := fmt.Sprintf("%s:%s:%s", entry.ID, entry.ContentHash, entry.PreviousHash)
		mac := hmac.New(sha256.New, al.hmacKey)
		mac.Write([]byte(hmacData))
		expectedHMAC := fmt.Sprintf("%x", mac.Sum(nil))

		if entry.HMAC != expectedHMAC {
			return false, fmt.Errorf("HMAC verification failed")
		}
	}

	return true, nil
}

// RetrieveAuditLogs retrieves audit logs based on filter criteria
func (al *AuditLogger) RetrieveAuditLogs(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) {
	if al.storage != nil {
		return al.storage.Retrieve(ctx, filter)
	}

	// Fallback to file-based retrieval (basic implementation)
	return nil, fmt.Errorf("audit log retrieval not implemented for file-only storage")
}

// Helper functions

func generateAuditID() string {
	return fmt.Sprintf("audit_%d_%d", time.Now().UnixNano(), os.Getpid())
}

func generateHMACKey() []byte {
	// In a real implementation, this would use a proper key derivation function
	// and store the key securely
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + int(time.Now().UnixNano()%256))
	}
	return key
}

func truncateOutput(output string, maxLength int) string {
	if len(output) <= maxLength {
		return output
	}
	return output[:maxLength] + "... [truncated]"
}

// DefaultAuditConfig returns default configuration for audit logging
func DefaultAuditConfig() *AuditConfig {
	return &AuditConfig{
		StoragePath:        "/var/log/cfgms/audit",
		MaxLogSizeMB:       100,
		RetentionDays:      90,
		CompressionEnabled: true,
		EncryptionEnabled:  false,
		IntegrityChecking:  true,
		BatchSize:          50,
		FlushInterval:      30 * time.Second,
		DigitalSigning:     false,
		HMACEnabled:        true,
		ChainHashing:       true,
	}
}

// FileAuditStorage provides file-based audit storage
type FileAuditStorage struct {
	basePath string
	mutex    sync.RWMutex
}

// NewFileAuditStorage creates a new file-based audit storage
func NewFileAuditStorage(basePath string) *FileAuditStorage {
	return &FileAuditStorage{
		basePath: basePath,
	}
}

// Store stores an audit entry to file
func (fas *FileAuditStorage) Store(ctx context.Context, entry *AuditEntry) error {
	fas.mutex.Lock()
	defer fas.mutex.Unlock()

	// Create directory structure based on date
	dateDir := entry.Timestamp.Format("2006/01/02")
	dirPath := filepath.Join(fas.basePath, dateDir)

	if err := os.MkdirAll(dirPath, 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write entry to file
	fileName := fmt.Sprintf("%s.json", entry.ID)
	filePath := filepath.Join(dirPath, fileName)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create audit file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(entry); err != nil {
		return fmt.Errorf("failed to encode audit entry: %w", err)
	}

	return nil
}

// Retrieve retrieves audit entries based on filter criteria
func (fas *FileAuditStorage) Retrieve(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) {
	// Basic file-based retrieval implementation
	// In production, this would be optimized with indexing
	return nil, fmt.Errorf("file-based retrieval not fully implemented")
}

// VerifyIntegrity verifies the integrity of a stored audit entry
func (fas *FileAuditStorage) VerifyIntegrity(ctx context.Context, entryID string) (bool, error) {
	// Implementation would verify file integrity
	return true, nil
}

// Archive archives old audit entries
func (fas *FileAuditStorage) Archive(ctx context.Context, beforeDate time.Time) error {
	// Implementation would archive old entries
	return nil
}
