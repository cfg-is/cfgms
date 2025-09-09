package script

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
)

// Module implements the modules.Module interface for script execution
type Module struct {
	mu sync.RWMutex
	// executions tracks ongoing script executions by resource ID
	executions map[string]*ExecutionState
	// auditLogger handles comprehensive audit logging
	auditLogger *AuditLogger
	// stewardID identifies the steward this module belongs to
	stewardID string
}

// ExecutionState tracks the state of a script execution
type ExecutionState struct {
	Config    *ScriptConfig
	Status    ExecutionStatus
	Result    *ExecutionResult
	Error     error
	StartTime int64
}

// New creates a new instance of the Script module
func New() modules.Module {
	return &Module{
		executions:  make(map[string]*ExecutionState),
		auditLogger: NewAuditLogger(1000), // Default 1000 records per steward
		stewardID:   "unknown",            // Will be set by steward when module is loaded
	}
}

// NewModule creates a new script module instance
func NewModule() *Module {
	return &Module{
		executions:  make(map[string]*ExecutionState),
		auditLogger: NewAuditLogger(1000),
		stewardID:   "unknown",
	}
}

// NewModuleWithConfig creates a new script module with specific configuration
func NewModuleWithConfig(stewardID string, maxAuditRecords int) *Module {
	return &Module{
		executions:  make(map[string]*ExecutionState),
		auditLogger: NewAuditLogger(maxAuditRecords),
		stewardID:   stewardID,
	}
}

// Get returns the current state of a script resource
func (m *Module) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	execution, exists := m.executions[resourceID]
	if !exists {
		// Return empty configuration for non-existent resources
		return &ScriptConfig{
			SigningPolicy: SigningPolicyNone,
		}, nil
	}

	// Return a copy of the configuration to prevent external modification
	config := *execution.Config
	return &config, nil
}

// Set executes a script with the given configuration
func (m *Module) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	scriptConfig, ok := config.(*ScriptConfig)
	if !ok {
		return fmt.Errorf("%w: expected ScriptConfig, got %T", modules.ErrInvalidInput, config)
	}

	// Validate the configuration
	if err := scriptConfig.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Create executor and validate shell availability
	executor := NewExecutor(scriptConfig)
	if err := executor.ValidateShellAvailability(); err != nil {
		return fmt.Errorf("shell validation failed: %w", err)
	}

	// Validate script signature if signing policy requires it
	if err := m.validateSignature(scriptConfig); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	// Track execution state
	var startTime int64
	if timestamp, ok := ctx.Value("timestamp").(int64); ok {
		startTime = timestamp
	} else {
		startTime = time.Now().Unix()
	}

	m.mu.Lock()
	m.executions[resourceID] = &ExecutionState{
		Config:    scriptConfig,
		Status:    StatusPending,
		StartTime: startTime,
	}
	m.mu.Unlock()

	// Update status to running
	m.updateExecutionStatus(resourceID, StatusRunning, nil, nil)

	// Execute the script
	result, err := executor.Execute(ctx)

	// Create audit record regardless of success/failure
	auditRecord := CreateAuditRecord(m.stewardID, resourceID, scriptConfig, result, err)
	if auditErr := m.auditLogger.LogExecution(ctx, auditRecord); auditErr != nil {
		// Log audit error but don't fail the execution
		fmt.Printf("Failed to log script execution audit: %v\n", auditErr)
	}

	if err != nil {
		m.updateExecutionStatus(resourceID, StatusFailed, nil, err)
		return fmt.Errorf("script execution failed: %w", err)
	}

	// Update execution state with result
	if result.ExitCode == 0 {
		m.updateExecutionStatus(resourceID, StatusCompleted, result, nil)
	} else {
		m.updateExecutionStatus(resourceID, StatusFailed, result,
			fmt.Errorf("script exited with code %d: %s", result.ExitCode, result.Stderr))
	}

	return nil
}

// updateExecutionStatus updates the execution status thread-safely
func (m *Module) updateExecutionStatus(resourceID string, status ExecutionStatus, result *ExecutionResult, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if execution, exists := m.executions[resourceID]; exists {
		execution.Status = status
		execution.Result = result
		execution.Error = err
	}
}

// validateSignature validates script signatures based on the signing policy
func (m *Module) validateSignature(config *ScriptConfig) error {
	switch config.SigningPolicy {
	case SigningPolicyNone:
		// No validation required
		return nil

	case SigningPolicyOptional:
		// Validate only if signature is present
		if config.Signature != nil {
			return m.verifySignature(config)
		}
		return nil

	case SigningPolicyRequired:
		// Signature must be present and valid
		if config.Signature == nil {
			return fmt.Errorf("%w: signature is required but not provided", modules.ErrInvalidInput)
		}
		return m.verifySignature(config)

	default:
		return fmt.Errorf("%w: invalid signing policy: %s", modules.ErrInvalidInput, config.SigningPolicy)
	}
}

// verifySignature performs the actual signature verification
func (m *Module) verifySignature(config *ScriptConfig) error {
	// TODO: Implement actual signature verification
	// This is a placeholder implementation

	if config.Signature == nil {
		return fmt.Errorf("%w: signature is required but not provided", modules.ErrInvalidInput)
	}

	// Basic validation that signature fields are present
	if config.Signature.Algorithm == "" {
		return fmt.Errorf("%w: signature algorithm is missing", modules.ErrInvalidInput)
	}
	if config.Signature.Signature == "" {
		return fmt.Errorf("%w: signature value is missing", modules.ErrInvalidInput)
	}
	if config.Signature.PublicKey == "" && config.Signature.Thumbprint == "" {
		return fmt.Errorf("%w: either public key or certificate thumbprint is required", modules.ErrInvalidInput)
	}

	// TODO: Implement cryptographic signature verification
	// - Parse public key or retrieve certificate by thumbprint
	// - Verify signature against script content using specified algorithm
	// - Return appropriate error if verification fails

	return nil
}

// GetExecutionState returns the current execution state for a resource
func (m *Module) GetExecutionState(resourceID string) (*ExecutionState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	execution, exists := m.executions[resourceID]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent external modification
	stateCopy := *execution
	return &stateCopy, true
}

// ListExecutions returns all current execution states
func (m *Module) ListExecutions() map[string]*ExecutionState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]*ExecutionState)
	for id, execution := range m.executions {
		// Return copies to prevent external modification
		executionCopy := *execution
		result[id] = &executionCopy
	}

	return result
}

// ClearExecution removes the execution state for a resource
func (m *Module) ClearExecution(resourceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.executions, resourceID)
}

// GetExecutionHistory returns the execution history for the steward
func (m *Module) GetExecutionHistory(limit int) ([]*AuditRecord, error) {
	return m.auditLogger.GetExecutionHistory(m.stewardID, limit)
}

// QueryExecutions searches execution history based on query parameters
func (m *Module) QueryExecutions(query *AuditQuery) ([]*AuditRecord, error) {
	if query.StewardID == "" {
		query.StewardID = m.stewardID
	}
	return m.auditLogger.QueryExecutions(query)
}

// GetExecutionMetrics returns aggregated metrics for the steward
func (m *Module) GetExecutionMetrics(since time.Time) (*AggregatedMetrics, error) {
	return m.auditLogger.GetExecutionMetrics(m.stewardID, since)
}

// SetStewardID updates the steward ID for this module instance
func (m *Module) SetStewardID(stewardID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stewardID = stewardID
}
