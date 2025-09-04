// Package config provides configuration rollback functionality using storage versioning
package config

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
)

// RollbackManager handles configuration rollback operations
type RollbackManager struct {
	configStore interfaces.ConfigStore
	manager     *Manager
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(configStore interfaces.ConfigStore) *RollbackManager {
	return &RollbackManager{
		configStore: configStore,
		manager:     NewManager(configStore),
	}
}

// NewRollbackManagerWithStorageManager creates a rollback manager from storage manager
func NewRollbackManagerWithStorageManager(storageManager *interfaces.StorageManager) *RollbackManager {
	configStore := storageManager.GetConfigStore()
	return &RollbackManager{
		configStore: configStore,
		manager:     NewManager(configStore),
	}
}

// RollbackRequest represents a configuration rollback request
type RollbackRequest struct {
	TenantID         string    `json:"tenant_id"`
	StewardID        string    `json:"steward_id"`
	TargetVersion    int64     `json:"target_version"`
	Reason           string    `json:"reason"`
	RequestedBy      string    `json:"requested_by"`
	RequestedAt      time.Time `json:"requested_at"`
	ValidateOnly     bool      `json:"validate_only"`     // If true, only validate rollback feasibility
	SkipValidation   bool      `json:"skip_validation"`   // Emergency rollback without validation
}

// RollbackResponse represents the result of a rollback operation
type RollbackResponse struct {
	Success         bool                         `json:"success"`
	RollbackID      string                       `json:"rollback_id"`
	PreviousVersion int64                        `json:"previous_version"`
	NewVersion      int64                        `json:"new_version"`
	RiskLevel       RollbackRiskLevel            `json:"risk_level"`
	Warnings        []string                     `json:"warnings"`
	Errors          []string                     `json:"errors"`
	ExecutedAt      time.Time                    `json:"executed_at"`
	ValidationIssues []*ConfigurationValidationError `json:"validation_issues,omitempty"`
}

// RollbackRiskLevel indicates the risk level of a rollback operation
type RollbackRiskLevel string

const (
	RollbackRiskLow      RollbackRiskLevel = "low"
	RollbackRiskMedium   RollbackRiskLevel = "medium"
	RollbackRiskHigh     RollbackRiskLevel = "high"
	RollbackRiskCritical RollbackRiskLevel = "critical"
)

// ConfigurationValidationError represents validation errors for rollback
type ConfigurationValidationError struct {
	Field       string `json:"field"`
	Message     string `json:"message"`
	Code        string `json:"code"`
	Severity    string `json:"severity"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// RollbackHistory represents a historical rollback operation
type RollbackHistory struct {
	RollbackID      string            `json:"rollback_id"`
	TenantID        string            `json:"tenant_id"`
	StewardID       string            `json:"steward_id"`
	FromVersion     int64             `json:"from_version"`
	ToVersion       int64             `json:"to_version"`
	Reason          string            `json:"reason"`
	ExecutedBy      string            `json:"executed_by"`
	ExecutedAt      time.Time         `json:"executed_at"`
	RiskLevel       RollbackRiskLevel `json:"risk_level"`
	Success         bool              `json:"success"`
	ErrorMessage    string            `json:"error_message,omitempty"`
}

// PerformRollback rolls back a configuration to a specific version
func (rm *RollbackManager) PerformRollback(ctx context.Context, request *RollbackRequest) (*RollbackResponse, error) {
	response := &RollbackResponse{
		RollbackID:  rm.generateRollbackID(),
		ExecutedAt:  time.Now(),
		Warnings:    []string{},
		Errors:      []string{},
	}

	// Get current configuration for comparison
	currentConfig, err := rm.manager.GetConfiguration(ctx, request.TenantID, request.StewardID)
	if err != nil {
		response.Errors = append(response.Errors, fmt.Sprintf("Failed to retrieve current configuration: %v", err))
		return response, err
	}

	// Get target version configuration
	targetConfig, err := rm.manager.GetConfigurationVersion(ctx, request.TenantID, request.StewardID, request.TargetVersion)
	if err != nil {
		response.Errors = append(response.Errors, fmt.Sprintf("Failed to retrieve target version %d: %v", request.TargetVersion, err))
		return response, err
	}

	// Get configuration history to determine current version
	history, err := rm.manager.GetConfigurationHistory(ctx, request.TenantID, request.StewardID, 1)
	if err != nil {
		response.Errors = append(response.Errors, fmt.Sprintf("Failed to retrieve configuration history: %v", err))
		return response, err
	}

	if len(history) > 0 {
		response.PreviousVersion = history[0].Version
	}

	// Assess rollback risk
	riskAssessment := rm.assessRollbackRisk(currentConfig, targetConfig)
	response.RiskLevel = riskAssessment.Level
	response.Warnings = append(response.Warnings, riskAssessment.Warnings...)

	// Validation phase
	if !request.SkipValidation {
		validationErrors := rm.validateRollback(ctx, currentConfig, targetConfig, request)
		response.ValidationIssues = validationErrors
		
		// Check for critical validation errors
		hasCriticalErrors := false
		for _, err := range validationErrors {
			if err.Severity == "critical" {
				hasCriticalErrors = true
				response.Errors = append(response.Errors, fmt.Sprintf("Critical validation error in %s: %s", err.Field, err.Message))
			}
		}

		if hasCriticalErrors {
			response.Success = false
			return response, fmt.Errorf("rollback blocked by critical validation errors")
		}
	}

	// If validation only, return without performing rollback
	if request.ValidateOnly {
		response.Success = true
		return response, nil
	}

	// Perform the actual rollback by storing the target configuration as new version
	if err := rm.manager.StoreConfiguration(ctx, request.TenantID, request.StewardID, targetConfig); err != nil {
		response.Errors = append(response.Errors, fmt.Sprintf("Failed to store rollback configuration: %v", err))
		response.Success = false
		return response, err
	}

	// Get the new version number
	newHistory, err := rm.manager.GetConfigurationHistory(ctx, request.TenantID, request.StewardID, 1)
	if err == nil && len(newHistory) > 0 {
		response.NewVersion = newHistory[0].Version
	}

	// Record rollback history
	rollbackHistory := &RollbackHistory{
		RollbackID:  response.RollbackID,
		TenantID:    request.TenantID,
		StewardID:   request.StewardID,
		FromVersion: response.PreviousVersion,
		ToVersion:   response.NewVersion,
		Reason:      request.Reason,
		ExecutedBy:  request.RequestedBy,
		ExecutedAt:  response.ExecutedAt,
		RiskLevel:   response.RiskLevel,
		Success:     true,
	}

	if err := rm.storeRollbackHistory(ctx, rollbackHistory); err != nil {
		// Don't fail the rollback for history storage issues, just warn
		response.Warnings = append(response.Warnings, fmt.Sprintf("Failed to store rollback history: %v", err))
	}

	response.Success = true
	return response, nil
}

// RollbackRiskAssessment represents the result of rollback risk analysis
type RollbackRiskAssessment struct {
	Level     RollbackRiskLevel
	Warnings  []string
	Factors   []string
}

// assessRollbackRisk analyzes the risk level of rolling back from current to target config
func (rm *RollbackManager) assessRollbackRisk(current, target *stewardconfig.StewardConfig) *RollbackRiskAssessment {
	assessment := &RollbackRiskAssessment{
		Level:    RollbackRiskLow,
		Warnings: []string{},
		Factors:  []string{},
	}

	riskFactors := 0

	// Check for resource changes
	currentResourceMap := make(map[string]*stewardconfig.ResourceConfig)
	for _, resource := range current.Resources {
		currentResourceMap[resource.Name] = &resource
	}

	targetResourceMap := make(map[string]*stewardconfig.ResourceConfig)
	for _, resource := range target.Resources {
		targetResourceMap[resource.Name] = &resource
	}

	// Check for removed resources
	for name := range currentResourceMap {
		if _, exists := targetResourceMap[name]; !exists {
			riskFactors++
			assessment.Factors = append(assessment.Factors, fmt.Sprintf("Resource '%s' will be removed", name))
			assessment.Warnings = append(assessment.Warnings, fmt.Sprintf("Rolling back will remove resource '%s'", name))
		}
	}

	// Check for module changes
	for name, targetResource := range targetResourceMap {
		if currentResource, exists := currentResourceMap[name]; exists {
			if currentResource.Module != targetResource.Module {
				riskFactors += 2 // Module changes are higher risk
				assessment.Factors = append(assessment.Factors, fmt.Sprintf("Resource '%s' module changed from %s to %s", name, currentResource.Module, targetResource.Module))
				assessment.Warnings = append(assessment.Warnings, fmt.Sprintf("Resource '%s' will change from module %s to %s", name, currentResource.Module, targetResource.Module))
			}
		}
	}

	// Check for steward settings changes
	if current.Steward.Mode != target.Steward.Mode {
		riskFactors++
		assessment.Factors = append(assessment.Factors, fmt.Sprintf("Steward mode changed from %s to %s", current.Steward.Mode, target.Steward.Mode))
		assessment.Warnings = append(assessment.Warnings, fmt.Sprintf("Steward mode will change from %s to %s", current.Steward.Mode, target.Steward.Mode))
	}

	// Determine risk level based on factors
	switch {
	case riskFactors >= 5:
		assessment.Level = RollbackRiskCritical
	case riskFactors >= 3:
		assessment.Level = RollbackRiskHigh
	case riskFactors >= 1:
		assessment.Level = RollbackRiskMedium
	default:
		assessment.Level = RollbackRiskLow
	}

	return assessment
}

// validateRollback performs validation checks before rollback
func (rm *RollbackManager) validateRollback(ctx context.Context, current, target *stewardconfig.StewardConfig, request *RollbackRequest) []*ConfigurationValidationError {
	var errors []*ConfigurationValidationError

	// Validate target configuration structure
	if err := rm.manager.ValidateConfiguration(ctx, target); err != nil {
		errors = append(errors, &ConfigurationValidationError{
			Field:    "target_configuration",
			Message:  fmt.Sprintf("Target configuration is invalid: %v", err),
			Code:     "INVALID_TARGET_CONFIG",
			Severity: "critical",
		})
	}

	// Check for dependency issues
	currentModules := make(map[string]bool)
	for _, resource := range current.Resources {
		currentModules[resource.Module] = true
	}

	targetModules := make(map[string]bool)
	for _, resource := range target.Resources {
		targetModules[resource.Module] = true
	}

	// Warn about module dependencies that might be removed
	for module := range currentModules {
		if !targetModules[module] {
			errors = append(errors, &ConfigurationValidationError{
				Field:    "module_dependencies",
				Message:  fmt.Sprintf("Module '%s' will no longer be used after rollback", module),
				Code:     "MODULE_REMOVED",
				Severity: "warning",
				Suggestion: "Ensure that removing this module won't break system functionality",
			})
		}
	}

	// Check for configuration format consistency
	if request.TenantID == "" {
		errors = append(errors, &ConfigurationValidationError{
			Field:    "tenant_id",
			Message:  "Tenant ID is required for rollback",
			Code:     "TENANT_REQUIRED",
			Severity: "critical",
		})
	}

	if request.StewardID == "" {
		errors = append(errors, &ConfigurationValidationError{
			Field:    "steward_id",
			Message:  "Steward ID is required for rollback",
			Code:     "STEWARD_REQUIRED",
			Severity: "critical",
		})
	}

	return errors
}

// GetRollbackHistory retrieves rollback history for a configuration
func (rm *RollbackManager) GetRollbackHistory(ctx context.Context, tenantID, stewardID string) ([]*RollbackHistory, error) {
	// For now, we'll store rollback history as configs in a special namespace
	// In a full implementation, this might use a dedicated audit store
	
	filter := &interfaces.ConfigFilter{
		TenantID:  tenantID,
		Namespace: "rollback-history",
		Names:     []string{stewardID},
		SortBy:    "created_at",
		Order:     "desc",
	}

	historyEntries, err := rm.configStore.ListConfigs(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve rollback history: %w", err)
	}

	var history []*RollbackHistory
	for _, entry := range historyEntries {
		var rollbackHistory RollbackHistory
		if err := yaml.Unmarshal(entry.Data, &rollbackHistory); err != nil {
			continue // Skip malformed entries
		}
		history = append(history, &rollbackHistory)
	}

	return history, nil
}

// storeRollbackHistory stores rollback operation history
func (rm *RollbackManager) storeRollbackHistory(ctx context.Context, rollbackHistory *RollbackHistory) error {
	historyData, err := yaml.Marshal(rollbackHistory)
	if err != nil {
		return fmt.Errorf("failed to marshal rollback history: %w", err)
	}

	configEntry := &interfaces.ConfigEntry{
		Key: &interfaces.ConfigKey{
			TenantID:  rollbackHistory.TenantID,
			Namespace: "rollback-history",
			Name:      rollbackHistory.StewardID,
		},
		Data:      historyData,
		Format:    interfaces.ConfigFormatYAML,
		CreatedAt: rollbackHistory.ExecutedAt,
		UpdatedAt: rollbackHistory.ExecutedAt,
		CreatedBy: rollbackHistory.ExecutedBy,
		UpdatedBy: rollbackHistory.ExecutedBy,
		Source:    "rollback-manager",
		Tags:      []string{"rollback-history", string(rollbackHistory.RiskLevel)},
		Metadata: map[string]interface{}{
			"rollback_id":   rollbackHistory.RollbackID,
			"from_version":  rollbackHistory.FromVersion,
			"to_version":    rollbackHistory.ToVersion,
			"risk_level":    string(rollbackHistory.RiskLevel),
		},
	}

	return rm.configStore.StoreConfig(ctx, configEntry)
}

// generateRollbackID generates a unique identifier for rollback operations
func (rm *RollbackManager) generateRollbackID() string {
	return fmt.Sprintf("rollback-%d", time.Now().UnixNano())
}

// CanRollback checks if a rollback is possible for the given configuration
func (rm *RollbackManager) CanRollback(ctx context.Context, tenantID, stewardID string, targetVersion int64) (bool, []string, error) {
	// Check if target version exists
	_, err := rm.manager.GetConfigurationVersion(ctx, tenantID, stewardID, targetVersion)
	if err != nil {
		return false, []string{fmt.Sprintf("Target version %d not found: %v", targetVersion, err)}, nil
	}

	// Check if current configuration exists
	currentConfig, err := rm.manager.GetConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		return false, []string{fmt.Sprintf("Cannot retrieve current configuration: %v", err)}, nil
	}

	// Get target configuration for risk assessment
	targetConfig, err := rm.manager.GetConfigurationVersion(ctx, tenantID, stewardID, targetVersion)
	if err != nil {
		return false, []string{fmt.Sprintf("Cannot retrieve target configuration: %v", err)}, nil
	}

	// Assess risk and validate
	riskAssessment := rm.assessRollbackRisk(currentConfig, targetConfig)
	validationRequest := &RollbackRequest{
		TenantID:      tenantID,
		StewardID:     stewardID,
		TargetVersion: targetVersion,
		ValidateOnly:  true,
	}
	
	validationErrors := rm.validateRollback(ctx, currentConfig, targetConfig, validationRequest)
	
	var issues []string
	issues = append(issues, riskAssessment.Warnings...)
	
	for _, err := range validationErrors {
		if err.Severity == "critical" {
			return false, append(issues, fmt.Sprintf("Critical: %s", err.Message)), nil
		}
		if err.Severity == "error" {
			issues = append(issues, fmt.Sprintf("Error: %s", err.Message))
		}
	}

	return true, issues, nil
}