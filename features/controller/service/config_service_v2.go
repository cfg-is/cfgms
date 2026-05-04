// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package service provides Epic 6 compliant configuration service using ConfigStore interface
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/rollback"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ConfigurationServiceV2 implements Epic 6 compliant Configuration service
// This replaces the in-memory storage with persistent ConfigStore
type ConfigurationServiceV2 struct {
	logger              logging.Logger
	configManager       *config.Manager
	rollbackManager     rollback.RollbackManager
	inheritanceResolver *config.InheritanceResolver
	validationManager   *config.ValidationManager
	controllerSvc       *ControllerService
	storageManager      *interfaces.StorageManager
}

// NewConfigurationServiceV2 creates a new Epic 6 compliant Configuration service
func NewConfigurationServiceV2(logger logging.Logger, storageManager *interfaces.StorageManager, controllerSvc *ControllerService) *ConfigurationServiceV2 {
	return &ConfigurationServiceV2{
		logger:              logger,
		configManager:       config.NewManagerWithStorageManager(storageManager),
		inheritanceResolver: config.NewInheritanceResolverWithStorageManager(storageManager),
		validationManager:   config.NewValidationManager(storageManager.GetConfigStore()),
		controllerSvc:       controllerSvc,
		storageManager:      storageManager,
	}
}

// SetRollbackManager wires the canonical rollback manager into the service.
func (s *ConfigurationServiceV2) SetRollbackManager(m rollback.RollbackManager) {
	s.rollbackManager = m
}

// GetConfiguration retrieves configuration for a specific steward using ConfigStore
func (s *ConfigurationServiceV2) GetConfiguration(ctx context.Context, req *controller.ConfigRequest) (*controller.ConfigResponse, error) {
	sanitizedModules := make([]string, len(req.Modules))
	for i, m := range req.Modules {
		sanitizedModules[i] = logging.SanitizeLogValue(m)
	}
	s.logger.Debug("Configuration request received", "steward_id", logging.SanitizeLogValue(req.StewardId), "modules", sanitizedModules)

	// Extract tenant context
	tenantID := extractTenantID(ctx)

	// Verify steward exists and belongs to the tenant
	if s.controllerSvc != nil {
		stewardInfo, exists := s.controllerSvc.GetStewardInfo(req.StewardId)
		if !exists {
			s.logger.Warn("Configuration request from unknown steward", "steward_id", logging.SanitizeLogValue(req.StewardId))
			return &controller.ConfigResponse{
				Status: &common.Status{
					Code:    common.Status_NOT_FOUND,
					Message: "Steward not found",
				},
			}, nil
		}

		// Check tenant isolation
		if stewardInfo.TenantID != tenantID {
			s.logger.Warn("Configuration request cross-tenant access denied",
				"steward_id", logging.SanitizeLogValue(req.StewardId),
				"steward_tenant", logging.SanitizeLogValue(stewardInfo.TenantID),
				"request_tenant", logging.SanitizeLogValue(tenantID))
			return &controller.ConfigResponse{
				Status: &common.Status{
					Code:    common.Status_UNAUTHORIZED,
					Message: "Cross-tenant access denied",
				},
			}, nil
		}
	}

	// Get configuration with inheritance from storage
	stewardConfig, err := s.configManager.GetConfigurationWithInheritance(ctx, tenantID, req.StewardId)
	if err != nil {
		s.logger.Debug("No configuration found for steward", "steward_id", logging.SanitizeLogValue(req.StewardId), "error", err)
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_NOT_FOUND,
				Message: "No configuration found for steward",
			},
		}, nil
	}

	// Filter configuration by requested modules if specified
	filteredConfig := s.filterConfigByModules(stewardConfig, req.Modules)

	// Convert Go struct to protobuf
	protoConfig, err := stewardconfig.ToProto(filteredConfig)
	if err != nil {
		s.logger.Error("Failed to convert configuration to protobuf", "steward_id", logging.SanitizeLogValue(req.StewardId), "error", err)
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_ERROR,
				Message: "Failed to serialize configuration",
			},
		}, nil
	}

	// Get version information from storage
	history, err := s.configManager.GetConfigurationHistory(ctx, tenantID, req.StewardId, 1)
	version := "unknown"
	if err == nil && len(history) > 0 {
		version = fmt.Sprintf("v%d", history[0].Version)
	}

	s.logger.Debug("Configuration retrieved successfully", "steward_id", logging.SanitizeLogValue(req.StewardId), "version", version)

	return &controller.ConfigResponse{
		Status: &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration retrieved successfully",
		},
		Config:  &controller.SignedConfig{Config: protoConfig}, // Unsigned, QUIC handler will sign
		Version: version,
	}, nil
}

// SetConfiguration stores a configuration for a specific steward using ConfigStore
func (s *ConfigurationServiceV2) SetConfiguration(ctx context.Context, tenantID, stewardID string, config *stewardconfig.StewardConfig) error {
	// Validate configuration before storing
	validationResult := s.validationManager.ValidateConfiguration(ctx, tenantID, stewardID, config)
	if !validationResult.Valid {
		var errorMessages []string
		for _, err := range validationResult.Errors {
			errorMessages = append(errorMessages, fmt.Sprintf("%s: %s", err.Field, err.Message))
		}
		return fmt.Errorf("configuration validation failed: %v", errorMessages)
	}

	// Log validation warnings
	for _, warning := range validationResult.Warnings {
		s.logger.Warn("Configuration validation warning",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"field", logging.SanitizeLogValue(warning.Field),
			"message", logging.SanitizeLogValue(warning.Message))
	}

	// Store configuration
	if err := s.configManager.StoreConfiguration(ctx, tenantID, stewardID, config); err != nil {
		return fmt.Errorf("failed to store configuration: %w", err)
	}

	s.logger.Info("Configuration stored successfully",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"steward_id", logging.SanitizeLogValue(stewardID))

	return nil
}

// GetEffectiveConfiguration returns the effective configuration with inheritance metadata
func (s *ConfigurationServiceV2) GetEffectiveConfiguration(ctx context.Context, tenantID, stewardID string) (*config.EffectiveConfiguration, error) {
	return s.inheritanceResolver.ResolveConfiguration(ctx, tenantID, stewardID)
}

// RollbackConfiguration performs configuration rollback via the canonical rollback manager.
func (s *ConfigurationServiceV2) RollbackConfiguration(ctx context.Context, request *config.RollbackRequest) (*config.RollbackResponse, error) {
	if s.rollbackManager == nil {
		return nil, fmt.Errorf("rollback manager not initialized")
	}

	s.logger.Info("Configuration rollback requested",
		"steward_id", logging.SanitizeLogValue(request.StewardID),
		"target_version", request.TargetVersion,
		"reason", logging.SanitizeLogValue(request.Reason))

	translated := s.translateRollbackRequest(request)
	op, err := s.rollbackManager.ExecuteRollback(ctx, translated)
	if err != nil {
		s.logger.Error("Configuration rollback failed",
			"steward_id", logging.SanitizeLogValue(request.StewardID),
			"target_version", request.TargetVersion,
			"error", err)
		return &config.RollbackResponse{
			Success:  false,
			Errors:   []string{err.Error()},
			Warnings: []string{},
		}, err
	}

	var errors []string
	if op.Result != nil {
		for _, f := range op.Result.Failures {
			errors = append(errors, f.Error)
		}
	}

	response := &config.RollbackResponse{
		RollbackID: op.ID,
		Success:    op.Status == rollback.RollbackStatusCompleted,
		Errors:     errors,
		Warnings:   []string{},
	}

	if response.Success {
		s.logger.Info("Configuration rollback successful",
			"steward_id", logging.SanitizeLogValue(request.StewardID),
			"rollback_id", op.ID)
	}

	return response, nil
}

// translateRollbackRequest maps a config.RollbackRequest to the canonical rollback.RollbackRequest.
// RollbackTo uses fmt.Sprintf("v%d", ...) — the git-backed rollback manager resolves version refs.
func (s *ConfigurationServiceV2) translateRollbackRequest(req *config.RollbackRequest) rollback.RollbackRequest {
	return rollback.RollbackRequest{
		TargetID:   req.StewardID,
		TargetType: rollback.TargetTypeSteward,
		RollbackTo: fmt.Sprintf("v%d", req.TargetVersion),
		Reason:     req.Reason,
		DryRun:     req.ValidateOnly,
		Options: rollback.RollbackOptions{
			SkipValidation: req.SkipValidation,
		},
	}
}

// ListConfigurations lists all configurations for a tenant
func (s *ConfigurationServiceV2) ListConfigurations(ctx context.Context, tenantID string) ([]*config.ConfigurationSummary, error) {
	return s.configManager.ListConfigurations(ctx, tenantID)
}

// GetConfigurationHistory retrieves version history for a configuration
func (s *ConfigurationServiceV2) GetConfigurationHistory(ctx context.Context, tenantID, stewardID string, limit int) ([]*config.ConfigurationVersion, error) {
	return s.configManager.GetConfigurationHistory(ctx, tenantID, stewardID, limit)
}

// BatchSetConfigurations stores multiple configurations atomically
func (s *ConfigurationServiceV2) BatchSetConfigurations(ctx context.Context, configs []*config.BatchConfigurationEntry) error {
	// Validate all configurations first
	for _, entry := range configs {
		validationResult := s.validationManager.ValidateConfiguration(ctx, entry.TenantID, entry.StewardID, entry.Config)
		if !validationResult.Valid {
			var errorMessages []string
			for _, err := range validationResult.Errors {
				errorMessages = append(errorMessages, fmt.Sprintf("%s: %s", err.Field, err.Message))
			}
			return fmt.Errorf("validation failed for steward %s: %v", entry.StewardID, errorMessages)
		}
	}

	// Store all configurations in batch
	if err := s.configManager.BatchStoreConfigurations(ctx, configs); err != nil {
		return fmt.Errorf("failed to store configurations in batch: %w", err)
	}

	s.logger.Info("Batch configuration storage completed", "count", len(configs))
	return nil
}

// ValidateConfig validates a configuration using comprehensive validation
func (s *ConfigurationServiceV2) ValidateConfig(ctx context.Context, req *controller.ConfigValidationRequest) (*controller.ConfigValidationResponse, error) {
	s.logger.Debug("Configuration validation request received", "version", logging.SanitizeLogValue(req.Version))

	// Parse configuration
	var stewardConfig stewardconfig.StewardConfig
	if err := json.Unmarshal(req.Config, &stewardConfig); err != nil {
		s.logger.Error("Failed to parse configuration for validation", "error", err)
		return &controller.ConfigValidationResponse{
			Status: &common.Status{
				Code:    common.Status_ERROR,
				Message: "Invalid configuration format",
			},
			Errors: []*controller.ValidationError{
				{
					Field:   "config",
					Message: fmt.Sprintf("JSON parsing error: %v", err),
					Level:   controller.ValidationError_CRITICAL,
					Code:    "JSON_PARSING_ERROR",
				},
			},
		}, nil
	}

	// Extract tenant and steward ID from context (simplified)
	tenantID := extractTenantID(ctx)
	stewardID := "validation" // For validation-only requests

	// Use comprehensive validation framework
	validationResult := s.validationManager.ValidateConfiguration(ctx, tenantID, stewardID, &stewardConfig)

	// Convert validation result to proto format
	var validationErrors []*controller.ValidationError
	for _, issue := range validationResult.Errors {
		protoLevel := s.convertValidationLevel(issue.Level)
		validationErrors = append(validationErrors, &controller.ValidationError{
			Field:      issue.Field,
			Message:    issue.Message,
			Level:      protoLevel,
			Code:       issue.Code,
			Suggestion: issue.Suggestion,
		})
	}

	for _, warning := range validationResult.Warnings {
		protoLevel := s.convertValidationLevel(warning.Level)
		validationErrors = append(validationErrors, &controller.ValidationError{
			Field:      warning.Field,
			Message:    warning.Message,
			Level:      protoLevel,
			Code:       warning.Code,
			Suggestion: warning.Suggestion,
		})
	}

	// Determine response status
	var status *common.Status
	if !validationResult.Valid {
		status = &common.Status{
			Code:    common.Status_ERROR,
			Message: "Configuration has critical errors that prevent operation",
		}
	} else if len(validationResult.Warnings) > 0 {
		status = &common.Status{
			Code:    common.Status_OK,
			Message: fmt.Sprintf("Configuration is valid with %d warnings", len(validationResult.Warnings)),
		}
	} else {
		status = &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration is fully valid",
		}
	}

	s.logger.Debug("Configuration validation completed",
		"version", logging.SanitizeLogValue(req.Version),
		"valid", validationResult.Valid,
		"errors", len(validationResult.Errors),
		"warnings", len(validationResult.Warnings))

	return &controller.ConfigValidationResponse{
		Status: status,
		Errors: validationErrors,
		Metadata: map[string]string{
			"validation_timestamp": time.Now().Format(time.RFC3339),
			"total_issues":         fmt.Sprintf("%d", len(validationResult.Errors)+len(validationResult.Warnings)),
			"storage_provider":     s.storageManager.GetProviderName(),
		},
	}, nil
}

// Helper methods

// filterConfigByModules filters configuration to include only requested modules
func (s *ConfigurationServiceV2) filterConfigByModules(config *stewardconfig.StewardConfig, modules []string) *stewardconfig.StewardConfig {
	if len(modules) == 0 {
		return config
	}

	// Create a set of requested modules
	moduleSet := make(map[string]bool)
	for _, module := range modules {
		moduleSet[module] = true
	}

	// Filter resources
	filteredConfig := *config
	filteredConfig.Resources = nil

	for _, resource := range config.Resources {
		if moduleSet[resource.Module] {
			filteredConfig.Resources = append(filteredConfig.Resources, resource)
		}
	}

	return &filteredConfig
}

// convertValidationLevel converts internal validation level to proto level
func (s *ConfigurationServiceV2) convertValidationLevel(level string) controller.ValidationError_Level {
	switch level {
	case "info":
		return controller.ValidationError_INFO
	case "warning":
		return controller.ValidationError_WARNING
	case "error":
		return controller.ValidationError_ERROR
	case "critical":
		return controller.ValidationError_CRITICAL
	default:
		return controller.ValidationError_ERROR
	}
}

// GetStorageStats returns storage statistics
func (s *ConfigurationServiceV2) GetStorageStats(ctx context.Context) (*cfgconfig.ConfigStats, error) {
	return s.configManager.GetConfigurationStats(ctx)
}
