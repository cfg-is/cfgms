// Package service provides Epic 6 compliant configuration service using ConfigStore interface
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/validation"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ConfigurationServiceV2 implements Epic 6 compliant Configuration gRPC service
// This replaces the in-memory storage with persistent ConfigStore
type ConfigurationServiceV2 struct {
	controller.UnimplementedConfigurationServiceServer
	
	logger           logging.Logger
	configManager    *config.Manager
	rollbackManager  *config.RollbackManager
	inheritanceResolver *config.InheritanceResolver
	validationManager *config.ValidationManager
	controllerSvc    *ControllerService
	validator        *validation.Validator
	storageManager   *interfaces.StorageManager
}

// NewConfigurationServiceV2 creates a new Epic 6 compliant Configuration service
func NewConfigurationServiceV2(logger logging.Logger, storageManager *interfaces.StorageManager, controllerSvc *ControllerService) *ConfigurationServiceV2 {
	return &ConfigurationServiceV2{
		logger:              logger,
		configManager:       config.NewManagerWithStorageManager(storageManager),
		rollbackManager:     config.NewRollbackManagerWithStorageManager(storageManager),
		inheritanceResolver: config.NewInheritanceResolverWithStorageManager(storageManager),
		validationManager:   config.NewValidationManager(storageManager.GetConfigStore()),
		controllerSvc:       controllerSvc,
		validator:           validation.NewValidator(),
		storageManager:      storageManager,
	}
}

// GetConfiguration retrieves configuration for a specific steward using ConfigStore
func (s *ConfigurationServiceV2) GetConfiguration(ctx context.Context, req *controller.ConfigRequest) (*controller.ConfigResponse, error) {
	s.logger.Debug("Configuration request received", "steward_id", req.StewardId, "modules", req.Modules)
	
	// Extract tenant context
	tenantID := s.extractTenantID(ctx)
	
	// Verify steward exists and belongs to the tenant
	if s.controllerSvc != nil {
		stewardInfo, exists := s.controllerSvc.GetStewardInfo(req.StewardId)
		if !exists {
			s.logger.Warn("Configuration request from unknown steward", "steward_id", req.StewardId)
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
				"steward_id", req.StewardId,
				"steward_tenant", stewardInfo.TenantID,
				"request_tenant", tenantID)
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
		s.logger.Debug("No configuration found for steward", "steward_id", req.StewardId, "error", err)
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_NOT_FOUND,
				Message: "No configuration found for steward",
			},
		}, nil
	}
	
	// Filter configuration by requested modules if specified
	filteredConfig := s.filterConfigByModules(stewardConfig, req.Modules)
	
	// Convert to JSON
	configData, err := json.Marshal(filteredConfig)
	if err != nil {
		s.logger.Error("Failed to marshal configuration", "steward_id", req.StewardId, "error", err)
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
	
	s.logger.Debug("Configuration retrieved successfully", "steward_id", req.StewardId, "version", version)
	
	return &controller.ConfigResponse{
		Status: &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration retrieved successfully",
		},
		Config:  configData,
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
			"steward_id", stewardID,
			"field", warning.Field,
			"message", warning.Message)
	}
	
	// Store configuration
	if err := s.configManager.StoreConfiguration(ctx, tenantID, stewardID, config); err != nil {
		return fmt.Errorf("failed to store configuration: %w", err)
	}
	
	s.logger.Info("Configuration stored successfully",
		"tenant_id", tenantID,
		"steward_id", stewardID)
	
	return nil
}

// GetEffectiveConfiguration returns the effective configuration with inheritance metadata
func (s *ConfigurationServiceV2) GetEffectiveConfiguration(ctx context.Context, tenantID, stewardID string) (*config.EffectiveConfiguration, error) {
	return s.inheritanceResolver.ResolveConfiguration(ctx, tenantID, stewardID)
}

// RollbackConfiguration performs configuration rollback using storage versioning
func (s *ConfigurationServiceV2) RollbackConfiguration(ctx context.Context, request *config.RollbackRequest) (*config.RollbackResponse, error) {
	s.logger.Info("Configuration rollback requested",
		"tenant_id", request.TenantID,
		"steward_id", request.StewardID,
		"target_version", request.TargetVersion,
		"reason", request.Reason,
		"requested_by", request.RequestedBy)
	
	response, err := s.rollbackManager.PerformRollback(ctx, request)
	if err != nil {
		s.logger.Error("Configuration rollback failed",
			"tenant_id", request.TenantID,
			"steward_id", request.StewardID,
			"target_version", request.TargetVersion,
			"error", err)
		return response, err
	}
	
	if response.Success {
		s.logger.Info("Configuration rollback successful",
			"tenant_id", request.TenantID,
			"steward_id", request.StewardID,
			"rollback_id", response.RollbackID,
			"from_version", response.PreviousVersion,
			"to_version", response.NewVersion,
			"risk_level", response.RiskLevel)
	}
	
	return response, nil
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
	s.logger.Debug("Configuration validation request received", "version", req.Version)
	
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
	tenantID := s.extractTenantID(ctx)
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
		"version", req.Version,
		"valid", validationResult.Valid,
		"errors", len(validationResult.Errors),
		"warnings", len(validationResult.Warnings))
	
	return &controller.ConfigValidationResponse{
		Status: status,
		Errors: validationErrors,
		Metadata: map[string]string{
			"validation_timestamp": time.Now().Format(time.RFC3339),
			"total_issues": fmt.Sprintf("%d", len(validationResult.Errors)+len(validationResult.Warnings)),
			"storage_provider": s.storageManager.GetProviderName(),
		},
	}, nil
}

// StreamConfigurationUpdates streams configuration updates to stewards
// This would need to be enhanced with storage-based change notifications
func (s *ConfigurationServiceV2) StreamConfigurationUpdates(req *controller.ConfigStreamRequest, stream controller.ConfigurationService_StreamConfigurationUpdatesServer) error {
	s.logger.Debug("Configuration stream request received", "steward_id", req.StewardId, "modules", req.Modules)
	
	// Verify steward exists
	if s.controllerSvc != nil {
		if _, exists := s.controllerSvc.GetStewardInfo(req.StewardId); !exists {
			return fmt.Errorf("steward %s not found", req.StewardId)
		}
	}
	
	tenantID := s.extractTenantID(stream.Context())
	
	// Send initial configuration if it exists
	stewardConfig, err := s.configManager.GetConfigurationWithInheritance(stream.Context(), tenantID, req.StewardId)
	if err == nil {
		// Filter configuration by modules if specified
		var configBytes []byte
		
		if len(req.Modules) > 0 {
			filtered := s.filterConfigByModules(stewardConfig, req.Modules)
			configBytes, err = json.Marshal(filtered)
		} else {
			configBytes, err = json.Marshal(stewardConfig)
		}
		
		if err != nil {
			s.logger.Error("Failed to marshal configuration", "error", err)
			return fmt.Errorf("failed to marshal configuration: %w", err)
		}
		
		// Get version
		history, _ := s.configManager.GetConfigurationHistory(stream.Context(), tenantID, req.StewardId, 1)
		version := "unknown"
		if len(history) > 0 {
			version = fmt.Sprintf("v%d", history[0].Version)
		}
		
		initialUpdate := &controller.ConfigurationUpdate{
			StewardId:  req.StewardId,
			Config:     configBytes,
			Version:    version,
			Timestamp:  timestamppb.Now(),
			UpdateType: controller.ConfigurationUpdate_INITIAL,
		}
		
		if err := stream.Send(initialUpdate); err != nil {
			s.logger.Error("Failed to send initial configuration", "error", err)
			return fmt.Errorf("failed to send initial configuration: %w", err)
		}
		
		s.logger.Debug("Initial configuration sent", "steward_id", req.StewardId)
	}
	
	// For now, keep connection open but don't send updates
	// In a full implementation, this would listen for storage change notifications
	<-stream.Context().Done()
	s.logger.Debug("Configuration stream context done", "steward_id", req.StewardId)
	return nil
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

// extractTenantID extracts tenant ID from gRPC metadata
func (s *ConfigurationServiceV2) extractTenantID(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		s.logger.Debug("No metadata found in context, using default tenant")
		return "default"
	}
	
	values := md.Get("tenant-id")
	if len(values) > 0 && values[0] != "" {
		return values[0]
	}
	
	s.logger.Debug("No tenant-id in metadata, using default tenant")
	return "default"
}

// GetStorageStats returns storage statistics
func (s *ConfigurationServiceV2) GetStorageStats(ctx context.Context) (*interfaces.ConfigStats, error) {
	return s.configManager.GetConfigurationStats(ctx)
}