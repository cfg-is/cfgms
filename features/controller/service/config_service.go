// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/validation"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Regex pattern for validating identifiers (prevents log injection)
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// EffectiveConfig represents the final configuration after applying inheritance
type EffectiveConfig struct {
	StewardID   string                        `json:"steward_id"`
	TenantID    string                        `json:"tenant_id"`
	Resources   map[string]*EffectiveResource `json:"resources"`
	Steward     *EffectiveSection             `json:"steward"`
	Modules     map[string]*EffectiveValue    `json:"modules"`
	GeneratedAt time.Time                     `json:"generated_at"`
}

// EffectiveResource represents a resource configuration with inheritance tracking
type EffectiveResource struct {
	Name   string                     `json:"name"`
	Module string                     `json:"module"`
	Config map[string]*EffectiveValue `json:"config"`
	Source string                     `json:"source"` // Which level provided this resource
	Level  int                        `json:"level"`  // Hierarchy level (0=msp, 1=client, 2=group, 3=device)
}

// EffectiveSection represents a configuration section with inheritance tracking
type EffectiveSection struct {
	Values map[string]*EffectiveValue `json:"values"`
}

// EffectiveValue represents a single configuration value with its source
type EffectiveValue struct {
	Value  interface{} `json:"value"`
	Source string      `json:"source"` // Which level provided this value
	Level  int         `json:"level"`  // Hierarchy level
}

// ConfigurationService implements the Configuration service
type ConfigurationService struct {
	logger         logging.Logger
	mu             sync.RWMutex
	configurations map[string]*StoredConfiguration
	controllerSvc  *ControllerService
	validator      *validation.Validator

	// Configuration streaming
	subscribers map[string]chan *controller.ConfigurationUpdate
}

// StoredConfiguration represents a configuration stored in the controller
type StoredConfiguration struct {
	StewardID   string
	TenantID    string // Multi-tenant support
	Version     string
	Config      *stewardconfig.StewardConfig
	LastUpdated time.Time
	CreatedAt   time.Time
}

// NewConfigurationService creates a new Configuration service
func NewConfigurationService(logger logging.Logger, controllerSvc *ControllerService) *ConfigurationService {
	return &ConfigurationService{
		logger:         logger,
		configurations: make(map[string]*StoredConfiguration),
		controllerSvc:  controllerSvc,
		validator:      validation.NewValidator(),
		subscribers:    make(map[string]chan *controller.ConfigurationUpdate),
	}
}

// GetConfiguration retrieves configuration for a specific steward
func (s *ConfigurationService) GetConfiguration(ctx context.Context, req *controller.ConfigRequest) (*controller.ConfigResponse, error) {
	if !identifierRegex.MatchString(req.StewardId) {
		s.logger.Warn("Invalid steward ID format in configuration request")
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_ERROR,
				Message: "Invalid steward ID format",
			},
		}, nil
	}

	s.logger.Debug("Configuration request received", "steward_id", req.StewardId, "modules", req.Modules)

	// Extract tenant context
	tenantID := s.extractTenantID(ctx)

	// Verify steward exists and belongs to the tenant (if registered)
	// Allow unregistered stewards to proceed if configuration exists (for bootstrapping/testing)
	if s.controllerSvc != nil {
		stewardInfo, exists := s.controllerSvc.GetStewardInfo(req.StewardId)
		if exists {
			// Steward is registered, enforce tenant isolation
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
		} else {
			// Steward not registered yet - allow if config exists (bootstrapping/testing scenario)
			s.logger.Debug("Configuration request from unregistered steward, checking if config exists",
				"steward_id", req.StewardId)
		}
	}

	// Use tenant-aware configuration retrieval
	storedConfig, exists := s.GetTenantConfiguration(tenantID, req.StewardId)

	if !exists {
		s.logger.Debug("No configuration found for steward", "steward_id", req.StewardId)
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_NOT_FOUND,
				Message: "No configuration found for steward",
			},
		}, nil
	}

	// Filter configuration by requested modules if specified
	filteredConfig := s.filterConfigByModules(storedConfig.Config, req.Modules)

	s.logger.Debug("GetConfiguration: sending config", "steward_id", req.StewardId, "resources", len(filteredConfig.Resources))

	// Convert Go struct to protobuf (returns unsigned config, signing happens in QUIC handler)
	protoConfig, err := stewardconfig.ToProto(filteredConfig)
	if err != nil {
		s.logger.Error("Failed to convert configuration to protobuf", "steward_id", req.StewardId, "error", err)
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_ERROR,
				Message: "Failed to serialize configuration",
			},
		}, nil
	}

	s.logger.Debug("Configuration retrieved successfully", "steward_id", req.StewardId, "version", storedConfig.Version)

	// Return unsigned protobuf config (QUIC handler will sign it)
	// Note: Config field is now *SignedConfig, but we set it to nil here
	// The QUIC handler is responsible for signing and wrapping in SignedConfig
	return &controller.ConfigResponse{
		Status: &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration retrieved successfully",
		},
		Config:  &controller.SignedConfig{Config: protoConfig}, // Unsigned for now
		Version: storedConfig.Version,
	}, nil
}

// ReportConfigStatus handles configuration status reports from stewards
func (s *ConfigurationService) ReportConfigStatus(ctx context.Context, req *controller.ConfigStatusReport) (*common.Status, error) {
	if !identifierRegex.MatchString(req.StewardId) {
		s.logger.Warn("Invalid steward ID format in status report")
		return &common.Status{
			Code:    common.Status_ERROR,
			Message: "Invalid steward ID format",
		}, nil
	}

	s.logger.Debug("Configuration status report received",
		"steward_id", req.StewardId,
		"config_version", req.ConfigVersion,
		"status", req.Status.Code,
		"modules", len(req.Modules))

	// Verify steward exists
	if s.controllerSvc != nil {
		if _, exists := s.controllerSvc.GetStewardInfo(req.StewardId); !exists {
			s.logger.Warn("Status report from unknown steward", "steward_id", req.StewardId)
			return &common.Status{
				Code:    common.Status_NOT_FOUND,
				Message: "Steward not found",
			}, nil
		}
	}

	// Log module status details
	for _, moduleStatus := range req.Modules {
		s.logger.Debug("Module status reported",
			"steward_id", req.StewardId,
			"module", moduleStatus.Name,
			"status", moduleStatus.Status.Code,
			"message", moduleStatus.Message)
	}

	s.logger.Info("Configuration status report processed",
		"steward_id", req.StewardId,
		"config_version", req.ConfigVersion,
		"overall_status", req.Status.Code)

	return &common.Status{
		Code:    common.Status_OK,
		Message: "Status report processed successfully",
	}, nil
}

// ValidateConfig validates a configuration using the comprehensive validation framework
func (s *ConfigurationService) ValidateConfig(ctx context.Context, req *controller.ConfigValidationRequest) (*controller.ConfigValidationResponse, error) {
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

	// Use comprehensive validation framework
	validationResult := s.validator.ValidateConfiguration(stewardConfig)

	// Convert validation issues to proto format
	var validationErrors []*controller.ValidationError
	for _, issue := range validationResult.Issues {
		protoLevel := s.convertValidationLevel(issue.Level)
		validationErrors = append(validationErrors, &controller.ValidationError{
			Field:      issue.Field,
			Message:    issue.Message,
			Level:      protoLevel,
			Code:       issue.Code,
			Suggestion: issue.Suggestion,
		})
	}

	// Determine response status
	var status *common.Status
	if validationResult.HasCriticalErrors() {
		status = &common.Status{
			Code:    common.Status_ERROR,
			Message: "Configuration has critical errors that prevent operation",
		}
	} else if validationResult.HasErrors() {
		status = &common.Status{
			Code:    common.Status_ERROR,
			Message: "Configuration has errors that should be fixed",
		}
	} else if len(validationResult.Issues) > 0 {
		status = &common.Status{
			Code:    common.Status_OK,
			Message: fmt.Sprintf("Configuration is valid with %d warnings/suggestions", len(validationResult.Issues)),
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
		"issues", len(validationResult.Issues),
		"duration", validationResult.Duration)

	return &controller.ConfigValidationResponse{
		Status: status,
		Errors: validationErrors,
		Metadata: map[string]string{
			"validation_duration":  validationResult.Duration.String(),
			"validation_timestamp": validationResult.StartTime.Format(time.RFC3339),
			"total_issues":         fmt.Sprintf("%d", len(validationResult.Issues)),
		},
	}, nil
}

// convertValidationLevel converts internal validation level to proto level
func (s *ConfigurationService) convertValidationLevel(level validation.ValidationLevel) controller.ValidationError_Level {
	switch level {
	case validation.ValidationLevelInfo:
		return controller.ValidationError_INFO
	case validation.ValidationLevelWarning:
		return controller.ValidationError_WARNING
	case validation.ValidationLevelError:
		return controller.ValidationError_ERROR
	case validation.ValidationLevelCritical:
		return controller.ValidationError_CRITICAL
	default:
		return controller.ValidationError_ERROR
	}
}

// SetConfiguration stores a configuration for a specific steward
func (s *ConfigurationService) SetConfiguration(stewardID string, config *stewardconfig.StewardConfig) error {
	// Use default tenant for backward compatibility
	return s.SetTenantConfiguration("default", stewardID, config)
}

// GetStoredConfiguration retrieves a stored configuration (backward compatibility with default tenant)
func (s *ConfigurationService) GetStoredConfiguration(stewardID string) (*StoredConfiguration, bool) {
	// Use default tenant for backward compatibility
	return s.GetTenantConfiguration("default", stewardID)
}

// filterConfigByModules filters configuration to include only requested modules
func (s *ConfigurationService) filterConfigByModules(config *stewardconfig.StewardConfig, modules []string) *stewardconfig.StewardConfig {
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

// StreamConfigurationUpdates streams configuration updates to stewards
// NOTE: Disabled - gRPC streaming removed. Use MQTT for real-time updates.
func (s *ConfigurationService) StreamConfigurationUpdates(req *controller.ConfigStreamRequest, stream interface{}) error {
	return fmt.Errorf("streaming not supported: gRPC removed, use MQTT for real-time configuration updates")
}

// notifyConfigurationUpdate notifies subscribers of a configuration update
func (s *ConfigurationService) notifyConfigurationUpdate(stewardID string, config *StoredConfiguration) {
	s.mu.RLock()
	updateChan, exists := s.subscribers[stewardID]
	s.mu.RUnlock()

	if !exists {
		return
	}

	configBytes, err := json.Marshal(config.Config)
	if err != nil {
		s.logger.Error("Failed to marshal configuration for update", "error", err)
		return
	}

	update := &controller.ConfigurationUpdate{
		StewardId:  stewardID,
		Config:     configBytes,
		Version:    config.Version,
		Timestamp:  timestamppb.Now(),
		UpdateType: controller.ConfigurationUpdate_UPDATE,
	}

	// Send update non-blocking
	select {
	case updateChan <- update:
		s.logger.Debug("Configuration update sent", "steward_id", stewardID)
	default:
		s.logger.Warn("Configuration update channel full, dropping update", "steward_id", stewardID)
	}
}

// Tenant-aware configuration management methods

// SetTenantConfiguration sets configuration for a steward within a specific tenant
func (s *ConfigurationService) SetTenantConfiguration(tenantID, stewardID string, config *stewardconfig.StewardConfig) error {
	key := s.makeTenantStewardKey(tenantID, stewardID)
	now := time.Now()

	storedConfig := &StoredConfiguration{
		StewardID:   stewardID,
		TenantID:    tenantID,
		Version:     s.generateVersion(),
		Config:      config,
		LastUpdated: now,
	}

	s.mu.Lock()
	existingConfig, exists := s.configurations[key]

	if exists {
		storedConfig.CreatedAt = existingConfig.CreatedAt
	} else {
		storedConfig.CreatedAt = now
	}

	s.configurations[key] = storedConfig
	s.mu.Unlock()

	s.logger.Info("Configuration stored for tenant steward",
		"tenant_id", tenantID,
		"steward_id", stewardID,
		"version", storedConfig.Version)

	// Notify if steward is subscribed (after releasing lock to avoid deadlock)
	s.notifyConfigurationUpdate(stewardID, storedConfig)

	return nil
}

// GetTenantConfiguration retrieves configuration for a steward within a specific tenant
func (s *ConfigurationService) GetTenantConfiguration(tenantID, stewardID string) (*StoredConfiguration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := s.makeTenantStewardKey(tenantID, stewardID)
	config, exists := s.configurations[key]
	if !exists {
		return nil, false
	}

	// Return a copy to prevent external modification
	configCopy := *config
	return &configCopy, true
}

// ListTenantConfigurations lists all configurations for a specific tenant
func (s *ConfigurationService) ListTenantConfigurations(tenantID string) []*StoredConfiguration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var configs []*StoredConfiguration

	for _, config := range s.configurations {
		if config.TenantID == tenantID {
			// Return a copy to prevent external modification
			configCopy := *config
			configs = append(configs, &configCopy)
		}
	}

	return configs
}

// GetEffectiveConfiguration returns the effective configuration for a steward
// after applying inheritance from the tenant hierarchy
func (s *ConfigurationService) GetEffectiveConfiguration(stewardID string) (*EffectiveConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Get steward info to determine tenant hierarchy
	stewardInfo, exists := s.controllerSvc.GetStewardInfo(stewardID)
	if !exists {
		return nil, fmt.Errorf("steward not found: %s", stewardID)
	}

	// For now, implement basic inheritance from tenant config to device config
	// This is a simplified version - full hierarchy will be implemented later

	// Start with device-specific config
	deviceConfig, deviceExists := s.configurations[stewardID]

	// Get tenant-level config as base
	tenantKey := fmt.Sprintf("%s:", stewardInfo.TenantID)
	var tenantConfig *StoredConfiguration
	for key, config := range s.configurations {
		if strings.HasPrefix(key, tenantKey) && config.TenantID == stewardInfo.TenantID {
			tenantConfig = config
			break
		}
	}

	// Build effective configuration
	effective := &EffectiveConfig{
		StewardID:   stewardID,
		TenantID:    stewardInfo.TenantID,
		Resources:   make(map[string]*EffectiveResource),
		Steward:     &EffectiveSection{Values: make(map[string]*EffectiveValue)},
		Modules:     make(map[string]*EffectiveValue),
		GeneratedAt: time.Now(),
	}

	// Apply tenant-level configuration first (base layer)
	if tenantConfig != nil && tenantConfig.Config != nil {
		s.applyConfigurationLayer(effective, tenantConfig, "tenant", 1)
	}

	// Apply device-specific configuration (override layer)
	if deviceExists && deviceConfig.Config != nil {
		s.applyConfigurationLayer(effective, deviceConfig, "device", 3)
	}

	// If no configuration found at any level, return basic structure
	if !deviceExists && tenantConfig == nil {
		s.logger.Debug("No configuration found for steward", "steward_id", stewardID)
	}

	return effective, nil
}

// applyConfigurationLayer applies a configuration layer to the effective config
func (s *ConfigurationService) applyConfigurationLayer(effective *EffectiveConfig, stored *StoredConfiguration, source string, level int) {
	if stored.Config == nil {
		return
	}

	// Apply resources
	for _, resource := range stored.Config.Resources {
		resourceName := resource.Name

		// Create or update resource (declarative - entire resource replaces)
		effective.Resources[resourceName] = &EffectiveResource{
			Name:   resource.Name,
			Module: resource.Module,
			Config: make(map[string]*EffectiveValue),
			Source: source,
			Level:  level,
		}

		// Apply all config values for this resource
		for key, value := range resource.Config {
			effective.Resources[resourceName].Config[key] = &EffectiveValue{
				Value:  value,
				Source: source,
				Level:  level,
			}
		}
	}

	// Apply steward settings
	if stored.Config.Steward.ID != "" {
		effective.Steward.Values["id"] = &EffectiveValue{
			Value:  stored.Config.Steward.ID,
			Source: source,
			Level:  level,
		}
	}

	if stored.Config.Steward.Mode != "" {
		effective.Steward.Values["mode"] = &EffectiveValue{
			Value:  string(stored.Config.Steward.Mode),
			Source: source,
			Level:  level,
		}
	}

	// Apply modules
	for moduleName, modulePath := range stored.Config.Modules {
		effective.Modules[moduleName] = &EffectiveValue{
			Value:  modulePath,
			Source: source,
			Level:  level,
		}
	}
}

// DeleteTenantConfiguration removes configuration for a steward within a specific tenant
func (s *ConfigurationService) DeleteTenantConfiguration(tenantID, stewardID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.makeTenantStewardKey(tenantID, stewardID)
	_, exists := s.configurations[key]
	if exists {
		delete(s.configurations, key)
		s.logger.Info("Configuration deleted for tenant steward",
			"tenant_id", tenantID,
			"steward_id", stewardID)
	}

	return exists
}

// makeTenantStewardKey creates a unique key for tenant-scoped steward configurations
func (s *ConfigurationService) makeTenantStewardKey(tenantID, stewardID string) string {
	return fmt.Sprintf("%s:%s", tenantID, stewardID)
}

// versionCounter ensures unique version strings without relying on time-based uniqueness
var versionCounter atomic.Int64

// generateVersion generates a new version string
func (s *ConfigurationService) generateVersion() string {
	return fmt.Sprintf("v%d.%d", time.Now().Unix(), versionCounter.Add(1))
}

// extractTenantID extracts tenant ID from context
func (s *ConfigurationService) extractTenantID(ctx context.Context) string {
	// Extract tenant ID from context value (set by MQTT/HTTP handlers)
	if tenantID, ok := ctx.Value("tenant-id").(string); ok && tenantID != "" {
		return tenantID
	}

	s.logger.Debug("No tenant-id in context, using default tenant")
	return "default"
}
