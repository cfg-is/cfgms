package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/validation"
	"github.com/cfgis/cfgms/pkg/logging"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ConfigurationService implements the Configuration gRPC service
type ConfigurationService struct {
	controller.UnimplementedConfigurationServiceServer
	
	logger        logging.Logger
	mu            sync.RWMutex
	configurations map[string]*StoredConfiguration
	controllerSvc *ControllerService
	validator     *validation.Validator
	
	// Configuration streaming
	subscribers map[string]chan *controller.ConfigurationUpdate
}

// StoredConfiguration represents a configuration stored in the controller
type StoredConfiguration struct {
	StewardID     string
	Version       string
	Config        *stewardconfig.StewardConfig
	LastUpdated   time.Time
	CreatedAt     time.Time
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
	s.logger.Debug("Configuration request received", "steward_id", req.StewardId, "modules", req.Modules)
	
	// Verify steward exists
	if s.controllerSvc != nil {
		if _, exists := s.controllerSvc.GetStewardInfo(req.StewardId); !exists {
			s.logger.Warn("Configuration request from unknown steward", "steward_id", req.StewardId)
			return &controller.ConfigResponse{
				Status: &common.Status{
					Code:    common.Status_NOT_FOUND,
					Message: "Steward not found",
				},
			}, nil
		}
	}
	
	s.mu.RLock()
	storedConfig, exists := s.configurations[req.StewardId]
	s.mu.RUnlock()
	
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
	
	s.logger.Debug("Configuration retrieved successfully", "steward_id", req.StewardId, "version", storedConfig.Version)
	
	return &controller.ConfigResponse{
		Status: &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration retrieved successfully",
		},
		Config:  configData,
		Version: storedConfig.Version,
	}, nil
}

// ReportConfigStatus handles configuration status reports from stewards
func (s *ConfigurationService) ReportConfigStatus(ctx context.Context, req *controller.ConfigStatusReport) (*common.Status, error) {
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
			"validation_duration": validationResult.Duration.String(),
			"validation_timestamp": validationResult.StartTime.Format(time.RFC3339),
			"total_issues": fmt.Sprintf("%d", len(validationResult.Issues)),
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
	s.mu.Lock()
	defer s.mu.Unlock()
	
	version := fmt.Sprintf("v%d", time.Now().Unix())
	now := time.Now()
	
	// Create or update stored configuration
	storedConfig := &StoredConfiguration{
		StewardID:   stewardID,
		Version:     version,
		Config:      config,
		LastUpdated: now,
	}
	
	if existing, exists := s.configurations[stewardID]; exists {
		storedConfig.CreatedAt = existing.CreatedAt
	} else {
		storedConfig.CreatedAt = now
	}
	
	s.configurations[stewardID] = storedConfig
	
	s.logger.Info("Configuration stored", "steward_id", stewardID, "version", version)
	
	// Notify subscribers of the update
	s.notifyConfigurationUpdate(stewardID, storedConfig)
	
	return nil
}

// GetStoredConfiguration retrieves a stored configuration
func (s *ConfigurationService) GetStoredConfiguration(stewardID string) (*StoredConfiguration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	config, exists := s.configurations[stewardID]
	return config, exists
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
func (s *ConfigurationService) StreamConfigurationUpdates(req *controller.ConfigStreamRequest, stream controller.ConfigurationService_StreamConfigurationUpdatesServer) error {
	s.logger.Debug("Configuration stream request received", "steward_id", req.StewardId, "modules", req.Modules)
	
	// Verify steward exists
	if s.controllerSvc != nil {
		if _, exists := s.controllerSvc.GetStewardInfo(req.StewardId); !exists {
			return fmt.Errorf("steward %s not found", req.StewardId)
		}
	}
	
	// Create subscriber channel
	s.mu.Lock()
	updateChan := make(chan *controller.ConfigurationUpdate, 10)
	s.subscribers[req.StewardId] = updateChan
	s.mu.Unlock()
	
	// Clean up subscriber when done
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, req.StewardId)
		close(updateChan)
		s.mu.Unlock()
	}()
	
	// Send initial configuration if it exists
	s.mu.RLock()
	storedConfig, exists := s.configurations[req.StewardId]
	s.mu.RUnlock()
	
	if exists {
		// Filter configuration by modules if specified
		var configBytes []byte
		var err error
		
		if len(req.Modules) > 0 {
			filtered := s.filterConfigByModules(storedConfig.Config, req.Modules)
			configBytes, err = json.Marshal(filtered)
		} else {
			configBytes, err = json.Marshal(storedConfig.Config)
		}
		
		if err != nil {
			s.logger.Error("Failed to marshal configuration", "error", err)
			return fmt.Errorf("failed to marshal configuration: %w", err)
		}
		
		initialUpdate := &controller.ConfigurationUpdate{
			StewardId:  req.StewardId,
			Config:     configBytes,
			Version:    storedConfig.Version,
			Timestamp:  timestamppb.Now(),
			UpdateType: controller.ConfigurationUpdate_INITIAL,
		}
		
		if err := stream.Send(initialUpdate); err != nil {
			s.logger.Error("Failed to send initial configuration", "error", err)
			return fmt.Errorf("failed to send initial configuration: %w", err)
		}
		
		s.logger.Debug("Initial configuration sent", "steward_id", req.StewardId)
	}
	
	// Listen for updates
	for {
		select {
		case update, ok := <-updateChan:
			if !ok {
				return nil
			}
			
			// Filter by modules if specified
			if len(req.Modules) > 0 {
				// Parse the configuration to filter it
				var config stewardconfig.StewardConfig
				if err := json.Unmarshal(update.Config, &config); err == nil {
					filtered := s.filterConfigByModules(&config, req.Modules)
					if filteredBytes, err := json.Marshal(filtered); err == nil {
						update.Config = filteredBytes
					}
				}
			}
			
			if err := stream.Send(update); err != nil {
				s.logger.Error("Failed to send configuration update", "error", err)
				return fmt.Errorf("failed to send configuration update: %w", err)
			}
			
		case <-stream.Context().Done():
			s.logger.Debug("Configuration stream context done", "steward_id", req.StewardId)
			return nil
		}
	}
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