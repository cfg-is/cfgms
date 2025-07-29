package intune_policy

import (
	"context"
	"fmt"
	"strings"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/modules/m365/auth"
	"github.com/cfgis/cfgms/features/modules/m365/graph"
	"gopkg.in/yaml.v3"
)

// intunePolicyModule implements the Module interface for Intune device configuration management
type intunePolicyModule struct {
	authProvider auth.Provider
	graphClient  graph.Client
}

// New creates a new instance of the Intune Policy module
func New(authProvider auth.Provider, graphClient graph.Client) modules.Module {
	return &intunePolicyModule{
		authProvider: authProvider,
		graphClient:  graphClient,
	}
}

// IntunePolicyConfig represents the configuration for an Intune device configuration policy
type IntunePolicyConfig struct {
	// Basic policy properties
	DisplayName             string `yaml:"display_name"`
	Description             string `yaml:"description"`
	DeviceConfigurationType string `yaml:"device_configuration_type"` // Type of configuration (e.g., windows10GeneralConfiguration)
	
	// Policy settings - flexible structure to accommodate different policy types
	Settings map[string]interface{} `yaml:"settings"`
	
	// Assignments - which groups/users this policy applies to
	Assignments []PolicyAssignment `yaml:"assignments,omitempty"`
	
	// Tenant configuration
	TenantID string `yaml:"tenant_id"`
	
	// Managed fields - controls which fields Set() will modify
	ManagedFieldsList []string `yaml:"managed_fields,omitempty"`
}

// PolicyAssignment represents an assignment of a policy to groups or users
type PolicyAssignment struct {
	// Target specifies what this assignment targets
	Target PolicyAssignmentTarget `yaml:"target"`
	
	// Intent specifies the assignment intent (required, available, etc.)
	Intent string `yaml:"intent,omitempty"` // apply, remove
	
	// Settings for the assignment
	Settings *PolicyAssignmentSettings `yaml:"settings,omitempty"`
}

// PolicyAssignmentTarget specifies the target of an assignment
type PolicyAssignmentTarget struct {
	// TargetType specifies the type of target (allUsers, allDevices, groupAssignmentTarget, etc.)
	TargetType string `yaml:"target_type"`
	
	// GroupID for group-based assignments
	GroupID string `yaml:"group_id,omitempty"`
	
	// IncludeGroups for inclusion-based assignments
	IncludeGroups []string `yaml:"include_groups,omitempty"`
	
	// ExcludeGroups for exclusion-based assignments
	ExcludeGroups []string `yaml:"exclude_groups,omitempty"`
}

// PolicyAssignmentSettings contains settings for policy assignments
type PolicyAssignmentSettings struct {
	// DeviceAndAppManagementAssignmentFilterType
	FilterType string `yaml:"filter_type,omitempty"` // none, include, exclude
	
	// DeviceAndAppManagementAssignmentFilterId
	FilterID string `yaml:"filter_id,omitempty"`
	
	// Additional settings as needed
	AdditionalSettings map[string]interface{} `yaml:"additional_settings,omitempty"`
}

// Common Intune policy types
const (
	// Windows 10 configuration types
	Windows10GeneralConfiguration           = "microsoft.graph.windows10GeneralConfiguration"
	Windows10EndpointProtectionConfiguration = "microsoft.graph.windows10EndpointProtectionConfiguration"
	Windows10SecureAssessmentConfiguration   = "microsoft.graph.windows10SecureAssessmentConfiguration"
	
	// macOS configuration types
	MacOSGeneralDeviceConfiguration         = "microsoft.graph.macOSGeneralDeviceConfiguration"
	MacOSDeviceFeaturesConfiguration       = "microsoft.graph.macOSDeviceFeaturesConfiguration"
	
	// iOS configuration types
	IosGeneralDeviceConfiguration          = "microsoft.graph.iosGeneralDeviceConfiguration"
	IosDeviceFeaturesConfiguration         = "microsoft.graph.iosDeviceFeaturesConfiguration"
	
	// Android configuration types
	AndroidGeneralDeviceConfiguration      = "microsoft.graph.androidGeneralDeviceConfiguration"
	AndroidWorkProfileGeneralDeviceConfiguration = "microsoft.graph.androidWorkProfileGeneralDeviceConfiguration"
)

// AsMap returns the configuration as a map for efficient field-by-field comparison
func (c *IntunePolicyConfig) AsMap() map[string]interface{} {
	result := map[string]interface{}{
		"display_name":               c.DisplayName,
		"description":                c.Description,
		"device_configuration_type":  c.DeviceConfigurationType,
		"settings":                   c.Settings,
		"tenant_id":                  c.TenantID,
	}
	
	if len(c.Assignments) > 0 {
		result["assignments"] = c.Assignments
	}
	
	return result
}

// ToYAML serializes the configuration to YAML for export/storage
func (c *IntunePolicyConfig) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

// FromYAML deserializes YAML data into the configuration
func (c *IntunePolicyConfig) FromYAML(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Validate ensures the configuration is valid
func (c *IntunePolicyConfig) Validate() error {
	if c.DisplayName == "" {
		return fmt.Errorf("display_name is required")
	}
	
	if c.DeviceConfigurationType == "" {
		return fmt.Errorf("device_configuration_type is required")
	}
	
	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	
	if c.Settings == nil || len(c.Settings) == 0 {
		return fmt.Errorf("settings cannot be empty")
	}
	
	// Validate assignments
	for i, assignment := range c.Assignments {
		if err := c.validateAssignment(assignment); err != nil {
			return fmt.Errorf("invalid assignment at index %d: %w", i, err)
		}
	}
	
	return nil
}

// validateAssignment validates a single policy assignment
func (c *IntunePolicyConfig) validateAssignment(assignment PolicyAssignment) error {
	if assignment.Target.TargetType == "" {
		return fmt.Errorf("target.target_type is required")
	}
	
	validTargetTypes := []string{
		"allUsers", "allDevices", "groupAssignmentTarget", 
		"exclusionGroupAssignmentTarget", "configurationManagerCollectionAssignmentTarget",
	}
	
	if !contains(validTargetTypes, assignment.Target.TargetType) {
		return fmt.Errorf("invalid target_type: %s, must be one of: %v", assignment.Target.TargetType, validTargetTypes)
	}
	
	// Validate group-specific assignments
	if assignment.Target.TargetType == "groupAssignmentTarget" || assignment.Target.TargetType == "exclusionGroupAssignmentTarget" {
		if assignment.Target.GroupID == "" && len(assignment.Target.IncludeGroups) == 0 {
			return fmt.Errorf("group_id or include_groups must be specified for group-based assignments")
		}
	}
	
	return nil
}

// GetManagedFields returns the list of fields this configuration manages
func (c *IntunePolicyConfig) GetManagedFields() []string {
	// If explicitly specified, use those fields
	if len(c.ManagedFieldsList) > 0 {
		return c.ManagedFieldsList
	}
	
	// Default managed fields
	fields := []string{"display_name", "description", "settings"}
	
	if len(c.Assignments) > 0 {
		fields = append(fields, "assignments")
	}
	
	return fields
}

// Set creates or updates an Intune device configuration policy according to the configuration
func (m *intunePolicyModule) Set(ctx context.Context, resourceID string, config modules.ConfigState) error {
	// Convert ConfigState to IntunePolicyConfig
	configMap := config.AsMap()
	intuneConfig := &IntunePolicyConfig{}
	
	// Map basic fields
	if displayName, ok := configMap["display_name"].(string); ok {
		intuneConfig.DisplayName = displayName
	}
	if description, ok := configMap["description"].(string); ok {
		intuneConfig.Description = description
	}
	if deviceConfigType, ok := configMap["device_configuration_type"].(string); ok {
		intuneConfig.DeviceConfigurationType = deviceConfigType
	}
	if tenantID, ok := configMap["tenant_id"].(string); ok {
		intuneConfig.TenantID = tenantID
	}
	
	// Map settings
	if settings, ok := configMap["settings"].(map[string]interface{}); ok {
		intuneConfig.Settings = settings
	}
	
	// Map assignments
	if assignments, ok := configMap["assignments"].([]PolicyAssignment); ok {
		intuneConfig.Assignments = assignments
	}
	
	// Validate configuration
	if err := intuneConfig.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, intuneConfig.TenantID)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}
	
	// Parse configuration ID from resource ID if provided
	configurationID := extractConfigurationID(resourceID)
	
	// Check if configuration exists
	var existingConfig *graph.DeviceConfiguration
	if configurationID != "" {
		existingConfig, err = m.graphClient.GetDeviceConfiguration(ctx, token, configurationID)
		if err != nil {
			if !graph.IsNotFoundError(err) {
				return fmt.Errorf("failed to check if configuration exists: %w", err)
			}
			// Configuration doesn't exist, we'll create it
		}
	}
	
	if existingConfig == nil {
		// Create new configuration
		return m.createConfiguration(ctx, token, intuneConfig)
	}
	
	// Update existing configuration with only managed fields
	return m.updateConfiguration(ctx, token, intuneConfig, existingConfig)
}

// Get retrieves the current configuration of an Intune device configuration policy
func (m *intunePolicyModule) Get(ctx context.Context, resourceID string) (modules.ConfigState, error) {
	// Parse resource ID to extract tenant ID and configuration ID
	// Format: tenantID:configurationID
	tenantID, configurationID, err := parseIntuneResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid resource ID format: %w", err)
	}
	
	// Authenticate with Microsoft Graph
	token, err := m.authProvider.GetAccessToken(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with Microsoft Graph: %w", err)
	}
	
	// Get configuration from Graph API
	deviceConfig, err := m.graphClient.GetDeviceConfiguration(ctx, token, configurationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get configuration from Graph API: %w", err)
	}
	
	// Convert Graph configuration to our config format
	config := &IntunePolicyConfig{
		DisplayName:             deviceConfig.DisplayName,
		Description:             deviceConfig.Description,
		DeviceConfigurationType: deviceConfig.DeviceConfigurationType,
		Settings:                deviceConfig.Settings,
		TenantID:                tenantID,
		// Note: Assignments would need separate API calls to retrieve
	}
	
	return config, nil
}

// createConfiguration creates a new Intune device configuration policy
func (m *intunePolicyModule) createConfiguration(ctx context.Context, token *auth.AccessToken, config *IntunePolicyConfig) error {
	request := &graph.CreateDeviceConfigurationRequest{
		DeviceConfigurationType: config.DeviceConfigurationType,
		DisplayName:            config.DisplayName,
		Description:            config.Description,
		Settings:               config.Settings,
	}
	
	// Create the configuration
	deviceConfig, err := m.graphClient.CreateDeviceConfiguration(ctx, token, request)
	if err != nil {
		return fmt.Errorf("failed to create configuration: %w", err)
	}
	
	// Apply assignments if specified
	if len(config.Assignments) > 0 {
		if err := m.assignConfiguration(ctx, token, deviceConfig.ID, config.Assignments); err != nil {
			return fmt.Errorf("failed to assign configuration: %w", err)
		}
	}
	
	return nil
}

// updateConfiguration updates an existing Intune device configuration policy with only the managed fields
func (m *intunePolicyModule) updateConfiguration(ctx context.Context, token *auth.AccessToken, config *IntunePolicyConfig, existingConfig *graph.DeviceConfiguration) error {
	managedFields := config.GetManagedFields()
	updateRequest := &graph.UpdateDeviceConfigurationRequest{}
	
	// Only update managed fields
	for _, field := range managedFields {
		switch field {
		case "display_name":
			if config.DisplayName != existingConfig.DisplayName {
				updateRequest.DisplayName = &config.DisplayName
			}
		case "description":
			if config.Description != existingConfig.Description {
				updateRequest.Description = &config.Description
			}
		case "settings":
			// Always update settings if managed (complex comparison would be needed for partial updates)
			updateRequest.Settings = config.Settings
		}
	}
	
	// Update the configuration if there are changes
	if updateRequest.DisplayName != nil || updateRequest.Description != nil || updateRequest.Settings != nil {
		if err := m.graphClient.UpdateDeviceConfiguration(ctx, token, existingConfig.ID, updateRequest); err != nil {
			return fmt.Errorf("failed to update configuration: %w", err)
		}
	}
	
	// Handle assignments if managed
	if contains(managedFields, "assignments") && len(config.Assignments) > 0 {
		if err := m.assignConfiguration(ctx, token, existingConfig.ID, config.Assignments); err != nil {
			return fmt.Errorf("failed to update configuration assignments: %w", err)
		}
	}
	
	return nil
}

// assignConfiguration assigns the configuration to the specified targets
func (m *intunePolicyModule) assignConfiguration(ctx context.Context, token *auth.AccessToken, configurationID string, assignments []PolicyAssignment) error {
	// Note: In a real implementation, this would use the Graph API assignments endpoint
	// For now, this is a placeholder that demonstrates the structure
	
	for _, assignment := range assignments {
		// Convert our assignment format to Graph API format and make assignment calls
		// This would involve calling something like:
		// POST /deviceManagement/deviceConfigurations/{id}/assign
		
		// Placeholder logging
		fmt.Printf("Assigning configuration %s to target type %s\n", configurationID, assignment.Target.TargetType)
		
		// In real implementation:
		// - Build assignment request based on assignment.Target
		// - Call Graph API to create assignment
		// - Handle assignment-specific errors
	}
	
	return nil
}

// parseIntuneResourceID parses a resource ID into tenant ID and configuration ID
// Format: tenantID:configurationID
func parseIntuneResourceID(resourceID string) (tenantID, configurationID string, err error) {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("resource ID must be in format 'tenantID:configurationID'")
	}
	return parts[0], parts[1], nil
}

// extractConfigurationID extracts configuration ID from resource ID (may be empty for new configurations)
func extractConfigurationID(resourceID string) string {
	parts := strings.SplitN(resourceID, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// GetPolicyTemplates returns common policy templates for different platforms
func GetPolicyTemplates() map[string]IntunePolicyConfig {
	return map[string]IntunePolicyConfig{
		"windows10_security_baseline": {
			DisplayName:             "Windows 10 Security Baseline",
			Description:             "Basic security configuration for Windows 10 devices",
			DeviceConfigurationType: Windows10GeneralConfiguration,
			Settings: map[string]interface{}{
				"passwordRequired":                    true,
				"passwordMinimumLength":               8,
				"passwordRequiredType":                "alphanumeric",
				"passwordPreviousPasswordBlockCount":  5,
				"passwordMinimumCharacterSetCount":    2,
				"passwordExpirationDays":              90,
				"passwordMinutesOfInactivityBeforeScreenTimeout": 15,
				"passwordSignInFailureCountBeforeFactoryReset":   10,
				"defenderRequireRealTimeMonitoring":   true,
				"defenderRequireBehaviorMonitoring":   true,
				"defenderRequireNetworkInspectionSystem": true,
				"defenderScanDownloads":               true,
				"defenderScheduleScanDay":             "everyday",
				"defenderScanType":                    "quick",
				"defenderSystemScanSchedule":          "userDefined",
				"smartScreenEnabled":                  true,
				"smartScreenBlockPromptOverride":      true,
				"smartScreenBlockPromptOverrideForFiles": true,
				"storageBlockRemovableStorage":        false,
				"storageRequireMobileDeviceEncryption": true,
			},
		},
		"macos_security_baseline": {
			DisplayName:             "macOS Security Baseline",
			Description:             "Basic security configuration for macOS devices",
			DeviceConfigurationType: MacOSGeneralDeviceConfiguration,
			Settings: map[string]interface{}{
				"passwordRequired":                    true,
				"passwordMinimumLength":               8,
				"passwordRequiredType":                "alphanumeric",
				"passwordPreviousPasswordBlockCount":  5,
				"passwordMinimumCharacterSetCount":    2,
				"passwordExpirationDays":              90,
				"passwordMinutesOfInactivityBeforeScreenTimeout": 15,
				"passwordSignInFailureCountBeforeWipe": 10,
				"systemIntegrityProtectionEnabled":    true,
				"firewallEnabled":                     true,
				"firewallBlockAllIncoming":            false,
				"firewallEnableStealthMode":           true,
				"gatekeeperAllowedAppSource":          "macAppStoreAndIdentifiedDevelopers",
			},
		},
		"ios_security_baseline": {
			DisplayName:             "iOS Security Baseline",
			Description:             "Basic security configuration for iOS devices",
			DeviceConfigurationType: IosGeneralDeviceConfiguration,
			Settings: map[string]interface{}{
				"passcodeRequired":                    true,
				"passcodeMinimumLength":               6,
				"passcodeRequiredType":                "numeric",
				"passcodePreviousPasscodeBlockCount":  5,
				"passcodeMinimumCharacterSetCount":    1,
				"passcodeExpirationDays":              90,
				"passcodeMinutesOfInactivityBeforeScreenTimeout": 15,
				"passcodeSignInFailureCountBeforeWipe": 10,
				"touchIdTimeoutInHours":               48,
				"faceIdBlocked":                       false,
				"appStoreBlockAutomaticDownloads":     false,
				"appStoreBlocked":                     false,
				"appStoreBlockUIAppInstallation":      false,
				"appStoreRequirePassword":             "always",
				"bluetoothBlockModification":          false,
				"cameraBlocked":                       false,
				"cellularBlockDataRoaming":            true,
				"cellularBlockGlobalBackgroundFetchWhileRoaming": true,
			},
		},
		"android_security_baseline": {
			DisplayName:             "Android Security Baseline",
			Description:             "Basic security configuration for Android devices",
			DeviceConfigurationType: AndroidGeneralDeviceConfiguration,
			Settings: map[string]interface{}{
				"passwordRequired":                    true,
				"passwordMinimumLength":               6,
				"passwordRequiredType":                "numeric",
				"passwordPreviousPasswordBlockCount":  5,
				"passwordExpirationDays":              90,
				"passwordMinutesOfInactivityBeforeScreenTimeout": 15,
				"passwordSignInFailureCountBeforeFactoryReset": 10,
				"storageRequireDeviceEncryption":      true,
				"storageRequireRemovableStorageEncryption": true,
				"securityRequireVerifyApps":           true,
				"deviceCompliancePolicyScript":        nil,
				"securityBlockJailbrokenDevices":      true,
				"locationServicesBlocked":             false,
				"googleAccountsBlocked":               false,
				"googlePlayStoreBlocked":              false,
				"kioskModeBlockSleepButton":           false,
				"kioskModeBlockVolumeButtons":         false,
			},
		},
	}
}