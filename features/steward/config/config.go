// Package config provides configuration loading and validation for standalone steward operation.
//
// This package handles hostname.cfg files that define steward settings, resource
// configurations, and error handling policies for standalone mode operation.
//
// Configuration files are searched in platform-specific locations:
//   - Current working directory (highest priority)
//   - User configuration directories
//   - System configuration directories
//
// Basic usage:
//
//	// Load configuration from default search paths
//	config, err := config.LoadConfiguration("")
//	if err != nil {
//		return fmt.Errorf("failed to load config: %w", err)
//	}
//
//	// Get list of required modules
//	modules := config.GetConfiguredModules(config)
//
//	// Validate configuration
//	if err := config.ValidateConfiguration(config); err != nil {
//		return fmt.Errorf("invalid config: %w", err)
//	}
//
// Configuration file format (YAML):
//
//	steward:
//	  id: hostname
//	  mode: standalone
//	  logging:
//	    level: info
//	    format: text
//	  error_handling:
//	    module_load_failure: continue
//	    resource_failure: warn
//	    configuration_error: fail
//
//	resources:
//	  - name: example-directory
//	    module: directory
//	    config:
//	      path: /opt/example
//	      permissions: 755
//
// #nosec G304 - Steward configuration system requires file access for loading config files
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// StewardConfig represents the complete steward configuration loaded from hostname.cfg.
//
// This is the root configuration structure that contains all settings needed
// for standalone steward operation, including steward-specific settings,
// resource definitions, and optional module path mappings.
type StewardConfig struct {
	// Steward contains steward-specific configuration settings
	Steward StewardSettings `yaml:"steward"`

	// Resources defines the list of resources to be managed
	Resources []ResourceConfig `yaml:"resources"`

	// Modules provides optional custom paths for specific modules
	Modules map[string]string `yaml:"modules,omitempty"` // module_name -> custom_path
}

// StewardSettings contains steward-specific configuration options.
//
// These settings control steward behavior, logging, error handling,
// and module discovery paths.
type StewardSettings struct {
	// ID is the unique identifier for this steward instance
	ID string `yaml:"id"`

	// Mode defines the operation mode (standalone or controller)
	Mode OperationMode `yaml:"mode"`

	// ModulePaths lists additional directories to search for modules
	ModulePaths []string `yaml:"module_paths,omitempty"`

	// Logging configures log output format and verbosity
	Logging LoggingConfig `yaml:"logging"`

	// ErrorHandling defines how to handle various error conditions
	ErrorHandling ErrorHandlingConfig `yaml:"error_handling"`
}

// ResourceConfig defines a single resource to be managed by the steward.
//
// Each resource specifies which module should manage it and provides
// module-specific configuration data.
type ResourceConfig struct {
	// Name is the unique identifier for this resource
	Name string `yaml:"name"`

	// Module is the name of the module that will manage this resource
	Module string `yaml:"module"`

	// Config contains module-specific configuration data
	Config map[string]interface{} `yaml:"config"`
}

// OperationMode defines how the steward operates.
type OperationMode string

const (
	// ModeStandalone operates using local configuration files and modules
	ModeStandalone OperationMode = "standalone"

	// ModeController connects to a remote CFGMS controller (legacy)
	ModeController OperationMode = "controller"
)

// LoggingConfig defines logging output settings.
type LoggingConfig struct {
	// Level sets the logging verbosity (debug, info, warn, error)
	Level string `yaml:"level"`

	// Format sets the log output format (text, json)
	Format string `yaml:"format"`
}

// ErrorHandlingConfig defines how to handle various error conditions.
//
// Each error type can be configured to continue (log and proceed),
// warn (log warning and proceed), or fail (log error and stop).
type ErrorHandlingConfig struct {
	// ModuleLoadFailure defines how to handle module loading errors
	ModuleLoadFailure ErrorAction `yaml:"module_load_failure"`

	// ResourceFailure defines how to handle resource execution errors
	ResourceFailure ErrorAction `yaml:"resource_failure"`

	// ConfigurationError defines how to handle configuration validation errors
	ConfigurationError ErrorAction `yaml:"configuration_error"`
}

// ErrorAction defines the available error handling strategies.
type ErrorAction string

const (
	// ActionContinue logs the error and continues execution
	ActionContinue ErrorAction = "continue"

	// ActionFail logs the error and stops execution
	ActionFail ErrorAction = "fail"

	// ActionWarn logs a warning and continues execution
	ActionWarn ErrorAction = "warn"
)

// LoadConfiguration searches for and loads the steward configuration from hostname.cfg.
//
// If configPath is empty, searches platform-specific locations for hostname.cfg
// using the current hostname. If configPath is provided, loads from that specific file.
//
// Configuration search order (when configPath is empty):
//  1. Current working directory/hostname.cfg
//  2. User configuration directories
//  3. System configuration directories
//
// The function automatically applies defaults for optional fields and validates
// the complete configuration before returning.
//
// Returns the loaded and validated configuration, or an error if no configuration
// is found, parsing fails, or validation fails.
func LoadConfiguration(configPath string) (StewardConfig, error) {
	var config StewardConfig

	// If specific path provided, use it
	if configPath != "" {
		return loadFromPath(configPath)
	}

	// Search for configuration file in priority order
	searchPaths := getConfigSearchPaths()

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return loadFromPath(path)
		}
	}

	return config, fmt.Errorf("no configuration file found in search paths")
}

// loadFromPath loads configuration from a specific file path
func loadFromPath(configPath string) (StewardConfig, error) {
	var config StewardConfig

	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("failed to parse configuration: %w", err)
	}

	// Apply defaults
	applyDefaults(&config)

	// Validate configuration
	if err := ValidateConfiguration(config); err != nil {
		return config, fmt.Errorf("configuration validation failed: %w", err)
	}

	return config, nil
}

// getConfigSearchPaths returns the prioritized list of configuration search paths
func getConfigSearchPaths() []string {
	var paths []string

	// Get hostname for the config file name
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost"
	}
	configFileName := hostname + ".cfg"

	// Current working directory (highest priority)
	if cwd, err := os.Getwd(); err == nil {
		paths = append(paths, filepath.Join(cwd, configFileName))
	}

	// Platform-specific paths
	switch runtime.GOOS {
	case "windows":
		// Windows: ProgramData and user profile
		if programData := os.Getenv("PROGRAMDATA"); programData != "" {
			paths = append(paths, filepath.Join(programData, "cfgms", configFileName))
		}
		if userProfile := os.Getenv("USERPROFILE"); userProfile != "" {
			paths = append(paths, filepath.Join(userProfile, ".cfgms", configFileName))
		}

	case "darwin":
		// macOS: system and user Library
		paths = append(paths,
			filepath.Join("/Library", "Application Support", "cfgms", configFileName),
			filepath.Join("/usr", "local", "etc", "cfgms", configFileName),
		)
		if homeDir := os.Getenv("HOME"); homeDir != "" {
			paths = append(paths,
				filepath.Join(homeDir, "Library", "Application Support", "cfgms", configFileName),
				filepath.Join(homeDir, ".cfgms", configFileName),
			)
		}

	case "linux":
		// Linux: standard system and user paths
		paths = append(paths,
			filepath.Join("/etc", "cfgms", configFileName),
			filepath.Join("/usr", "local", "etc", "cfgms", configFileName),
		)
		if homeDir := os.Getenv("HOME"); homeDir != "" {
			paths = append(paths,
				filepath.Join(homeDir, ".config", "cfgms", configFileName),
				filepath.Join(homeDir, ".cfgms", configFileName),
			)
		}
	}

	return paths
}

// applyDefaults sets default values for configuration fields
func applyDefaults(config *StewardConfig) {
	// Set default steward settings
	if config.Steward.Mode == "" {
		config.Steward.Mode = ModeStandalone
	}

	if config.Steward.Logging.Level == "" {
		config.Steward.Logging.Level = "info"
	}

	if config.Steward.Logging.Format == "" {
		config.Steward.Logging.Format = "text"
	}

	// Set default error handling
	if config.Steward.ErrorHandling.ModuleLoadFailure == "" {
		config.Steward.ErrorHandling.ModuleLoadFailure = ActionContinue
	}

	if config.Steward.ErrorHandling.ResourceFailure == "" {
		config.Steward.ErrorHandling.ResourceFailure = ActionWarn
	}

	if config.Steward.ErrorHandling.ConfigurationError == "" {
		config.Steward.ErrorHandling.ConfigurationError = ActionFail
	}

	// Set default steward ID if not provided
	if config.Steward.ID == "" {
		if hostname, err := os.Hostname(); err == nil {
			config.Steward.ID = hostname
		} else {
			config.Steward.ID = "unknown"
		}
	}
}

// ValidateConfiguration checks if the configuration is valid
func ValidateConfiguration(config StewardConfig) error {
	// Validate steward settings
	if config.Steward.ID == "" {
		return fmt.Errorf("steward ID is required")
	}

	// Validate operation mode
	switch config.Steward.Mode {
	case ModeStandalone, ModeController:
		// Valid modes
	default:
		return fmt.Errorf("invalid operation mode: %s", config.Steward.Mode)
	}

	// Validate logging level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	isValidLevel := false
	for _, level := range validLogLevels {
		if config.Steward.Logging.Level == level {
			isValidLevel = true
			break
		}
	}
	if !isValidLevel {
		return fmt.Errorf("invalid log level: %s", config.Steward.Logging.Level)
	}

	// Validate resources
	resourceNames := make(map[string]bool)
	for i, resource := range config.Resources {
		if resource.Name == "" {
			return fmt.Errorf("resource %d: name is required", i)
		}

		if resource.Module == "" {
			return fmt.Errorf("resource %s: module is required", resource.Name)
		}

		if resourceNames[resource.Name] {
			return fmt.Errorf("duplicate resource name: %s", resource.Name)
		}
		resourceNames[resource.Name] = true

		if resource.Config == nil {
			return fmt.Errorf("resource %s: config is required", resource.Name)
		}
	}

	return nil
}

// GetConfiguredModules returns a list of module names required by the configuration
func GetConfiguredModules(config StewardConfig) []string {
	moduleSet := make(map[string]bool)

	for _, resource := range config.Resources {
		moduleSet[resource.Module] = true
	}

	modules := make([]string, 0, len(moduleSet))
	for module := range moduleSet {
		modules = append(modules, module)
	}

	return modules
}
