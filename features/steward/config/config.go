package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// StewardConfig represents the complete steward configuration
type StewardConfig struct {
	Steward   StewardSettings      `yaml:"steward"`
	Resources []ResourceConfig     `yaml:"resources"`
	Modules   map[string]string    `yaml:"modules,omitempty"` // module_name -> custom_path
}

// StewardSettings contains steward-specific configuration
type StewardSettings struct {
	ID           string              `yaml:"id"`
	Mode         OperationMode       `yaml:"mode"`
	ModulePaths  []string           `yaml:"module_paths,omitempty"`
	Logging      LoggingConfig      `yaml:"logging"`
	ErrorHandling ErrorHandlingConfig `yaml:"error_handling"`
}

// ResourceConfig defines a single resource to be managed
type ResourceConfig struct {
	Name     string                 `yaml:"name"`
	Module   string                 `yaml:"module"`
	Config   map[string]interface{} `yaml:"config"`
}

// OperationMode defines how the steward operates
type OperationMode string

const (
	ModeStandalone  OperationMode = "standalone"
	ModeController  OperationMode = "controller"
)

// LoggingConfig defines logging settings
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// ErrorHandlingConfig defines error handling behavior
type ErrorHandlingConfig struct {
	ModuleLoadFailure   ErrorAction `yaml:"module_load_failure"`
	ResourceFailure     ErrorAction `yaml:"resource_failure"`
	ConfigurationError  ErrorAction `yaml:"configuration_error"`
}

// ErrorAction defines how to handle errors
type ErrorAction string

const (
	ActionContinue ErrorAction = "continue"
	ActionFail     ErrorAction = "fail"
	ActionWarn     ErrorAction = "warn"
)

// LoadConfiguration searches for and loads the steward configuration
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