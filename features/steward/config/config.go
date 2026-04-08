// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
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
	"regexp"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

// envVarPattern matches ${VAR} patterns without defaults
// It excludes ${VAR:-default} and ${VAR:=default} patterns
var envVarPattern = regexp.MustCompile(`\$\{([^}:]+)\}`)

// envVarWithDefaultPattern matches ${VAR:-default} and ${VAR:=default} patterns
var envVarWithDefaultPattern = regexp.MustCompile(`\$\{([^}:]+):-([^}]*)\}`)

// validateEnvVars checks that all referenced environment variables (without defaults) are set.
// This provides fail-safe behavior: if a config references ${VAR} and VAR is not set,
// the application fails fast instead of silently using an empty value.
func validateEnvVars(content string) error {
	matches := envVarPattern.FindAllStringSubmatch(content, -1)
	var missing []string

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		varName := match[1]
		if _, exists := os.LookupEnv(varName); !exists {
			missing = append(missing, varName)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %v (use ${VAR:-default} syntax to provide defaults)", missing)
	}

	return nil
}

// expandEnvWithDefaults expands environment variables with support for ${VAR:-default} syntax.
// This extends Go's os.ExpandEnv to support shell-style defaults.
func expandEnvWithDefaults(content string) string {
	// First, expand ${VAR:-default} patterns
	result := envVarWithDefaultPattern.ReplaceAllStringFunc(content, func(match string) string {
		parts := envVarWithDefaultPattern.FindStringSubmatch(match)
		if len(parts) < 3 {
			return match
		}
		varName := parts[1]
		defaultValue := parts[2]
		if value, exists := os.LookupEnv(varName); exists {
			return value
		}
		return defaultValue
	})

	// Then expand remaining ${VAR} patterns using os.ExpandEnv
	return os.ExpandEnv(result)
}

// StewardConfig represents the complete steward configuration loaded from hostname.cfg.
//
// This is the root configuration structure that contains all settings needed
// for standalone steward operation, including steward-specific settings,
// resource definitions, and optional module path mappings.
type StewardConfig struct {
	// Steward contains steward-specific configuration settings
	Steward StewardSettings `yaml:"steward" json:"steward"`

	// Resources defines the list of resources to be managed
	Resources []ResourceConfig `yaml:"resources" json:"resources"`

	// Modules provides optional custom paths for specific modules
	Modules map[string]string `yaml:"modules,omitempty" json:"modules,omitempty"` // module_name -> custom_path
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

	// Secrets configures the steward secret store
	Secrets SecretsConfig `yaml:"secrets,omitempty"`

	// ConvergeInterval is how often the steward re-converges against the cfg
	// (e.g. "30m", "5m", "1h"). Defaults to "30m" when not specified.
	// Applies in both standalone and controller-connected modes.
	ConvergeInterval string `yaml:"converge_interval,omitempty"`

	// ScriptSigning configures script signing policy, trust modes, and trusted key allowlist.
	// Child tenants inherit this config and may only tighten (not loosen) the policy.
	ScriptSigning ScriptSigningConfig `yaml:"script_signing,omitempty"`
}

// SecretsConfig defines configuration for steward-side secret storage.
type SecretsConfig struct {
	// SecretsDir overrides the default platform-specific secrets directory
	SecretsDir string `yaml:"secrets_dir,omitempty"`

	// Provider selects the secrets provider (default: "steward")
	Provider string `yaml:"provider,omitempty"`
}

// ScriptSigningPolicy defines the enforcement level for script signatures at the steward level.
type ScriptSigningPolicy string

const (
	// ScriptSigningPolicyNone does not require or validate script signatures.
	ScriptSigningPolicyNone ScriptSigningPolicy = "none"

	// ScriptSigningPolicyOptional validates signatures when present but does not require them.
	ScriptSigningPolicyOptional ScriptSigningPolicy = "optional"

	// ScriptSigningPolicyRequired rejects any script that lacks a valid signature.
	ScriptSigningPolicyRequired ScriptSigningPolicy = "required"
)

// ScriptTrustMode defines which signing keys or CAs are considered trustworthy.
type ScriptTrustMode string

const (
	// TrustModeAnyValid accepts any valid signature from a well-formed key.
	TrustModeAnyValid ScriptTrustMode = "any_valid"

	// TrustModeTrustedKeys accepts signatures only from keys in TrustedKeys.
	TrustModeTrustedKeys ScriptTrustMode = "trusted_keys"

	// TrustModeTrustedKeysAndPublic accepts TrustedKeys and, when AllowPublicCA is true, public CAs.
	TrustModeTrustedKeysAndPublic ScriptTrustMode = "trusted_keys_and_public"
)

// TrustedKeyRef identifies a trusted signing key or certificate by name, thumbprint, or key reference.
type TrustedKeyRef struct {
	// Name is a human-readable label for this key entry.
	Name string `yaml:"name"`

	// Thumbprint is the certificate thumbprint used to identify the key.
	Thumbprint string `yaml:"thumbprint,omitempty"`

	// PublicKeyRef is an opaque reference to a public key stored in the secrets provider.
	PublicKeyRef string `yaml:"public_key_ref,omitempty"`
}

// ScriptSigningConfig defines the steward-level script signing policy and trust configuration.
//
// Config inheritance: child tenants inherit parent config via MergeScriptSigningConfig.
// Children may tighten policy (e.g. optional→required) but may not loosen it.
type ScriptSigningConfig struct {
	// Policy sets the enforcement level: none, optional, or required.
	Policy ScriptSigningPolicy `yaml:"policy,omitempty"`

	// TrustMode defines which keys are accepted: any_valid, trusted_keys, or trusted_keys_and_public.
	TrustMode ScriptTrustMode `yaml:"trust_mode,omitempty"`

	// TrustedKeys lists keys/certificates that are allowed to sign scripts.
	// Required when TrustMode is trusted_keys or trusted_keys_and_public.
	TrustedKeys []TrustedKeyRef `yaml:"trusted_keys,omitempty"`

	// AllowPublicCA, when true alongside trusted_keys_and_public mode, also accepts
	// signatures from public certificate authorities.
	AllowPublicCA bool `yaml:"allow_public_ca,omitempty"`

	// ScriptRepoURL is the MSP-level Git repository URL for the tenant's script store.
	// Tenant-scoped; child tenants may override this to point to their own repo.
	ScriptRepoURL string `yaml:"script_repo_url,omitempty"`
}

// ResourceConfig defines a single resource to be managed by the steward.
//
// Each resource specifies which module should manage it and provides
// module-specific configuration data.
type ResourceConfig struct {
	// Name is the unique identifier for this resource
	Name string `yaml:"name" json:"name"`

	// Module is the name of the module that will manage this resource
	Module string `yaml:"module" json:"module"`

	// Config contains module-specific configuration data
	Config map[string]interface{} `yaml:"config" json:"config"`
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

	content := string(data)

	// Validate that all referenced env vars (without defaults) are set
	// This provides fail-safe behavior for missing env vars
	if err := validateEnvVars(content); err != nil {
		return config, fmt.Errorf("configuration validation failed: %w", err)
	}

	// Expand environment variables in the configuration content
	// This supports ${VAR} and ${VAR:-default} syntax for explicit env var references
	expandedData := expandEnvWithDefaults(content)

	if err := yaml.Unmarshal([]byte(expandedData), &config); err != nil {
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

	// Set default convergence interval
	if config.Steward.ConvergeInterval == "" {
		config.Steward.ConvergeInterval = "30m"
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

// scriptSigningPolicyLevel returns the numeric strictness level of a signing policy.
// Higher values are more restrictive. Returns -1 for unknown values.
func scriptSigningPolicyLevel(p ScriptSigningPolicy) int {
	switch p {
	case ScriptSigningPolicyNone, "":
		return 0
	case ScriptSigningPolicyOptional:
		return 1
	case ScriptSigningPolicyRequired:
		return 2
	}
	return -1
}

// validateScriptSigningConfig validates a ScriptSigningConfig for internal consistency.
func validateScriptSigningConfig(cfg ScriptSigningConfig) error {
	// Validate policy value
	switch cfg.Policy {
	case ScriptSigningPolicyNone, ScriptSigningPolicyOptional, ScriptSigningPolicyRequired, "":
		// valid
	default:
		return fmt.Errorf("invalid script_signing policy %q: must be none, optional, or required", cfg.Policy)
	}

	// Validate trust_mode value
	switch cfg.TrustMode {
	case TrustModeAnyValid, TrustModeTrustedKeys, TrustModeTrustedKeysAndPublic, "":
		// valid
	default:
		return fmt.Errorf("invalid script_signing trust_mode %q: must be any_valid, trusted_keys, or trusted_keys_and_public", cfg.TrustMode)
	}

	// trusted_keys and trusted_keys_and_public require a non-empty key list
	if cfg.TrustMode == TrustModeTrustedKeys || cfg.TrustMode == TrustModeTrustedKeysAndPublic {
		if len(cfg.TrustedKeys) == 0 {
			return fmt.Errorf("script_signing trust_mode %q requires at least one entry in trusted_keys", cfg.TrustMode)
		}
	}

	// Each key ref must have at least a thumbprint or public_key_ref
	for i, key := range cfg.TrustedKeys {
		if key.Thumbprint == "" && key.PublicKeyRef == "" {
			return fmt.Errorf("script_signing trusted_keys[%d] (%q): must provide thumbprint or public_key_ref", i, key.Name)
		}
	}

	return nil
}

// MergeScriptSigningConfig merges a parent ScriptSigningConfig into a child, applying inheritance rules.
//
// The child inherits all parent settings that the child has not explicitly set.
// Policy may only be tightened (none→optional→required) — if the child specifies a policy
// less restrictive than the parent's, an error is returned.
func MergeScriptSigningConfig(parent, child ScriptSigningConfig) (ScriptSigningConfig, error) {
	// Apply parent defaults where child has not set values
	result := child

	// Inherit policy from parent if child has none
	if result.Policy == "" {
		result.Policy = parent.Policy
	}
	if result.Policy == "" {
		result.Policy = ScriptSigningPolicyNone
	}

	// Enforce tightening-only: child cannot loosen what parent has set
	parentLevel := scriptSigningPolicyLevel(parent.Policy)
	childLevel := scriptSigningPolicyLevel(result.Policy)
	if parentLevel < 0 || childLevel < 0 {
		return ScriptSigningConfig{}, fmt.Errorf("invalid signing policy value")
	}
	if childLevel < parentLevel {
		return ScriptSigningConfig{}, fmt.Errorf(
			"child tenant cannot loosen script_signing policy: parent requires %q, child specified %q",
			parent.Policy, child.Policy,
		)
	}

	// Inherit trust_mode from parent if child has none
	if result.TrustMode == "" {
		result.TrustMode = parent.TrustMode
	}

	// Inherit trusted_keys from parent if child has none
	if len(result.TrustedKeys) == 0 && len(parent.TrustedKeys) > 0 {
		result.TrustedKeys = parent.TrustedKeys
	}

	// AllowPublicCA: child inherits parent value if not set (bool — treat parent true as inherited)
	if !result.AllowPublicCA && parent.AllowPublicCA {
		result.AllowPublicCA = parent.AllowPublicCA
	}

	// ScriptRepoURL: child overrides parent; inherit if child has none
	if result.ScriptRepoURL == "" {
		result.ScriptRepoURL = parent.ScriptRepoURL
	}

	return result, nil
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

	// Validate convergence interval (only when explicitly set; empty means default will apply)
	if config.Steward.ConvergeInterval != "" {
		d, err := time.ParseDuration(config.Steward.ConvergeInterval)
		if err != nil {
			return fmt.Errorf("invalid converge_interval %q: must be a valid duration (e.g. \"30m\", \"5m\", \"1h\")", config.Steward.ConvergeInterval)
		}
		if d <= 0 {
			return fmt.Errorf("converge_interval must be positive, got %q", config.Steward.ConvergeInterval)
		}
	}

	// Validate script signing config
	if err := validateScriptSigningConfig(config.Steward.ScriptSigning); err != nil {
		return fmt.Errorf("script_signing configuration invalid: %w", err)
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

// GetConvergeInterval returns the parsed convergence interval for this configuration.
// Falls back to 30 minutes if the field is empty or unparseable (should not happen
// after validation, but guards against direct struct construction in tests).
func GetConvergeInterval(cfg StewardConfig) time.Duration {
	if cfg.Steward.ConvergeInterval == "" {
		return 30 * time.Minute
	}
	d, err := time.ParseDuration(cfg.Steward.ConvergeInterval)
	if err != nil || d <= 0 {
		return 30 * time.Minute
	}
	return d
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
