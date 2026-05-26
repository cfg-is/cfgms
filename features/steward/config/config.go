// SPDX-License-Identifier: AGPL-3.0-only
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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/modules/script"
)

// Type aliases — re-export from stewardtypes so existing callers compile unchanged.
type (
	StewardConfig       = stewardtypes.StewardConfig
	StewardSettings     = stewardtypes.StewardSettings
	ResourceConfig      = stewardtypes.ResourceConfig
	ErrorHandlingConfig = stewardtypes.ErrorHandlingConfig
	DriftMode           = stewardtypes.DriftMode
	LoggingConfig       = stewardtypes.LoggingConfig
	SecretsConfig       = stewardtypes.SecretsConfig
	ScriptSigningConfig = stewardtypes.ScriptSigningConfig
	ScriptSigningPolicy = stewardtypes.ScriptSigningPolicy
	ScriptTrustMode     = stewardtypes.ScriptTrustMode
	TrustedKeyRef       = stewardtypes.TrustedKeyRef
	OperationMode       = stewardtypes.OperationMode
	ErrorAction         = stewardtypes.ErrorAction
)

// Constant re-exports from stewardtypes.
const (
	ScriptSigningPolicyNone       = stewardtypes.ScriptSigningPolicyNone
	ScriptSigningPolicyOptional   = stewardtypes.ScriptSigningPolicyOptional
	ScriptSigningPolicyRequired   = stewardtypes.ScriptSigningPolicyRequired
	TrustModeAnyValid             = stewardtypes.TrustModeAnyValid
	TrustModeTrustedKeys          = stewardtypes.TrustModeTrustedKeys
	TrustModeTrustedKeysAndPublic = stewardtypes.TrustModeTrustedKeysAndPublic
	ModeStandalone                = stewardtypes.ModeStandalone
	ModeController                = stewardtypes.ModeController
	DriftModeApply                = stewardtypes.DriftModeApply
	DriftModeMonitor              = stewardtypes.DriftModeMonitor
	ActionContinue                = stewardtypes.ActionContinue
	ActionFail                    = stewardtypes.ActionFail
	ActionWarn                    = stewardtypes.ActionWarn
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

	dec := yaml.NewDecoder(strings.NewReader(expandedData))
	dec.KnownFields(true)
	if err := dec.Decode(&config); err != nil {
		// An empty (or whitespace-only) configuration file yields io.EOF from the
		// streaming decoder. Treat it as an empty config: defaults are applied below
		// and ID falls back to the hostname.
		if !errors.Is(err, io.EOF) {
			return config, fmt.Errorf("failed to parse configuration: %w", err)
		}
	}

	// Security invariant: DriftMode must come from controller-delivered cfg only.
	// Clear any local-file value so a tampered hostname.cfg cannot flip a
	// controller-connected steward into monitor mode.
	config.Steward.DriftMode = ""

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

// validateScriptSigningConfig delegates to the shared stewardtypes validator.
// Kept as a package-internal function so tests in this package can call it directly.
func validateScriptSigningConfig(cfg ScriptSigningConfig) error {
	return stewardtypes.ValidateScriptSigningConfig(cfg)
}

// BuildModuleSigningConfig converts a steward ScriptSigningConfig into the
// script.ModuleSigningConfig consumed by the script module and the steward
// command handler's pre-dispatch signature verification (Issue #1671).
//
// It is used by both standalone-mode wiring (steward.go) and controller-connected
// wiring (client.TransportClient) so the two paths cannot diverge.
func BuildModuleSigningConfig(cfg ScriptSigningConfig) script.ModuleSigningConfig {
	entries := make([]script.TrustedKeyEntry, len(cfg.TrustedKeys))
	for i, key := range cfg.TrustedKeys {
		entries[i] = script.TrustedKeyEntry{
			Name:         key.Name,
			Thumbprint:   key.Thumbprint,
			PublicKeyRef: key.PublicKeyRef,
		}
	}
	return script.ModuleSigningConfig{
		TrustMode:     script.TrustMode(cfg.TrustMode),
		TrustedKeys:   entries,
		AllowPublicCA: cfg.AllowPublicCA,
	}
}
