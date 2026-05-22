// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package stewardtypes

import (
	"fmt"
	"time"
)

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

// ValidateScriptSigningConfig validates a ScriptSigningConfig for internal consistency.
func ValidateScriptSigningConfig(cfg ScriptSigningConfig) error {
	switch cfg.Policy {
	case ScriptSigningPolicyNone, ScriptSigningPolicyOptional, ScriptSigningPolicyRequired, "":
		// valid
	default:
		return fmt.Errorf("invalid script_signing policy %q: must be none, optional, or required", cfg.Policy)
	}

	switch cfg.TrustMode {
	case TrustModeAnyValid, TrustModeTrustedKeys, TrustModeTrustedKeysAndPublic, "":
		// valid
	default:
		return fmt.Errorf("invalid script_signing trust_mode %q: must be any_valid, trusted_keys, or trusted_keys_and_public", cfg.TrustMode)
	}

	if cfg.TrustMode == TrustModeTrustedKeys || cfg.TrustMode == TrustModeTrustedKeysAndPublic {
		if len(cfg.TrustedKeys) == 0 {
			return fmt.Errorf("script_signing trust_mode %q requires at least one entry in trusted_keys", cfg.TrustMode)
		}
	}

	for i, key := range cfg.TrustedKeys {
		if key.Thumbprint == "" && key.PublicKeyRef == "" {
			return fmt.Errorf("script_signing trusted_keys[%d] (%q): must provide thumbprint or public_key_ref", i, key.Name)
		}
	}

	if cfg.RequireSignedAdhoc && (cfg.Policy == ScriptSigningPolicyNone || cfg.Policy == "") {
		return fmt.Errorf("script_signing require_signed_adhoc requires policy optional or required, got %q", cfg.Policy)
	}

	return nil
}

// ValidateConfiguration checks if the configuration is valid.
func ValidateConfiguration(config StewardConfig) error {
	if config.Steward.ID == "" {
		return fmt.Errorf("steward ID is required")
	}

	switch config.Steward.Mode {
	case ModeStandalone, ModeController:
		// valid
	default:
		return fmt.Errorf("invalid operation mode: %s", config.Steward.Mode)
	}

	if config.Steward.Logging.Level != "" {
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
	}

	if config.Steward.ConvergeInterval != "" {
		d, err := time.ParseDuration(config.Steward.ConvergeInterval)
		if err != nil {
			return fmt.Errorf("invalid converge_interval %q: must be a valid duration (e.g. \"30m\", \"5m\", \"1h\")", config.Steward.ConvergeInterval)
		}
		if d <= 0 {
			return fmt.Errorf("converge_interval must be positive, got %q", config.Steward.ConvergeInterval)
		}
	}

	if err := ValidateScriptSigningConfig(config.Steward.ScriptSigning); err != nil {
		return fmt.Errorf("script_signing configuration invalid: %w", err)
	}

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

// MergeScriptSigningConfig merges a parent ScriptSigningConfig into a child, applying inheritance rules.
//
// The child inherits all parent settings that the child has not explicitly set.
// Policy may only be tightened (none→optional→required) — if the child specifies a policy
// less restrictive than the parent's, an error is returned.
func MergeScriptSigningConfig(parent, child ScriptSigningConfig) (ScriptSigningConfig, error) {
	result := child

	if result.Policy == "" {
		result.Policy = parent.Policy
	}
	if result.Policy == "" {
		result.Policy = ScriptSigningPolicyNone
	}

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

	if result.TrustMode == "" {
		result.TrustMode = parent.TrustMode
	}

	if len(result.TrustedKeys) == 0 && len(parent.TrustedKeys) > 0 {
		result.TrustedKeys = parent.TrustedKeys
	}

	if !result.AllowPublicCA && parent.AllowPublicCA {
		result.AllowPublicCA = parent.AllowPublicCA
	}

	if !result.RequireSignedAdhoc && parent.RequireSignedAdhoc {
		result.RequireSignedAdhoc = parent.RequireSignedAdhoc
	}

	return result, nil
}

// GetConvergeInterval returns the parsed convergence interval.
// Falls back to 30 minutes if the field is empty or unparseable.
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

// GetConfiguredModules returns a deduplicated list of module names required by the configuration.
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
