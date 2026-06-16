// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package stewardtypes provides the shared data types and validation functions
// for steward configuration used by both the controller and the steward.
//
// These types are extracted so the controller can reference steward configuration
// shapes without importing steward-internal packages.
package stewardtypes

import "time"

// StewardConfig represents the complete steward configuration.
type StewardConfig struct {
	Steward         StewardSettings   `yaml:"steward" json:"steward"`
	Resources       []ResourceConfig  `yaml:"resources" json:"resources"`
	Modules         map[string]string `yaml:"modules,omitempty" json:"modules,omitempty"`
	RequiredModules []RequiredModule  `yaml:"required_modules,omitempty" json:"required_modules,omitempty"`
}

// StewardSettings contains steward-specific configuration options.
type StewardSettings struct {
	ID          string        `yaml:"id"`
	Mode        OperationMode `yaml:"mode"`
	ModulePaths []string      `yaml:"module_paths,omitempty"`
	Logging     LoggingConfig `yaml:"logging"`

	ErrorHandling ErrorHandlingConfig `yaml:"error_handling"`
	Secrets       SecretsConfig       `yaml:"secrets,omitempty"`

	// ConvergeInterval is how often the steward re-converges (e.g. "30m").
	ConvergeInterval string `yaml:"converge_interval,omitempty"`

	// ScriptSigning configures script signing policy and trusted keys.
	// Child tenants may only tighten (not loosen) the inherited policy.
	ScriptSigning ScriptSigningConfig `yaml:"script_signing,omitempty"`

	// ModuleTrust configures module trust policy and additional trusted publishers.
	ModuleTrust ModuleTrustConfig `yaml:"module_trust,omitempty"`

	// SignedCommandReplayWindow is the maximum age of an accepted command timestamp.
	SignedCommandReplayWindow time.Duration `yaml:"signed_command_replay_window,omitempty"`

	// SignedCommandMaxParamsBytes is the maximum JSON-serialized size of Command.Params.
	SignedCommandMaxParamsBytes int `yaml:"signed_command_max_params_bytes,omitempty"`

	// DriftMode controls how the steward responds to detected configuration drift.
	// Must be sourced exclusively from the controller-delivered cfg.
	DriftMode DriftMode `yaml:"drift_mode,omitempty"`

	// Upgrade configures the steward upgrade policy. (Issue #1943)
	Upgrade UpgradeConfig `yaml:"upgrade,omitempty"`
}

// UpgradeConfig holds upgrade-related steward policy settings. (Issue #1943)
type UpgradeConfig struct {
	// AllowDowngrade permits installing a version older than or equal to the
	// running version. Disabled by default to prevent accidental rollbacks.
	AllowDowngrade bool `yaml:"allow_downgrade,omitempty"`
}

// SecretsConfig defines configuration for steward-side secret storage.
type SecretsConfig struct {
	SecretsDir string `yaml:"secrets_dir,omitempty"`
	Provider   string `yaml:"provider,omitempty"`
}

// ScriptSigningPolicy defines the enforcement level for script signatures.
type ScriptSigningPolicy string

const (
	ScriptSigningPolicyNone     ScriptSigningPolicy = "none"
	ScriptSigningPolicyOptional ScriptSigningPolicy = "optional"
	ScriptSigningPolicyRequired ScriptSigningPolicy = "required"
)

// ScriptTrustMode defines which signing keys or CAs are considered trustworthy.
type ScriptTrustMode string

const (
	TrustModeAnyValid             ScriptTrustMode = "any_valid"
	TrustModeTrustedKeys          ScriptTrustMode = "trusted_keys"
	TrustModeTrustedKeysAndPublic ScriptTrustMode = "trusted_keys_and_public"
)

// TrustedKeyRef identifies a trusted signing key by name, thumbprint, or key reference.
type TrustedKeyRef struct {
	Name         string `yaml:"name"`
	Thumbprint   string `yaml:"thumbprint,omitempty"`
	PublicKeyRef string `yaml:"public_key_ref,omitempty"`
}

// ScriptSigningConfig defines the steward-level script signing policy.
//
// Child tenants inherit parent config via MergeScriptSigningConfig and may only
// tighten policy (none→optional→required), never loosen it.
type ScriptSigningConfig struct {
	Policy        ScriptSigningPolicy `yaml:"policy,omitempty"`
	TrustMode     ScriptTrustMode     `yaml:"trust_mode,omitempty"`
	TrustedKeys   []TrustedKeyRef     `yaml:"trusted_keys,omitempty"`
	AllowPublicCA bool                `yaml:"allow_public_ca,omitempty"`

	// RequireSignedAdhoc requires a valid signature on all ad-hoc script commands.
	// Incompatible with policy: none.
	RequireSignedAdhoc bool `yaml:"require_signed_adhoc,omitempty"`
}

// ResourceConfig defines a single resource to be managed by the steward.
type ResourceConfig struct {
	Name   string                 `yaml:"name" json:"name"`
	Module string                 `yaml:"module" json:"module"`
	Config map[string]interface{} `yaml:"config" json:"config"`
}

// OperationMode defines how the steward operates.
type OperationMode string

const (
	ModeStandalone OperationMode = "standalone"
	ModeController OperationMode = "controller"
)

// DriftMode defines how the steward responds to detected configuration drift.
// Set exclusively from controller-delivered cfg bytes — never from local steward.cfg.
type DriftMode string

const (
	DriftModeApply   DriftMode = "apply"
	DriftModeMonitor DriftMode = "monitor"
)

// LoggingConfig defines logging output settings.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// ErrorHandlingConfig defines how to handle various error conditions.
type ErrorHandlingConfig struct {
	ModuleLoadFailure  ErrorAction `yaml:"module_load_failure"`
	ResourceFailure    ErrorAction `yaml:"resource_failure"`
	ConfigurationError ErrorAction `yaml:"configuration_error"`
}

// ErrorAction defines the available error handling strategies.
type ErrorAction string

const (
	ActionContinue ErrorAction = "continue"
	ActionFail     ErrorAction = "fail"
	ActionWarn     ErrorAction = "warn"
)

// ModuleTrustMode defines how the steward verifies module bundles.
type ModuleTrustMode string

const (
	// ModuleTrustModeStrict requires the steward to independently verify publisher
	// signatures, consulting AdditionalPublishers in addition to baked-in identities.
	ModuleTrustModeStrict ModuleTrustMode = "strict"

	// ModuleTrustModeController delegates trust decisions to the controller (default).
	// The steward accepts any bundle the controller has approved.
	ModuleTrustModeController ModuleTrustMode = "controller"

	// ModuleTrustModeBypass disables all trust enforcement. Development use only.
	ModuleTrustModeBypass ModuleTrustMode = "bypass"
)

// ModuleTrustConfig configures module trust policy for the steward.
// Placed alongside ScriptSigning as steward security posture configuration.
type ModuleTrustConfig struct {
	// Mode controls how module bundle signatures are verified.
	// Valid values: "strict", "controller" (default), "bypass".
	Mode ModuleTrustMode `yaml:"mode,omitempty" json:"mode,omitempty"`

	// AdditionalPublishers lists publisher identifiers trusted in addition to
	// the CFGMS publisher identity baked into the steward binary.
	// Only consulted when Mode is "strict".
	AdditionalPublishers []string `yaml:"additional_publishers,omitempty" json:"additional_publishers,omitempty"`
}

// RequiredModule declares a module bundle that must be present and approved in
// the controller cache before this cfg file can be deployed to stewards.
// Name is the full "publisher/name" identifier; Version is a semver constraint.
type RequiredModule struct {
	Name    string `yaml:"name" json:"name"`
	Version string `yaml:"version" json:"version"`
}
