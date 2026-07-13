// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package config provides configuration inheritance logic using storage backend queries
package config

import (
	"context"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	controllerconfig "github.com/cfgis/cfgms/features/controller/config"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// configSourceRouter is the minimal interface that InheritanceResolver requires from
// a ConfigSourceRouter. Defined here (not in pkg/configrouting/interfaces) to avoid
// a circular import: pkg/configrouting/interfaces imports pkg/config for ConfigSourceInfo,
// so pkg/config cannot import pkg/configrouting/interfaces in return.
// The concrete *controllerRouter in pkg/configrouting/providers/controller satisfies this
// interface by duck-typing; no explicit declaration is needed there.
type configSourceRouter interface {
	cfgconfig.ConfigStore
	// SnapshotSources resolves the config source for every tenant in tenantPath atomically.
	SnapshotSources(ctx context.Context, tenantPath []string) (map[string]*ConfigSourceInfo, error)
}

// clusterMembership is the minimal interface InheritanceResolver requires to look up
// which clusters a steward belongs to. Defined locally (same pattern as configSourceRouter)
// to avoid importing features/controller/clusterregistry into pkg/config, which would
// create a circular dependency. The concrete *clusterregistry.Registry in
// features/controller/clusterregistry satisfies this interface by duck-typing.
type clusterMembership interface {
	// MemberClusters returns the sorted cluster names that stewardID belongs to.
	// Returns nil when the steward has no cluster membership.
	MemberClusters(stewardID string) []string
}

// RoleFragment pairs a role's name with its StewardConfig fragment for merge ordering.
// Returned by roleConfigProvider.MatchingRoleFragments, sorted alphabetically by Name
// so that multiple matching roles produce a deterministic merge order.
type RoleFragment struct {
	Name   string
	Config stewardconfig.StewardConfig
}

// roleConfigProvider is the minimal interface InheritanceResolver requires to fetch
// role config fragments that match a steward's DNA + tags. Defined locally (same
// pattern as clusterMembership) to avoid importing features/controller/fleet into
// pkg/config, which would create a circular dependency. The concrete
// *roleConfigAdapter in features/controller/service satisfies this by duck-typing.
type roleConfigProvider interface {
	// MatchingRoleFragments returns the role config fragments whose selectors match
	// stewardID, sorted alphabetically by role name. Returns nil, nil when no roles
	// match. A non-nil error is non-fatal to the caller — the resolver logs and
	// skips the role layer entirely rather than failing resolution.
	MatchingRoleFragments(ctx context.Context, stewardID string) ([]RoleFragment, error)
}

// cfgStoreAsRouter wraps a plain ConfigStore to satisfy configSourceRouter.
// SnapshotSources always returns ConfigSourceTypeController for backward compatibility
// (used by NewInheritanceResolverWithStorageManager which has no router available).
type cfgStoreAsRouter struct {
	cfgconfig.ConfigStore
}

func (s *cfgStoreAsRouter) SnapshotSources(_ context.Context, tenantPath []string) (map[string]*ConfigSourceInfo, error) {
	m := make(map[string]*ConfigSourceInfo, len(tenantPath))
	for _, tid := range tenantPath {
		m[tid] = &ConfigSourceInfo{Type: ConfigSourceTypeController}
	}
	return m, nil
}

// InheritanceResolver handles configuration inheritance across tenant hierarchy
type InheritanceResolver struct {
	configStore       configSourceRouter
	clientTenantStore business.ClientTenantStore
	tenantStore       business.TenantStore
	clusterRegistry   clusterMembership  // optional; nil means no cluster-policies cascade
	roleProvider      roleConfigProvider // optional; nil means no role-policies cascade
	logger            logging.Logger     // never nil after construction; see log()
}

// log returns the resolver's logger, defaulting to a NoopLogger when the resolver
// was constructed without one (e.g. a zero-value struct in a test). This guarantees
// the cluster cascade can always emit a warning without a nil-pointer panic.
func (ir *InheritanceResolver) log() logging.Logger {
	if ir.logger == nil {
		return logging.NewNoopLogger()
	}
	return ir.logger
}

// WithLogger returns the resolver with logger installed as its warning/error sink.
// Passing nil restores the default (a real stdout logger). Callers use this to route
// inheritance diagnostics (e.g. corrupt cluster-policies documents) into their own
// logging pipeline instead of the process default.
func (ir *InheritanceResolver) WithLogger(logger logging.Logger) *InheritanceResolver {
	if logger == nil {
		logger = logging.NewLogger("info")
	}
	ir.logger = logger
	return ir
}

// NewInheritanceResolver creates an InheritanceResolver backed by a ConfigSourceRouter.
// Pass a *controllerRouter (or any configSourceRouter implementation) so that
// SnapshotSources is called once per cascade for atomic source resolution.
func NewInheritanceResolver(configStore configSourceRouter, clientTenantStore business.ClientTenantStore, tenantStore business.TenantStore) *InheritanceResolver {
	return &InheritanceResolver{
		configStore:       configStore,
		clientTenantStore: clientTenantStore,
		tenantStore:       tenantStore,
		logger:            logging.NewLogger("info"),
	}
}

// NewInheritanceResolverWithStorageManager creates an inheritance resolver from a storage
// manager. The underlying ConfigStore is wrapped in a cfgStoreAsRouter adapter that always
// returns ConfigSourceTypeController from SnapshotSources (backward-compatible default).
// Prefer NewInheritanceResolver with a real ConfigSourceRouter for production deployments.
func NewInheritanceResolverWithStorageManager(storageManager *interfaces.StorageManager) *InheritanceResolver {
	return &InheritanceResolver{
		configStore:       &cfgStoreAsRouter{ConfigStore: storageManager.GetConfigStore()},
		clientTenantStore: storageManager.GetClientTenantStore(),
		tenantStore:       storageManager.GetTenantStore(),
		logger:            logging.NewLogger("info"),
	}
}

// NewInheritanceResolverWithClusters creates an InheritanceResolver with a cluster
// membership provider wired in. When registry is non-nil, ResolveConfiguration applies
// cluster-policies configs after the tenant hierarchy and before device-level config.
// Pass nil for registry to get byte-identical behavior to NewInheritanceResolver.
func NewInheritanceResolverWithClusters(configStore configSourceRouter, clientTenantStore business.ClientTenantStore, tenantStore business.TenantStore, registry clusterMembership) *InheritanceResolver {
	return &InheritanceResolver{
		configStore:       configStore,
		clientTenantStore: clientTenantStore,
		tenantStore:       tenantStore,
		clusterRegistry:   registry,
		logger:            logging.NewLogger("info"),
	}
}

// NewInheritanceResolverWithRoles creates an InheritanceResolver with both a cluster
// membership provider and a role config provider wired in. Pass nil for either to
// disable that cascade layer. Role fragments are applied after cluster-policies and
// before device-level config (precedence order: cluster < role < device).
func NewInheritanceResolverWithRoles(configStore configSourceRouter, clientTenantStore business.ClientTenantStore, tenantStore business.TenantStore, registry clusterMembership, roles roleConfigProvider) *InheritanceResolver {
	return &InheritanceResolver{
		configStore:       configStore,
		clientTenantStore: clientTenantStore,
		tenantStore:       tenantStore,
		clusterRegistry:   registry,
		roleProvider:      roles,
		logger:            logging.NewLogger("info"),
	}
}

// EffectiveConfiguration represents the final configuration after inheritance
type EffectiveConfiguration struct {
	StewardID   string                        `json:"steward_id"`
	TenantID    string                        `json:"tenant_id"`
	Config      *stewardconfig.StewardConfig  `json:"config"`
	Sources     map[string]*InheritanceSource `json:"sources"` // Tracks source of each configuration element
	GeneratedAt time.Time                     `json:"generated_at"`
}

// InheritanceSource tracks where a configuration element came from
type InheritanceSource struct {
	Level      int       `json:"level"` // 0=MSP, 1=Client, 2=Group, 3=Device
	TenantID   string    `json:"tenant_id"`
	ConfigName string    `json:"config_name"`
	Version    int64     `json:"version"`
	UpdatedAt  time.Time `json:"updated_at"`
	Source     string    `json:"source"` // Description of the source
}

// InheritanceLevel represents the hierarchy levels in multi-tenant configuration
type InheritanceLevel int

const (
	LevelMSP    InheritanceLevel = 0 // MSP-wide policies
	LevelClient InheritanceLevel = 1 // Client-specific overrides
	LevelGroup  InheritanceLevel = 2 // Group configurations
	LevelDevice InheritanceLevel = 3 // Device-specific configurations
)

// ResolveConfiguration resolves configuration with full tenant hierarchy inheritance.
// SnapshotSources is called once before the cascade loop so that every level in the
// hierarchy uses the same generation of source routing decisions — preventing a
// mid-cascade source redirect from causing partial data from two different stores.
func (ir *InheritanceResolver) ResolveConfiguration(ctx context.Context, tenantID, stewardID string) (*EffectiveConfiguration, error) {
	// Get tenant hierarchy path
	tenantPath, err := ir.getTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant hierarchy: %w", err)
	}

	// Snapshot all config sources atomically before entering the cascade loop.
	sourcesSnapshot, err := ir.configStore.SnapshotSources(ctx, tenantPath)
	if err != nil {
		return nil, fmt.Errorf("failed to snapshot config sources: %w", err)
	}

	// Initialize effective configuration
	effective := &EffectiveConfiguration{
		StewardID:   stewardID,
		TenantID:    tenantID,
		Config:      &stewardconfig.StewardConfig{},
		Sources:     make(map[string]*InheritanceSource),
		GeneratedAt: time.Now(),
	}

	// Apply configurations from MSP level down to device level using the pre-snapshotted sources.
	for level, currentTenantID := range tenantPath {
		source := sourcesSnapshot[currentTenantID]
		if err := ir.applyConfigurationLevel(ctx, effective, currentTenantID, stewardID, level, source); err != nil {
			return nil, fmt.Errorf("failed to apply configuration at level %d (tenant %s): %w", level, currentTenantID, err)
		}
	}

	// Apply cluster-policies after tenant hierarchy and before device config.
	// Cluster membership is a device-level concept: the config key uses tenantID
	// (the device's own tenant), not any ancestor tenantID from the loop above.
	// A registry hiccup must not fail resolution — log and treat as no membership.
	if ir.clusterRegistry != nil {
		clusterNames := ir.clusterRegistry.MemberClusters(stewardID)
		for _, clusterName := range clusterNames {
			if err := ir.applyClusterConfiguration(ctx, effective, tenantID, clusterName); err != nil {
				// Non-fatal: parse failure for one cluster must not block others.
				// Missing cluster config is already silently skipped inside applyClusterConfiguration,
				// so an error here signals a corrupt document that must be surfaced, not swallowed.
				ir.log().WarnCtx(ctx, "skipping cluster-policies config for cluster; treating as no membership",
					"steward_id", stewardID,
					"tenant_id", tenantID,
					"cluster", clusterName,
					"error", err.Error())
			}
		}
	}

	// Apply role-policies after cluster-policies and before device config.
	// Each role whose selector matches this steward contributes a config fragment.
	// Fragments are applied in alphabetical role-name order so multiple matching
	// roles produce a deterministic merge (later name overrides earlier for the same
	// resource). A provider hiccup must not fail resolution — log and treat as no roles.
	if ir.roleProvider != nil {
		fragments, err := ir.roleProvider.MatchingRoleFragments(ctx, stewardID)
		if err != nil {
			ir.log().WarnCtx(ctx, "skipping role-policies; treating as no roles",
				"steward_id", stewardID,
				"tenant_id", tenantID,
				"error", err.Error())
		} else {
			for _, frag := range fragments {
				ir.applyRoleFragment(effective, tenantID, frag)
			}
		}
	}

	// Apply device-specific configuration last (highest priority)
	if err := ir.applyDeviceConfiguration(ctx, effective, tenantID, stewardID); err != nil {
		return nil, fmt.Errorf("failed to apply device configuration: %w", err)
	}

	return effective, nil
}

// getTenantPath returns the tenant hierarchy path from root to the specified tenant
func (ir *InheritanceResolver) getTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	return ir.tenantStore.GetTenantPath(ctx, tenantID)
}

// applyConfigurationLevel applies configuration from a specific hierarchy level.
// source is the pre-snapshotted ConfigSourceInfo for this tenant, resolved once by
// ResolveConfiguration before the cascade loop. In Phase 1 the router always returns
// ConfigSourceTypeController so the configStore.GetConfig call below routes there;
// Phase 2 (Story C) will use source.Type to dispatch to a git store.
func (ir *InheritanceResolver) applyConfigurationLevel(ctx context.Context, effective *EffectiveConfiguration, tenantID, stewardID string, level int, source *ConfigSourceInfo) error {
	_ = source // Phase 1: routing handled internally by configStore (always controller)
	// Try to get configuration at this level
	var configNamespace string
	var configName string

	switch InheritanceLevel(level) {
	case LevelMSP:
		configNamespace = "msp-policies"
		configName = "global"
	case LevelClient:
		configNamespace = "client-policies"
		configName = tenantID
	case LevelGroup:
		configNamespace = "group-policies"
		configName = fmt.Sprintf("%s-groups", tenantID)
	default:
		return nil // Skip unknown levels
	}

	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: configNamespace,
		Name:      configName,
	}

	configEntry, err := ir.configStore.GetConfig(ctx, configKey)
	if err != nil {
		// No configuration at this level is OK - continue with inheritance
		return nil
	}

	// Parse the configuration
	var levelConfig stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &levelConfig); err != nil {
		return fmt.Errorf("failed to parse configuration at level %d: %w", level, err)
	}

	// Create inheritance source tracking
	inheritSrc := &InheritanceSource{
		Level:      level,
		TenantID:   tenantID,
		ConfigName: configName,
		Version:    configEntry.Version,
		UpdatedAt:  configEntry.UpdatedAt,
		Source:     fmt.Sprintf("Level %d (%s)", level, configNamespace),
	}

	// Apply configuration using declarative merging (named resources replace entirely)
	ir.applyConfigurationWithSource(effective, &levelConfig, inheritSrc)

	return nil
}

// applyClusterConfiguration looks up cluster-policies/<clusterName> for the given tenant
// and merges it into effective. Missing cluster configs are non-fatal (same as missing
// tenant-level configs in applyConfigurationLevel). The config key uses the device's own
// tenantID so that cluster membership is scoped to the device's tenant, not any ancestor.
func (ir *InheritanceResolver) applyClusterConfiguration(ctx context.Context, effective *EffectiveConfiguration, tenantID, clusterName string) error {
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "cluster-policies",
		Name:      clusterName,
	}

	configEntry, err := ir.configStore.GetConfig(ctx, configKey)
	if err != nil {
		// No cluster-policies document for this cluster is non-fatal.
		return nil
	}

	var clusterConfig stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &clusterConfig); err != nil {
		return fmt.Errorf("failed to parse cluster configuration for %q: %w", clusterName, err)
	}

	inheritSrc := &InheritanceSource{
		Level:      int(LevelGroup) + 1, // between Group(2) and Device(3) in merge order
		TenantID:   tenantID,
		ConfigName: clusterName,
		Version:    configEntry.Version,
		UpdatedAt:  configEntry.UpdatedAt,
		Source:     fmt.Sprintf("Cluster (cluster-policies/%s)", clusterName),
	}

	ir.applyConfigurationWithSource(effective, &clusterConfig, inheritSrc)
	return nil
}

// applyRoleFragment merges a single role config fragment into effective. The
// InheritanceSource level (LevelGroup+2) places role fragments between
// cluster-policies (LevelGroup+1) and device-level (LevelDevice) in source metadata.
func (ir *InheritanceResolver) applyRoleFragment(effective *EffectiveConfiguration, tenantID string, frag RoleFragment) {
	inheritSrc := &InheritanceSource{
		Level:      int(LevelGroup) + 2, // between cluster-policies and device in merge order
		TenantID:   tenantID,
		ConfigName: frag.Name,
		Source:     fmt.Sprintf("Role (role-policies/%s)", frag.Name),
	}
	ir.applyConfigurationWithSource(effective, &frag.Config, inheritSrc)
}

// applyDeviceConfiguration applies device-specific configuration
func (ir *InheritanceResolver) applyDeviceConfiguration(ctx context.Context, effective *EffectiveConfiguration, tenantID, stewardID string) error {
	configKey := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "stewards",
		Name:      stewardID,
	}

	configEntry, err := ir.configStore.GetConfig(ctx, configKey)
	if err != nil {
		// No device-specific configuration is OK
		return nil
	}

	// Parse the configuration
	var deviceConfig stewardconfig.StewardConfig
	if err := yaml.Unmarshal(configEntry.Data, &deviceConfig); err != nil {
		return fmt.Errorf("failed to parse device configuration: %w", err)
	}

	// Create inheritance source tracking
	source := &InheritanceSource{
		Level:      int(LevelDevice),
		TenantID:   tenantID,
		ConfigName: stewardID,
		Version:    configEntry.Version,
		UpdatedAt:  configEntry.UpdatedAt,
		Source:     "Device Configuration",
	}

	// Apply device configuration (highest priority)
	ir.applyConfigurationWithSource(effective, &deviceConfig, source)

	return nil
}

// applyConfigurationWithSource applies configuration and tracks inheritance sources
func (ir *InheritanceResolver) applyConfigurationWithSource(effective *EffectiveConfiguration, config *stewardconfig.StewardConfig, source *InheritanceSource) {
	// Initialize effective config if needed
	if effective.Config == nil {
		effective.Config = &stewardconfig.StewardConfig{
			Resources: []stewardconfig.ResourceConfig{},
			Modules:   make(map[string]string),
		}
	}

	// Apply resources using declarative merging (named resources replace
	// entirely), PRESERVING declaration order. Inter-resource ordering is
	// load-bearing for dependency chains: a vSwitch must be created before the
	// VM that attaches to it, and on teardown the VM must be deleted before its
	// vSwitch (Hyper-V refuses to remove a switch still in use by a running VM).
	// The steward executor applies resources in slice order, so rebuilding the
	// slice from a Go map here (whose iteration order is randomised) made those
	// chains converge in a non-deterministic order and fail intermittently —
	// e.g. a delete cycle attempting Remove-VMSwitch before the VM was removed.
	// A child config that overrides a base resource keeps the base resource's
	// position; genuinely new resources append in declaration order.
	indexByName := make(map[string]int, len(effective.Config.Resources)+len(config.Resources))
	merged := make([]stewardconfig.ResourceConfig, 0, len(effective.Config.Resources)+len(config.Resources))
	upsert := func(resource stewardconfig.ResourceConfig) {
		if i, ok := indexByName[resource.Name]; ok {
			merged[i] = resource // override in place, preserving position
			return
		}
		indexByName[resource.Name] = len(merged)
		merged = append(merged, resource)
	}
	for _, resource := range effective.Config.Resources {
		upsert(resource)
	}
	for _, resource := range config.Resources {
		upsert(resource)
		effective.Sources[fmt.Sprintf("resource.%s", resource.Name)] = source
	}
	effective.Config.Resources = merged

	// Apply steward settings
	if config.Steward.ID != "" {
		effective.Config.Steward.ID = config.Steward.ID
		effective.Sources["steward.id"] = source
	}

	if config.Steward.Mode != "" {
		effective.Config.Steward.Mode = config.Steward.Mode
		effective.Sources["steward.mode"] = source
	}

	if len(config.Steward.ModulePaths) > 0 {
		effective.Config.Steward.ModulePaths = config.Steward.ModulePaths
		effective.Sources["steward.module_paths"] = source
	}

	// ConvergeInterval and DriftMode are scalar steward settings that follow
	// the same later-overrides-earlier rule as ID/Mode/ModulePaths. Without
	// this, a cascade-enabled tenant loses the configured interval and the
	// steward falls back to its 30-minute default — breaking drift-correction
	// SLAs inside any tenant hierarchy.
	if config.Steward.ConvergeInterval != "" {
		effective.Config.Steward.ConvergeInterval = config.Steward.ConvergeInterval
		effective.Sources["steward.converge_interval"] = source
	}

	if config.Steward.DriftMode != "" {
		effective.Config.Steward.DriftMode = config.Steward.DriftMode
		effective.Sources["steward.drift_mode"] = source
	}

	// Upgrade settings — carry desired_version and allow_downgrade through the
	// tenant hierarchy so MSP-level upgrade policy propagates to child stewards.
	if config.Steward.Upgrade.DesiredVersion != "" {
		effective.Config.Steward.Upgrade.DesiredVersion = config.Steward.Upgrade.DesiredVersion
		effective.Sources["steward.upgrade.desired_version"] = source
	}
	// allow_downgrade uses "more-permissive-wins" semantics (a child cannot
	// revoke a parent-granted permission within a single inheritance pass).
	// This matches the existing bool-inheritance pattern in this function and
	// is intentional: MSPs opt tenants into downgrade by setting it true;
	// steward-level override is not supported for this field.
	if config.Steward.Upgrade.AllowDowngrade {
		effective.Config.Steward.Upgrade.AllowDowngrade = true
		effective.Sources["steward.upgrade.allow_downgrade"] = source
	}

	// Apply logging settings
	if config.Steward.Logging.Level != "" {
		effective.Config.Steward.Logging.Level = config.Steward.Logging.Level
		effective.Sources["steward.logging.level"] = source
	}

	if config.Steward.Logging.Format != "" {
		effective.Config.Steward.Logging.Format = config.Steward.Logging.Format
		effective.Sources["steward.logging.format"] = source
	}

	// Apply error handling settings
	if config.Steward.ErrorHandling.ModuleLoadFailure != "" {
		effective.Config.Steward.ErrorHandling.ModuleLoadFailure = config.Steward.ErrorHandling.ModuleLoadFailure
		effective.Sources["steward.error_handling.module_load_failure"] = source
	}

	if config.Steward.ErrorHandling.ResourceFailure != "" {
		effective.Config.Steward.ErrorHandling.ResourceFailure = config.Steward.ErrorHandling.ResourceFailure
		effective.Sources["steward.error_handling.resource_failure"] = source
	}

	if config.Steward.ErrorHandling.ConfigurationError != "" {
		effective.Config.Steward.ErrorHandling.ConfigurationError = config.Steward.ErrorHandling.ConfigurationError
		effective.Sources["steward.error_handling.configuration_error"] = source
	}

	// Apply module mappings
	if effective.Config.Modules == nil {
		effective.Config.Modules = make(map[string]string)
	}

	for moduleName, modulePath := range config.Modules {
		effective.Config.Modules[moduleName] = modulePath
		effective.Sources[fmt.Sprintf("modules.%s", moduleName)] = source
	}
}

// GetConfigurationSource returns the inheritance source for a specific configuration element
func (ir *InheritanceResolver) GetConfigurationSource(ctx context.Context, tenantID, stewardID, configPath string) (*InheritanceSource, error) {
	effective, err := ir.ResolveConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		return nil, err
	}

	source, exists := effective.Sources[configPath]
	if !exists {
		return nil, fmt.Errorf("configuration path '%s' not found", configPath)
	}

	return source, nil
}

// ValidateInheritance validates that the inheritance chain is consistent
func (ir *InheritanceResolver) ValidateInheritance(ctx context.Context, tenantID, stewardID string) (*InheritanceValidationResult, error) {
	result := &InheritanceValidationResult{
		Valid:    true,
		Issues:   []string{},
		Warnings: []string{},
	}

	// Resolve configuration to check for issues
	effective, err := ir.ResolveConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("Failed to resolve configuration: %v", err))
		return result, nil
	}

	// Validate the effective configuration
	if err := stewardconfig.ValidateConfiguration(*effective.Config); err != nil {
		result.Valid = false
		result.Issues = append(result.Issues, fmt.Sprintf("Effective configuration is invalid: %v", err))
	}

	// Check for common inheritance issues
	resourceModules := make(map[string]string)
	for _, resource := range effective.Config.Resources {
		if existingModule, exists := resourceModules[resource.Name]; exists && existingModule != resource.Module {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Resource '%s' module conflict: was %s, now %s", resource.Name, existingModule, resource.Module))
		}
		resourceModules[resource.Name] = resource.Module
	}

	// Check for missing steward ID
	if effective.Config.Steward.ID == "" {
		result.Warnings = append(result.Warnings, "Steward ID not set at any inheritance level")
	}

	return result, nil
}

// InheritanceValidationResult represents the result of inheritance validation
type InheritanceValidationResult struct {
	Valid    bool     `json:"valid"`
	Issues   []string `json:"issues"`
	Warnings []string `json:"warnings"`
}

// GetInheritanceTrace returns a detailed trace of configuration inheritance
func (ir *InheritanceResolver) GetInheritanceTrace(ctx context.Context, tenantID, stewardID string) (*InheritanceTrace, error) {
	effective, err := ir.ResolveConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		return nil, err
	}

	trace := &InheritanceTrace{
		StewardID:   stewardID,
		TenantID:    tenantID,
		Sources:     effective.Sources,
		GeneratedAt: effective.GeneratedAt,
		Elements:    make(map[string]*TraceElement),
	}

	// Create trace elements for each configuration path
	for configPath, source := range effective.Sources {
		trace.Elements[configPath] = &TraceElement{
			Path:        configPath,
			Value:       ir.getConfigValue(effective.Config, configPath),
			Source:      source,
			Description: ir.getPathDescription(configPath),
		}
	}

	return trace, nil
}

// InheritanceTrace provides detailed tracing of configuration inheritance
type InheritanceTrace struct {
	StewardID   string                        `json:"steward_id"`
	TenantID    string                        `json:"tenant_id"`
	Sources     map[string]*InheritanceSource `json:"sources"`
	Elements    map[string]*TraceElement      `json:"elements"`
	GeneratedAt time.Time                     `json:"generated_at"`
}

// TraceElement represents a single traced configuration element
type TraceElement struct {
	Path        string             `json:"path"`
	Value       interface{}        `json:"value"`
	Source      *InheritanceSource `json:"source"`
	Description string             `json:"description"`
}

// getConfigValue extracts the value at a specific configuration path
func (ir *InheritanceResolver) getConfigValue(config *stewardconfig.StewardConfig, path string) interface{} {
	return nil
}

// ResolveRingVersion resolves the effective desired_version for a steward based on its
// deployment_ring DNA attribute and the controller's ring configuration.
//
// The function reads dnaAttrs["deployment_ring"], validates it against the declared ring
// set, and returns the matching ring's desired_version. When the attribute is absent or
// names a ring not in the set, the configured fallback ring is used instead.
//
// Return values:
//   - version: the resolved ring's desired_version (empty when the ring has no version set)
//   - resolvedRing: the ring name that was matched or fell back to
//   - didFallback: true when the original ring was absent or not found in the ring set
//   - originalValue: the raw deployment_ring attribute from dnaAttrs (may be empty)
//
// This function augments (does not replace) the path-based desired_version from the
// inheritance resolver: the caller should apply the returned version only when non-empty,
// overriding any tenant-path desired_version per the precedence rule.
func ResolveRingVersion(dnaAttrs map[string]string, rings controllerconfig.DeploymentRingConfig) (version, resolvedRing string, didFallback bool, originalValue string) {
	originalValue = dnaAttrs["deployment_ring"]

	byName := make(map[string]*controllerconfig.RingSpec, len(rings.Rings))
	for i := range rings.Rings {
		byName[rings.Rings[i].Name] = &rings.Rings[i]
	}

	fallbackName := rings.FallbackRing
	if fallbackName == "" {
		fallbackName = controllerconfig.DefaultFallbackRing
	}

	if originalValue != "" {
		if ring, ok := byName[originalValue]; ok {
			return ring.DesiredVersion, ring.Name, false, originalValue
		}
		didFallback = true
	} else {
		didFallback = true
	}

	if ring, ok := byName[fallbackName]; ok {
		return ring.DesiredVersion, ring.Name, didFallback, originalValue
	}
	return "", fallbackName, didFallback, originalValue
}

// getPathDescription returns a human-readable description of a configuration path
func (ir *InheritanceResolver) getPathDescription(path string) string {
	descriptions := map[string]string{
		"steward.id":             "Unique identifier for this steward instance",
		"steward.mode":           "Operation mode (standalone or controller)",
		"steward.logging.level":  "Logging verbosity level",
		"steward.logging.format": "Log output format",
		"steward.error_handling.module_load_failure": "How to handle module loading errors",
		"steward.error_handling.resource_failure":    "How to handle resource execution errors",
		"steward.error_handling.configuration_error": "How to handle configuration validation errors",
	}

	if desc, exists := descriptions[path]; exists {
		return desc
	}

	// Handle dynamic paths like resources and modules
	if len(path) > 9 && path[:9] == "resource." {
		return fmt.Sprintf("Configuration for resource '%s'", path[9:])
	}

	if len(path) > 8 && path[:8] == "modules." {
		return fmt.Sprintf("Path mapping for module '%s'", path[8:])
	}

	return "Configuration element"
}
