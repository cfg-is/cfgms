// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package service provides Epic 6 compliant configuration service using ConfigStore interface
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	common "github.com/cfgis/cfgms/api/proto/common"
	controller "github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/config/rollback"
	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	clusterregistry "github.com/cfgis/cfgms/features/controller/clusterregistry"
	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/pkg/config"
	controllerrouter "github.com/cfgis/cfgms/pkg/configrouting/providers/controller"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ValidationFailedError is returned by SetConfiguration when the supplied
// configuration fails pre-storage validation. The Errors slice contains only
// config-derived validation failures (e.g. INVALID_RESOURCE_NAME) — infrastructure
// errors such as TENANT_LOOKUP_ERROR are stripped before the error is constructed
// and logged separately, so this type is safe to forward to the API caller.
type ValidationFailedError struct {
	Errors []config.ValidationError
}

func (e *ValidationFailedError) Error() string {
	if len(e.Errors) == 0 {
		return "configuration validation failed"
	}
	msgs := make([]string, len(e.Errors))
	for i, ve := range e.Errors {
		msgs[i] = fmt.Sprintf("%s: %s", ve.Field, ve.Message)
	}
	return "configuration validation failed: " + strings.Join(msgs, "; ")
}

// clusterRegistryAdapter adapts *ControllerService to the clusterMembership interface
// expected by pkg/config.InheritanceResolver. It builds a fresh Registry snapshot on
// each MemberClusters call from the controller's live in-memory steward state, which
// reflects DNA attributes last published by each steward's DNARefreshLoop ticker
// (default 30 min — eventually consistent by design; see Issue #2425 Out of Scope).
type clusterRegistryAdapter struct {
	controllerSvc *ControllerService
}

// MemberClusters returns the sorted cluster names that stewardID belongs to,
// derived from the current in-memory steward DNA attributes. Cluster membership
// is scoped to the queried steward's own tenant so that same-named clusters in
// different tenants cannot pollute each other's member lists (BuildRegistry
// contract: "Tenant scoping must be applied by the caller").
func (a *clusterRegistryAdapter) MemberClusters(stewardID string) []string {
	info, exists := a.controllerSvc.GetStewardInfo(stewardID)
	if !exists {
		return nil
	}
	tenantID := info.TenantID

	stewards := a.controllerSvc.GetAllStewards()
	fleetData := make([]fleet.StewardData, 0, len(stewards))
	for _, s := range stewards {
		if s.TenantID != tenantID {
			continue // scope to this steward's tenant only
		}
		var attrs map[string]string
		if s.DNA != nil {
			attrs = s.DNA.Attributes
		}
		var frags []*common.Fragment
		if s.DNA != nil {
			frags = s.DNA.Fragments
		}
		fleetData = append(fleetData, fleet.StewardData{
			ID:            s.ID,
			TenantID:      s.TenantID,
			DNAAttributes: attrs,
			DNAFragments:  frags,
		})
	}
	reg := clusterregistry.BuildRegistry(fleetData)
	return reg.MemberClusters(stewardID)
}

// storedRoleConfig is the JSON shape written by handlers_roles.go (features/controller/api).
// Duplicated here without importing the api package to break the service→api→service cycle.
type storedRoleConfig struct {
	Name     string                     `json:"name"`
	Selector string                     `json:"selector"`
	Fragment stewardtypes.StewardConfig `json:"fragment"`
}

// singleStewardProvider is a fleet.StewardProvider wrapping exactly one StewardData.
// Used by roleConfigAdapter to check filter matches via the canonical fleet.MemoryQuery
// (which calls the unexported matchesFilter) — one matcher, two consumers (Issue #2546).
type singleStewardProvider struct{ s fleet.StewardData }

func (p *singleStewardProvider) GetAllStewards() []fleet.StewardData {
	return []fleet.StewardData{p.s}
}

// roleConfigAdapter adapts the controller's config store and steward state to the
// roleConfigProvider interface expected by pkg/config.InheritanceResolver.
// It lists all role-policies for the steward's tenant, parses each selector, and
// returns the fragments whose selector matches the steward's current DNA + tags.
type roleConfigAdapter struct {
	controllerSvc *ControllerService
	configStore   cfgconfig.ConfigStore
	logger        logging.Logger
}

// MatchingRoleFragments returns the role config fragments whose selectors match
// stewardID's current DNA + controller-stored tags, sorted alphabetically by role name.
// DNA currency: os/arch/runtime_os are eventually-consistent (steward-reported, refreshed
// on DNARefreshLoop; default 30 min); tags are always-current (controller store, updated
// on each tag admin call). Dynamic-attribute correctness is tracked by epic #2520 — do
// not block on it.
func (a *roleConfigAdapter) MatchingRoleFragments(ctx context.Context, stewardID string) ([]config.RoleFragment, error) {
	info, exists := a.controllerSvc.GetStewardInfo(stewardID)
	if !exists {
		return nil, nil
	}

	// Build DNA attrs map; merge in controller-stored tags so tag: selector terms work.
	attrs := make(map[string]string)
	if info.DNA != nil {
		for k, v := range info.DNA.Attributes {
			attrs[k] = v
		}
	}
	if ts := a.controllerSvc.TagStore(); ts != nil {
		attrs = mergeTagsIntoAttrs(attrs, ts.TagsFor(stewardID))
	}

	entries, err := a.configStore.ListConfigs(ctx, &cfgconfig.ConfigFilter{
		TenantID:  info.TenantID,
		Namespace: "role-policies",
	})
	if err != nil {
		return nil, fmt.Errorf("role adapter: list role-policies for tenant %s: %w",
			logging.SanitizeLogValue(info.TenantID), err)
	}

	stewardData := fleet.StewardData{
		ID:            stewardID,
		TenantID:      info.TenantID,
		DNAAttributes: attrs,
	}
	q := fleet.NewMemoryQuery(&singleStewardProvider{s: stewardData})

	var matched []config.RoleFragment
	for _, entry := range entries {
		var rc storedRoleConfig
		if err := json.Unmarshal(entry.Data, &rc); err != nil {
			a.logger.Warn("role adapter: skipping malformed role config entry",
				"name", logging.SanitizeLogValue(entry.Key.Name),
				"error", err)
			continue
		}
		filter, _, err := selector.Parse(rc.Selector)
		if err != nil {
			a.logger.Warn("role adapter: skipping role config with unparseable selector",
				"name", logging.SanitizeLogValue(rc.Name),
				"error", err)
			continue
		}
		count, _ := q.Count(ctx, filter)
		if count > 0 {
			matched = append(matched, config.RoleFragment{
				Name:   rc.Name,
				Config: rc.Fragment,
			})
		}
	}

	// Sort alphabetically by role name for deterministic merge order; later name
	// overrides earlier for the same resource name (same upsert semantics as other layers).
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].Name < matched[j].Name
	})

	return matched, nil
}

// mergeTagsIntoAttrs returns a copy of attrs with ctrlTags merged into the "tags" key.
// DNA-reported tags come first; controller-stored tags follow; duplicates are dropped.
// Never mutates the input map — attrs may alias info.DNA.Attributes (shared, cached ref).
func mergeTagsIntoAttrs(attrs map[string]string, ctrlTags []string) map[string]string {
	if len(ctrlTags) == 0 {
		return attrs
	}
	merged := make(map[string]string, len(attrs)+1)
	for k, v := range attrs {
		merged[k] = v
	}
	seen := make(map[string]struct{})
	var all []string
	for _, t := range strings.Split(merged["tags"], ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			all = append(all, t)
		}
	}
	for _, t := range ctrlTags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, dup := seen[t]; !dup {
			seen[t] = struct{}{}
			all = append(all, t)
		}
	}
	merged["tags"] = strings.Join(all, ",")
	return merged
}

// FanoutCallback is invoked inside SetConfiguration after a successful ConfigStore write.
// tenantID matches the authenticated tenant that issued the write; cfgID is the steward
// config identifier. The callback must not block — hand off expensive work to a goroutine.
type FanoutCallback func(ctx context.Context, tenantID string, cfgID string)

// ConfigurationServiceV2 implements Epic 6 compliant Configuration service
// This replaces the in-memory storage with persistent ConfigStore
type ConfigurationServiceV2 struct {
	logger              logging.Logger
	configManager       *config.Manager
	rollbackManager     rollback.RollbackManager
	inheritanceResolver *config.InheritanceResolver
	validationManager   *config.ValidationManager
	controllerSvc       *ControllerService
	storageManager      *interfaces.StorageManager
	fanoutCallback      FanoutCallback
	callbackMu          sync.RWMutex
	routerCloser        func() // stops the router's background cache goroutine
}

// NewConfigurationServiceV2 creates a new Epic 6 compliant Configuration service.
// A ConfigSourceRouter wrapping the storage manager's config and tenant stores is
// constructed here and injected into the InheritanceResolver so that SnapshotSources
// is called once per cascade (atomic source resolution, per story #1393).
// When controllerSvc is non-nil, cluster-policies cascade is enabled via a
// clusterRegistryAdapter that derives membership from the live in-memory fleet state
// (eventually consistent; see Issue #2425).
func NewConfigurationServiceV2(logger logging.Logger, storageManager *interfaces.StorageManager, controllerSvc *ControllerService) *ConfigurationServiceV2 {
	router := controllerrouter.NewControllerRouter(
		storageManager.GetConfigStore(),
		storageManager.GetTenantStore(),
	)

	var ir *config.InheritanceResolver
	if controllerSvc != nil {
		ir = config.NewInheritanceResolverWithRoles(
			router,
			storageManager.GetClientTenantStore(),
			storageManager.GetTenantStore(),
			&clusterRegistryAdapter{controllerSvc: controllerSvc},
			&roleConfigAdapter{
				controllerSvc: controllerSvc,
				configStore:   storageManager.GetConfigStore(),
				logger:        logger,
			},
		)
	} else {
		ir = config.NewInheritanceResolver(router, storageManager.GetClientTenantStore(), storageManager.GetTenantStore())
	}

	svc := &ConfigurationServiceV2{
		logger:              logger,
		configManager:       config.NewManagerWithStorageManager(storageManager),
		inheritanceResolver: ir,
		validationManager:   config.NewValidationManager(storageManager.GetConfigStore(), storageManager.GetTenantStore()),
		controllerSvc:       controllerSvc,
		storageManager:      storageManager,
	}
	if c, ok := router.(interface{ Close() }); ok {
		svc.routerCloser = c.Close
	}
	return svc
}

// Close stops the router's background cache cleanup goroutine. Safe to call multiple times.
func (s *ConfigurationServiceV2) Close() {
	if s.routerCloser != nil {
		s.routerCloser()
	}
}

// SetRollbackManager wires the canonical rollback manager into the service.
func (s *ConfigurationServiceV2) SetRollbackManager(m rollback.RollbackManager) {
	s.rollbackManager = m
}

// RegisterFanoutCallback registers a callback that is invoked once, synchronously,
// after every successful ConfigStore write in SetConfiguration. The callback is
// unreachable from any other code path. Pass nil to deregister.
func (s *ConfigurationServiceV2) RegisterFanoutCallback(fn FanoutCallback) {
	s.callbackMu.Lock()
	defer s.callbackMu.Unlock()
	s.fanoutCallback = fn
}

// GetConfiguration retrieves configuration for a specific steward using ConfigStore
func (s *ConfigurationServiceV2) GetConfiguration(ctx context.Context, req *controller.ConfigRequest) (*controller.ConfigResponse, error) {
	sanitizedModules := make([]string, len(req.Modules))
	for i, m := range req.Modules {
		sanitizedModules[i] = logging.SanitizeLogValue(m)
	}
	s.logger.Debug("Configuration request received", "steward_id", logging.SanitizeLogValue(req.StewardId), "modules", sanitizedModules)

	// Resolve the tenant the configuration is stored under. Per-steward config
	// lives under the steward's own tenant, so look the steward up first and
	// use its tenant for retrieval — not the ctx tenant, which the
	// mTLS-authenticated data-plane sync path does not set. (Issue #1572)
	tenantID := extractTenantID(ctx)

	if s.controllerSvc != nil {
		stewardInfo, exists := s.controllerSvc.GetStewardInfo(req.StewardId)
		if !exists {
			s.logger.Warn("Configuration request from unknown steward", "steward_id", logging.SanitizeLogValue(req.StewardId))
			return &controller.ConfigResponse{
				Status: &common.Status{
					Code:    common.Status_NOT_FOUND,
					Message: "Steward not found",
				},
			}, nil
		}

		// Cross-tenant guard: a caller presenting an explicit, non-empty tenant
		// context must match the steward's tenant. The data-plane sync path
		// (steward authenticated by its mTLS CN) carries no tenant context and
		// is trusted to resolve to the steward's own tenant. (Issue #1572)
		if reqTenant, ok := ctx.Value(ctxkeys.TenantID).(string); ok && reqTenant != "" && reqTenant != stewardInfo.TenantID {
			s.logger.Warn("Configuration request cross-tenant access denied",
				"steward_id", logging.SanitizeLogValue(req.StewardId),
				"steward_tenant", logging.SanitizeLogValue(stewardInfo.TenantID),
				"request_tenant", logging.SanitizeLogValue(reqTenant))
			return &controller.ConfigResponse{
				Status: &common.Status{
					Code:    common.Status_UNAUTHORIZED,
					Message: "Cross-tenant access denied",
				},
			}, nil
		}
		tenantID = stewardInfo.TenantID
	}

	// Resolve full tenant-cascade-merged effective config via InheritanceResolver.
	// ResolveConfiguration walks the ancestor chain (MSP→Client→Group→Device),
	// child resources overriding parent resources of the same name (Issue #1722).
	effective, err := s.inheritanceResolver.ResolveConfiguration(ctx, tenantID, req.StewardId)
	if err != nil {
		// ResolveConfiguration walks the steward's tenant ancestor chain, which
		// requires the tenant to exist as a full tenant-hierarchy record. A
		// steward can be registered under a tenant that exists only as an
		// identifier — created from a registration token, never promoted to a
		// TenantData record — and such a tenant has no ancestor chain to walk.
		// Fall back to delivering the device-level config directly so SyncConfig
		// still serves the steward; the full cascade still applies whenever the
		// tenant hierarchy is known. (Issue #1722)
		effective = s.resolveDeviceLevelFallback(ctx, tenantID, req.StewardId)
		if effective == nil {
			s.logger.Debug("No configuration found for steward", "steward_id", logging.SanitizeLogValue(req.StewardId), "error", err)
			return &controller.ConfigResponse{
				Status: &common.Status{
					Code:    common.Status_NOT_FOUND,
					Message: "No configuration found for steward",
				},
			}, nil
		}
	}
	if len(effective.Sources) == 0 {
		s.logger.Debug("No configuration found for steward at any hierarchy level", "steward_id", logging.SanitizeLogValue(req.StewardId))
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_NOT_FOUND,
				Message: "No configuration found for steward",
			},
		}, nil
	}

	// Apply ring-resolved desired_version override. The ring takes precedence over any
	// tenant-path desired_version when the steward belongs to a ring with a non-empty version.
	if s.controllerSvc != nil {
		if info, exists := s.controllerSvc.GetStewardInfo(req.StewardId); exists && info.DNA != nil {
			version, ring, didFallback, original := s.controllerSvc.ResolveRingVersion(info.DNA.Attributes)
			if didFallback {
				s.logger.Warn("deployment_ring_fallback",
					"steward_id", logging.SanitizeLogValue(req.StewardId),
					"ring_value", logging.SanitizeLogValue(original),
					"fallback_ring", logging.SanitizeLogValue(ring),
				)
			}
			if version != "" {
				effective.Config.Steward.Upgrade.DesiredVersion = version
			}
		}
	}

	// Filter configuration by requested modules if specified
	filteredConfig := s.filterConfigByModules(effective.Config, req.Modules)

	// Convert Go struct to protobuf
	protoConfig, err := stewardtypes.ToProto(filteredConfig)
	if err != nil {
		s.logger.Error("Failed to convert configuration to protobuf", "steward_id", logging.SanitizeLogValue(req.StewardId), "error", err)
		return &controller.ConfigResponse{
			Status: &common.Status{
				Code:    common.Status_ERROR,
				Message: "Failed to serialize configuration",
			},
		}, nil
	}

	// Get version information from storage
	history, err := s.configManager.GetConfigurationHistory(ctx, tenantID, req.StewardId, 1)
	version := "unknown"
	if err == nil && len(history) > 0 {
		version = fmt.Sprintf("v%d", history[0].Version)
	}

	s.logger.Debug("Configuration retrieved successfully", "steward_id", logging.SanitizeLogValue(req.StewardId), "version", version)

	return &controller.ConfigResponse{
		Status: &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration retrieved successfully",
		},
		Config:  &controller.SignedConfig{Config: protoConfig}, // Unsigned, QUIC handler will sign
		Version: version,
	}, nil
}

// resolveDeviceLevelFallback returns the steward's device-level configuration as an
// EffectiveConfiguration when the full tenant cascade cannot be resolved because the
// steward's tenant has no tenant-hierarchy record. It returns nil — leaving the caller
// to report NOT_FOUND — when the tenant does exist (the cascade error is then a genuine
// failure that must not be masked) or when no device-level config is stored for the
// steward. (Issue #1722)
func (s *ConfigurationServiceV2) resolveDeviceLevelFallback(ctx context.Context, tenantID, stewardID string) *config.EffectiveConfiguration {
	if _, err := s.storageManager.GetTenantStore().GetTenant(ctx, tenantID); err == nil {
		// The tenant exists as a full record, so the cascade failure is a real
		// error — do not paper over it with a device-only fallback.
		return nil
	}

	deviceCfg, err := s.configManager.GetConfiguration(ctx, tenantID, stewardID)
	if err != nil {
		return nil
	}

	return &config.EffectiveConfiguration{
		StewardID: stewardID,
		TenantID:  tenantID,
		Config:    deviceCfg,
		Sources: map[string]*config.InheritanceSource{
			"steward.config": {
				Level:    int(config.LevelDevice),
				TenantID: tenantID,
				Source:   "Device Configuration (tenant has no hierarchy record)",
			},
		},
		GeneratedAt: time.Now(),
	}
}

// SetConfiguration stores a configuration for a specific steward using ConfigStore
func (s *ConfigurationServiceV2) SetConfiguration(ctx context.Context, tenantID, stewardID string, config *stewardtypes.StewardConfig) error {
	// Validate configuration before storing
	validationResult := s.validationManager.ValidateConfiguration(ctx, tenantID, stewardID, config)
	if !validationResult.Valid {
		// Separate config-derived errors (safe to return) from infrastructure errors.
		// TENANT_LOOKUP_ERROR wraps a raw storage backend message that must not be
		// forwarded to the caller; it is logged here instead.
		vfe := &ValidationFailedError{}
		for _, e := range validationResult.Errors {
			if e.Code == "TENANT_LOOKUP_ERROR" {
				s.logger.Error("Infrastructure error during configuration validation",
					"tenant_id", logging.SanitizeLogValue(tenantID),
					"steward_id", logging.SanitizeLogValue(stewardID),
					"code", e.Code)
				continue
			}
			vfe.Errors = append(vfe.Errors, e)
		}
		if len(vfe.Errors) > 0 {
			return vfe
		}
		return fmt.Errorf("configuration validation failed: infrastructure error")
	}

	// Log validation warnings
	for _, warning := range validationResult.Warnings {
		s.logger.Warn("Configuration validation warning",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"field", logging.SanitizeLogValue(warning.Field),
			"message", logging.SanitizeLogValue(warning.Message))
	}

	// Store configuration
	if err := s.configManager.StoreConfiguration(ctx, tenantID, stewardID, config); err != nil {
		return fmt.Errorf("failed to store configuration: %w", err)
	}

	s.logger.Info("Configuration stored successfully",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"steward_id", logging.SanitizeLogValue(stewardID))

	s.callbackMu.RLock()
	cb := s.fanoutCallback
	s.callbackMu.RUnlock()
	if cb != nil {
		cb(ctx, tenantID, stewardID)
	}

	return nil
}

// GetEffectiveConfiguration returns the effective configuration with inheritance metadata
func (s *ConfigurationServiceV2) GetEffectiveConfiguration(ctx context.Context, tenantID, stewardID string) (*config.EffectiveConfiguration, error) {
	return s.inheritanceResolver.ResolveConfiguration(ctx, tenantID, stewardID)
}

// GetConfigStore returns the underlying config store for direct namespace access
// (e.g., reading cluster-policies or role-policies entries by key).
func (s *ConfigurationServiceV2) GetConfigStore() cfgconfig.ConfigStore {
	return s.storageManager.GetConfigStore()
}

// GetClusterDeclaredResources returns the resource configs stored in the
// cluster-policies/<clusterName> document for the given tenant. These are the
// resources declared to exist in the cluster (the "declared" side of the
// reconciliation comparison against the actual cluster registry).
//
// Returns nil resources (no error) when no cluster-policies document exists for
// the cluster — the caller treats this as an empty declared set, meaning
// only dead-owner and split-brain conditions can be detected (not create-coverage
// gaps). A non-nil error is returned only for genuine parse failures.
func (s *ConfigurationServiceV2) GetClusterDeclaredResources(ctx context.Context, tenantID, clusterName string) ([]stewardtypes.ResourceConfig, error) {
	key := &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "cluster-policies",
		Name:      clusterName,
	}
	entry, err := s.storageManager.GetConfigStore().GetConfig(ctx, key)
	if err != nil {
		return nil, nil // not found is non-fatal; no declared resources
	}
	var cfg stewardtypes.StewardConfig
	if err := yaml.Unmarshal(entry.Data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing cluster-policies/%s: %w", clusterName, err)
	}
	return cfg.Resources, nil
}

// RollbackConfiguration performs configuration rollback via the canonical rollback manager.
func (s *ConfigurationServiceV2) RollbackConfiguration(ctx context.Context, request *config.RollbackRequest) (*config.RollbackResponse, error) {
	if s.rollbackManager == nil {
		return nil, fmt.Errorf("rollback manager not initialized")
	}

	s.logger.Info("Configuration rollback requested",
		"steward_id", logging.SanitizeLogValue(request.StewardID),
		"target_version", request.TargetVersion,
		"reason", logging.SanitizeLogValue(request.Reason))

	translated := s.translateRollbackRequest(request)
	op, err := s.rollbackManager.ExecuteRollback(ctx, translated)
	if err != nil {
		s.logger.Error("Configuration rollback failed",
			"steward_id", logging.SanitizeLogValue(request.StewardID),
			"target_version", request.TargetVersion,
			"error", err)
		return &config.RollbackResponse{
			Success:  false,
			Errors:   []string{err.Error()},
			Warnings: []string{},
		}, err
	}

	var errors []string
	if op.Result != nil {
		for _, f := range op.Result.Failures {
			errors = append(errors, f.Error)
		}
	}

	response := &config.RollbackResponse{
		RollbackID: op.ID,
		Success:    op.Status == rollback.RollbackStatusCompleted,
		Errors:     errors,
		Warnings:   []string{},
	}

	if response.Success {
		s.logger.Info("Configuration rollback successful",
			"steward_id", logging.SanitizeLogValue(request.StewardID),
			"rollback_id", op.ID)
	}

	return response, nil
}

// translateRollbackRequest maps a config.RollbackRequest to the canonical rollback.RollbackRequest.
// RollbackTo uses fmt.Sprintf("v%d", ...) — the git-backed rollback manager resolves version refs.
func (s *ConfigurationServiceV2) translateRollbackRequest(req *config.RollbackRequest) rollback.RollbackRequest {
	return rollback.RollbackRequest{
		TargetID:   req.StewardID,
		TargetType: rollback.TargetTypeSteward,
		RollbackTo: fmt.Sprintf("v%d", req.TargetVersion),
		Reason:     req.Reason,
		DryRun:     req.ValidateOnly,
		Options: rollback.RollbackOptions{
			SkipValidation: req.SkipValidation,
		},
	}
}

// ListConfigurations lists all configurations for a tenant
func (s *ConfigurationServiceV2) ListConfigurations(ctx context.Context, tenantID string) ([]*config.ConfigurationSummary, error) {
	return s.configManager.ListConfigurations(ctx, tenantID)
}

// DeleteConfiguration removes a stored steward configuration
func (s *ConfigurationServiceV2) DeleteConfiguration(ctx context.Context, tenantID, stewardID string) error {
	return s.configManager.DeleteConfiguration(ctx, tenantID, stewardID)
}

// GetConfigurationHistory retrieves version history for a configuration
func (s *ConfigurationServiceV2) GetConfigurationHistory(ctx context.Context, tenantID, stewardID string, limit int) ([]*config.ConfigurationVersion, error) {
	return s.configManager.GetConfigurationHistory(ctx, tenantID, stewardID, limit)
}

// BatchSetConfigurations stores multiple configurations atomically
func (s *ConfigurationServiceV2) BatchSetConfigurations(ctx context.Context, configs []*config.BatchConfigurationEntry) error {
	// Validate all configurations first
	for _, entry := range configs {
		validationResult := s.validationManager.ValidateConfiguration(ctx, entry.TenantID, entry.StewardID, entry.Config)
		if !validationResult.Valid {
			var errorMessages []string
			for _, err := range validationResult.Errors {
				errorMessages = append(errorMessages, fmt.Sprintf("%s: %s", err.Field, err.Message))
			}
			return fmt.Errorf("validation failed for steward %s: %v", entry.StewardID, errorMessages)
		}
	}

	// Store all configurations in batch
	if err := s.configManager.BatchStoreConfigurations(ctx, configs); err != nil {
		return fmt.Errorf("failed to store configurations in batch: %w", err)
	}

	s.logger.Info("Batch configuration storage completed", "count", len(configs))
	return nil
}

// ValidateConfig validates a configuration using comprehensive validation
func (s *ConfigurationServiceV2) ValidateConfig(ctx context.Context, req *controller.ConfigValidationRequest) (*controller.ConfigValidationResponse, error) {
	s.logger.Debug("Configuration validation request received", "version", logging.SanitizeLogValue(req.Version))

	// Parse configuration
	var stewardConfig stewardtypes.StewardConfig
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

	// Extract tenant and steward ID from context (simplified)
	tenantID := extractTenantID(ctx)
	stewardID := "validation" // For validation-only requests

	// Use comprehensive validation framework
	validationResult := s.validationManager.ValidateConfiguration(ctx, tenantID, stewardID, &stewardConfig)

	// Convert validation result to proto format
	var validationErrors []*controller.ValidationError
	for _, issue := range validationResult.Errors {
		protoLevel := s.convertValidationLevel(issue.Level)
		validationErrors = append(validationErrors, &controller.ValidationError{
			Field:      issue.Field,
			Message:    issue.Message,
			Level:      protoLevel,
			Code:       issue.Code,
			Suggestion: issue.Suggestion,
		})
	}

	for _, warning := range validationResult.Warnings {
		protoLevel := s.convertValidationLevel(warning.Level)
		validationErrors = append(validationErrors, &controller.ValidationError{
			Field:      warning.Field,
			Message:    warning.Message,
			Level:      protoLevel,
			Code:       warning.Code,
			Suggestion: warning.Suggestion,
		})
	}

	// Determine response status
	var status *common.Status
	if !validationResult.Valid {
		status = &common.Status{
			Code:    common.Status_ERROR,
			Message: "Configuration has critical errors that prevent operation",
		}
	} else if len(validationResult.Warnings) > 0 {
		status = &common.Status{
			Code:    common.Status_OK,
			Message: fmt.Sprintf("Configuration is valid with %d warnings", len(validationResult.Warnings)),
		}
	} else {
		status = &common.Status{
			Code:    common.Status_OK,
			Message: "Configuration is fully valid",
		}
	}

	s.logger.Debug("Configuration validation completed",
		"version", logging.SanitizeLogValue(req.Version),
		"valid", validationResult.Valid,
		"errors", len(validationResult.Errors),
		"warnings", len(validationResult.Warnings))

	return &controller.ConfigValidationResponse{
		Status: status,
		Errors: validationErrors,
		Metadata: map[string]string{
			"validation_timestamp": time.Now().Format(time.RFC3339),
			"total_issues":         fmt.Sprintf("%d", len(validationResult.Errors)+len(validationResult.Warnings)),
			"storage_provider":     s.storageManager.GetProviderName(),
		},
	}, nil
}

// Helper methods

// filterConfigByModules filters configuration to include only requested modules
func (s *ConfigurationServiceV2) filterConfigByModules(config *stewardtypes.StewardConfig, modules []string) *stewardtypes.StewardConfig {
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

// convertValidationLevel converts internal validation level to proto level
func (s *ConfigurationServiceV2) convertValidationLevel(level string) controller.ValidationError_Level {
	switch level {
	case "info":
		return controller.ValidationError_INFO
	case "warning":
		return controller.ValidationError_WARNING
	case "error":
		return controller.ValidationError_ERROR
	case "critical":
		return controller.ValidationError_CRITICAL
	default:
		return controller.ValidationError_ERROR
	}
}

// GetStorageStats returns storage statistics
func (s *ConfigurationServiceV2) GetStorageStats(ctx context.Context) (*cfgconfig.ConfigStats, error) {
	return s.configManager.GetConfigurationStats(ctx)
}
