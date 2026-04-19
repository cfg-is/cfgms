// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package config provides configuration management including per-tenant config source routing.
package config

import (
	"context"
	"fmt"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// Well-known metadata keys used in TenantData.Metadata to declare config source routing.
// A tenant that does not declare a source inherits from its nearest ancestor that does.
// The root tenant defaults to ConfigSourceTypeController when no metadata is set.
const (
	// MetadataKeyConfigSourceType is "controller" (default) or "git".
	MetadataKeyConfigSourceType = "config_source_type"
	// MetadataKeyConfigSourceURL is the remote URL for a git source.
	MetadataKeyConfigSourceURL = "config_source_url"
	// MetadataKeyConfigSourceBranch is the branch to check out (git sources only).
	MetadataKeyConfigSourceBranch = "config_source_branch"
	// MetadataKeyConfigSourcePath is an optional sub-directory within the repository.
	MetadataKeyConfigSourcePath = "config_source_path"
	// MetadataKeyConfigSourceCredential references a secret for authentication.
	MetadataKeyConfigSourceCredential = "config_source_credential"
	// MetadataKeyConfigSourcePollInterval controls how often to sync from git (e.g. "5m").
	MetadataKeyConfigSourcePollInterval = "config_source_poll_interval"
)

// Config source type values.
const (
	// ConfigSourceTypeController routes config fetches to the controller's storage provider.
	// This is the default for all tenants and is backward compatible.
	ConfigSourceTypeController = "controller"
	// ConfigSourceTypeGit routes config fetches to an external git repository.
	// External git integration is implemented in Phase 2 (separate story).
	ConfigSourceTypeGit = "git"
)

// ConfigSourceInfo holds the resolved config source for a tenant.
type ConfigSourceInfo struct {
	// TenantID is the tenant this info was resolved for.
	TenantID string
	// SourceType is ConfigSourceTypeController or ConfigSourceTypeGit.
	SourceType string
	// URL is the remote URL (git sources only).
	URL string
	// Branch is the git branch (git sources only).
	Branch string
	// Path is the optional sub-directory within the repository (git sources only).
	Path string
	// Credential is a secret reference for authentication (git sources only).
	Credential string
	// PollInterval is the sync frequency as a duration string (git sources only).
	PollInterval string
	// InheritedFrom is the ancestor tenant ID this source was inherited from.
	// Empty when the tenant declares its own source.
	InheritedFrom string
}

// ConfigSourceRouter implements cfgconfig.ConfigStore and routes each config
// operation to the appropriate per-tenant store.
//
// Phase 1 behavior: all tenants route to the controller's default store.
// Routing metadata is read and resolved so that callers can inspect the
// declared source, but the actual storage backend does not change until
// Phase 2 (external git integration).
//
// The router sits between InheritanceResolver and ConfigStore:
//
//	InheritanceResolver → ConfigSourceRouter → ConfigStore (per-tenant)
type ConfigSourceRouter struct {
	// defaultStore is the controller's storage provider, used for all phase-1 routing.
	defaultStore cfgconfig.ConfigStore
	// tenantStore resolves tenant metadata and hierarchy paths.
	tenantStore business.TenantStore
}

// NewConfigSourceRouter creates a ConfigSourceRouter backed by defaultStore.
// All config operations are forwarded to defaultStore until Phase 2 adds
// external git backing stores.
func NewConfigSourceRouter(defaultStore cfgconfig.ConfigStore, tenantStore business.TenantStore) *ConfigSourceRouter {
	return &ConfigSourceRouter{
		defaultStore: defaultStore,
		tenantStore:  tenantStore,
	}
}

// GetEffectiveConfigSource resolves the config source for tenantID by walking
// up the tenant hierarchy until an explicit source declaration is found.
// If no ancestor declares a source the function returns the controller default.
//
// Inheritance rules (nearest-ancestor wins):
//  1. Tenant owns MetadataKeyConfigSourceType → use it, InheritedFrom=""
//  2. Walk parent chain root-ward; first ancestor with the key wins
//  3. No ancestor → return ConfigSourceTypeController, InheritedFrom=""
func (r *ConfigSourceRouter) GetEffectiveConfigSource(ctx context.Context, tenantID string) (*ConfigSourceInfo, error) {
	// Verify the tenant exists first so we surface a clear error for unknown IDs.
	if _, err := r.tenantStore.GetTenant(ctx, tenantID); err != nil {
		return nil, fmt.Errorf("tenant %q not found: %w", tenantID, err)
	}

	// GetTenantPath returns [root, …, tenantID] (root-first ordering).
	path, err := r.tenantStore.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant path for %q: %w", tenantID, err)
	}

	// Walk from the target tenant upward (leaf → root) to find the nearest
	// ancestor that declares a config source.
	for i := len(path) - 1; i >= 0; i-- {
		ancestor := path[i]
		tenant, err := r.tenantStore.GetTenant(ctx, ancestor)
		if err != nil {
			// Ancestor disappeared mid-walk; skip gracefully.
			continue
		}
		sourceType, ok := tenant.Metadata[MetadataKeyConfigSourceType]
		if !ok || sourceType == "" {
			continue
		}

		info := &ConfigSourceInfo{
			TenantID:     tenantID,
			SourceType:   sourceType,
			URL:          tenant.Metadata[MetadataKeyConfigSourceURL],
			Branch:       tenant.Metadata[MetadataKeyConfigSourceBranch],
			Path:         tenant.Metadata[MetadataKeyConfigSourcePath],
			Credential:   tenant.Metadata[MetadataKeyConfigSourceCredential],
			PollInterval: tenant.Metadata[MetadataKeyConfigSourcePollInterval],
		}
		if ancestor != tenantID {
			info.InheritedFrom = ancestor
		}
		return info, nil
	}

	// No ancestor declared a source: default to controller.
	return &ConfigSourceInfo{
		TenantID:   tenantID,
		SourceType: ConfigSourceTypeController,
	}, nil
}

// storeFor returns the ConfigStore to use for the given tenantID.
// In Phase 1 this always returns the default store.
// Phase 2 will swap in a git-backed store when the effective source is "git".
func (r *ConfigSourceRouter) storeFor(_ context.Context, _ string) cfgconfig.ConfigStore {
	// Phase 1: always use the default (controller) store.
	return r.defaultStore
}

// -----------------------------------------------------------------------
// cfgconfig.ConfigStore implementation — all methods delegate to storeFor.
// -----------------------------------------------------------------------

func (r *ConfigSourceRouter) StoreConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	return r.storeFor(ctx, config.Key.TenantID).StoreConfig(ctx, config)
}

func (r *ConfigSourceRouter) GetConfig(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return r.storeFor(ctx, key.TenantID).GetConfig(ctx, key)
}

func (r *ConfigSourceRouter) DeleteConfig(ctx context.Context, key *cfgconfig.ConfigKey) error {
	return r.storeFor(ctx, key.TenantID).DeleteConfig(ctx, key)
}

func (r *ConfigSourceRouter) ListConfigs(ctx context.Context, filter *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	return r.storeFor(ctx, filter.TenantID).ListConfigs(ctx, filter)
}

func (r *ConfigSourceRouter) GetConfigHistory(ctx context.Context, key *cfgconfig.ConfigKey, limit int) ([]*cfgconfig.ConfigEntry, error) {
	return r.storeFor(ctx, key.TenantID).GetConfigHistory(ctx, key, limit)
}

func (r *ConfigSourceRouter) GetConfigVersion(ctx context.Context, key *cfgconfig.ConfigKey, version int64) (*cfgconfig.ConfigEntry, error) {
	return r.storeFor(ctx, key.TenantID).GetConfigVersion(ctx, key, version)
}

func (r *ConfigSourceRouter) StoreConfigBatch(ctx context.Context, configs []*cfgconfig.ConfigEntry) error {
	if len(configs) == 0 {
		return nil
	}
	// All entries in a batch share the same effective store for Phase 1.
	return r.storeFor(ctx, configs[0].Key.TenantID).StoreConfigBatch(ctx, configs)
}

func (r *ConfigSourceRouter) DeleteConfigBatch(ctx context.Context, keys []*cfgconfig.ConfigKey) error {
	if len(keys) == 0 {
		return nil
	}
	return r.storeFor(ctx, keys[0].TenantID).DeleteConfigBatch(ctx, keys)
}

func (r *ConfigSourceRouter) ResolveConfigWithInheritance(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return r.storeFor(ctx, key.TenantID).ResolveConfigWithInheritance(ctx, key)
}

func (r *ConfigSourceRouter) ValidateConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	tenantID := ""
	if config.Key != nil {
		tenantID = config.Key.TenantID
	}
	return r.storeFor(ctx, tenantID).ValidateConfig(ctx, config)
}

func (r *ConfigSourceRouter) GetConfigStats(ctx context.Context) (*cfgconfig.ConfigStats, error) {
	return r.defaultStore.GetConfigStats(ctx)
}
