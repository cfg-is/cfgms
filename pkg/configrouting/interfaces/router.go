// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines the ConfigSourceRouter contract for per-tenant config source routing.
package interfaces

import (
	"context"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ConfigSourceRouter wraps cfgconfig.ConfigStore and adds per-tenant config source routing.
// Implementations resolve which backing store (controller, git, etc.) to use for each
// tenant based on mount-point metadata, caching resolution decisions with a 1-minute TTL.
//
// Phase 1 routes every tenant to the controller's own store.
// Phase 2 (Story C) extends storeForSource to dispatch git sources without changing this interface.
type ConfigSourceRouter interface {
	cfgconfig.ConfigStore

	// GetEffectiveConfigSource returns the resolved config source for tenantID.
	// Walks TenantStore.GetTenantPath leaf-to-root and returns the first ancestor
	// (inclusive) with config_source_type in metadata. Falls back to
	// ConfigSourceTypeController when no metadata is present.
	GetEffectiveConfigSource(ctx context.Context, tenantID string) (*pkgconfig.ConfigSourceInfo, error)

	// SnapshotSources resolves the config source for every tenant in tenantPath in a
	// single atomic pass, acquiring the cache read-lock before iterating.
	// The returned map contains deep copies — callers must not retain references to cached values.
	// InheritanceResolver calls this once before the cascade loop to prevent
	// mid-cascade source redirects.
	SnapshotSources(ctx context.Context, tenantPath []string) (map[string]*pkgconfig.ConfigSourceInfo, error)

	// InvalidateTenantCache immediately evicts the cached source resolution for tenantID.
	// Called by tenant.Manager.UpdateTenant after a successful store update.
	InvalidateTenantCache(tenantID string)
}
