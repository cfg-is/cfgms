// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package controller provides the ConfigSourceRouter implementation that routes tenant
// config reads to the appropriate backing store — controller store or git store.
//
// Phase 2 (Story C) extends storeForSource to dispatch git sources without modifying
// this router's interface or the cache/snapshot machinery defined here.
package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	routerinterfaces "github.com/cfgis/cfgms/pkg/configrouting/interfaces"
	gitprovider "github.com/cfgis/cfgms/pkg/configrouting/providers/git"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const sourceCacheTTL = time.Minute

// controllerRouter implements ConfigSourceRouter routing reads to the appropriate store.
type controllerRouter struct {
	controllerStore cfgconfig.ConfigStore
	tenantStore     business.TenantStore
	sourceCache     *cache.Cache
	// snapshotMu serialises InvalidateTenantCache against SnapshotSources so that
	// a snapshot never straddles a cache flush — every entry in the snapshot is
	// resolved from the same generation of the cache.
	snapshotMu sync.RWMutex

	// git source fields (nil when not configured — controller-only mode)
	secretStore   secretsiface.SecretStore
	gitWorkDir    string
	logger        logging.Logger
	gitStoreMu    sync.Mutex
	gitStoreCache map[string]*gitprovider.GitConfigStore // key: tenantID+":"+sha256(url)
}

// NewControllerRouter creates a ConfigSourceRouter that delegates all reads and writes
// to controllerStore. tenantStore is used to resolve the tenant hierarchy for source
// resolution and cross-tenant access checks.
func NewControllerRouter(controllerStore cfgconfig.ConfigStore, tenantStore business.TenantStore) routerinterfaces.ConfigSourceRouter {
	return &controllerRouter{
		controllerStore: controllerStore,
		tenantStore:     tenantStore,
		sourceCache: cache.NewCache(cache.CacheConfig{
			Name:            "configrouting-source",
			MaxRuntimeItems: 10000,
			DefaultTTL:      sourceCacheTTL,
			CleanupInterval: 5 * time.Minute,
			EvictionPolicy:  cache.EvictionLRU,
		}),
	}
}

// NewControllerRouterWithGit creates a ConfigSourceRouter that supports both controller
// and external HTTPS git config sources. secretStore is used to fetch git credentials at
// transport time. gitWorkDir is the base directory for cloned repositories.
func NewControllerRouterWithGit(
	controllerStore cfgconfig.ConfigStore,
	tenantStore business.TenantStore,
	secretStore secretsiface.SecretStore,
	gitWorkDir string,
	logger logging.Logger,
) routerinterfaces.ConfigSourceRouter {
	return &controllerRouter{
		controllerStore: controllerStore,
		tenantStore:     tenantStore,
		sourceCache: cache.NewCache(cache.CacheConfig{
			Name:            "configrouting-source",
			MaxRuntimeItems: 10000,
			DefaultTTL:      sourceCacheTTL,
			CleanupInterval: 5 * time.Minute,
			EvictionPolicy:  cache.EvictionLRU,
		}),
		secretStore:   secretStore,
		gitWorkDir:    gitWorkDir,
		logger:        logger,
		gitStoreCache: make(map[string]*gitprovider.GitConfigStore),
	}
}

// GetEffectiveConfigSource resolves the config source for tenantID, walking the tenant
// path leaf-to-root and returning the first ancestor (inclusive) that has
// config_source_type in its metadata. Results are cached for sourceCacheTTL.
func (r *controllerRouter) GetEffectiveConfigSource(ctx context.Context, tenantID string) (*pkgconfig.ConfigSourceInfo, error) {
	if cached, ok := r.sourceCache.Get(tenantID); ok {
		info := cached.(pkgconfig.ConfigSourceInfo)
		return &info, nil
	}

	path, err := r.tenantStore.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant path for %q: %w", tenantID, err)
	}

	// Walk leaf-to-root: GetTenantPath returns root→leaf, so iterate in reverse.
	for i := len(path) - 1; i >= 0; i-- {
		tid := path[i]
		tenant, err := r.tenantStore.GetTenant(ctx, tid)
		if err != nil {
			continue // skip tenants that can't be loaded
		}
		if _, hasType := tenant.Metadata[pkgconfig.MetaKeyConfigSourceType]; hasType {
			info, err := pkgconfig.ParseConfigSource(tenant.Metadata)
			if err != nil {
				return nil, fmt.Errorf("invalid config source metadata for tenant %q: %w", tid, err)
			}
			if info.Type == pkgconfig.ConfigSourceTypeGit {
				slog.Debug("config source router: git source resolved",
					"tenant_id", logging.SanitizeLogValue(tenantID),
					"resolved_from", logging.SanitizeLogValue(tid),
					"url", logging.SanitizeLogValue(info.URL),
				)
			}
			_ = r.sourceCache.Set(tenantID, *info, sourceCacheTTL)
			return info, nil
		}
	}

	// No metadata found anywhere in the hierarchy — default to controller.
	info := &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeController}
	_ = r.sourceCache.Set(tenantID, *info, sourceCacheTTL)
	return info, nil
}

// SnapshotSources resolves config sources for every tenant in tenantPath in a single
// atomic pass. Holds snapshotMu.RLock() throughout so that InvalidateTenantCache
// cannot flush the cache mid-iteration, keeping the snapshot internally consistent.
// Each returned *ConfigSourceInfo is a deep copy; callers must not retain references.
func (r *controllerRouter) SnapshotSources(ctx context.Context, tenantPath []string) (map[string]*pkgconfig.ConfigSourceInfo, error) {
	r.snapshotMu.RLock()
	defer r.snapshotMu.RUnlock()

	result := make(map[string]*pkgconfig.ConfigSourceInfo, len(tenantPath))
	for _, tenantID := range tenantPath {
		info, err := r.GetEffectiveConfigSource(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("snapshot: failed to resolve source for tenant %q: %w", tenantID, err)
		}
		copied := *info // deep copy — ConfigSourceInfo contains no pointer fields that need cloning
		result[tenantID] = &copied
	}
	return result, nil
}

// InvalidateTenantCache evicts the cached source resolution for tenantID. Acquires
// snapshotMu.Lock() so that in-flight snapshots complete before the entry is removed.
func (r *controllerRouter) InvalidateTenantCache(tenantID string) {
	r.snapshotMu.Lock()
	defer r.snapshotMu.Unlock()
	r.sourceCache.Delete(tenantID)
}

// storeForSource returns the ConfigStore to use for the given tenantID and source.
// Returns controllerStore for controller sources or when git dependencies are not wired.
// Returns a cached GitConfigStore for git sources; constructs one on first access.
func (r *controllerRouter) storeForSource(ctx context.Context, tenantID string, info *pkgconfig.ConfigSourceInfo) cfgconfig.ConfigStore {
	if info.Type != pkgconfig.ConfigSourceTypeGit || r.secretStore == nil || r.gitWorkDir == "" {
		return r.controllerStore
	}

	urlHash := fmt.Sprintf("%x", sha256.Sum256([]byte(info.URL)))
	cacheKey := tenantID + ":" + urlHash

	r.gitStoreMu.Lock()
	defer r.gitStoreMu.Unlock()

	if gs, ok := r.gitStoreCache[cacheKey]; ok {
		return gs
	}

	logger := r.logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	gs, err := gitprovider.NewGitConfigStore(ctx, info, tenantID, r.secretStore, r.gitWorkDir, logger)
	if err != nil {
		slog.Warn("configrouting: failed to create git store, falling back to controller store",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"url", logging.SanitizeLogValue(info.URL),
			"error_category", "initialization_failure",
		)
		return r.controllerStore
	}

	r.gitStoreCache[cacheKey] = gs
	return gs
}

// checkCrossTenant returns an error if the context tenant cannot access tenantID's config.
// Rules (skip check when either side is unset/default for backward compatibility):
//   - same tenant → allowed
//   - tenantID is an ancestor of the context tenant → allowed (cascade reads ancestors)
//   - otherwise → cross-tenant denied
func (r *controllerRouter) checkCrossTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return nil // empty TenantID is handled as "route to controllerStore" elsewhere
	}
	ctxTenant, ok := ctx.Value(ctxkeys.TenantID).(string)
	if !ok || ctxTenant == "" || ctxTenant == "default" {
		return nil // no authenticated context tenant — backward-compat passthrough
	}
	if ctxTenant == tenantID {
		return nil
	}
	// Allow reads of ancestor tenants (InheritanceResolver walking up the hierarchy).
	isAncestor, err := r.tenantStore.IsTenantAncestor(ctx, tenantID, ctxTenant)
	if err != nil {
		return fmt.Errorf("cross-tenant check for tenant %q: %w", tenantID, err)
	}
	if !isAncestor {
		return fmt.Errorf("cross-tenant access denied: caller %q cannot access tenant %q",
			ctxTenant, tenantID)
	}
	return nil
}

// routeRead resolves the store for tenantID and delegates the actual call to fn.
// Empty TenantID bypasses resolution and goes to controllerStore.
func (r *controllerRouter) routeRead(ctx context.Context, tenantID string, fn func(cfgconfig.ConfigStore) error) error {
	if tenantID == "" {
		return fn(r.controllerStore)
	}
	if err := r.checkCrossTenant(ctx, tenantID); err != nil {
		return err
	}
	info, err := r.GetEffectiveConfigSource(ctx, tenantID)
	if err != nil {
		return err
	}
	return fn(r.storeForSource(ctx, tenantID, info))
}

// --- ConfigStore read methods ---

func (r *controllerRouter) GetConfig(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	var result *cfgconfig.ConfigEntry
	err := r.routeRead(ctx, key.TenantID, func(s cfgconfig.ConfigStore) error {
		var e error
		result, e = s.GetConfig(ctx, key)
		return e
	})
	return result, err
}

func (r *controllerRouter) ListConfigs(ctx context.Context, filter *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	tenantID := ""
	if filter != nil {
		tenantID = filter.TenantID
	}
	var result []*cfgconfig.ConfigEntry
	err := r.routeRead(ctx, tenantID, func(s cfgconfig.ConfigStore) error {
		var e error
		result, e = s.ListConfigs(ctx, filter)
		return e
	})
	return result, err
}

func (r *controllerRouter) GetConfigHistory(ctx context.Context, key *cfgconfig.ConfigKey, limit int) ([]*cfgconfig.ConfigEntry, error) {
	var result []*cfgconfig.ConfigEntry
	err := r.routeRead(ctx, key.TenantID, func(s cfgconfig.ConfigStore) error {
		var e error
		result, e = s.GetConfigHistory(ctx, key, limit)
		return e
	})
	return result, err
}

func (r *controllerRouter) GetConfigVersion(ctx context.Context, key *cfgconfig.ConfigKey, version int64) (*cfgconfig.ConfigEntry, error) {
	var result *cfgconfig.ConfigEntry
	err := r.routeRead(ctx, key.TenantID, func(s cfgconfig.ConfigStore) error {
		var e error
		result, e = s.GetConfigVersion(ctx, key, version)
		return e
	})
	return result, err
}

func (r *controllerRouter) ResolveConfigWithInheritance(ctx context.Context, key *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	var result *cfgconfig.ConfigEntry
	err := r.routeRead(ctx, key.TenantID, func(s cfgconfig.ConfigStore) error {
		var e error
		result, e = s.ResolveConfigWithInheritance(ctx, key)
		return e
	})
	return result, err
}

// --- ConfigStore write methods — always route to controllerStore ---
// External git sources are read-only; all writes go to the controller store regardless
// of the declared source type.

func (r *controllerRouter) StoreConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	return r.controllerStore.StoreConfig(ctx, config)
}

func (r *controllerRouter) DeleteConfig(ctx context.Context, key *cfgconfig.ConfigKey) error {
	return r.controllerStore.DeleteConfig(ctx, key)
}

func (r *controllerRouter) StoreConfigBatch(ctx context.Context, configs []*cfgconfig.ConfigEntry) error {
	return r.controllerStore.StoreConfigBatch(ctx, configs)
}

func (r *controllerRouter) DeleteConfigBatch(ctx context.Context, keys []*cfgconfig.ConfigKey) error {
	return r.controllerStore.DeleteConfigBatch(ctx, keys)
}

func (r *controllerRouter) ValidateConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	return r.controllerStore.ValidateConfig(ctx, config)
}

func (r *controllerRouter) GetConfigStats(ctx context.Context) (*cfgconfig.ConfigStats, error) {
	return r.controllerStore.GetConfigStats(ctx)
}
