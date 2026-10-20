// SPDX-License-Identifier: AGPL-3.0-only
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
	"errors"
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

const (
	// maxGitStoreEntries bounds the number of live git store cache entries (and so
	// clone directories) across all tenants. Least-recently-used entries are evicted.
	maxGitStoreEntries = 256

	// gitStoreTTL is deliberately very long: a git store must not silently expire.
	// Entries leave the cache by per-tenant replacement or the LRU bound.
	gitStoreTTL = 100 * 365 * 24 * time.Hour

	// defaultGitOperationTimeout bounds a single git clone or pull so that a remote
	// that never answers cannot hold a request (or a clone directory) indefinitely.
	defaultGitOperationTimeout = 2 * time.Minute

	// defaultMaxGitCacheBytes bounds the total on-disk bytes of all cached clones.
	defaultMaxGitCacheBytes int64 = 4 << 30
)

// RouterOption configures optional router behaviour.
type RouterOption func(*controllerRouter)

// WithGitOperationTimeout sets the deadline applied to each git clone and pull.
// Non-positive values keep the default.
func WithGitOperationTimeout(d time.Duration) RouterOption {
	return func(r *controllerRouter) {
		if d > 0 {
			r.gitOpTimeout = d
		}
	}
}

// WithMaxGitCloneBytes sets the per-clone byte limit. Non-positive values keep the default.
func WithMaxGitCloneBytes(n int64) RouterOption {
	return func(r *controllerRouter) {
		if n > 0 {
			r.maxCloneBytes = n
		}
	}
}

// WithMaxGitCacheBytes sets the total byte budget for all cached clones; least-recently-used
// clones are evicted when it is exceeded. Non-positive values keep the default.
func WithMaxGitCacheBytes(n int64) RouterOption {
	return func(r *controllerRouter) {
		if n > 0 {
			r.maxCacheBytes = n
		}
	}
}

// WithMaxGitConfigFileBytes sets the per-file read limit for git-backed config reads.
func WithMaxGitConfigFileBytes(n int64) RouterOption {
	return func(r *controllerRouter) {
		if n > 0 {
			r.maxFileBytes = n
		}
	}
}

// WithMaxGitListReadBytes sets the total bytes one git-backed config listing may read.
func WithMaxGitListReadBytes(n int64) RouterOption {
	return func(r *controllerRouter) {
		if n > 0 {
			r.maxListBytes = n
		}
	}
}

// gitStoreCall is a git store construction in flight for one cache key. Callers that
// need the same key wait on done and share the result instead of cloning again.
type gitStoreCall struct {
	done  chan struct{}
	store *gitprovider.GitConfigStore
	err   error
}

// gitStoreEntry is the value held in the git store cache.
type gitStoreEntry struct {
	store    *gitprovider.GitConfigStore
	tenantID string
	repoDir  string
}

// pendingRemoval is a clone directory whose cache entry has left the cache.
type pendingRemoval struct {
	key string
	gitStoreEntry
}

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
	secretStore secretsiface.SecretStore
	gitWorkDir  string
	logger      logging.Logger
	// gitStoreMu guards the git store bookkeeping (cache lookup/insert, tenantGitKey,
	// inflight) and serialises clone directory removal against those. It is never held
	// across network I/O: construction runs outside it, serialised per cache key by
	// inflight, and a key under construction is never removed by a drain. It is never
	// held by the cache's eviction callback either; the callback only queues the
	// directory in pendingRemovals, and whoever holds (or next takes) gitStoreMu drains it.
	gitStoreMu      sync.Mutex
	inflight        map[string]*gitStoreCall // cache key -> construction in flight (guarded by gitStoreMu)
	gitOpTimeout    time.Duration
	gitStoreCache   *cache.Cache      // key: tenantID+":"+sha256(url); value: gitStoreEntry
	tenantGitKey    map[string]string // tenantID -> its single live cache key (guarded by gitStoreMu)
	pendingMu       sync.Mutex
	pendingRemovals []pendingRemoval

	maxCloneBytes int64
	maxCacheBytes int64
	maxFileBytes  int64
	maxListBytes  int64
	// gitUsage tracks each live entry's clone bytes and recency for the byte budget
	// (guarded by gitStoreMu). Stale keys are pruned when the budget is enforced.
	gitUsage map[string]*gitUsage
	useSeq   uint64
}

// gitUsage is the byte-budget bookkeeping for one cached clone.
type gitUsage struct {
	bytes   int64
	lastUse uint64
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
	opts ...RouterOption,
) routerinterfaces.ConfigSourceRouter {
	r := &controllerRouter{
		controllerStore: controllerStore,
		tenantStore:     tenantStore,
		sourceCache: cache.NewCache(cache.CacheConfig{
			Name:            "configrouting-source",
			MaxRuntimeItems: 10000,
			DefaultTTL:      sourceCacheTTL,
			CleanupInterval: 5 * time.Minute,
			EvictionPolicy:  cache.EvictionLRU,
		}),
		secretStore:  secretStore,
		gitWorkDir:   gitWorkDir,
		logger:       logger,
		tenantGitKey: make(map[string]string),
		inflight:     make(map[string]*gitStoreCall),
		gitOpTimeout: defaultGitOperationTimeout,

		maxCloneBytes: gitprovider.DefaultMaxCloneBytes,
		maxCacheBytes: defaultMaxGitCacheBytes,
		maxFileBytes:  gitprovider.DefaultMaxConfigFileBytes,
		maxListBytes:  gitprovider.DefaultMaxListReadBytes,
		gitUsage:      make(map[string]*gitUsage),
	}
	for _, opt := range opts {
		opt(r)
	}
	r.gitStoreCache = r.newGitStoreCache(maxGitStoreEntries)
	return r
}

// newGitStoreCache builds the bounded git store cache whose eviction callback queues
// the departing entry's clone directory for removal.
func (r *controllerRouter) newGitStoreCache(maxEntries int) *cache.Cache {
	return cache.NewCache(cache.CacheConfig{
		Name:            "configrouting-git-store",
		MaxRuntimeItems: maxEntries,
		DefaultTTL:      gitStoreTTL,
		CleanupInterval: 5 * time.Minute,
		EvictionPolicy:  cache.EvictionLRU,
		OnEvict:         r.onGitStoreEvicted,
	})
}

// onGitStoreEvicted runs after the cache mutex is released. It queues the clone
// directory and removes it right away unless gitStoreMu is held — in which case the
// holder (storeForSource) drains the queue before it returns.
func (r *controllerRouter) onGitStoreEvicted(key string, value interface{}) {
	entry, ok := value.(gitStoreEntry)
	if !ok {
		return
	}
	r.pendingMu.Lock()
	r.pendingRemovals = append(r.pendingRemovals, pendingRemoval{key: key, gitStoreEntry: entry})
	r.pendingMu.Unlock()

	if r.gitStoreMu.TryLock() {
		r.drainPendingRemovalsLocked()
		r.gitStoreMu.Unlock()
	}
}

// drainPendingRemovalsLocked removes the queued clone directories. Caller holds
// gitStoreMu. A directory whose key is back in the cache (re-created after it was
// evicted) is live and is left alone.
func (r *controllerRouter) drainPendingRemovalsLocked() {
	r.pendingMu.Lock()
	pending := r.pendingRemovals
	r.pendingRemovals = nil
	r.pendingMu.Unlock()
	if len(pending) == 0 {
		return
	}

	live := make(map[string]struct{})
	for _, k := range r.gitStoreCache.Keys() {
		live[k] = struct{}{}
	}
	logger := r.logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	for _, p := range pending {
		if _, isLive := live[p.key]; isLive {
			continue
		}
		if _, building := r.inflight[p.key]; building {
			// The key is being (re)built; its directory is not ours to remove yet.
			// Requeue so the construction's completion drains it.
			r.pendingMu.Lock()
			r.pendingRemovals = append(r.pendingRemovals, p)
			r.pendingMu.Unlock()
			continue
		}
		if r.tenantGitKey[p.tenantID] == p.key {
			delete(r.tenantGitKey, p.tenantID)
		}
		if err := gitprovider.RemoveCloneDir(r.gitWorkDir, p.repoDir); err != nil {
			logger.Warn("configrouting: failed to remove evicted git clone directory",
				"tenant_id", logging.SanitizeLogValue(p.tenantID),
				"error", logging.SanitizeLogValue(err.Error()),
			)
		}
	}
}

// Close stops the background cache cleanup goroutines. Call on shutdown or after tests.
// Clone directories are left in place.
func (r *controllerRouter) Close() {
	r.sourceCache.Close()
	if r.gitStoreCache != nil {
		r.gitStoreCache.Close()
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
			if errors.Is(err, business.ErrTenantDoesNotExist) {
				continue // absent level
			}
			return nil, fmt.Errorf("failed to load tenant %q on config source path: %w", logging.SanitizeLogValue(tid), err)
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
// Returns controllerStore for controller sources or when git dependencies are not wired
// (no secret store or no work directory). Returns a cached GitConfigStore for git
// sources; constructs one on first access.
//
// It fails closed: when the effective source is git and the git store cannot be
// constructed, it returns an error and never the controller store — a fallback would
// make reads report "not found" from the wrong store and send writes to it.
//
// A tenant has at most one live cache entry. When the tenant's source URL changes, the
// previous entry is deleted and its clone directory removed; the cache is also bounded
// by maxGitStoreEntries (LRU), and every entry that leaves it has its clone removed.
func (r *controllerRouter) storeForSource(ctx context.Context, tenantID string, info *pkgconfig.ConfigSourceInfo) (cfgconfig.ConfigStore, error) {
	if info.Type != pkgconfig.ConfigSourceTypeGit || r.secretStore == nil || r.gitWorkDir == "" {
		return r.controllerStore, nil
	}

	urlHash := fmt.Sprintf("%x", sha256.Sum256([]byte(info.URL)))
	cacheKey := tenantID + ":" + urlHash

	r.gitStoreMu.Lock()
	// Clear out directories of entries evicted since the last call before any
	// directory for this key is (re)created.
	r.drainPendingRemovalsLocked()

	if v, ok := r.gitStoreCache.Get(cacheKey); ok {
		r.touchUsageLocked(cacheKey)
		r.unlockAndDrain()
		return v.(gitStoreEntry).store, nil
	}

	// Another caller is already building this source: share its result.
	if call, ok := r.inflight[cacheKey]; ok {
		r.unlockAndDrain()
		select {
		case <-call.done:
		case <-ctx.Done():
			return nil, fmt.Errorf("git config source for tenant %q is unavailable", tenantID)
		}
		if call.err != nil {
			return nil, call.err
		}
		return call.store, nil
	}

	// A different URL for this tenant replaces its previous entry.
	if oldKey, ok := r.tenantGitKey[tenantID]; ok && oldKey != cacheKey {
		r.gitStoreCache.Delete(oldKey)
		delete(r.tenantGitKey, tenantID)
		r.drainPendingRemovalsLocked()
	}

	call := &gitStoreCall{done: make(chan struct{})}
	r.inflight[cacheKey] = call
	r.gitStoreMu.Unlock()

	// Network I/O runs without gitStoreMu so one slow remote cannot block other
	// sources. It is detached from the caller's cancellation (other callers may be
	// sharing it) and bounded by the git operation deadline instead.
	logger := r.logger
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	buildCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.gitOpTimeout)
	gs, err := gitprovider.NewGitConfigStore(buildCtx, info, tenantID, r.secretStore, r.gitWorkDir, logger,
		gitprovider.WithMaxCloneBytes(r.maxCloneBytes),
		gitprovider.WithMaxConfigFileBytes(r.maxFileBytes),
		gitprovider.WithMaxListReadBytes(r.maxListBytes),
	)
	cancel()
	var cloneBytes int64
	if err == nil {
		cloneBytes = gs.CloneBytes()
	}

	r.gitStoreMu.Lock()
	delete(r.inflight, cacheKey)
	if err != nil {
		slog.Warn("configrouting: failed to create git store",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"url", logging.SanitizeLogValue(info.URL),
			"error_category", "initialization_failure",
			"error", logging.SanitizeLogValue(err.Error()),
		)
		// The cause (which can carry work-directory paths) is logged, not returned.
		call.err = fmt.Errorf("git config source for tenant %q is unavailable", tenantID)
	} else {
		// A concurrent build for another source of this tenant may have landed first;
		// the tenant keeps a single live entry.
		if oldKey, ok := r.tenantGitKey[tenantID]; ok && oldKey != cacheKey {
			r.gitStoreCache.Delete(oldKey)
		}
		r.tenantGitKey[tenantID] = cacheKey
		_ = r.gitStoreCache.Set(cacheKey, gitStoreEntry{store: gs, tenantID: tenantID, repoDir: gs.RepoDir()}, gitStoreTTL)
		r.useSeq++
		r.gitUsage[cacheKey] = &gitUsage{bytes: cloneBytes, lastUse: r.useSeq}
		r.enforceByteBudgetLocked(cacheKey)
		call.store = gs
	}
	close(call.done)
	r.unlockAndDrain()

	if call.err != nil {
		return nil, call.err
	}
	return call.store, nil
}

// touchUsageLocked marks key as the most recently used clone. Caller holds gitStoreMu.
func (r *controllerRouter) touchUsageLocked(key string) {
	if u, ok := r.gitUsage[key]; ok {
		r.useSeq++
		u.lastUse = r.useSeq
	}
}

// enforceByteBudgetLocked evicts least-recently-used clones, never keep (the entry just
// added), until the cached clones fit maxCacheBytes. Eviction goes through the cache so
// the clone directory is removed by the pending-removal path. Caller holds gitStoreMu.
func (r *controllerRouter) enforceByteBudgetLocked(keep string) {
	live := make(map[string]struct{})
	for _, k := range r.gitStoreCache.Keys() {
		live[k] = struct{}{}
	}
	var total int64
	for k, u := range r.gitUsage {
		if _, ok := live[k]; !ok {
			delete(r.gitUsage, k)
			continue
		}
		total += u.bytes
	}
	for total > r.maxCacheBytes {
		victim := ""
		var oldest uint64
		for k, u := range r.gitUsage {
			if k == keep {
				continue
			}
			if victim == "" || u.lastUse < oldest {
				victim, oldest = k, u.lastUse
			}
		}
		if victim == "" {
			return
		}
		total -= r.gitUsage[victim].bytes
		delete(r.gitUsage, victim)
		r.gitStoreCache.Delete(victim)
	}
}

// unlockAndDrain drains queued clone removals, releases gitStoreMu (held by the
// caller) and picks up anything an eviction callback queued after the drain.
func (r *controllerRouter) unlockAndDrain() {
	r.drainPendingRemovalsLocked()
	r.gitStoreMu.Unlock()
	r.pendingMu.Lock()
	queued := len(r.pendingRemovals) > 0
	r.pendingMu.Unlock()
	if queued {
		r.gitStoreMu.Lock()
		r.drainPendingRemovalsLocked()
		r.gitStoreMu.Unlock()
	}
}

// SyncTenantWithRemote pulls the remote for tenantID's git source and returns the
// SHA before and after the pull. Returns ("","",nil) for non-git tenants or when
// git dependencies are not configured. Implements the tenantRemoteSyncer interface
// consumed by SyncService in pkg/configrouting.
func (r *controllerRouter) SyncTenantWithRemote(ctx context.Context, tenantID string) (prevSHA, newSHA string, err error) {
	info, err := r.GetEffectiveConfigSource(ctx, tenantID)
	if err != nil {
		return "", "", fmt.Errorf("sync: failed to get source info for %q: %w", tenantID, err)
	}
	if info.Type != pkgconfig.ConfigSourceTypeGit {
		return "", "", nil
	}

	store, err := r.storeForSource(ctx, tenantID, info)
	if err != nil {
		return "", "", fmt.Errorf("sync: %w", err)
	}
	gitStore, ok := store.(*gitprovider.GitConfigStore)
	if !ok {
		return "", "", nil // git dependencies not configured
	}

	prevSHA, err = gitStore.GetCurrentSHA()
	if err != nil {
		slog.Warn("sync: failed to read pre-pull HEAD SHA",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error_category", "sha_read_failure",
		)
		return "", "", fmt.Errorf("sync: failed to read pre-pull HEAD for %q: %w", tenantID, err)
	}
	syncCtx, cancel := context.WithTimeout(ctx, r.gitOpTimeout)
	defer cancel()
	newSHA, err = gitStore.SyncWithRemote(syncCtx)
	return prevSHA, newSHA, err
}

// checkCrossTenant returns an error if the context tenant cannot access tenantID's config.
// Rules (skip check when the context carries no tenant at all, for backward
// compatibility with internal callers that never wire per-request tenant
// context — e.g. background reconciliation, migration jobs):
//   - same tenant → allowed
//   - tenantID is an ancestor of the context tenant → allowed (cascade reads ancestors)
//   - otherwise → cross-tenant denied
//
// No tenant ID — "default" and "root" included — is treated as a bypass value
// here: each is a genuine tenant ID, not a sentinel for "unauthenticated." A
// caller actually authenticated as such a tenant is subject to the same
// same-tenant/ancestor rules as any other tenant; treating it as an automatic
// passthrough would let that principal read any other tenant's config,
// including tenants with no ancestor relationship to it at all — the gap this
// function exists to close.
func (r *controllerRouter) checkCrossTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return nil // empty TenantID is handled as "route to controllerStore" elsewhere
	}
	ctxTenant, unrestricted, ok := ctxkeys.TenantRestriction(ctx)
	if !ok {
		return fmt.Errorf("cross-tenant access denied: caller has no tenant scope for tenant %q", tenantID)
	}
	if unrestricted {
		return nil // root-scoped caller or system-internal context (Issue #4665)
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
	store, err := r.storeForSource(ctx, tenantID, info)
	if err != nil {
		return err
	}
	return fn(store)
}

// checkWriteTargets verifies, for every tenant a write touches, that a git-sourced
// tenant's git store can be constructed. Writes still land in the controller store
// (git sources are read-only), but a git tenant whose source is broken fails the
// write instead of silently proceeding. A source that cannot be resolved at all does
// not block the write, which never depended on source resolution.
func (r *controllerRouter) checkWriteTargets(ctx context.Context, tenantIDs ...string) error {
	for _, tenantID := range tenantIDs {
		if tenantID == "" {
			continue
		}
		info, err := r.GetEffectiveConfigSource(ctx, tenantID)
		if err != nil {
			continue
		}
		if _, err := r.storeForSource(ctx, tenantID, info); err != nil {
			return err
		}
	}
	return nil
}

func entryTenant(e *cfgconfig.ConfigEntry) string {
	if e == nil || e.Key == nil {
		return ""
	}
	return e.Key.TenantID
}

func keyTenant(k *cfgconfig.ConfigKey) string {
	if k == nil {
		return ""
	}
	return k.TenantID
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

// --- ConfigStore write methods — always route to controllerStore (after checkWriteTargets) ---
// External git sources are read-only; all writes go to the controller store regardless
// of the declared source type.

func (r *controllerRouter) StoreConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	if err := r.checkWriteTargets(ctx, entryTenant(config)); err != nil {
		return err
	}
	return r.controllerStore.StoreConfig(ctx, config)
}

func (r *controllerRouter) DeleteConfig(ctx context.Context, key *cfgconfig.ConfigKey) error {
	if err := r.checkWriteTargets(ctx, keyTenant(key)); err != nil {
		return err
	}
	return r.controllerStore.DeleteConfig(ctx, key)
}

func (r *controllerRouter) StoreConfigBatch(ctx context.Context, configs []*cfgconfig.ConfigEntry) error {
	tenants := make([]string, 0, len(configs))
	for _, c := range configs {
		tenants = append(tenants, entryTenant(c))
	}
	if err := r.checkWriteTargets(ctx, tenants...); err != nil {
		return err
	}
	return r.controllerStore.StoreConfigBatch(ctx, configs)
}

func (r *controllerRouter) DeleteConfigBatch(ctx context.Context, keys []*cfgconfig.ConfigKey) error {
	tenants := make([]string, 0, len(keys))
	for _, k := range keys {
		tenants = append(tenants, keyTenant(k))
	}
	if err := r.checkWriteTargets(ctx, tenants...); err != nil {
		return err
	}
	return r.controllerStore.DeleteConfigBatch(ctx, keys)
}

func (r *controllerRouter) ValidateConfig(ctx context.Context, config *cfgconfig.ConfigEntry) error {
	return r.controllerStore.ValidateConfig(ctx, config)
}

func (r *controllerRouter) GetConfigStats(ctx context.Context) (*cfgconfig.ConfigStats, error) {
	return r.controllerStore.GetConfigStats(ctx)
}
