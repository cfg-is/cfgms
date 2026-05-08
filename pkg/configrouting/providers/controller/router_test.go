// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package controller

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	flatfile "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test-double TenantStore ---

// simpleTenantStore is a test-double TenantStore backed by an in-memory map.
// Not a mock — uses real logic to walk the parent chain.
type simpleTenantStore struct {
	tenants map[string]*business.TenantData
}

func newSimpleTenantStore() *simpleTenantStore {
	return &simpleTenantStore{tenants: make(map[string]*business.TenantData)}
}

func (s *simpleTenantStore) add(id, parentID string, metadata map[string]string) {
	s.tenants[id] = &business.TenantData{
		ID:       id,
		Name:     id,
		ParentID: parentID,
		Metadata: metadata,
		Status:   business.TenantStatusActive,
	}
}

func (s *simpleTenantStore) Initialize(_ context.Context) error { return nil }
func (s *simpleTenantStore) Close() error                       { return nil }

func (s *simpleTenantStore) CreateTenant(_ context.Context, t *business.TenantData) error {
	s.tenants[t.ID] = t
	return nil
}
func (s *simpleTenantStore) GetTenant(_ context.Context, id string) (*business.TenantData, error) {
	t, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant not found: %s", id)
	}
	return t, nil
}
func (s *simpleTenantStore) UpdateTenant(_ context.Context, t *business.TenantData) error {
	s.tenants[t.ID] = t
	return nil
}
func (s *simpleTenantStore) DeleteTenant(_ context.Context, id string) error {
	delete(s.tenants, id)
	return nil
}
func (s *simpleTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	out := make([]*business.TenantData, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	return out, nil
}
func (s *simpleTenantStore) GetTenantHierarchy(_ context.Context, id string) (*business.TenantHierarchy, error) {
	path, err := s.GetTenantPath(context.Background(), id)
	if err != nil {
		return nil, err
	}
	return &business.TenantHierarchy{TenantID: id, Path: path, Depth: len(path) - 1}, nil
}
func (s *simpleTenantStore) GetChildTenants(_ context.Context, parentID string) ([]*business.TenantData, error) {
	var children []*business.TenantData
	for _, t := range s.tenants {
		if t.ParentID == parentID {
			children = append(children, t)
		}
	}
	return children, nil
}

// GetTenantPath returns the path from root to tenantID by walking parent links.
func (s *simpleTenantStore) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	var path []string
	cur := tenantID
	seen := make(map[string]bool)
	for {
		if seen[cur] {
			return nil, fmt.Errorf("cycle detected in tenant hierarchy for %q", tenantID)
		}
		seen[cur] = true
		path = append([]string{cur}, path...)
		t, ok := s.tenants[cur]
		if !ok {
			return nil, fmt.Errorf("tenant not found: %s", cur)
		}
		if t.ParentID == "" {
			break
		}
		cur = t.ParentID
	}
	return path, nil
}

// IsTenantAncestor returns true if ancestorID is a (transitive) ancestor of descendantID.
func (s *simpleTenantStore) IsTenantAncestor(_ context.Context, ancestorID, descendantID string) (bool, error) {
	cur := descendantID
	seen := make(map[string]bool)
	for {
		if seen[cur] {
			return false, nil
		}
		seen[cur] = true
		t, ok := s.tenants[cur]
		if !ok {
			return false, nil
		}
		if t.ParentID == ancestorID {
			return true, nil
		}
		if t.ParentID == "" {
			return false, nil
		}
		cur = t.ParentID
	}
}

// --- test-double ConfigStore ---

// recordingConfigStore is a test-double ConfigStore that counts how many times
// it is called. Used to verify the cross-tenant check blocks store access.
type recordingConfigStore struct {
	callCount int64
}

func (r *recordingConfigStore) record()      { atomic.AddInt64(&r.callCount, 1) }
func (r *recordingConfigStore) calls() int64 { return atomic.LoadInt64(&r.callCount) }

func (r *recordingConfigStore) StoreConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	r.record()
	return nil
}
func (r *recordingConfigStore) GetConfig(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	r.record()
	return nil, cfgconfig.ErrConfigNotFound
}
func (r *recordingConfigStore) DeleteConfig(_ context.Context, _ *cfgconfig.ConfigKey) error {
	r.record()
	return nil
}
func (r *recordingConfigStore) ListConfigs(_ context.Context, _ *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	r.record()
	return nil, nil
}
func (r *recordingConfigStore) GetConfigHistory(_ context.Context, _ *cfgconfig.ConfigKey, _ int) ([]*cfgconfig.ConfigEntry, error) {
	r.record()
	return nil, nil
}
func (r *recordingConfigStore) GetConfigVersion(_ context.Context, _ *cfgconfig.ConfigKey, _ int64) (*cfgconfig.ConfigEntry, error) {
	r.record()
	return nil, cfgconfig.ErrConfigNotFound
}
func (r *recordingConfigStore) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	r.record()
	return nil
}
func (r *recordingConfigStore) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	r.record()
	return nil
}
func (r *recordingConfigStore) ResolveConfigWithInheritance(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	r.record()
	return nil, cfgconfig.ErrConfigNotFound
}
func (r *recordingConfigStore) ValidateConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	r.record()
	return nil
}
func (r *recordingConfigStore) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	r.record()
	return nil, nil
}

// --- helpers ---

// ctxWithTenant returns a context carrying the given tenant ID.
func ctxWithTenant(tenantID string) context.Context {
	return context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
}

// --- unit tests ---

func TestGetEffectiveConfigSource_DefaultController(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", nil)

	router := NewControllerRouter(&recordingConfigStore{}, ts).(*controllerRouter)
	info, err := router.GetEffectiveConfigSource(context.Background(), "root")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type)
}

func TestGetEffectiveConfigSource_InheritsParent(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", map[string]string{
		pkgconfig.MetaKeyConfigSourceType: string(pkgconfig.ConfigSourceTypeController),
	})
	ts.add("child", "root", nil) // child has no metadata — inherits root

	router := NewControllerRouter(&recordingConfigStore{}, ts).(*controllerRouter)
	info, err := router.GetEffectiveConfigSource(context.Background(), "child")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type)
}

func TestGetEffectiveConfigSource_ChildOverridesParent(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", map[string]string{
		pkgconfig.MetaKeyConfigSourceType: string(pkgconfig.ConfigSourceTypeController),
	})
	// child has its own metadata — should be returned first (leaf-to-root walk)
	ts.add("child", "root", map[string]string{
		pkgconfig.MetaKeyConfigSourceType: string(pkgconfig.ConfigSourceTypeController),
	})

	router := NewControllerRouter(&recordingConfigStore{}, ts).(*controllerRouter)
	// The child-level entry is resolved first because we walk leaf-to-root.
	info, err := router.GetEffectiveConfigSource(context.Background(), "child")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type)
}

func TestGetEffectiveConfigSource_EmptyTenantIDRoutesToController(t *testing.T) {
	cs := &recordingConfigStore{}
	ts := newSimpleTenantStore()
	router := NewControllerRouter(cs, ts)

	// GetConfig with empty TenantID must route to controllerStore without a cross-tenant error.
	key := &cfgconfig.ConfigKey{TenantID: "", Namespace: "ns", Name: "cfg"}
	_, err := router.GetConfig(context.Background(), key)
	// ErrConfigNotFound is expected (recordingConfigStore returns it) — not a routing error.
	assert.ErrorIs(t, err, cfgconfig.ErrConfigNotFound)
	assert.Equal(t, int64(1), cs.calls(), "store must be called for empty TenantID")
}

func TestConfigSourceRouter_CrossTenantRejected(t *testing.T) {
	cs := &recordingConfigStore{}
	ts := newSimpleTenantStore()
	ts.add("tenant-a", "", nil)
	ts.add("tenant-b", "", nil) // no relationship with tenant-a

	router := NewControllerRouter(cs, ts)
	ctx := ctxWithTenant("tenant-a")

	key := &cfgconfig.ConfigKey{TenantID: "tenant-b", Namespace: "ns", Name: "cfg"}
	_, err := router.GetConfig(ctx, key)
	require.Error(t, err, "cross-tenant access must be rejected")
	assert.Contains(t, err.Error(), "cross-tenant access denied")
	assert.Equal(t, int64(0), cs.calls(), "underlying store must never be called on cross-tenant rejection")
}

func TestConfigSourceRouter_CacheInvalidatedOnTenantUpdate(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", nil)

	r := NewControllerRouter(&recordingConfigStore{}, ts).(*controllerRouter)
	ctx := context.Background()

	// Prime the cache.
	info1, err := r.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info1.Type)
	assert.Equal(t, 1, r.sourceCache.Size(), "cache should hold one entry")

	// Invalidate — simulates what tenant.Manager does after UpdateTenant.
	r.InvalidateTenantCache("root")
	assert.Equal(t, 0, r.sourceCache.Size(), "cache entry must be evicted")

	// Mutate the tenant metadata to confirm fresh resolution occurs.
	ts.tenants["root"].Metadata = map[string]string{
		pkgconfig.MetaKeyConfigSourceType: string(pkgconfig.ConfigSourceTypeController),
	}
	info2, err := r.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info2.Type)
	assert.Equal(t, 1, r.sourceCache.Size(), "cache should be repopulated after re-resolution")
}

func TestSnapshotSources_AtomicResolution(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", map[string]string{
		pkgconfig.MetaKeyConfigSourceType: string(pkgconfig.ConfigSourceTypeController),
	})
	ts.add("msp", "root", nil)
	ts.add("client", "msp", nil)

	router := NewControllerRouter(&recordingConfigStore{}, ts)
	ctx := context.Background()

	tenantPath := []string{"root", "msp", "client"}
	snapshot, err := router.SnapshotSources(ctx, tenantPath)
	require.NoError(t, err)
	require.Len(t, snapshot, 3, "snapshot must contain an entry for every path element")

	for _, tid := range tenantPath {
		info, ok := snapshot[tid]
		require.True(t, ok, "snapshot missing entry for %q", tid)
		assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type)
	}
}

func TestSnapshotSources_DeepCopyNoSharedRefs(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", nil)

	router := NewControllerRouter(&recordingConfigStore{}, ts)
	ctx := context.Background()

	snapshot, err := router.SnapshotSources(ctx, []string{"root"})
	require.NoError(t, err)

	// Mutate the snapshot entry; the cache must not reflect the mutation.
	snapshotEntry := snapshot["root"]
	snapshotEntry.Branch = "mutated"

	// Fetch again — cached value should be unchanged.
	info, err := router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.NotEqual(t, "mutated", info.Branch, "cached value must not share memory with snapshot copy")
}

func TestWriteMethodsAlwaysUseControllerStore(t *testing.T) {
	cs := &recordingConfigStore{}
	ts := newSimpleTenantStore()

	router := NewControllerRouter(cs, ts)
	ctx := context.Background()

	entry := &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "t", Namespace: "ns", Name: "cfg"},
		Data: []byte("data"),
	}
	require.NoError(t, router.StoreConfig(ctx, entry))
	require.NoError(t, router.DeleteConfig(ctx, entry.Key))
	require.NoError(t, router.StoreConfigBatch(ctx, []*cfgconfig.ConfigEntry{entry}))
	require.NoError(t, router.DeleteConfigBatch(ctx, []*cfgconfig.ConfigKey{entry.Key}))

	assert.Equal(t, int64(4), cs.calls(), "all four write calls must reach the controller store")
}

func TestGetEffectiveConfigSource_Cached(t *testing.T) {
	pathCallCount := 0
	ts := &callCountingTenantStore{
		inner:     newSimpleTenantStore(),
		pathCalls: &pathCallCount,
	}
	ts.inner.add("root", "", nil)

	router := NewControllerRouter(&recordingConfigStore{}, ts).(*controllerRouter)
	ctx := context.Background()

	// First call must hit the tenant store.
	_, err := router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, 1, pathCallCount)

	// Second call must be served from cache without re-hitting the store.
	_, err = router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, 1, pathCallCount, "cache must prevent a second GetTenantPath call")
}

// callCountingTenantStore wraps simpleTenantStore and counts GetTenantPath calls.
type callCountingTenantStore struct {
	inner     *simpleTenantStore
	pathCalls *int
}

func (s *callCountingTenantStore) Initialize(_ context.Context) error { return nil }
func (s *callCountingTenantStore) Close() error                       { return nil }
func (s *callCountingTenantStore) CreateTenant(ctx context.Context, t *business.TenantData) error {
	return s.inner.CreateTenant(ctx, t)
}
func (s *callCountingTenantStore) GetTenant(ctx context.Context, id string) (*business.TenantData, error) {
	return s.inner.GetTenant(ctx, id)
}
func (s *callCountingTenantStore) UpdateTenant(ctx context.Context, t *business.TenantData) error {
	return s.inner.UpdateTenant(ctx, t)
}
func (s *callCountingTenantStore) DeleteTenant(ctx context.Context, id string) error {
	return s.inner.DeleteTenant(ctx, id)
}
func (s *callCountingTenantStore) ListTenants(ctx context.Context, f *business.TenantFilter) ([]*business.TenantData, error) {
	return s.inner.ListTenants(ctx, f)
}
func (s *callCountingTenantStore) GetTenantHierarchy(ctx context.Context, id string) (*business.TenantHierarchy, error) {
	return s.inner.GetTenantHierarchy(ctx, id)
}
func (s *callCountingTenantStore) GetChildTenants(ctx context.Context, id string) ([]*business.TenantData, error) {
	return s.inner.GetChildTenants(ctx, id)
}
func (s *callCountingTenantStore) GetTenantPath(ctx context.Context, id string) ([]string, error) {
	*s.pathCalls++
	return s.inner.GetTenantPath(ctx, id)
}
func (s *callCountingTenantStore) IsTenantAncestor(ctx context.Context, a, d string) (bool, error) {
	return s.inner.IsTenantAncestor(ctx, a, d)
}

// --- integration test: real FlatFileConfigStore + simpleTenantStore across 3-level hierarchy ---

func TestIntegration_RouterWith3LevelHierarchy(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("root", "", map[string]string{
		pkgconfig.MetaKeyConfigSourceType: string(pkgconfig.ConfigSourceTypeController),
	})
	ts.add("msp", "root", nil)
	ts.add("client", "msp", nil)

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	router := NewControllerRouter(cs, ts)
	ctx := context.Background()

	// Write via the write path (always controllerStore).
	entry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "client", Namespace: "policies", Name: "baseline"},
		Data:   []byte("steward: {}"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, router.StoreConfig(ctx, entry))

	// Read back via the read path (routes through source resolution).
	got, err := router.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	assert.Equal(t, entry.Data, got.Data)

	// SnapshotSources must resolve all three levels.
	path := []string{"root", "msp", "client"}
	snapshot, err := router.SnapshotSources(ctx, path)
	require.NoError(t, err)
	for _, tid := range path {
		info, ok := snapshot[tid]
		require.True(t, ok, "snapshot missing entry for %q", tid)
		assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type, "all tenants route to controller in Phase 1")
	}

	// InvalidateTenantCache must not break subsequent reads.
	router.InvalidateTenantCache("client")
	info, err := router.GetEffectiveConfigSource(ctx, "client")
	require.NoError(t, err)
	assert.Equal(t, pkgconfig.ConfigSourceTypeController, info.Type)
}

func TestIntegration_CrossTenantRejectedRealFlatfileStore(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("org-a", "", nil)
	ts.add("org-b", "", nil) // completely separate root — no relationship

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	router := NewControllerRouter(cs, ts)
	ctx := ctxWithTenant("org-a")

	key := &cfgconfig.ConfigKey{TenantID: "org-b", Namespace: "ns", Name: "cfg"}
	_, err = router.GetConfig(ctx, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cross-tenant access denied")
}

// fakeClock is a Clock implementation for testing cache TTL without real sleep.
type fakeClock struct{ now time.Time }

func (f *fakeClock) Now() time.Time { return f.now }

func TestCacheTTL_ExpiredEntryNotReturned(t *testing.T) {
	start := time.Now()
	clk := &fakeClock{now: start}
	shortTTL := 50 * time.Millisecond

	c := cache.NewCache(cache.CacheConfig{
		Name:            "test-ttl",
		MaxRuntimeItems: 100,
		DefaultTTL:      shortTTL,
		EvictionPolicy:  cache.EvictionLRU,
		Clock:           clk,
	})

	// Inject a value directly with the short TTL so we don't fight the router's
	// hard-coded sourceCacheTTL constant in GetEffectiveConfigSource.
	require.NoError(t, c.Set("root", pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeController}, shortTTL))
	assert.Equal(t, 1, c.Size())

	// Advance the fake clock past the TTL — no real sleep needed.
	clk.now = start.Add(100 * time.Millisecond)
	_, ok := c.Get("root")
	assert.False(t, ok, "cache must not return an expired entry")
}
