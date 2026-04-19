// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// inMemoryTenantStore is a minimal in-memory TenantStore for testing
type inMemoryTenantStore struct {
	tenants map[string]*business.TenantData
}

func newInMemoryTenantStore() *inMemoryTenantStore {
	return &inMemoryTenantStore{
		tenants: make(map[string]*business.TenantData),
	}
}

func (s *inMemoryTenantStore) CreateTenant(_ context.Context, tenant *business.TenantData) error {
	s.tenants[tenant.ID] = tenant
	return nil
}

func (s *inMemoryTenantStore) GetTenant(_ context.Context, tenantID string) (*business.TenantData, error) {
	t, ok := s.tenants[tenantID]
	if !ok {
		return nil, &cfgconfig.ConfigValidationError{Field: "tenant_id", Message: "tenant not found", Code: "TENANT_NOT_FOUND"}
	}
	return t, nil
}

func (s *inMemoryTenantStore) UpdateTenant(_ context.Context, tenant *business.TenantData) error {
	s.tenants[tenant.ID] = tenant
	return nil
}

func (s *inMemoryTenantStore) DeleteTenant(_ context.Context, tenantID string) error {
	delete(s.tenants, tenantID)
	return nil
}

func (s *inMemoryTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	var result []*business.TenantData
	for _, t := range s.tenants {
		result = append(result, t)
	}
	return result, nil
}

func (s *inMemoryTenantStore) GetTenantHierarchy(_ context.Context, tenantID string) (*business.TenantHierarchy, error) {
	path, err := s.GetTenantPath(context.Background(), tenantID)
	if err != nil {
		return nil, err
	}
	children, _ := s.GetChildTenants(context.Background(), tenantID)
	childIDs := make([]string, 0, len(children))
	for _, c := range children {
		childIDs = append(childIDs, c.ID)
	}
	return &business.TenantHierarchy{
		TenantID: tenantID,
		Path:     path,
		Depth:    len(path) - 1,
		Children: childIDs,
	}, nil
}

func (s *inMemoryTenantStore) GetChildTenants(_ context.Context, parentID string) ([]*business.TenantData, error) {
	var result []*business.TenantData
	for _, t := range s.tenants {
		if t.ParentID == parentID {
			result = append(result, t)
		}
	}
	return result, nil
}

// GetTenantPath returns the path from root to the given tenant (root first).
func (s *inMemoryTenantStore) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	var path []string
	current := tenantID
	seen := make(map[string]bool)
	for {
		if seen[current] {
			return nil, &cfgconfig.ConfigValidationError{Field: "tenant_id", Message: "circular hierarchy detected", Code: "CIRCULAR_HIERARCHY"}
		}
		seen[current] = true
		path = append([]string{current}, path...)
		t, ok := s.tenants[current]
		if !ok {
			break
		}
		if t.ParentID == "" {
			break
		}
		current = t.ParentID
	}
	return path, nil
}

func (s *inMemoryTenantStore) IsTenantAncestor(_ context.Context, ancestorID, descendantID string) (bool, error) {
	current := descendantID
	seen := make(map[string]bool)
	for {
		if seen[current] {
			return false, nil
		}
		seen[current] = true
		t, ok := s.tenants[current]
		if !ok {
			return false, nil
		}
		if t.ParentID == ancestorID {
			return true, nil
		}
		if t.ParentID == "" {
			return false, nil
		}
		current = t.ParentID
	}
}

func (s *inMemoryTenantStore) Initialize(_ context.Context) error { return nil }
func (s *inMemoryTenantStore) Close() error                       { return nil }

// helpers for building test tenant hierarchies

func newTenant(id, parentID string, metadata map[string]string) *business.TenantData {
	return &business.TenantData{
		ID:        id,
		Name:      id,
		ParentID:  parentID,
		Metadata:  metadata,
		Status:    business.TenantStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

// TestConfigSourceMetadataKeys verifies constants are defined and non-empty.
func TestConfigSourceMetadataKeys(t *testing.T) {
	assert.NotEmpty(t, MetadataKeyConfigSourceType)
	assert.NotEmpty(t, MetadataKeyConfigSourceURL)
	assert.NotEmpty(t, MetadataKeyConfigSourceBranch)
	assert.NotEmpty(t, MetadataKeyConfigSourcePath)
	assert.NotEmpty(t, MetadataKeyConfigSourceCredential)
	assert.NotEmpty(t, MetadataKeyConfigSourcePollInterval)
	assert.Equal(t, "controller", ConfigSourceTypeController)
	assert.Equal(t, "git", ConfigSourceTypeGit)
}

// TestNewConfigSourceRouter verifies constructor returns a non-nil, functional
// router that implements cfgconfig.ConfigStore.
func TestNewConfigSourceRouter(t *testing.T) {
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)
	require.NotNil(t, router)

	// Verify it satisfies the interface at compile time and is usable at runtime.
	var cs cfgconfig.ConfigStore = router
	require.NotNil(t, cs)

	// GetConfigStats is a zero-dependency operation that confirms the router
	// correctly delegates to the underlying store.
	stats, err := router.GetConfigStats(context.Background())
	require.NoError(t, err)
	require.NotNil(t, stats)
}

// TestGetEffectiveConfigSource_ExplicitController verifies that a tenant with
// config_source_type=controller resolves to a controller source.
func TestGetEffectiveConfigSource_ExplicitController(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("root", "", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeController,
	})))

	router := NewConfigSourceRouter(store, ts)
	info, err := router.GetEffectiveConfigSource(ctx, "root")
	require.NoError(t, err)
	assert.Equal(t, "root", info.TenantID)
	assert.Equal(t, ConfigSourceTypeController, info.SourceType)
	assert.Empty(t, info.InheritedFrom)
}

// TestGetEffectiveConfigSource_ExplicitGit verifies that a tenant with
// config_source_type=git resolves to a git source with all metadata fields.
func TestGetEffectiveConfigSource_ExplicitGit(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("msp", "", map[string]string{
		MetadataKeyConfigSourceType:         ConfigSourceTypeGit,
		MetadataKeyConfigSourceURL:          "git@github.com:clientG/cfgs.git",
		MetadataKeyConfigSourceBranch:       "main",
		MetadataKeyConfigSourcePath:         "stewards/",
		MetadataKeyConfigSourceCredential:   "secret:clientG-deploy-key",
		MetadataKeyConfigSourcePollInterval: "5m",
	})))

	router := NewConfigSourceRouter(store, ts)
	info, err := router.GetEffectiveConfigSource(ctx, "msp")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeGit, info.SourceType)
	assert.Equal(t, "git@github.com:clientG/cfgs.git", info.URL)
	assert.Equal(t, "main", info.Branch)
	assert.Equal(t, "stewards/", info.Path)
	assert.Equal(t, "secret:clientG-deploy-key", info.Credential)
	assert.Equal(t, "5m", info.PollInterval)
	assert.Empty(t, info.InheritedFrom)
}

// TestGetEffectiveConfigSource_Default verifies that a tenant with no metadata
// at any level defaults to controller source.
func TestGetEffectiveConfigSource_Default(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("root", "", nil)))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("child", "root", nil)))

	router := NewConfigSourceRouter(store, ts)
	info, err := router.GetEffectiveConfigSource(ctx, "child")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeController, info.SourceType)
}

// TestGetEffectiveConfigSource_InheritedFromParent verifies that a tenant
// without its own config source declaration inherits from its parent.
func TestGetEffectiveConfigSource_InheritedFromParent(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("msp", "", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeGit,
		MetadataKeyConfigSourceURL:  "git@github.com:msp/cfgs.git",
	})))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("client", "msp", nil)))

	router := NewConfigSourceRouter(store, ts)
	info, err := router.GetEffectiveConfigSource(ctx, "client")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeGit, info.SourceType)
	assert.Equal(t, "git@github.com:msp/cfgs.git", info.URL)
	assert.Equal(t, "msp", info.InheritedFrom)
}

// TestGetEffectiveConfigSource_InheritedFromGrandparent verifies multi-level
// inheritance: child → parent (no source) → grandparent (has source).
func TestGetEffectiveConfigSource_InheritedFromGrandparent(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("root", "", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeGit,
		MetadataKeyConfigSourceURL:  "git@github.com:root/cfgs.git",
	})))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("mid", "root", nil)))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("leaf", "mid", nil)))

	router := NewConfigSourceRouter(store, ts)
	info, err := router.GetEffectiveConfigSource(ctx, "leaf")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeGit, info.SourceType)
	assert.Equal(t, "root", info.InheritedFrom)
}

// TestGetEffectiveConfigSource_ChildOverridesParent verifies that a child's
// explicit declaration takes precedence over the parent's.
func TestGetEffectiveConfigSource_ChildOverridesParent(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("msp", "", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeGit,
		MetadataKeyConfigSourceURL:  "git@github.com:msp/cfgs.git",
	})))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("client", "msp", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeController,
	})))

	router := NewConfigSourceRouter(store, ts)
	info, err := router.GetEffectiveConfigSource(ctx, "client")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeController, info.SourceType)
	assert.Empty(t, info.InheritedFrom) // own declaration, not inherited
}

// TestGetEffectiveConfigSource_MultipleTenantsDifferentSources tests multiple
// tenants with different declared sources resolve independently.
func TestGetEffectiveConfigSource_MultipleTenantsDifferentSources(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("msp", "", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeController,
	})))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("clientA", "msp", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeGit,
		MetadataKeyConfigSourceURL:  "git@github.com:clientA/cfgs.git",
	})))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("clientB", "msp", nil)))
	require.NoError(t, ts.CreateTenant(ctx, newTenant("clientC", "msp", map[string]string{
		MetadataKeyConfigSourceType: ConfigSourceTypeController,
	})))

	router := NewConfigSourceRouter(store, ts)

	// clientA: own git declaration
	infoA, err := router.GetEffectiveConfigSource(ctx, "clientA")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeGit, infoA.SourceType)
	assert.Equal(t, "git@github.com:clientA/cfgs.git", infoA.URL)
	assert.Empty(t, infoA.InheritedFrom)

	// clientB: no metadata → inherits controller from msp
	infoB, err := router.GetEffectiveConfigSource(ctx, "clientB")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeController, infoB.SourceType)
	assert.Equal(t, "msp", infoB.InheritedFrom)

	// clientC: explicit controller
	infoC, err := router.GetEffectiveConfigSource(ctx, "clientC")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceTypeController, infoC.SourceType)
	assert.Empty(t, infoC.InheritedFrom)
}

// TestGetEffectiveConfigSource_UnknownTenant verifies that requesting the
// effective source for a completely unknown tenant returns an error.
func TestGetEffectiveConfigSource_UnknownTenant(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)
	_, err := router.GetEffectiveConfigSource(ctx, "does-not-exist")
	assert.Error(t, err)
}

// -----------------------------------------------------------------------
// ConfigStore interface delegation tests
// -----------------------------------------------------------------------

// TestConfigSourceRouter_DelegatesStoreConfig verifies that StoreConfig
// forwards to the default store (backward-compatible, phase 1).
func TestConfigSourceRouter_DelegatesStoreConfig(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	require.NoError(t, ts.CreateTenant(ctx, newTenant("t1", "", nil)))

	router := NewConfigSourceRouter(store, ts)

	entry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "stewards", Name: "s1"},
		Data:   []byte("key: value"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, router.StoreConfig(ctx, entry))

	got, err := router.GetConfig(ctx, entry.Key)
	require.NoError(t, err)
	assert.Equal(t, entry.Data, got.Data)
}

// TestConfigSourceRouter_DelegatesDeleteConfig verifies delete forwarding.
func TestConfigSourceRouter_DelegatesDeleteConfig(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()
	require.NoError(t, ts.CreateTenant(ctx, newTenant("t1", "", nil)))

	router := NewConfigSourceRouter(store, ts)

	entry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "stewards", Name: "s1"},
		Data:   []byte("key: value"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, router.StoreConfig(ctx, entry))
	require.NoError(t, router.DeleteConfig(ctx, entry.Key))

	_, err := router.GetConfig(ctx, entry.Key)
	assert.Error(t, err)
}

// TestConfigSourceRouter_DelegatesListConfigs verifies list forwarding.
func TestConfigSourceRouter_DelegatesListConfigs(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()
	require.NoError(t, ts.CreateTenant(ctx, newTenant("t1", "", nil)))

	router := NewConfigSourceRouter(store, ts)

	for _, name := range []string{"s1", "s2"} {
		require.NoError(t, router.StoreConfig(ctx, &cfgconfig.ConfigEntry{
			Key:    &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "stewards", Name: name},
			Data:   []byte("key: val"),
			Format: cfgconfig.ConfigFormatYAML,
		}))
	}

	list, err := router.ListConfigs(ctx, &cfgconfig.ConfigFilter{TenantID: "t1"})
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

// TestConfigSourceRouter_DelegatesHistory verifies history forwarding.
func TestConfigSourceRouter_DelegatesHistory(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()
	require.NoError(t, ts.CreateTenant(ctx, newTenant("t1", "", nil)))

	router := NewConfigSourceRouter(store, ts)
	key := &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "stewards", Name: "s1"}

	for i := 0; i < 3; i++ {
		require.NoError(t, router.StoreConfig(ctx, &cfgconfig.ConfigEntry{
			Key:    key,
			Data:   []byte("v"),
			Format: cfgconfig.ConfigFormatYAML,
		}))
	}

	history, err := router.GetConfigHistory(ctx, key, 10)
	require.NoError(t, err)
	assert.NotEmpty(t, history)
}

// TestConfigSourceRouter_DelegatesStats verifies stats delegation.
func TestConfigSourceRouter_DelegatesStats(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)
	stats, err := router.GetConfigStats(ctx)
	require.NoError(t, err)
	assert.NotNil(t, stats)
}

// TestConfigSourceRouter_DelegatesValidateConfig verifies validate delegation.
func TestConfigSourceRouter_DelegatesValidateConfig(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)
	err := router.ValidateConfig(ctx, &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "n"},
	})
	assert.NoError(t, err)
}

// TestConfigSourceRouter_DelegatesResolveWithInheritance verifies
// ResolveConfigWithInheritance delegation.
func TestConfigSourceRouter_DelegatesResolveWithInheritance(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)
	key := &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "n"}

	require.NoError(t, store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    key,
		Data:   []byte("ok: true"),
		Format: cfgconfig.ConfigFormatYAML,
	}))

	got, err := router.ResolveConfigWithInheritance(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, []byte("ok: true"), got.Data)
}

// TestConfigSourceRouter_DelegatesBatchOperations verifies batch operation
// forwarding.
func TestConfigSourceRouter_DelegatesBatchOperations(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)

	entries := []*cfgconfig.ConfigEntry{
		{Key: &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "a"}, Data: []byte("a: 1"), Format: cfgconfig.ConfigFormatYAML},
		{Key: &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "b"}, Data: []byte("b: 2"), Format: cfgconfig.ConfigFormatYAML},
	}
	require.NoError(t, router.StoreConfigBatch(ctx, entries))

	keys := []*cfgconfig.ConfigKey{entries[0].Key, entries[1].Key}
	require.NoError(t, router.DeleteConfigBatch(ctx, keys))

	_, err := router.GetConfig(ctx, entries[0].Key)
	assert.Error(t, err)
}

// TestConfigSourceRouter_GetConfigVersion delegates to default store.
func TestConfigSourceRouter_GetConfigVersion(t *testing.T) {
	ctx := context.Background()
	store := NewMockConfigStore()
	ts := newInMemoryTenantStore()

	router := NewConfigSourceRouter(store, ts)
	key := &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "cfg"}

	// Store two versions
	require.NoError(t, router.StoreConfig(ctx, &cfgconfig.ConfigEntry{Key: key, Data: []byte("v1"), Format: cfgconfig.ConfigFormatYAML}))
	require.NoError(t, router.StoreConfig(ctx, &cfgconfig.ConfigEntry{Key: key, Data: []byte("v2"), Format: cfgconfig.ConfigFormatYAML}))

	// Version 1 should be in history
	entry, err := router.GetConfigVersion(ctx, key, 1)
	require.NoError(t, err)
	assert.Equal(t, []byte("v1"), entry.Data)
}
