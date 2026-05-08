// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package configrouting

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gogittransport "github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/audit"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	configroutingiface "github.com/cfgis/cfgms/pkg/configrouting/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// ---- test-double TenantStore ----

// syncTestTenantStore is a real in-memory TenantStore that walks parent links.
type syncTestTenantStore struct {
	mu      sync.RWMutex
	tenants map[string]*business.TenantData
}

func newSyncTestTenantStore() *syncTestTenantStore {
	return &syncTestTenantStore{tenants: make(map[string]*business.TenantData)}
}

func (s *syncTestTenantStore) add(id, parentID string, metadata map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[id] = &business.TenantData{
		ID:       id,
		Name:     id,
		ParentID: parentID,
		Metadata: metadata,
		Status:   business.TenantStatusActive,
	}
}

func (s *syncTestTenantStore) Initialize(_ context.Context) error { return nil }
func (s *syncTestTenantStore) Close() error                       { return nil }

func (s *syncTestTenantStore) CreateTenant(_ context.Context, t *business.TenantData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[t.ID] = t
	return nil
}
func (s *syncTestTenantStore) GetTenant(_ context.Context, id string) (*business.TenantData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("tenant not found: %s", id)
	}
	return t, nil
}
func (s *syncTestTenantStore) UpdateTenant(_ context.Context, t *business.TenantData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[t.ID] = t
	return nil
}
func (s *syncTestTenantStore) DeleteTenant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, id)
	return nil
}
func (s *syncTestTenantStore) ListTenants(_ context.Context, _ *business.TenantFilter) ([]*business.TenantData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*business.TenantData, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	return out, nil
}
func (s *syncTestTenantStore) GetTenantHierarchy(_ context.Context, id string) (*business.TenantHierarchy, error) {
	path, err := s.GetTenantPath(context.Background(), id)
	if err != nil {
		return nil, err
	}
	return &business.TenantHierarchy{TenantID: id, Path: path, Depth: len(path) - 1}, nil
}
func (s *syncTestTenantStore) GetChildTenants(_ context.Context, parentID string) ([]*business.TenantData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var children []*business.TenantData
	for _, t := range s.tenants {
		if t.ParentID == parentID {
			children = append(children, t)
		}
	}
	return children, nil
}
func (s *syncTestTenantStore) GetTenantPath(_ context.Context, tenantID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
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
func (s *syncTestTenantStore) IsTenantAncestor(_ context.Context, ancestorID, descendantID string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
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

// compile-time check
var _ business.TenantStore = (*syncTestTenantStore)(nil)

// ---- test-double ConfigSourceRouter + tenantRemoteSyncer ----

// syncResult is the per-tenant sync outcome that syncTestRouter returns.
type syncResult struct {
	prevSHA string
	newSHA  string
	err     error
}

// syncTestRouter is a test double that implements ConfigSourceRouter and
// tenantRemoteSyncer with controllable sync outcomes.
type syncTestRouter struct {
	mu          sync.Mutex
	sources     map[string]*pkgconfig.ConfigSourceInfo
	syncResults map[string]syncResult
	syncCalls   map[string]int64
}

func newSyncTestRouter() *syncTestRouter {
	return &syncTestRouter{
		sources:     make(map[string]*pkgconfig.ConfigSourceInfo),
		syncResults: make(map[string]syncResult),
		syncCalls:   make(map[string]int64),
	}
}

func (r *syncTestRouter) setSource(tenantID string, info *pkgconfig.ConfigSourceInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sources[tenantID] = info
}

func (r *syncTestRouter) setSyncResult(tenantID string, res syncResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncResults[tenantID] = res
}

// tenantRemoteSyncer implementation
func (r *syncTestRouter) SyncTenantWithRemote(_ context.Context, tenantID string) (string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.syncCalls[tenantID]++
	res := r.syncResults[tenantID]
	return res.prevSHA, res.newSHA, res.err
}

// ConfigSourceRouter methods
func (r *syncTestRouter) GetEffectiveConfigSource(_ context.Context, tenantID string) (*pkgconfig.ConfigSourceInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if info, ok := r.sources[tenantID]; ok {
		return info, nil
	}
	return &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeController}, nil
}

func (r *syncTestRouter) SnapshotSources(_ context.Context, tenantPath []string) (map[string]*pkgconfig.ConfigSourceInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[string]*pkgconfig.ConfigSourceInfo, len(tenantPath))
	for _, id := range tenantPath {
		if info, ok := r.sources[id]; ok {
			cp := *info
			result[id] = &cp
		} else {
			result[id] = &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeController}
		}
	}
	return result, nil
}

func (r *syncTestRouter) InvalidateTenantCache(_ string) {}

// ConfigStore no-op methods to satisfy cfgconfig.ConfigStore
func (r *syncTestRouter) GetConfig(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (r *syncTestRouter) ListConfigs(_ context.Context, _ *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	return nil, nil
}
func (r *syncTestRouter) GetConfigHistory(_ context.Context, _ *cfgconfig.ConfigKey, _ int) ([]*cfgconfig.ConfigEntry, error) {
	return nil, nil
}
func (r *syncTestRouter) GetConfigVersion(_ context.Context, _ *cfgconfig.ConfigKey, _ int64) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (r *syncTestRouter) ResolveConfigWithInheritance(_ context.Context, _ *cfgconfig.ConfigKey) (*cfgconfig.ConfigEntry, error) {
	return nil, cfgconfig.ErrConfigNotFound
}
func (r *syncTestRouter) ValidateConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error {
	return nil
}
func (r *syncTestRouter) GetConfigStats(_ context.Context) (*cfgconfig.ConfigStats, error) {
	return nil, nil
}
func (r *syncTestRouter) StoreConfig(_ context.Context, _ *cfgconfig.ConfigEntry) error { return nil }
func (r *syncTestRouter) DeleteConfig(_ context.Context, _ *cfgconfig.ConfigKey) error  { return nil }
func (r *syncTestRouter) StoreConfigBatch(_ context.Context, _ []*cfgconfig.ConfigEntry) error {
	return nil
}
func (r *syncTestRouter) DeleteConfigBatch(_ context.Context, _ []*cfgconfig.ConfigKey) error {
	return nil
}

// compile-time checks
var _ configroutingiface.ConfigSourceRouter = (*syncTestRouter)(nil)
var _ tenantRemoteSyncer = (*syncTestRouter)(nil)

// ---- test-double AuditStore ----

// captureAuditStore is a real in-memory AuditStore that records stored entries.
type captureAuditStore struct {
	mu      sync.Mutex
	entries []*business.AuditEntry
}

func (s *captureAuditStore) StoreAuditEntry(_ context.Context, e *business.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *e
	s.entries = append(s.entries, &cp)
	return nil
}

func (s *captureAuditStore) findByAction(action string) []*business.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []*business.AuditEntry
	for _, e := range s.entries {
		if e.Action == action {
			result = append(result, e)
		}
	}
	return result
}

func (s *captureAuditStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *captureAuditStore) GetAuditEntry(_ context.Context, _ string) (*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) ListAuditEntries(_ context.Context, _ *business.AuditFilter) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) StoreAuditBatch(_ context.Context, entries []*business.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		cp := *e
		s.entries = append(s.entries, &cp)
	}
	return nil
}
func (s *captureAuditStore) GetAuditsByUser(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) GetAuditsByResource(_ context.Context, _, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) GetAuditsByAction(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) GetFailedActions(_ context.Context, _ *business.TimeRange, _ int) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) GetSuspiciousActivity(_ context.Context, _ string, _ *business.TimeRange) ([]*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) GetAuditStats(_ context.Context) (*business.AuditStats, error) {
	return nil, nil
}
func (s *captureAuditStore) GetLastAuditEntry(_ context.Context, _ string) (*business.AuditEntry, error) {
	return nil, nil
}
func (s *captureAuditStore) ArchiveAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (s *captureAuditStore) PurgeAuditEntries(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (s *captureAuditStore) Close() error { return nil }

var _ business.AuditStore = (*captureAuditStore)(nil)

// ---- helpers ----

// newTestAuditManager creates a real audit.Manager backed by a captureAuditStore.
func newTestAuditManager(t *testing.T) (*audit.Manager, *captureAuditStore) {
	t.Helper()
	store := &captureAuditStore{}
	m, err := audit.NewManager(store, "sync-service-test")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = m.Stop(ctx)
	})
	return m, store
}

// noopCascade is a no-op cascade function for Phase 2.
func noopCascade(_ context.Context, _ string) error { return nil }

// gitSource returns a ConfigSourceInfo for a git-sourced tenant.
func gitSource(pollInterval time.Duration) *pkgconfig.ConfigSourceInfo {
	return &pkgconfig.ConfigSourceInfo{
		Type:         pkgconfig.ConfigSourceTypeGit,
		URL:          "https://git.example.com/repo.git",
		PollInterval: pollInterval,
	}
}

// ---- tests ----

func TestSyncService_SuccessfulPull(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)
	ts.add("tenant1", "root", nil)

	router := newSyncTestRouter()
	router.setSource("tenant1", gitSource(time.Hour))
	router.setSyncResult("tenant1", syncResult{prevSHA: "abc", newSHA: "def"})

	var cascadeCalled int64
	cascadeFn := func(_ context.Context, _ string) error {
		atomic.AddInt64(&cascadeCalled, 1)
		return nil
	}

	auditMgr, store := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), cascadeFn, "root")

	ctx := context.Background()
	info := gitSource(time.Hour)
	svc.syncOnce(ctx, "tenant1", info)

	ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(ctx2))

	events := store.findByAction("config_source_sync")
	require.Len(t, events, 1)
	assert.Equal(t, "tenant1", events[0].TenantID)
	assert.Equal(t, int64(1), atomic.LoadInt64(&cascadeCalled), "cascade must be called on successful pull with new commits")
}

func TestSyncService_PullFailurePreservesState(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)
	ts.add("tenant1", "root", nil)

	router := newSyncTestRouter()
	router.setSource("tenant1", gitSource(time.Hour))
	router.setSyncResult("tenant1", syncResult{err: errors.New("connection refused to git.example.com")})

	var cascadeCalled int64
	cascadeFn := func(_ context.Context, _ string) error {
		atomic.AddInt64(&cascadeCalled, 1)
		return nil
	}

	auditMgr, store := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), cascadeFn, "root")

	ctx := context.Background()
	info := gitSource(time.Hour)
	svc.syncOnce(ctx, "tenant1", info)

	ctx2, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(ctx2))

	assert.Equal(t, int64(0), atomic.LoadInt64(&cascadeCalled), "cascade must NOT be called on pull failure")

	failEvents := store.findByAction("config_source_sync_failed")
	require.Len(t, failEvents, 1, "one failure audit event must be recorded")
	assert.Equal(t, "tenant1", failEvents[0].TenantID)

	successEvents := store.findByAction("config_source_sync")
	assert.Empty(t, successEvents, "no success audit event must be recorded on failure")
}

func TestSyncService_StopDrainsGoroutines(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)
	ts.add("tenant1", "root", nil)
	ts.add("tenant2", "root", nil)

	router := newSyncTestRouter()
	// Use long poll intervals so goroutines never actually fire before Stop.
	router.setSource("tenant1", gitSource(time.Hour))
	router.setSource("tenant2", gitSource(time.Hour))
	router.setSyncResult("tenant1", syncResult{prevSHA: "a", newSHA: "a"}) // no change
	router.setSyncResult("tenant2", syncResult{prevSHA: "b", newSHA: "b"})

	auditMgr, _ := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), noopCascade, "root")

	runCtx := context.Background()
	svc.Run(runCtx)

	svc.mu.Lock()
	goroutineCount := len(svc.stops)
	svc.mu.Unlock()
	assert.Equal(t, 2, goroutineCount, "two goroutines should be running")

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, svc.Stop(stopCtx), "Stop must return nil when goroutines drain within timeout")
}

func TestSyncService_MinimumPollIntervalEnforced(t *testing.T) {
	// 500ms is below minPollInterval (1 minute) — must be floored.
	result := effectivePollInterval(500 * time.Millisecond)
	assert.Equal(t, minPollInterval, result, "intervals below 1 minute must be floored to 1 minute")
}

func TestSyncService_ZeroPollIntervalFloors(t *testing.T) {
	assert.Equal(t, minPollInterval, effectivePollInterval(0), "zero must floor to 1 minute")
	assert.Equal(t, minPollInterval, effectivePollInterval(-time.Second), "negative must floor to 1 minute")
}

func TestSyncService_NewTenantRegisteredAfterStart(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)
	ts.add("tenant1", "root", nil)

	router := newSyncTestRouter()
	// tenant1 has no git source initially — added after start.

	auditMgr, _ := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), noopCascade, "root")

	ctx := context.Background()
	svc.Run(ctx)

	svc.mu.Lock()
	initialCount := len(svc.stops)
	svc.mu.Unlock()
	assert.Equal(t, 0, initialCount, "no goroutines before Register")

	// Add git source and register.
	router.setSource("tenant1", gitSource(time.Hour))
	err := svc.Register("tenant1")
	require.NoError(t, err)

	svc.mu.Lock()
	newCount := len(svc.stops)
	svc.mu.Unlock()
	assert.Equal(t, 1, newCount, "one goroutine after Register")

	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, svc.Stop(stopCtx))
}

func TestSyncService_FailureCategoryClassification(t *testing.T) {
	cases := []struct {
		err      error
		expected string
	}{
		{gogittransport.ErrAuthorizationFailed, "credential_rejected"},
		{gogittransport.ErrAuthenticationRequired, "credential_rejected"},
		{gogittransport.ErrRepositoryNotFound, "repository_not_found"},
		{errors.New("HTTP 401 Unauthorized"), "credential_rejected"},
		{errors.New("HTTP 403 Forbidden"), "credential_rejected"},
		{errors.New("authentication failed"), "credential_rejected"},
		{errors.New("dial tcp: connection refused"), "network_unreachable"},
		{errors.New("i/o timeout"), "network_unreachable"},
		{errors.New("dns lookup failed"), "network_unreachable"},
		{errors.New("network unreachable"), "network_unreachable"},
		{errors.New("repository not found: 404"), "repository_not_found"},
		{errors.New("remote: not found"), "repository_not_found"},
		{errors.New("something completely unexpected"), "unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			got := classifySyncFailure(tc.err)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestSyncService_BothSHAsInSuccessEvent(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)
	ts.add("tenant1", "root", nil)

	router := newSyncTestRouter()
	router.setSource("tenant1", gitSource(time.Hour))
	router.setSyncResult("tenant1", syncResult{
		prevSHA: "aabbccdd1111111111111111111111111111111111",
		newSHA:  "eeff00112222222222222222222222222222222222",
	})

	auditMgr, store := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), noopCascade, "root")

	ctx := context.Background()
	svc.syncOnce(ctx, "tenant1", gitSource(time.Hour))

	flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	events := store.findByAction("config_source_sync")
	require.Len(t, events, 1)

	details := events[0].Details
	require.NotNil(t, details, "event must have details")
	assert.Equal(t, "aabbccdd1111111111111111111111111111111111", details["previous_sha"], "previous_sha must be recorded")
	assert.Equal(t, "eeff00112222222222222222222222222222222222", details["new_sha"], "new_sha must be recorded")
}

func TestSyncService_ApacheBoundary(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root-a", "", nil)
	ts.add("root-b", "", nil)
	ts.add("tenant-under-b", "root-b", nil)

	router := newSyncTestRouter()
	router.setSource("tenant-under-b", gitSource(time.Hour))

	auditMgr, _ := newTestAuditManager(t)
	// Service is scoped to root-a.
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), noopCascade, "root-a")

	ctx := context.Background()
	svc.Run(ctx)
	defer func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = svc.Stop(stopCtx)
	}()

	// Registering a tenant whose root is root-b must return ErrCrossRootBoundary.
	err := svc.Register("tenant-under-b")
	assert.ErrorIs(t, err, ErrCrossRootBoundary,
		"Register must return ErrCrossRootBoundary for tenants outside the construction-time root")
}

// TestSyncService_NoNewCommitsSkipsCascade verifies that when prevSHA == newSHA,
// cascade is not triggered (already up-to-date).
func TestSyncService_NoNewCommitsSkipsCascade(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)

	router := newSyncTestRouter()
	router.setSyncResult("tenant1", syncResult{prevSHA: "samesha", newSHA: "samesha"})

	var cascadeCalled int64
	cascadeFn := func(_ context.Context, _ string) error {
		atomic.AddInt64(&cascadeCalled, 1)
		return nil
	}

	auditMgr, store := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), cascadeFn, "root")

	svc.syncOnce(context.Background(), "tenant1", gitSource(time.Hour))

	flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, auditMgr.Flush(flushCtx))

	assert.Equal(t, int64(0), atomic.LoadInt64(&cascadeCalled), "cascade must not be called when SHAs are equal")
	assert.Equal(t, 0, store.count(), "no audit events when already up-to-date")
}

// TestSyncService_RunIsIdempotent verifies that calling Run twice does not start duplicate goroutines.
func TestSyncService_RunIsIdempotent(t *testing.T) {
	ts := newSyncTestTenantStore()
	ts.add("root", "", nil)
	ts.add("tenant1", "root", nil)

	router := newSyncTestRouter()
	router.setSource("tenant1", gitSource(time.Hour))

	auditMgr, _ := newTestAuditManager(t)
	svc := NewSyncService(router, ts, auditMgr, logging.NewNoopLogger(), noopCascade, "root")

	ctx := context.Background()
	svc.Run(ctx)
	svc.Run(ctx) // second call is a no-op

	svc.mu.Lock()
	count := len(svc.stops)
	svc.mu.Unlock()
	assert.Equal(t, 1, count, "second Run must not start duplicate goroutines")

	stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	require.NoError(t, svc.Stop(stopCtx))
}
