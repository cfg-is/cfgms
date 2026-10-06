// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	gitclient "github.com/go-git/go-git/v5/plumbing/transport/client"
	gitserver "github.com/go-git/go-git/v5/plumbing/transport/server"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/configrouting"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// This file proves the Issue #4408 wiring — NewConfigurationServiceV2 built with
// WithGitRouter, its router handed to configrouting.NewSyncService, and the
// resulting service's Run/Stop lifecycle — using the exact construction sequence
// features/controller/server/server.go's NewServer performs. It does not stand up
// a full Server (certs, QUIC, HTTP) because none of that is part of what Issue
// #4408 wires; it builds the same ConfigurationServiceV2 + SyncService pair
// directly, which is what Start()/Stop() drive.

// wiringTestSecretStore is a real in-memory SecretStore (not a mock) for these
// tests: no git source in this file needs actual credentials (the in-memory git
// transport below requires none), but NewControllerRouterWithGit requires a
// non-nil store to become git-capable.
type wiringTestSecretStore struct {
	mu      sync.Mutex
	secrets map[string]string
}

func newWiringTestSecretStore() *wiringTestSecretStore {
	return &wiringTestSecretStore{secrets: make(map[string]string)}
}

func (s *wiringTestSecretStore) GetSecret(_ context.Context, key string) (*secretsiface.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsiface.ErrSecretNotFound
	}
	return &secretsiface.Secret{Key: key, Value: v}, nil
}

func (s *wiringTestSecretStore) StoreSecret(_ context.Context, req *secretsiface.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return nil
}
func (s *wiringTestSecretStore) CompareAndSwapSecret(_ context.Context, _ string, _ int, req *secretsiface.SecretRequest) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return 1, true, nil
}
func (s *wiringTestSecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.secrets, key)
	return nil
}
func (s *wiringTestSecretStore) ListSecrets(_ context.Context, _ *secretsiface.SecretFilter) ([]*secretsiface.SecretMetadata, error) {
	return nil, nil
}
func (s *wiringTestSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsiface.Secret, error) {
	return nil, nil
}
func (s *wiringTestSecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsiface.SecretRequest) error {
	return nil
}
func (s *wiringTestSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsiface.Secret, error) {
	return nil, secretsiface.ErrSecretNotFound
}
func (s *wiringTestSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsiface.SecretVersion, error) {
	return nil, nil
}
func (s *wiringTestSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsiface.SecretMetadata, error) {
	return nil, nil
}
func (s *wiringTestSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *wiringTestSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *wiringTestSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *wiringTestSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *wiringTestSecretStore) Close() error                                             { return nil }

// cascadeRecorder records cascadeFn invocations so tests can assert which
// tenants were (and were not) cascaded without reaching into SyncService's
// unexported state.
type cascadeRecorder struct {
	mu    sync.Mutex
	calls map[string]int
}

func newCascadeRecorder() *cascadeRecorder {
	return &cascadeRecorder{calls: make(map[string]int)}
}

func (r *cascadeRecorder) record(tenantID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[tenantID]++
}

func (r *cascadeRecorder) count(tenantID string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[tenantID]
}

// installInMemoryGitTransport replaces go-git's "https" protocol handler with an
// in-process server backed by loader for the duration of the test, exactly as
// pkg/config/validator_test.go does for the same reason: tenant metadata's
// config_source_url must satisfy pkg/config's https-only SSRF guard
// (validateSourceURL), so the remote has to be addressed by a real "https://"
// URL — the in-memory transport then serves that URL without any real network
// or TLS listener. t.Cleanup restores the original handler.
func installInMemoryGitTransport(t *testing.T, loader gitserver.MapLoader) {
	t.Helper()
	original := gitclient.Protocols["https"]
	gitclient.InstallProtocol("https", gitserver.NewClient(loader))
	t.Cleanup(func() {
		gitclient.InstallProtocol("https", original)
	})
}

// newSeededBareRepo creates an in-memory bare repository containing one commit
// and returns its storer (to register with gitserver.MapLoader) together with
// the in-process *gogit.Repository handle so the test can push further commits
// directly — the "remote" push in these tests needs no network round trip
// because the server loader and this handle share the same storer.
func newSeededBareRepo(t *testing.T, path string, content []byte) (*memory.Storage, *gogit.Repository) {
	t.Helper()
	storer := memory.NewStorage()
	fs := memfs.New()
	repo, err := gogit.Init(storer, fs)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	f, err := fs.Create(path)
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = wt.Add(path)
	require.NoError(t, err)
	_, err = wt.Commit("initial", &gogit.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)

	return storer, repo
}

// pushCommit adds a second commit directly to repo's worktree — equivalent to a
// remote receiving a push, since repo shares its storer with the gitserver.MapLoader
// entry the system-under-test clones/pulls from.
func pushCommit(t *testing.T, repo *gogit.Repository, path string, content []byte) {
	t.Helper()
	wt, err := repo.Worktree()
	require.NoError(t, err)
	fs := wt.Filesystem
	f, err := fs.Create(path)
	require.NoError(t, err)
	_, err = f.Write(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = wt.Add(path)
	require.NoError(t, err)
	_, err = wt.Commit("update", &gogit.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)
}

// newWiredSyncService builds a ConfigurationServiceV2 and configrouting.SyncService
// through the exact same calls features/controller/server/server.go's NewServer
// makes: service.WithGitRouter for a git-capable router, then
// configService.ConfigSourceRouter() and configService.GetEffectiveConfiguration
// handed to configrouting.NewSyncService. rec, if non-nil, wraps cascadeFn to
// record which tenants were cascaded.
func newWiredSyncService(t *testing.T, tenantStore business.TenantStore, rootTenantID string, rec *cascadeRecorder) *configrouting.SyncService {
	t.Helper()
	storageManager := pkgtesting.SetupTestStorage(t)
	logger := logging.NewNoopLogger()

	auditManager, err := audit.NewManager(storageManager.GetAuditStore(), "test-controller")
	require.NoError(t, err)

	configService := service.NewConfigurationServiceV2(logger, storageManager, nil,
		service.WithGitRouter(newWiringTestSecretStore(), t.TempDir()))

	cascadeFn := func(ctx context.Context, tenantID string) error {
		_, err := configService.GetEffectiveConfiguration(ctx, tenantID, "")
		if rec != nil {
			rec.record(tenantID)
		}
		return err
	}

	return configrouting.NewSyncService(
		configService.ConfigSourceRouter(),
		tenantStore,
		auditManager,
		logger,
		cascadeFn,
		rootTenantID,
	)
}

// addWiringTestTenant persists a tenant in the real store backing tenantStore.
func addWiringTestTenant(t *testing.T, ts business.TenantStore, id, parentID string, metadata map[string]string) {
	t.Helper()
	require.NoError(t, ts.CreateTenant(context.Background(), &business.TenantData{
		ID:       id,
		Name:     id,
		ParentID: parentID,
		Metadata: metadata,
		Status:   business.TenantStatusActive,
	}))
}

// gitSourceMetadata returns tenant metadata declaring a git config source at url.
// PollInterval is set to exactly the 1-minute floor (minPollInterval in
// pkg/configrouting) — the lowest value effectivePollInterval will not raise —
// so the first real tick in these tests arrives as soon as SyncService allows.
func gitSourceMetadata(url string) map[string]string {
	return map[string]string{
		"config_source_type":          string(pkgconfig.ConfigSourceTypeGit),
		"config_source_url":           url,
		"config_source_poll_interval": "1m",
	}
}

// TestWiredSyncService_PullsAndCascadesWithinRootOnly is the REQUIRED pull test
// (Issue #4408): it proves the wired path — NewConfigurationServiceV2's
// WithGitRouter router handed to configrouting.NewSyncService — performs an actual
// git pull, observes the changed SHA, and invokes the cascade, all scoped to the
// configured root tenant. A second, git-sourced tenant under an unrelated root is
// present throughout and must never be pulled or cascaded, proving the periodic
// path enforces the same tenant containment as the on-request path (the second
// REQUIRED containment test, exercised in the same single tick window so only one
// test pays the 1-minute floor).
func TestWiredSyncService_PullsAndCascadesWithinRootOnly(t *testing.T) {
	inRootStorer, inRootRepo := newSeededBareRepo(t, "app.yaml", []byte("version: 1\n"))
	outOfRootStorer, outOfRootRepo := newSeededBareRepo(t, "app.yaml", []byte("other: 1\n"))

	const inRootURL = "https://configsync-wiring-test.cfgms.local/in-root-repo"
	const outOfRootURL = "https://configsync-wiring-test.cfgms.local/out-of-root-repo"
	installInMemoryGitTransport(t, gitserver.MapLoader{
		inRootURL:    inRootStorer,
		outOfRootURL: outOfRootStorer,
	})

	storageManager := pkgtesting.SetupTestStorage(t)
	tenantStore := storageManager.GetTenantStore()

	// In-root tree: rootTenantID is "sync-root-a"; "tenant-a1" is a git-sourced child.
	addWiringTestTenant(t, tenantStore, "sync-root-a", "", nil)
	addWiringTestTenant(t, tenantStore, "tenant-a1", "sync-root-a", gitSourceMetadata(inRootURL))

	// Out-of-root tree: a completely unrelated root, also git-sourced.
	addWiringTestTenant(t, tenantStore, "sync-root-b", "", nil)
	addWiringTestTenant(t, tenantStore, "tenant-b1", "sync-root-b", gitSourceMetadata(outOfRootURL))

	logger := logging.NewNoopLogger()
	auditManager, err := audit.NewManager(storageManager.GetAuditStore(), "test-controller")
	require.NoError(t, err)

	configService := service.NewConfigurationServiceV2(logger, storageManager, nil,
		service.WithGitRouter(newWiringTestSecretStore(), t.TempDir()))

	rec := newCascadeRecorder()
	cascadeFn := func(ctx context.Context, tenantID string) error {
		_, err := configService.GetEffectiveConfiguration(ctx, tenantID, "")
		rec.record(tenantID)
		return err
	}

	// Warm the git clone for tenant-a1 before Run() starts, through the same
	// router.GetConfig path on-request resolution already uses (routeRead ->
	// storeForSource). GitConfigStore clones on first access, not at
	// construction, so without this warm-up the FIRST periodic tick would
	// perform the initial clone itself — already observing both commits at
	// once (prevSHA == newSHA) — rather than observing the second commit as a
	// change, which is what this test needs to prove.
	_, _ = configService.ConfigSourceRouter().GetConfig(ctxkeys.WithSystem(context.Background()), &cfgconfig.ConfigKey{
		TenantID: "tenant-a1", Namespace: "warmup", Name: "warmup",
	})

	svc := configrouting.NewSyncService(
		configService.ConfigSourceRouter(),
		tenantStore,
		auditManager,
		logger,
		cascadeFn,
		"sync-root-a",
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Run(ctx)
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = svc.Stop(stopCtx)
	}()

	// Push a second commit to the in-root remote before the first tick fires
	// (minPollInterval is 1 minute, so there is ample time).
	pushCommit(t, inRootRepo, "app.yaml", []byte("version: 2\n"))
	pushCommit(t, outOfRootRepo, "app.yaml", []byte("other: 2\n"))

	require.Eventually(t, func() bool {
		return rec.count("tenant-a1") >= 1
	}, 90*time.Second, time.Second, "wired SyncService must pull and cascade the in-root git tenant after a new commit")

	assert.Equal(t, 0, rec.count("tenant-b1"),
		"wired SyncService scoped to sync-root-a must never cascade a tenant under an unrelated root")
}

// TestSyncService_RegisterRejectsCrossRootTenant is the second REQUIRED containment
// test: it proves the periodic path's boundary check directly and synchronously
// (no poll tick needed) — Register returns ErrCrossRootBoundary for a tenant whose
// hierarchy root differs from the SyncService's configured root, exactly as the
// acceptance criteria describe.
func TestSyncService_RegisterRejectsCrossRootTenant(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	tenantStore := storageManager.GetTenantStore()

	addWiringTestTenant(t, tenantStore, "sync-root-a", "", nil)
	addWiringTestTenant(t, tenantStore, "sync-root-b", "", nil)
	addWiringTestTenant(t, tenantStore, "tenant-b1", "sync-root-b", nil)

	svc := newWiredSyncService(t, tenantStore, "sync-root-a", nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.Run(ctx)
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		_ = svc.Stop(stopCtx)
	}()

	err := svc.Register("tenant-b1")
	assert.ErrorIs(t, err, configrouting.ErrCrossRootBoundary)
}

// TestSyncService_LifecycleTiedToContextCancellation proves the lifecycle
// requirement: cancelling the context passed to Run stops the per-tenant polling
// goroutine, and the test asserts the goroutine actually exits — Stop returning
// promptly (well under its own timeout, and without waiting anywhere near the
// 1-minute poll floor) is only possible if the ticker goroutine already observed
// ctx.Done() and returned.
func TestSyncService_LifecycleTiedToContextCancellation(t *testing.T) {
	storer, _ := newSeededBareRepo(t, "app.yaml", []byte("version: 1\n"))
	const url = "https://configsync-wiring-test.cfgms.local/lifecycle-repo"
	installInMemoryGitTransport(t, gitserver.MapLoader{url: storer})

	storageManager := pkgtesting.SetupTestStorage(t)
	tenantStore := storageManager.GetTenantStore()
	addWiringTestTenant(t, tenantStore, "sync-root-lifecycle", "", nil)
	addWiringTestTenant(t, tenantStore, "tenant-lifecycle-1", "sync-root-lifecycle", gitSourceMetadata(url))

	svc := newWiredSyncService(t, tenantStore, "sync-root-lifecycle", nil)

	ctx, cancel := context.WithCancel(context.Background())
	svc.Run(ctx)

	// Cancelling the controller's context (not calling Stop) is what Server.Stop
	// does via configSyncCancel — Run derives its own runCtx from this ctx via
	// context.WithCancel, so cancelling it here propagates the same way.
	cancel()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	start := time.Now()
	err := svc.Stop(stopCtx)
	elapsed := time.Since(start)

	require.NoError(t, err, "Stop must observe the already-cancelled context and drain promptly")
	assert.Less(t, elapsed, 5*time.Second, "the polling goroutine must exit promptly after context cancellation, not after a full poll interval")
}

// TestResolveRootTenantID verifies the server-side helper that supplies
// SyncService's rootTenantID resolves the root by position through the tenant
// manager (Issue #4542) and never fails startup: no root on an empty store, the
// single top-level tenant whatever its name, and no root once a second top-level
// tenant makes the tree ambiguous.
func TestResolveRootTenantID(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	tenantStore := storageManager.GetTenantStore()
	logger := logging.NewNoopLogger()
	resolve := func() string {
		// A fresh manager per call: the test seeds through the store, bypassing
		// the manager's own root-cache invalidation.
		return resolveRootTenantID(context.Background(), tenant.NewManager(tenantStore, nil), logger)
	}

	assert.Empty(t, resolve(), "an empty store has no root")

	addWiringTestTenant(t, tenantStore, "team-root", "", nil)
	addWiringTestTenant(t, tenantStore, "infra-hyperv", "team-root", nil)
	assert.Equal(t, "team-root", resolve(), "the single top-level tenant is the root, whatever its name")

	addWiringTestTenant(t, tenantStore, "root", "", nil)
	assert.Empty(t, resolve(), "a second top-level tenant makes the root ambiguous, even one named root")
}
