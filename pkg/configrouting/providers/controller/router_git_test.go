// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gitcfg "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	flatfile "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// gitRouterMemorySecretStore is a real in-memory SecretStore for git router tests.
// Lightweight in-memory implementation with real CRUD.
type gitRouterMemorySecretStore struct {
	secrets map[string]string
}

func newGitRouterSecretStore(pairs map[string]string) *gitRouterMemorySecretStore {
	if pairs == nil {
		pairs = make(map[string]string)
	}
	return &gitRouterMemorySecretStore{secrets: pairs}
}

func (s *gitRouterMemorySecretStore) GetSecret(_ context.Context, key string) (*secretsiface.Secret, error) {
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsiface.ErrSecretNotFound
	}
	return &secretsiface.Secret{Key: key, Value: v}, nil
}

func (s *gitRouterMemorySecretStore) StoreSecret(_ context.Context, req *secretsiface.SecretRequest) error {
	s.secrets[req.Key] = req.Value
	return nil
}
func (s *gitRouterMemorySecretStore) CompareAndSwapSecret(_ context.Context, _ string, _ int, req *secretsiface.SecretRequest) (int, bool, error) {
	s.secrets[req.Key] = req.Value
	return 1, true, nil
}
func (s *gitRouterMemorySecretStore) DeleteSecret(_ context.Context, key string) error {
	delete(s.secrets, key)
	return nil
}
func (s *gitRouterMemorySecretStore) ListSecrets(_ context.Context, _ *secretsiface.SecretFilter) ([]*secretsiface.SecretMetadata, error) {
	return nil, nil
}
func (s *gitRouterMemorySecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsiface.Secret, error) {
	return nil, nil
}
func (s *gitRouterMemorySecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsiface.SecretRequest) error {
	return nil
}
func (s *gitRouterMemorySecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsiface.Secret, error) {
	return nil, secretsiface.ErrSecretNotFound
}
func (s *gitRouterMemorySecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsiface.SecretVersion, error) {
	return nil, nil
}
func (s *gitRouterMemorySecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsiface.SecretMetadata, error) {
	return nil, nil
}
func (s *gitRouterMemorySecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *gitRouterMemorySecretStore) RotateSecret(_ context.Context, _ string, _ string) error {
	return nil
}
func (s *gitRouterMemorySecretStore) ExpireSecret(_ context.Context, _ string) error { return nil }
func (s *gitRouterMemorySecretStore) HealthCheck(_ context.Context) error            { return nil }
func (s *gitRouterMemorySecretStore) Close() error                                   { return nil }

// createBareRepoForRouterTest creates a bare git repo with the given files.
func createBareRepoForRouterTest(t *testing.T, files map[string][]byte) string {
	t.Helper()

	bareDir := t.TempDir()
	workDir := t.TempDir()

	_, err := gogit.PlainInit(bareDir, true)
	require.NoError(t, err)

	work, err := gogit.PlainInit(workDir, false)
	require.NoError(t, err)

	wt, err := work.Worktree()
	require.NoError(t, err)

	for relPath, content := range files {
		full := filepath.Join(workDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0750))
		require.NoError(t, os.WriteFile(full, content, 0600))
		_, err = wt.Add(relPath)
		require.NoError(t, err)
	}

	_, err = wt.Commit("initial", &gogit.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)

	_, err = work.CreateRemote(&gitcfg.RemoteConfig{Name: "origin", URLs: []string{bareDir}})
	require.NoError(t, err)
	require.NoError(t, work.Push(&gogit.PushOptions{RemoteName: "origin"}))

	return bareDir
}

// injectGitSource bypasses ParseConfigSource URL validation by injecting the
// ConfigSourceInfo directly into the router's source cache. This is necessary
// for local-repo tests because ParseConfigSource enforces HTTPS URLs (correct
// for production), but unit tests use local filesystem paths as fake remotes.
func injectGitSource(r *controllerRouter, tenantID string, source pkgconfig.ConfigSourceInfo) {
	_ = r.sourceCache.Set(tenantID, source, sourceCacheTTL)
}

// TestNewControllerRouterWithGit_RoutesGitTenantToGitStore verifies that storeForSource
// dispatches a git-source tenant to GitConfigStore and reads content from the cloned repo.
// Source info is injected directly into the cache to bypass HTTPS URL validation.
func TestNewControllerRouterWithGit_RoutesGitTenantToGitStore(t *testing.T) {
	const configContent = "git_routed: true\n"
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/policies/baseline.yaml": []byte(configContent),
	})

	ts := newTenantStore(t)
	addTenant(t, ts, "git-tenant", "", nil)
	addTenant(t, ts, "ctrl-tenant", "", nil)

	flatfileRoot := t.TempDir()
	controllerStore, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	gitWorkDir := t.TempDir()
	router := NewControllerRouterWithGit(controllerStore, ts, newGitRouterSecretStore(nil), gitWorkDir, logging.NewNoopLogger()).(*controllerRouter)

	// Inject git source directly (bypasses HTTPS validation — local repo only for tests).
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir,
		SubPath: "configs",
	})

	// Read from git-tenant — must be served from the cloned git repo.
	gitKey := &cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "policies", Name: "baseline"}
	entry, readErr := router.GetConfig(ctxkeys.WithSystem(context.Background()), gitKey)
	require.NoError(t, readErr, "git-tenant read must succeed")
	assert.Equal(t, configContent, string(entry.Data), "content must come from the git repo")

	// Write to git-tenant — always routes to controller store (git sources are read-only).
	writeEntry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "policies", Name: "new"},
		Data:   []byte("x: 1\n"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, router.StoreConfig(ctxkeys.WithSystem(context.Background()), writeEntry),
		"write must route to controller store regardless of source type")

	// ctrl-tenant (no git source) routes to controller store.
	_, notFoundErr := router.GetConfig(ctxkeys.WithSystem(context.Background()), &cfgconfig.ConfigKey{
		TenantID: "ctrl-tenant", Namespace: "policies", Name: "baseline",
	})
	assert.ErrorIs(t, notFoundErr, cfgconfig.ErrConfigNotFound,
		"ctrl-tenant read must route to controller store which has nothing stored")
}

// TestNewControllerRouterWithGit_FailsClosedOnInitFailure verifies that when GitConfigStore
// construction fails, reads and writes return an error — never the controller store's data
// and never ErrConfigNotFound from the wrong store — and no clone directory is left behind.
func TestNewControllerRouterWithGit_FailsClosedOnInitFailure(t *testing.T) {
	ts := newTenantStore(t)
	addTenant(t, ts, "git-tenant", "", nil)

	flatfileRoot := t.TempDir()
	controllerStore, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	gitWorkDir := t.TempDir()
	router := NewControllerRouterWithGit(controllerStore, ts, newGitRouterSecretStore(nil), gitWorkDir, logging.NewNoopLogger()).(*controllerRouter)
	defer router.Close()

	// A value in the controller store for the same key: a fallback would return it.
	controllerEntry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "fallback", Name: "cfg"},
		Data:   []byte("fallback: true\n"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, controllerStore.StoreConfig(ctxkeys.WithSystem(context.Background()), controllerEntry))

	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     "/nonexistent/repo/path",
		SubPath: "configs",
	})

	ctx := ctxkeys.WithSystem(context.Background())
	entry, readErr := router.GetConfig(ctx, controllerEntry.Key)
	require.Error(t, readErr, "unreachable git source must fail the read")
	assert.Nil(t, entry)
	assert.NotErrorIs(t, readErr, cfgconfig.ErrConfigNotFound, "must not look like a missing config")

	writeErr := router.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "ns", Name: "new"},
		Data:   []byte("x: 1\n"),
		Format: cfgconfig.ConfigFormatYAML,
	})
	require.Error(t, writeErr, "unreachable git source must fail the write")
	require.Error(t, router.DeleteConfig(ctx, controllerEntry.Key))
	require.Error(t, router.StoreConfigBatch(ctx, []*cfgconfig.ConfigEntry{{Key: controllerEntry.Key}}))
	require.Error(t, router.DeleteConfigBatch(ctx, []*cfgconfig.ConfigKey{controllerEntry.Key}))

	assert.Empty(t, dirEntries(t, gitWorkDir), "failed construction must leave no directory behind")
}

// dirEntries lists every path (relative) under root, excluding root itself.
func dirEntries(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != root {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	}))
	return out
}

func cloneDir(workDir, tenantID, url string) string {
	return filepath.Join(workDir, tenantID, fmt.Sprintf("%x", sha256.Sum256([]byte(url))))
}

func newGitTestRouter(t *testing.T, tenants ...string) (*controllerRouter, string) {
	t.Helper()
	return newGitTestRouterOpts(t, nil, tenants...)
}

func newGitTestRouterOpts(t *testing.T, opts []RouterOption, tenants ...string) (*controllerRouter, string) {
	t.Helper()
	ts := newTenantStore(t)
	for _, id := range tenants {
		addTenant(t, ts, id, "", nil)
	}
	cs, err := flatfile.NewFlatFileConfigStore(t.TempDir())
	require.NoError(t, err)
	workDir := t.TempDir()
	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), workDir, logging.NewNoopLogger(), opts...).(*controllerRouter)
	t.Cleanup(router.Close)
	return router, workDir
}

func gitInfo(url string) *pkgconfig.ConfigSourceInfo {
	return &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeGit, URL: url, SubPath: "configs"}
}

// TestStoreForSource_CacheBoundEvictsOldestAndRemovesClones verifies the global LRU bound:
// the cache never exceeds the bound and evicted entries' clone directories are removed.
func TestStoreForSource_CacheBoundEvictsOldestAndRemovesClones(t *testing.T) {
	const bound = 3
	tenants := []string{"t1", "t2", "t3", "t4", "t5"}
	router, workDir := newGitTestRouter(t, tenants...)
	router.gitStoreCache.Close()
	router.gitStoreCache = router.newGitStoreCache(bound)
	t.Cleanup(router.gitStoreCache.Close)

	ctx := ctxkeys.WithSystem(context.Background())
	urls := map[string]string{}
	for _, id := range tenants {
		urls[id] = createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte(id + "\n")})
		_, err := router.storeForSource(ctx, id, gitInfo(urls[id]))
		require.NoError(t, err)
		assert.LessOrEqual(t, router.gitStoreCache.Size(), bound)
	}

	assert.Equal(t, bound, router.gitStoreCache.Size(), "cache size stays at the bound")
	for _, id := range tenants[:2] {
		assert.NoDirExists(t, cloneDir(workDir, id, urls[id]), "evicted entry's clone must be removed")
	}
	for _, id := range tenants[2:] {
		assert.DirExists(t, cloneDir(workDir, id, urls[id]), "live entry's clone must remain")
	}
}

// TestStoreForSource_SourceChangeRemovesPreviousClone verifies a tenant keeps one live
// entry: changing its URL removes the old clone and leaves other tenants untouched.
func TestStoreForSource_SourceChangeRemovesPreviousClone(t *testing.T) {
	router, workDir := newGitTestRouter(t, "a", "b")
	ctx := ctxkeys.WithSystem(context.Background())

	urlA1 := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("a1\n")})
	urlA2 := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("a2\n")})
	urlB := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("b\n")})

	for id, u := range map[string]string{"a": urlA1, "b": urlB} {
		_, err := router.storeForSource(ctx, id, gitInfo(u))
		require.NoError(t, err)
	}
	require.DirExists(t, cloneDir(workDir, "a", urlA1))

	_, err := router.storeForSource(ctx, "a", gitInfo(urlA2))
	require.NoError(t, err)

	assert.NoDirExists(t, cloneDir(workDir, "a", urlA1), "previous source's clone must be removed")
	assert.DirExists(t, cloneDir(workDir, "a", urlA2))
	assert.DirExists(t, cloneDir(workDir, "b", urlB), "other tenants are untouched")
	assert.Equal(t, 2, router.gitStoreCache.Size(), "one live entry per tenant")
}

// TestStoreForSource_FailedConstructionLeavesNoDirectory covers the failed-clone path: the
// directory the call created is removed.
func TestStoreForSource_FailedConstructionLeavesNoDirectory(t *testing.T) {
	router, workDir := newGitTestRouter(t, "a")
	ctx := ctxkeys.WithSystem(context.Background())

	_, err := router.storeForSource(ctx, "a", gitInfo(filepath.Join(t.TempDir(), "missing")))
	require.Error(t, err)
	assert.Empty(t, dirEntries(t, workDir))
}

// TestStoreForSource_ConcurrentSameKeyKeepsClone hammers one key and a replacement to
// verify removal and re-creation are serialized: the live entry's clone always exists.
func TestStoreForSource_ConcurrentSameKeyKeepsClone(t *testing.T) {
	router, workDir := newGitTestRouter(t, "a")
	ctx := ctxkeys.WithSystem(context.Background())
	url1 := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("1\n")})
	url2 := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("2\n")})

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := url1
			if i%2 == 1 {
				u = url2
			}
			for j := 0; j < 5; j++ {
				_, err := router.storeForSource(ctx, "a", gitInfo(u))
				assert.NoError(t, err)
			}
		}(i)
	}
	wg.Wait()

	// Exactly one entry is live and its clone exists; the other is gone.
	require.Equal(t, 1, router.gitStoreCache.Size())
	var live int
	for _, u := range []string{url1, url2} {
		if _, err := os.Stat(cloneDir(workDir, "a", u)); err == nil {
			live++
		}
	}
	assert.Equal(t, 1, live)
}

// TestNewControllerRouterWithGit_GitStoreIsCached verifies that two reads for the same
// (tenant, URL) pair reuse the same GitConfigStore instance — no double-clone.
func TestNewControllerRouterWithGit_GitStoreIsCached(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/ns/cfg.yaml": []byte("cached: true\n"),
	})

	ts := newTenantStore(t)
	addTenant(t, ts, "t1", "", nil)

	flatfileRoot := t.TempDir()
	controllerStore, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	router := NewControllerRouterWithGit(controllerStore, ts, newGitRouterSecretStore(nil), t.TempDir(), logging.NewNoopLogger()).(*controllerRouter)

	injectGitSource(router, "t1", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir,
		SubPath: "configs",
	})

	key := &cfgconfig.ConfigKey{TenantID: "t1", Namespace: "ns", Name: "cfg"}

	// Two reads must not fail and must not double-clone.
	_, err = router.GetConfig(ctxkeys.WithSystem(context.Background()), key)
	require.NoError(t, err)
	_, err = router.GetConfig(ctxkeys.WithSystem(context.Background()), key)
	require.NoError(t, err)

	// Cache must hold exactly one entry for t1.
	cacheSize := router.gitStoreCache.Size()
	assert.Equal(t, 1, cacheSize, "git store cache must hold exactly one entry per (tenant,url)")
}

// TestStoreForSource_ControllerTypeReturnsControllerStore verifies that storeForSource
// returns the controller store for controller-type sources (regression test for Phase 1 behavior).
func TestStoreForSource_ControllerTypeReturnsControllerStore(t *testing.T) {
	cs := &recordingConfigStore{}
	ts := newTenantStore(t)

	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), t.TempDir(), logging.NewNoopLogger()).(*controllerRouter)
	ctrlSource := &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeController}

	store, err := router.storeForSource(ctxkeys.WithSystem(context.Background()), "any-tenant", ctrlSource)
	require.NoError(t, err)
	assert.Same(t, cs, store, "controller source must route to controllerStore")
}

// TestSyncTenantWithRemote_NonGitTenantReturnsEmpty verifies that SyncTenantWithRemote
// returns ("","",nil) for a tenant whose effective source is ConfigSourceTypeController.
func TestSyncTenantWithRemote_NonGitTenantReturnsEmpty(t *testing.T) {
	ts := newTenantStore(t)
	addTenant(t, ts, "ctrl-tenant", "", nil)

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), t.TempDir(), logging.NewNoopLogger()).(*controllerRouter)

	prevSHA, newSHA, syncErr := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "ctrl-tenant")
	require.NoError(t, syncErr)
	assert.Empty(t, prevSHA, "non-git tenant must return empty prevSHA")
	assert.Empty(t, newSHA, "non-git tenant must return empty newSHA")
}

// TestSyncTenantWithRemote_GitTenantReturnsSHAs verifies that SyncTenantWithRemote returns
// the SHA before and after the pull for a git-sourced tenant, and that they advance after a
// new commit is pushed to the remote.
func TestSyncTenantWithRemote_GitTenantReturnsSHAs(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/default/app.yaml": []byte("version: 1\n"),
	})

	ts := newTenantStore(t)
	addTenant(t, ts, "git-tenant", "", nil)

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	gitWorkDir := t.TempDir()
	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), gitWorkDir, logging.NewNoopLogger()).(*controllerRouter)
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir,
		SubPath: "configs",
	})

	// First call: prevSHA is the initial HEAD (already cloned), newSHA is the same (no new commits yet).
	prev1, new1, err := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "git-tenant")
	require.NoError(t, err)
	assert.Len(t, prev1, 40, "prevSHA must be a 40-char hex SHA")
	assert.Equal(t, prev1, new1, "prevSHA and newSHA are equal when there are no new commits")

	// Push a new commit to the remote so the next sync has something to pull.
	workDir2 := t.TempDir()
	cloned, cloneErr := gogit.PlainClone(workDir2, false, &gogit.CloneOptions{URL: remoteDir})
	require.NoError(t, cloneErr)
	wt, wtErr := cloned.Worktree()
	require.NoError(t, wtErr)
	require.NoError(t, os.MkdirAll(filepath.Join(workDir2, "configs", "default"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(workDir2, "configs", "default", "app.yaml"), []byte("version: 2\n"), 0600))
	_, addErr := wt.Add("configs/default/app.yaml")
	require.NoError(t, addErr)
	_, commitErr := wt.Commit("bump version", &gogit.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "t@t.com", When: time.Now()},
	})
	require.NoError(t, commitErr)
	require.NoError(t, cloned.Push(&gogit.PushOptions{RemoteName: "origin"}))

	// Second call: prevSHA is the old HEAD, newSHA is the new HEAD after pull.
	prev2, new2, err := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "git-tenant")
	require.NoError(t, err)
	assert.Equal(t, new1, prev2, "prevSHA on second call must equal the newSHA from first call")
	assert.NotEqual(t, prev2, new2, "newSHA must advance after remote receives a new commit")
	assert.Len(t, new2, 40)
}

// TestSyncTenantWithRemote_BrokenURLFailsClosed verifies that when the source URL is
// updated to a non-existent remote, constructing the git store fails and
// SyncTenantWithRemote returns an error instead of falling back to the controller store.
// The previous source's clone is removed and the failed one leaves nothing behind.
func TestSyncTenantWithRemote_BrokenURLFailsClosed(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/default/app.yaml": []byte("v1\n"),
	})

	ts := newTenantStore(t)
	addTenant(t, ts, "git-tenant", "", nil)

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	gitWorkDir := t.TempDir()
	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), gitWorkDir, logging.NewNoopLogger()).(*controllerRouter)
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir,
		SubPath: "configs",
	})

	// Prime the git store so it is cloned.
	_, _, primeErr := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "git-tenant")
	require.NoError(t, primeErr, "initial sync must succeed")

	// Break the remote by pointing the cached source at a non-existent URL.
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir + "-broken",
		SubPath: "configs",
	})

	// The cache key changed (URL hash changed), so storeForSource constructs a new
	// GitConfigStore for the broken URL; the clone fails and the error is returned.
	prev, newSHA, syncErr := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "git-tenant")
	require.Error(t, syncErr, "broken-URL source must not fall back to the controller store")
	assert.Empty(t, prev)
	assert.Empty(t, newSHA)
	assert.Empty(t, dirEntries(t, gitWorkDir), "old clone removed and failed clone left nothing behind")

	// Reads fail with a non-NotFound error too.
	_, getErr := router.GetConfig(ctxkeys.WithSystem(context.Background()),
		&cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "default", Name: "app"})
	require.Error(t, getErr)
	assert.NotErrorIs(t, getErr, cfgconfig.ErrConfigNotFound)
}

// TestSyncTenantWithRemote_PullErrorPropagatesFromBrokenRemote verifies that when the
// already-cached git store has its remote URL corrupted in .git/config, the next call
// to SyncTenantWithRemote propagates the pull error rather than silently swallowing it.
// This is distinct from BrokenURLFailsClosed, which tests a broken URL
// at construction time — here the git store is already cached so the pull error surfaces.
func TestSyncTenantWithRemote_PullErrorPropagatesFromBrokenRemote(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/default/app.yaml": []byte("v1\n"),
	})

	ts := newTenantStore(t)
	addTenant(t, ts, "git-tenant", "", nil)

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	gitWorkDir := t.TempDir()
	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), gitWorkDir, logging.NewNoopLogger()).(*controllerRouter)
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir,
		SubPath: "configs",
	})

	// Prime the git store — forces a clone and populates gitStoreCache.
	_, _, primeErr := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "git-tenant")
	require.NoError(t, primeErr, "initial sync must succeed")

	// Remove the remote so the next sync fails.
	require.NoError(t, os.RemoveAll(remoteDir))

	// SyncTenantWithRemote must propagate the pull error — the cached git store is used
	// directly (no fallback), so the broken remote surfaces as a returned error.
	_, _, syncErr := router.SyncTenantWithRemote(ctxkeys.WithSystem(context.Background()), "git-tenant")
	assert.Error(t, syncErr, "sync must return an error when the cached git store's remote is broken")
}

// slowRemote is an HTTP git remote that never answers until released. It records how
// many requests arrived and signals the first one.
type slowRemote struct {
	url      string
	requests atomic.Int64
	arrived  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (sr *slowRemote) releaseAll() { sr.once.Do(func() { close(sr.release) }) }

func newSlowRemote(t *testing.T) *slowRemote {
	t.Helper()
	sr := &slowRemote{arrived: make(chan struct{}, 16), release: make(chan struct{})}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		sr.requests.Add(1)
		sr.arrived <- struct{}{}
		select {
		case <-sr.release:
		case <-req.Context().Done():
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	sr.url = srv.URL + "/repo.git"
	t.Cleanup(srv.Close) // runs after the release below
	t.Cleanup(sr.releaseAll)
	return sr
}

func (sr *slowRemote) waitArrived(t *testing.T) {
	t.Helper()
	select {
	case <-sr.arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("clone request never reached the remote")
	}
}

// TestStoreForSource_HangingCloneDoesNotBlockCachedSource verifies the global lock is not
// held across a clone: a read of an already-cached source completes while another
// source's clone is hanging.
func TestStoreForSource_HangingCloneDoesNotBlockCachedSource(t *testing.T) {
	router, _ := newGitTestRouter(t, "a", "b")
	ctx := ctxkeys.WithSystem(context.Background())

	urlA := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("a\n")})
	_, err := router.storeForSource(ctx, "a", gitInfo(urlA))
	require.NoError(t, err)

	slow := newSlowRemote(t)
	slowDone := make(chan error, 1)
	go func() {
		_, e := router.storeForSource(ctx, "b", gitInfo(slow.url))
		slowDone <- e
	}()
	slow.waitArrived(t)

	cachedDone := make(chan error, 1)
	go func() {
		_, e := router.storeForSource(ctx, "a", gitInfo(urlA))
		cachedDone <- e
	}()
	select {
	case e := <-cachedDone:
		require.NoError(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("cached source blocked behind another source's hanging clone")
	}

	// A different, new source also clones in parallel with the hanging one.
	urlC := createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte("c\n")})
	newDone := make(chan error, 1)
	go func() {
		_, e := router.storeForSource(ctx, "c", gitInfo(urlC))
		newDone <- e
	}()
	select {
	case e := <-newDone:
		require.NoError(t, e)
	case <-time.After(5 * time.Second):
		t.Fatal("new source blocked behind another source's hanging clone")
	}

	slow.releaseAll()
	require.Error(t, <-slowDone)
}

// TestStoreForSource_ConcurrentSameNewSourceClonesOnce verifies two concurrent requests
// for the same new source share one clone.
func TestStoreForSource_ConcurrentSameNewSourceClonesOnce(t *testing.T) {
	router, workDir := newGitTestRouter(t, "a")
	ctx := ctxkeys.WithSystem(context.Background())
	slow := newSlowRemote(t)

	errs := make(chan error, 2)
	go func() {
		_, e := router.storeForSource(ctx, "a", gitInfo(slow.url))
		errs <- e
	}()
	slow.waitArrived(t)
	go func() {
		_, e := router.storeForSource(ctx, "a", gitInfo(slow.url))
		errs <- e
	}()
	time.Sleep(200 * time.Millisecond) // let the second caller join the in-flight build
	slow.releaseAll()

	require.Error(t, <-errs)
	require.Error(t, <-errs)
	assert.Equal(t, int64(1), slow.requests.Load(), "both callers must share one clone attempt")
	assert.Empty(t, dirEntries(t, workDir))
}

// TestStoreForSource_CloneDeadlineReturnsErrorAndLeavesNothing verifies a clone that
// exceeds the operation deadline fails and removes its directory.
func TestStoreForSource_CloneDeadlineReturnsErrorAndLeavesNothing(t *testing.T) {
	router, workDir := newGitTestRouterOpts(t, []RouterOption{WithGitOperationTimeout(300 * time.Millisecond)}, "a")
	ctx := ctxkeys.WithSystem(context.Background())
	slow := newSlowRemote(t)

	start := time.Now()
	_, err := router.storeForSource(ctx, "a", gitInfo(slow.url))
	require.Error(t, err)
	assert.Less(t, time.Since(start), 10*time.Second, "clone must be bounded by the deadline")
	assert.Empty(t, dirEntries(t, workDir), "timed-out clone must leave no directory")
}

// TestStoreForSource_ByteBudgetEvictsLRUAndRemovesClone verifies the total clone byte
// budget: once exceeded, the least-recently-used clone is evicted and its directory removed.
func TestStoreForSource_ByteBudgetEvictsLRUAndRemovesClone(t *testing.T) {
	payload := make([]byte, 64<<10)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	tenants := []string{"t1", "t2", "t3"}
	router, workDir := newGitTestRouter(t, tenants...)
	ctx := ctxkeys.WithSystem(context.Background())

	urls := map[string]string{}
	for _, id := range tenants {
		urls[id] = createBareRepoForRouterTest(t, map[string][]byte{
			"configs/ns/cfg.yaml": []byte(id + "\n"),
			"configs/blob.bin":    payload,
		})
	}

	// Measure one clone, then budget for two.
	_, err = router.storeForSource(ctx, "t1", gitInfo(urls["t1"]))
	require.NoError(t, err)
	one := router.gitUsage[tenants[0]+":"+fmt.Sprintf("%x", sha256.Sum256([]byte(urls["t1"])))].bytes
	require.Greater(t, one, int64(64<<10))
	router.maxCacheBytes = one*2 + one/2

	_, err = router.storeForSource(ctx, "t2", gitInfo(urls["t2"]))
	require.NoError(t, err)
	// Touch t1 so t2 is the least recently used.
	_, err = router.storeForSource(ctx, "t1", gitInfo(urls["t1"]))
	require.NoError(t, err)
	_, err = router.storeForSource(ctx, "t3", gitInfo(urls["t3"]))
	require.NoError(t, err)

	assert.NoDirExists(t, cloneDir(workDir, "t2", urls["t2"]), "LRU clone must be evicted and removed")
	assert.DirExists(t, cloneDir(workDir, "t1", urls["t1"]))
	assert.DirExists(t, cloneDir(workDir, "t3", urls["t3"]))
	assert.Equal(t, 2, router.gitStoreCache.Size())
}

// pushFileForRouterTest commits content at relPath to the bare remote at remoteDir.
func pushFileForRouterTest(t *testing.T, remoteDir, relPath string, content []byte) {
	t.Helper()
	dir := t.TempDir()
	work, err := gogit.PlainClone(dir, false, &gogit.CloneOptions{URL: remoteDir})
	require.NoError(t, err)
	wt, err := work.Worktree()
	require.NoError(t, err)
	full := filepath.Join(dir, filepath.FromSlash(relPath))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0750))
	require.NoError(t, os.WriteFile(full, content, 0600))
	_, err = wt.Add(relPath)
	require.NoError(t, err)
	_, err = wt.Commit("update "+relPath, &gogit.CommitOptions{
		Author: &object.Signature{Name: "Test", Email: "t@t.com", When: time.Now()},
	})
	require.NoError(t, err)
	require.NoError(t, work.Push(&gogit.PushOptions{RemoteName: "origin"}))
}

// TestSyncTenantWithRemote_SyncGrowthCountsAgainstByteBudget verifies a sync that grows
// a clone updates its recorded bytes and re-applies the cache byte budget, evicting the
// least-recently-used other clone.
func TestSyncTenantWithRemote_SyncGrowthCountsAgainstByteBudget(t *testing.T) {
	router, workDir := newGitTestRouter(t, "t1", "t2")
	ctx := ctxkeys.WithSystem(context.Background())

	urls := map[string]string{}
	for _, id := range []string{"t1", "t2"} {
		urls[id] = createBareRepoForRouterTest(t, map[string][]byte{"configs/ns/cfg.yaml": []byte(id + "\n")})
		injectGitSource(router, id, *gitInfo(urls[id]))
	}

	_, _, err := router.SyncTenantWithRemote(ctx, "t1")
	require.NoError(t, err)
	_, _, err = router.SyncTenantWithRemote(ctx, "t2")
	require.NoError(t, err)

	key2 := "t2:" + fmt.Sprintf("%x", sha256.Sum256([]byte(urls["t2"])))
	router.gitStoreMu.Lock()
	before := router.gitUsage[key2].bytes
	var total int64
	for _, u := range router.gitUsage {
		total += u.bytes
	}
	router.maxCacheBytes = total + total/2
	router.gitStoreMu.Unlock()

	payload := make([]byte, 4*int(total))
	_, err = rand.Read(payload)
	require.NoError(t, err)
	pushFileForRouterTest(t, urls["t2"], "configs/blob.bin", payload)

	_, _, err = router.SyncTenantWithRemote(ctx, "t2")
	require.NoError(t, err)

	router.gitStoreMu.Lock()
	u, ok := router.gitUsage[key2]
	require.True(t, ok)
	after := u.bytes
	router.gitStoreMu.Unlock()
	assert.Greater(t, after, before+int64(len(payload))/2, "a sync must refresh the clone's recorded bytes")
	assert.NoDirExists(t, cloneDir(workDir, "t1", urls["t1"]), "the grown clone must push the LRU clone out of the budget")
	assert.DirExists(t, cloneDir(workDir, "t2", urls["t2"]))
}
