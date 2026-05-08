// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gitcfg "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	flatfile "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// gitRouterMemorySecretStore is a real in-memory SecretStore for git router tests.
// Same pattern as simpleTenantStore: lightweight in-memory implementation with real CRUD.
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

	ts := newSimpleTenantStore()
	ts.add("git-tenant", "", nil)
	ts.add("ctrl-tenant", "", nil)

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
	entry, readErr := router.GetConfig(context.Background(), gitKey)
	require.NoError(t, readErr, "git-tenant read must succeed")
	assert.Equal(t, configContent, string(entry.Data), "content must come from the git repo")

	// Write to git-tenant — always routes to controller store (git sources are read-only).
	writeEntry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "policies", Name: "new"},
		Data:   []byte("x: 1\n"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, router.StoreConfig(context.Background(), writeEntry),
		"write must route to controller store regardless of source type")

	// ctrl-tenant (no git source) routes to controller store.
	_, notFoundErr := router.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID: "ctrl-tenant", Namespace: "policies", Name: "baseline",
	})
	assert.ErrorIs(t, notFoundErr, cfgconfig.ErrConfigNotFound,
		"ctrl-tenant read must route to controller store which has nothing stored")
}

// TestNewControllerRouterWithGit_FallsBackOnInitFailure verifies that when GitConfigStore
// construction fails, storeForSource falls back to the controller store.
func TestNewControllerRouterWithGit_FallsBackOnInitFailure(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("git-tenant", "", nil)

	flatfileRoot := t.TempDir()
	controllerStore, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	gitWorkDir := t.TempDir()
	router := NewControllerRouterWithGit(controllerStore, ts, newGitRouterSecretStore(nil), gitWorkDir, logging.NewNoopLogger()).(*controllerRouter)

	// Store a value in controller store for the git-tenant so we can detect fallback.
	controllerEntry := &cfgconfig.ConfigEntry{
		Key:    &cfgconfig.ConfigKey{TenantID: "git-tenant", Namespace: "fallback", Name: "cfg"},
		Data:   []byte("fallback: true\n"),
		Format: cfgconfig.ConfigFormatYAML,
	}
	require.NoError(t, controllerStore.StoreConfig(context.Background(), controllerEntry))

	// Inject a git source pointing to a non-existent repo to trigger init failure.
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     "/nonexistent/repo/path",
		SubPath: "configs",
	})

	// storeForSource must fall back to controller store when git init fails.
	entry, readErr := router.GetConfig(context.Background(), controllerEntry.Key)
	require.NoError(t, readErr, "fallback to controller store must succeed")
	assert.Equal(t, controllerEntry.Data, entry.Data, "fallback must return controller store data")
}

// TestNewControllerRouterWithGit_GitStoreIsCached verifies that two reads for the same
// (tenant, URL) pair reuse the same GitConfigStore instance — no double-clone.
func TestNewControllerRouterWithGit_GitStoreIsCached(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/ns/cfg.yaml": []byte("cached: true\n"),
	})

	ts := newSimpleTenantStore()
	ts.add("t1", "", nil)

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
	_, err = router.GetConfig(context.Background(), key)
	require.NoError(t, err)
	_, err = router.GetConfig(context.Background(), key)
	require.NoError(t, err)

	// Cache must hold exactly one entry for t1.
	router.gitStoreMu.Lock()
	cacheSize := len(router.gitStoreCache)
	router.gitStoreMu.Unlock()
	assert.Equal(t, 1, cacheSize, "git store cache must hold exactly one entry per (tenant,url)")
}

// TestStoreForSource_ControllerTypeReturnsControllerStore verifies that storeForSource
// returns the controller store for controller-type sources (regression test for Phase 1 behavior).
func TestStoreForSource_ControllerTypeReturnsControllerStore(t *testing.T) {
	cs := &recordingConfigStore{}
	ts := newSimpleTenantStore()

	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), t.TempDir(), logging.NewNoopLogger()).(*controllerRouter)
	ctrlSource := &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeController}

	store := router.storeForSource(context.Background(), "any-tenant", ctrlSource)
	assert.Same(t, cs, store, "controller source must route to controllerStore")
}

// TestSyncTenantWithRemote_NonGitTenantReturnsEmpty verifies that SyncTenantWithRemote
// returns ("","",nil) for a tenant whose effective source is ConfigSourceTypeController.
func TestSyncTenantWithRemote_NonGitTenantReturnsEmpty(t *testing.T) {
	ts := newSimpleTenantStore()
	ts.add("ctrl-tenant", "", nil)

	flatfileRoot := t.TempDir()
	cs, err := flatfile.NewFlatFileConfigStore(flatfileRoot)
	require.NoError(t, err)

	router := NewControllerRouterWithGit(cs, ts, newGitRouterSecretStore(nil), t.TempDir(), logging.NewNoopLogger()).(*controllerRouter)

	prevSHA, newSHA, syncErr := router.SyncTenantWithRemote(context.Background(), "ctrl-tenant")
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

	ts := newSimpleTenantStore()
	ts.add("git-tenant", "", nil)

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
	prev1, new1, err := router.SyncTenantWithRemote(context.Background(), "git-tenant")
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
	prev2, new2, err := router.SyncTenantWithRemote(context.Background(), "git-tenant")
	require.NoError(t, err)
	assert.Equal(t, new1, prev2, "prevSHA on second call must equal the newSHA from first call")
	assert.NotEqual(t, prev2, new2, "newSHA must advance after remote receives a new commit")
	assert.Len(t, new2, 40)
}

// TestSyncTenantWithRemote_BrokenURLFallsBackToControllerStore verifies the graceful
// degradation path: when the source URL is updated to a non-existent remote *before* the
// git store is constructed, storeForSource falls back to controllerStore (clone fails →
// no GitConfigStore → SyncTenantWithRemote returns ("","",nil), not an error).
func TestSyncTenantWithRemote_BrokenURLFallsBackToControllerStore(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/default/app.yaml": []byte("v1\n"),
	})

	ts := newSimpleTenantStore()
	ts.add("git-tenant", "", nil)

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
	_, _, primeErr := router.SyncTenantWithRemote(context.Background(), "git-tenant")
	require.NoError(t, primeErr, "initial sync must succeed")

	// Break the remote by pointing the cached source at a non-existent URL.
	injectGitSource(router, "git-tenant", pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteDir + "-broken",
		SubPath: "configs",
	})

	// The git store cache key changed (URL hash changed) so storeForSource will try to create
	// a new GitConfigStore pointing at the broken URL — construction will fail (clone error)
	// and storeForSource falls back to controllerStore, meaning SyncTenantWithRemote returns ("","",nil).
	// This is the expected graceful-degradation path.
	prev, newSHA, syncErr := router.SyncTenantWithRemote(context.Background(), "git-tenant")
	require.NoError(t, syncErr, "broken-URL fallback to controller store must not error")
	assert.Empty(t, prev)
	assert.Empty(t, newSHA)
}

// TestSyncTenantWithRemote_PullErrorPropagatesFromBrokenRemote verifies that when the
// already-cached git store has its remote URL corrupted in .git/config, the next call
// to SyncTenantWithRemote propagates the pull error rather than silently swallowing it.
// This is distinct from BrokenURLFallsBackToControllerStore, which tests a broken URL
// at construction time — here the git store is already cached so the pull error surfaces.
func TestSyncTenantWithRemote_PullErrorPropagatesFromBrokenRemote(t *testing.T) {
	remoteDir := createBareRepoForRouterTest(t, map[string][]byte{
		"configs/default/app.yaml": []byte("v1\n"),
	})

	ts := newSimpleTenantStore()
	ts.add("git-tenant", "", nil)

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
	_, _, primeErr := router.SyncTenantWithRemote(context.Background(), "git-tenant")
	require.NoError(t, primeErr, "initial sync must succeed")

	// Locate the cloned repo directory and corrupt its remote URL so the next pull fails.
	urlHash := fmt.Sprintf("%x", sha256.Sum256([]byte(remoteDir)))
	repoDir := filepath.Join(gitWorkDir, "git-tenant", urlHash)
	repo, openErr := gogit.PlainOpen(repoDir)
	require.NoError(t, openErr, "must be able to open the cloned repo")
	repoCfg, cfgErr := repo.Config()
	require.NoError(t, cfgErr)
	repoCfg.Remotes["origin"].URLs = []string{"/nonexistent/broken/remote"}
	require.NoError(t, repo.SetConfig(repoCfg))

	// SyncTenantWithRemote must propagate the pull error — the cached git store is used
	// directly (no fallback), so the broken remote surfaces as a returned error.
	_, _, syncErr := router.SyncTenantWithRemote(context.Background(), "git-tenant")
	assert.Error(t, syncErr, "sync must return an error when the cached git store's remote is broken")
}

// Compile-time check: business.TenantStore is satisfied by simpleTenantStore.
var _ business.TenantStore = (*simpleTenantStore)(nil)
