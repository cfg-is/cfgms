// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	stewardprovider "github.com/cfgis/cfgms/pkg/secrets/providers/steward"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// requireGit skips the test if the git binary is not found in PATH.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not found in PATH; skipping test that requires real git")
	}
}

// runGit runs a git command, failing the test on error. It returns stdout+stderr.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...) // #nosec G204 - controlled test command with validated args
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v in %q failed: %v\n%s", args, dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newTestRepo creates a bare git repository pre-populated with the given files.
// It returns:
//   - bareDir: path to the bare repository (use as OriginURL in ScopeBinding)
//   - workDir: path to a working clone of bareDir (use to push new commits)
//   - pushFiles: a helper function that commits and pushes files to the bare repo
func newTestRepo(t *testing.T, initialFiles map[string]string) (bareDir, workDir string, pushFiles func(map[string]string)) {
	t.Helper()
	requireGit(t)

	root := t.TempDir()
	src := filepath.Join(root, "src")   // non-bare source for creating initial content
	bare := filepath.Join(root, "bare") // bare repo used as fake remote origin
	work := filepath.Join(root, "work") // working clone for incremental commits

	// Initialise source repo.
	require.NoError(t, os.MkdirAll(src, 0750))
	runGit(t, src, "init", "-b", "main")
	runGit(t, src, "-c", "user.name=test", "-c", "user.email=test@test.com",
		"commit", "--allow-empty", "-m", "empty initial")

	// Write initial files into source repo.
	for name, content := range initialFiles {
		path := filepath.Join(src, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0750))
		require.NoError(t, os.WriteFile(path, []byte(content), 0640))
	}
	if len(initialFiles) > 0 {
		runGit(t, src, "add", ".")
		runGit(t, src, "-c", "user.name=test", "-c", "user.email=test@test.com",
			"commit", "-m", "initial files")
	}

	// Clone source to bare.
	runGit(t, root, "clone", "--bare", src, bare)

	// Clone bare to work so we can push incremental commits.
	runGit(t, root, "clone", bare, work)
	runGit(t, work, "config", "user.name", "test")
	runGit(t, work, "config", "user.email", "test@test.com")

	push := func(files map[string]string) {
		for name, content := range files {
			path := filepath.Join(work, name)
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0750))
			require.NoError(t, os.WriteFile(path, []byte(content), 0640))
		}
		runGit(t, work, "add", ".")
		runGit(t, work, "-c", "user.name=test", "-c", "user.email=test@test.com",
			"commit", "-m", "add files")
		runGit(t, work, "push", "origin", "main")
	}

	return bare, work, push
}

// newTestSyncer creates a Syncer wired to a real ConfigStore for testing.
func newTestSyncer(t *testing.T, opts ...gitsync.Option) (*gitsync.Syncer, cfgconfig.ConfigStore, *gitsync.BindingStore) {
	t.Helper()
	root := t.TempDir()

	store := pkgtesting.SetupTestStorage(t).GetConfigStore()

	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	logger := logging.ForComponent("gitsync-test")
	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logger, opts...)
	require.NoError(t, err)

	return syncer, store, bindings
}

// TestInitialSync verifies that the first TriggerSync call clones the origin
// and imports YAML/JSON config files into the ConfigStore.
func TestInitialSync(t *testing.T) {
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	syncer, store, bindings := newTestSyncer(t)

	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))

	ctx := context.Background()
	err := syncer.TriggerSync(ctx, binding)
	require.NoError(t, err)

	entry, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/test-tenant",
		Namespace: "policies",
		Name:      "policy1",
	})
	require.NoError(t, err)
	assert.Equal(t, "key: value\n", string(entry.Data))
	assert.Equal(t, cfgconfig.ConfigFormatYAML, entry.Format)
	assert.Equal(t, "git-sync", entry.CreatedBy)
}

// TestIncrementalSync verifies that adding a commit to the origin and
// triggering sync again updates the ConfigStore and advances the last-synced
// SHA.
func TestIncrementalSync(t *testing.T) {
	bareDir, _, pushFiles := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	syncer, store, bindings := newTestSyncer(t)

	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))

	ctx := context.Background()

	// First sync: imports policy1.
	err := syncer.TriggerSync(ctx, binding)
	require.NoError(t, err)

	sha1, ok := bindings.Get("root/test-tenant", "policies")
	require.True(t, ok)
	assert.NotEmpty(t, sha1.LastSyncedSHA)

	// Push a second commit.
	pushFiles(map[string]string{"policy2.yaml": "key2: value2\n"})

	// Second sync: should pull the new commit and import policy2.
	err = syncer.TriggerSync(ctx, binding)
	require.NoError(t, err)

	sha2, ok := bindings.Get("root/test-tenant", "policies")
	require.True(t, ok)
	assert.NotEmpty(t, sha2.LastSyncedSHA)
	assert.NotEqual(t, sha1.LastSyncedSHA, sha2.LastSyncedSHA, "SHA must advance on new commit")

	entry, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/test-tenant",
		Namespace: "policies",
		Name:      "policy2",
	})
	require.NoError(t, err)
	assert.Equal(t, "key2: value2\n", string(entry.Data))
}

// TestIdempotentSync verifies that triggering a sync twice on the same commit
// does not increment the ConfigEntry version (StoreConfig is called once, not
// twice).
func TestIdempotentSync(t *testing.T) {
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	syncer, store, bindings := newTestSyncer(t)

	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))

	ctx := context.Background()

	// First sync: imports policy1 at version 1.
	require.NoError(t, syncer.TriggerSync(ctx, binding))

	entry, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/test-tenant",
		Namespace: "policies",
		Name:      "policy1",
	})
	require.NoError(t, err)
	versionAfterFirstSync := entry.Version

	// Second sync on the same commit: SHA unchanged → import skipped.
	require.NoError(t, syncer.TriggerSync(ctx, binding))

	entry2, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/test-tenant",
		Namespace: "policies",
		Name:      "policy1",
	})
	require.NoError(t, err)
	assert.Equal(t, versionAfterFirstSync, entry2.Version,
		"version must not advance when SHA has not changed (idempotent import)")
}

// TestScopeIsolation verifies that a failure syncing one scope does not prevent
// other scopes from syncing successfully.
func TestScopeIsolation(t *testing.T) {
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	syncer, store, bindings := newTestSyncer(t)

	reachable := gitsync.ScopeBinding{
		TenantPath: "root/good-tenant",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	unreachable := gitsync.ScopeBinding{
		TenantPath: "root/bad-tenant",
		Namespace:  "policies",
		OriginURL:  "/nonexistent/path/that/does/not/exist",
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(reachable))
	require.NoError(t, bindings.Add(unreachable))

	ctx := context.Background()

	// Unreachable scope must return an error.
	err := syncer.TriggerSync(ctx, unreachable)
	assert.Error(t, err)
	assert.ErrorIs(t, err, gitsync.ErrOriginUnreachable)

	// Reachable scope must sync successfully regardless.
	err = syncer.TriggerSync(ctx, reachable)
	require.NoError(t, err)

	entry, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/good-tenant",
		Namespace: "policies",
		Name:      "policy1",
	})
	require.NoError(t, err)
	assert.Equal(t, "key: value\n", string(entry.Data))
}

// TestSyncScope_RejectsSymlinkEscapingWorkDir is the REQUIRED path-traversal
// test for Issue #4340: a symlink pre-planted at the exact scope directory
// name the syncer would use, pointing outside workDir, must be rejected
// rather than followed into a clone that writes outside the configured base
// directory.
func TestSyncScope_RejectsSymlinkEscapingWorkDir(t *testing.T) {
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	root := t.TempDir()
	workDir := filepath.Join(root, "repos")
	store := pkgtesting.SetupTestStorage(t).GetConfigStore()

	bindings, err := gitsync.NewBindingStore(t.TempDir())
	require.NoError(t, err)

	logger := logging.ForComponent("gitsync-test")
	syncer, err := gitsync.NewSyncer(store, bindings, workDir, logger)
	require.NoError(t, err)

	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))

	// Pre-create a symlink at the exact scope directory name the syncer
	// derives from the binding key ("root/test-tenant/policies" with "/"
	// replaced by "_"), pointing outside workDir.
	outside := t.TempDir()
	scopeDir := filepath.Join(workDir, "root_test-tenant_policies")
	require.NoError(t, os.Symlink(outside, scopeDir))

	err = syncer.TriggerSync(context.Background(), binding)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid scope path")

	// The clone must never have been written through the symlink into outside.
	entries, readErr := os.ReadDir(outside)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "sync must not write through a symlink that escapes workDir")
}

// TestPollingInterval verifies that a polling goroutine fires TriggerSync when
// the ticker fires.
//
// A controllable ticker (via WithTickerFunc) and a sync-done channel (via
// WithSyncNotify) are injected so the test does not need to sleep and does
// not depend on wall-clock timing. MinPollingInterval (60 s) is still
// respected at the binding level; only the ticker delivery is accelerated.
func TestPollingInterval(t *testing.T) {
	requireGit(t)

	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	// fakeTick delivers ticks on demand; syncDone signals when each TriggerSync
	// call has finished so we can assert without sleeping.
	fakeTick := make(chan time.Time, 1)
	syncDone := make(chan struct{}, 1)

	syncer, store, bindings := newTestSyncer(t,
		gitsync.WithTickerFunc(func(_ time.Duration) (<-chan time.Time, func()) {
			return fakeTick, func() {}
		}),
		gitsync.WithSyncNotify(syncDone),
	)

	binding := gitsync.ScopeBinding{
		TenantPath:      "root/poll-tenant",
		Namespace:       "policies",
		OriginURL:       bareDir,
		Branch:          "main",
		PollingInterval: gitsync.MinPollingInterval, // 60 s (minimum) — real interval, fake delivery
	}
	require.NoError(t, bindings.Add(binding))

	ctx := context.Background()
	require.NoError(t, syncer.Start(ctx))
	t.Cleanup(syncer.Stop)

	// Deliver one tick to trigger a polling sync cycle.
	fakeTick <- time.Now()

	// Wait for TriggerSync to complete without sleeping.
	select {
	case <-syncDone:
	case <-time.After(10 * time.Second):
		t.Fatal("polling sync did not complete within 10 seconds")
	}

	entry, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/poll-tenant",
		Namespace: "policies",
		Name:      "policy1",
	})
	require.NoError(t, err)
	assert.Equal(t, "key: value\n", string(entry.Data))
}

// TestPollingIntervalTooShort verifies that configuring a polling interval
// shorter than MinPollingInterval is rejected at binding-add time.
func TestPollingIntervalTooShort(t *testing.T) {
	root := t.TempDir()
	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	binding := gitsync.ScopeBinding{
		TenantPath:      "root/test",
		Namespace:       "policies",
		OriginURL:       "https://example.com/repo.git",
		Branch:          "main",
		PollingInterval: 30 * time.Second, // below MinPollingInterval
	}
	err = bindings.Add(binding)
	require.Error(t, err)
	assert.ErrorIs(t, err, gitsync.ErrIntervalTooShort)
}

// newTestStewardStore creates a real steward SecretStore in a temp dir.
// Skips the test when /etc/machine-id is absent (required for platform key
// derivation on Linux).
func newTestStewardStore(t *testing.T) secretsif.SecretStore {
	t.Helper()
	if _, err := os.Stat("/etc/machine-id"); os.IsNotExist(err) {
		t.Skip("skipping: /etc/machine-id not available (required for platform key derivation on Linux)")
	}
	provider := &stewardprovider.StewardProvider{}
	store, err := provider.CreateSecretStore(map[string]interface{}{
		"secrets_dir": t.TempDir(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestResolveCredentials_SecretScheme verifies that a "secret:<key>" CredentialsRef
// is resolved via the SecretStore and that the syncer succeeds when the secret exists.
// It also verifies that using a "secret:" ref without a configured SecretStore returns
// ErrAuthFailed.
func TestResolveCredentials_SecretScheme(t *testing.T) {
	requireGit(t)

	bareDir, _, _ := newTestRepo(t, map[string]string{
		"policy1.yaml": "key: value\n",
	})

	ctx := context.Background()
	const secretKey = "gitsync/test/token"
	const tokenValue = "test-git-token"

	t.Run("resolves secret and syncs successfully", func(t *testing.T) {
		store := newTestStewardStore(t)
		require.NoError(t, store.StoreSecret(ctx, &secretsif.SecretRequest{
			Key:       secretKey,
			Value:     tokenValue,
			CreatedBy: "test",
			TenantID:  "t1",
		}))

		syncer, configStore, bindings := newTestSyncer(t, gitsync.WithSecretStore(store))
		binding := gitsync.ScopeBinding{
			TenantPath:     "root/secret-scheme-tenant",
			Namespace:      "policies",
			OriginURL:      bareDir,
			Branch:         "main",
			CredentialsRef: "secret:" + secretKey,
		}
		require.NoError(t, bindings.Add(binding))

		require.NoError(t, syncer.TriggerSync(ctx, binding),
			"sync must succeed when SecretStore holds the credential")

		entry, err := configStore.GetConfig(ctx, &cfgconfig.ConfigKey{
			TenantID:  "root/secret-scheme-tenant",
			Namespace: "policies",
			Name:      "policy1",
		})
		require.NoError(t, err)
		assert.Equal(t, "key: value\n", string(entry.Data))
	})

	t.Run("returns ErrAuthFailed when SecretStore is not configured", func(t *testing.T) {
		syncer, _, bindings := newTestSyncer(t) // no WithSecretStore
		binding := gitsync.ScopeBinding{
			TenantPath:     "root/no-store-tenant",
			Namespace:      "policies",
			OriginURL:      bareDir,
			Branch:         "main",
			CredentialsRef: "secret:" + secretKey,
		}
		require.NoError(t, bindings.Add(binding))

		err := syncer.TriggerSync(ctx, binding)
		require.Error(t, err)
		assert.ErrorIs(t, err, gitsync.ErrAuthFailed,
			"missing SecretStore must be reported as ErrAuthFailed")
	})

	t.Run("returns ErrAuthFailed when secret key does not exist in store", func(t *testing.T) {
		store := newTestStewardStore(t)
		// Do NOT store the key — GetSecret will return ErrSecretNotFound.
		syncer, _, bindings := newTestSyncer(t, gitsync.WithSecretStore(store))
		binding := gitsync.ScopeBinding{
			TenantPath:     "root/missing-key-tenant",
			Namespace:      "policies",
			OriginURL:      bareDir,
			Branch:         "main",
			CredentialsRef: "secret:gitsync/nonexistent/key",
		}
		require.NoError(t, bindings.Add(binding))

		err := syncer.TriggerSync(ctx, binding)
		require.Error(t, err)
		assert.ErrorIs(t, err, gitsync.ErrAuthFailed,
			"missing secret key must be reported as ErrAuthFailed")
	})
}

// TestJSONConfigImport verifies that JSON config files are imported with the
// correct format.
func TestJSONConfigImport(t *testing.T) {
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"settings.json": `{"debug": true}`,
	})

	syncer, store, bindings := newTestSyncer(t)

	binding := gitsync.ScopeBinding{
		TenantPath: "root/json-tenant",
		Namespace:  "settings",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))

	ctx := context.Background()
	require.NoError(t, syncer.TriggerSync(ctx, binding))

	entry, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID:  "root/json-tenant",
		Namespace: "settings",
		Name:      "settings",
	})
	require.NoError(t, err)
	assert.Equal(t, cfgconfig.ConfigFormatJSON, entry.Format)
	assert.Contains(t, string(entry.Data), `"debug"`)
}

// pushSymlinks commits symlinks (name -> target) into the working clone and
// pushes them to origin. It skips only when os.Symlink itself fails (for
// example Windows without Developer Mode).
func pushSymlinks(t *testing.T, workDir string, links map[string]string) {
	t.Helper()
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(workDir, name)); err != nil {
			t.Skipf("cannot create symlink on this platform: %v", err)
		}
	}
	runGit(t, workDir, "add", ".")
	runGit(t, workDir, "-c", "user.name=test", "-c", "user.email=test@test.com",
		"commit", "-m", "add symlinks")
	runGit(t, workDir, "push", "origin", "main")
}

// syncSymlinkRepo syncs a repo containing good.yaml plus the given symlinks and
// returns the store after TriggerSync.
func syncSymlinkRepo(t *testing.T, links map[string]string) cfgconfig.ConfigStore {
	t.Helper()
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"good.yaml":   "key: good\n",
		"inside.yaml": "key: inside\n",
	})
	pushSymlinks(t, workDir, links)

	syncer, store, bindings := newTestSyncer(t)
	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant",
		Namespace:  "policies",
		OriginURL:  bareDir,
		Branch:     "main",
	}
	require.NoError(t, bindings.Add(binding))
	require.NoError(t, syncer.TriggerSync(context.Background(), binding))
	return store
}

func requireNoEntry(t *testing.T, store cfgconfig.ConfigStore, name string) {
	t.Helper()
	_, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID: "root/test-tenant", Namespace: "policies", Name: name,
	})
	require.Error(t, err, "entry %q must not be imported", name)
}

// TestSyncRefusesSymlinkToOutsideFile verifies a committed symlink pointing
// outside the checkout is not imported and its target content never reaches
// the ConfigStore.
func TestSyncRefusesSymlinkToOutsideFile(t *testing.T) {
	const secret = "TOP-SECRET-OUTSIDE-CONTENT"
	outside := filepath.Join(t.TempDir(), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte(secret), 0600))

	store := syncSymlinkRepo(t, map[string]string{"leak.yaml": outside})

	ctx := context.Background()
	good, err := store.GetConfig(ctx, &cfgconfig.ConfigKey{
		TenantID: "root/test-tenant", Namespace: "policies", Name: "good",
	})
	require.NoError(t, err)
	assert.Equal(t, "key: good\n", string(good.Data))
	requireNoEntry(t, store, "leak")

	for _, name := range []string{"good", "inside", "leak"} {
		e, getErr := store.GetConfig(ctx, &cfgconfig.ConfigKey{
			TenantID: "root/test-tenant", Namespace: "policies", Name: name,
		})
		if getErr == nil {
			assert.NotContains(t, string(e.Data), secret)
		}
	}
}

// TestSyncRefusesSymlinkInsideCheckout verifies symlinks are refused even when
// the target is another regular file inside the same checkout.
func TestSyncRefusesSymlinkInsideCheckout(t *testing.T) {
	store := syncSymlinkRepo(t, map[string]string{"alias.yaml": "inside.yaml"})

	requireNoEntry(t, store, "alias")
	e, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID: "root/test-tenant", Namespace: "policies", Name: "inside",
	})
	require.NoError(t, err)
	assert.Equal(t, "key: inside\n", string(e.Data))
}

// failDeleteStore wraps a real ConfigStore and fails every DeleteConfig.
type failDeleteStore struct {
	cfgconfig.ConfigStore
}

func (failDeleteStore) DeleteConfig(context.Context, *cfgconfig.ConfigKey) error {
	return errors.New("injected delete failure")
}

func commitRemoval(t *testing.T, workDir string, remove, rename map[string]string) {
	t.Helper()
	for _, name := range keysOf(remove) {
		runGit(t, workDir, "rm", name)
	}
	for from, to := range rename {
		runGit(t, workDir, "mv", from, to)
	}
	runGit(t, workDir, "-c", "user.name=test", "-c", "user.email=test@test.com",
		"commit", "-m", "remove files")
	runGit(t, workDir, "push", "origin", "main")
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func getEntry(store cfgconfig.ConfigStore, ns, name string) error {
	_, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID: "root/test-tenant", Namespace: ns, Name: name,
	})
	return err
}

func TestSyncDeletesEntriesRemovedAtOrigin(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"a.yaml": "a: 1\n",
		"b.yaml": "b: 1\n",
	})
	syncer, store, bindings := newTestSyncer(t)
	binding := gitsync.ScopeBinding{TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main"}
	require.NoError(t, bindings.Add(binding))
	ctx := context.Background()

	// Entries that must survive: manual entry in the same namespace and a
	// git-sync entry in another namespace.
	require.NoError(t, store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "root/test-tenant", Namespace: "policies", Name: "manual"},
		Data: []byte("m: 1\n"), Format: cfgconfig.ConfigFormatYAML, Source: "ui", CreatedBy: "admin", UpdatedBy: "admin",
	}))
	require.NoError(t, store.StoreConfig(ctx, &cfgconfig.ConfigEntry{
		Key:  &cfgconfig.ConfigKey{TenantID: "root/test-tenant", Namespace: "other", Name: "b"},
		Data: []byte("o: 1\n"), Format: cfgconfig.ConfigFormatYAML, Source: "git-sync:elsewhere@abcd1234", CreatedBy: "git-sync", UpdatedBy: "git-sync",
	}))

	require.NoError(t, syncer.TriggerSync(ctx, binding))
	require.NoError(t, getEntry(store, "policies", "b"))

	commitRemoval(t, workDir, map[string]string{"b.yaml": ""}, nil)
	require.NoError(t, syncer.TriggerSync(ctx, binding))

	assert.Error(t, getEntry(store, "policies", "b"), "removed file's entry must be deleted")
	assert.NoError(t, getEntry(store, "policies", "a"))
	assert.NoError(t, getEntry(store, "policies", "manual"))
	assert.NoError(t, getEntry(store, "other", "b"))

	head := runGit(t, workDir, "rev-parse", "HEAD")
	got, ok := bindings.Get("root/test-tenant", "policies")
	require.True(t, ok)
	assert.Equal(t, strings.TrimSpace(head), got.LastSyncedSHA)
}

func TestSyncRenameRemovesOldName(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{"a.yaml": "a: 1\n"})
	syncer, store, bindings := newTestSyncer(t)
	binding := gitsync.ScopeBinding{TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main"}
	require.NoError(t, bindings.Add(binding))
	ctx := context.Background()

	require.NoError(t, syncer.TriggerSync(ctx, binding))
	commitRemoval(t, workDir, nil, map[string]string{"a.yaml": "c.yaml"})
	require.NoError(t, syncer.TriggerSync(ctx, binding))

	assert.NoError(t, getEntry(store, "policies", "c"))
	assert.Error(t, getEntry(store, "policies", "a"))
}

func TestSyncDeleteErrorKeepsLastSyncedSHA(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"a.yaml": "a: 1\n",
		"b.yaml": "b: 1\n",
	})
	root := t.TempDir()
	real := pkgtesting.SetupTestStorage(t).GetConfigStore()
	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	good, err := gitsync.NewSyncer(real, bindings, filepath.Join(root, "repos"), logging.ForComponent("gitsync-test"))
	require.NoError(t, err)
	failing, err := gitsync.NewSyncer(failDeleteStore{real}, bindings, filepath.Join(root, "repos"), logging.ForComponent("gitsync-test"))
	require.NoError(t, err)

	binding := gitsync.ScopeBinding{TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main"}
	require.NoError(t, bindings.Add(binding))
	ctx := context.Background()

	require.NoError(t, good.TriggerSync(ctx, binding))
	before, _ := bindings.Get("root/test-tenant", "policies")
	require.NotEmpty(t, before.LastSyncedSHA)

	commitRemoval(t, workDir, map[string]string{"b.yaml": ""}, nil)
	require.Error(t, failing.TriggerSync(ctx, binding))

	after, _ := bindings.Get("root/test-tenant", "policies")
	assert.Equal(t, before.LastSyncedSHA, after.LastSyncedSHA, "SHA must not advance when deletion fails")

	// Retry with a working store converges.
	require.NoError(t, good.TriggerSync(ctx, binding))
	assert.Error(t, getEntry(real, "policies", "b"))
}

// overlapStore wraps a real ConfigStore and records the highest number of
// ListConfigs calls (made by the prune step) in flight at once.
type overlapStore struct {
	cfgconfig.ConfigStore
	inFlight, maxInFlight atomic.Int32
}

func (o *overlapStore) ListConfigs(ctx context.Context, f *cfgconfig.ConfigFilter) ([]*cfgconfig.ConfigEntry, error) {
	n := o.inFlight.Add(1)
	defer o.inFlight.Add(-1)
	for {
		m := o.maxInFlight.Load()
		if n <= m || o.maxInFlight.CompareAndSwap(m, n) {
			break
		}
	}
	time.Sleep(50 * time.Millisecond)
	return o.ConfigStore.ListConfigs(ctx, f)
}

func TestConcurrentSyncsOfOneScopeAreSerialized(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"a.yaml": "a: 1\n",
		"b.yaml": "b: 1\n",
	})
	root := t.TempDir()
	real := pkgtesting.SetupTestStorage(t).GetConfigStore()
	store := &overlapStore{ConfigStore: real}
	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)
	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logging.ForComponent("gitsync-test"))
	require.NoError(t, err)

	binding := gitsync.ScopeBinding{TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main"}
	require.NoError(t, bindings.Add(binding))
	ctx := context.Background()
	require.NoError(t, syncer.TriggerSync(ctx, binding))
	store.maxInFlight.Store(0)

	commitRemoval(t, workDir, map[string]string{"b.yaml": ""}, nil)

	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = syncer.TriggerSync(ctx, binding)
		}()
	}
	wg.Wait()
	for _, e := range errs {
		require.NoError(t, e)
	}

	assert.EqualValues(t, 1, store.maxInFlight.Load(), "syncs of one scope must not overlap")
	assert.NoError(t, getEntry(real, "policies", "a"))
	assert.Error(t, getEntry(real, "policies", "b"))
	got, _ := bindings.Get("root/test-tenant", "policies")
	assert.Equal(t, runGit(t, workDir, "rev-parse", "HEAD"), got.LastSyncedSHA)
}

// TestSyncRefusesOversizedConfigFile verifies a file over the configured
// maximum is refused while its sibling files still import.
func TestSyncRefusesOversizedConfigFile(t *testing.T) {
	const maxSize = 64
	bareDir, _, _ := newTestRepo(t, map[string]string{
		"small.yaml": "key: small\n",
		"exact.yaml": "k: " + strings.Repeat("x", maxSize-3),
		"big.yaml":   "k: " + strings.Repeat("x", maxSize-2),
		"other.json": `{"a":1}`,
	})

	syncer, store, bindings := newTestSyncer(t, gitsync.WithMaxConfigFileSize(maxSize))
	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main",
	}
	require.NoError(t, bindings.Add(binding))
	require.NoError(t, syncer.TriggerSync(context.Background(), binding))

	requireNoEntry(t, store, "big")
	for _, name := range []string{"small", "exact", "other"} {
		_, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
			TenantID: "root/test-tenant", Namespace: "policies", Name: name,
		})
		assert.NoError(t, err, "entry %q must import", name)
	}
}

// TestSyncSkipsInvalidConfigNames verifies files whose derived names are
// empty or invalid are skipped without aborting the sync.
func TestSyncSkipsInvalidConfigNames(t *testing.T) {
	bareDir, workDir, _ := newTestRepo(t, map[string]string{
		"good.yaml":  "key: good\n",
		".yaml":      "key: empty\n",
		"..yaml":     "key: dots\n",
		"trail..yml": "key: trailing\n",
	})

	syncer, store, bindings := newTestSyncer(t)
	binding := gitsync.ScopeBinding{
		TenantPath: "root/test-tenant", Namespace: "policies", OriginURL: bareDir, Branch: "main",
	}
	require.NoError(t, bindings.Add(binding))
	require.NoError(t, syncer.TriggerSync(context.Background(), binding))

	_, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID: "root/test-tenant", Namespace: "policies", Name: "good",
	})
	require.NoError(t, err)
	requireNoEntry(t, store, "")
	requireNoEntry(t, store, ".")
	requireNoEntry(t, store, ".yaml")
	requireNoEntry(t, store, "trail.")

	head := runGit(t, workDir, "rev-parse", "HEAD")
	got, ok := bindings.Get("root/test-tenant", "policies")
	require.True(t, ok)
	assert.Equal(t, strings.TrimSpace(head), got.LastSyncedSHA)
}
