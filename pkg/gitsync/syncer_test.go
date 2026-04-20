// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
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

// newTestSyncer creates a Syncer wired to a FlatFileConfigStore for testing.
func newTestSyncer(t *testing.T, opts ...gitsync.Option) (*gitsync.Syncer, *flatfile.FlatFileConfigStore, *gitsync.BindingStore) {
	t.Helper()
	root := t.TempDir()

	store, err := flatfile.NewFlatFileConfigStore(filepath.Join(root, "configs"))
	require.NoError(t, err)

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
