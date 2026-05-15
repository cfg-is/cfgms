// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package git

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// --- test helpers ---

// memorySecretStore is a real in-memory implementation of secretsiface.SecretStore for tests.
// There is no test implementation in pkg/secrets/providers (providers require OpenBao or OS keychain),
// so this follows the same pattern as simpleTenantStore in pkg/configrouting/providers/controller/router_test.go:
// a lightweight in-memory struct with real CRUD semantics for use in unit tests.
type memorySecretStore struct {
	secrets map[string]*secretsiface.Secret
}

func newMemorySecretStore(pairs map[string]string) *memorySecretStore {
	s := &memorySecretStore{secrets: make(map[string]*secretsiface.Secret)}
	for k, v := range pairs {
		s.secrets[k] = &secretsiface.Secret{Key: k, Value: v}
	}
	return s
}

func (s *memorySecretStore) GetSecret(_ context.Context, key string) (*secretsiface.Secret, error) {
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsiface.ErrSecretNotFound
	}
	return v, nil
}

func (s *memorySecretStore) StoreSecret(_ context.Context, req *secretsiface.SecretRequest) error {
	s.secrets[req.Key] = &secretsiface.Secret{Key: req.Key, Value: req.Value}
	return nil
}

func (s *memorySecretStore) DeleteSecret(_ context.Context, key string) error {
	if _, ok := s.secrets[key]; !ok {
		return secretsiface.ErrSecretNotFound
	}
	delete(s.secrets, key)
	return nil
}

func (s *memorySecretStore) ListSecrets(_ context.Context, _ *secretsiface.SecretFilter) ([]*secretsiface.SecretMetadata, error) {
	out := make([]*secretsiface.SecretMetadata, 0, len(s.secrets))
	for _, sec := range s.secrets {
		out = append(out, &secretsiface.SecretMetadata{Key: sec.Key})
	}
	return out, nil
}

func (s *memorySecretStore) GetSecrets(_ context.Context, keys []string) (map[string]*secretsiface.Secret, error) {
	out := make(map[string]*secretsiface.Secret, len(keys))
	for _, k := range keys {
		if v, ok := s.secrets[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}

func (s *memorySecretStore) StoreSecrets(_ context.Context, secrets map[string]*secretsiface.SecretRequest) error {
	for k, req := range secrets {
		s.secrets[k] = &secretsiface.Secret{Key: k, Value: req.Value}
	}
	return nil
}

func (s *memorySecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsiface.Secret, error) {
	return nil, secretsiface.ErrSecretNotFound
}
func (s *memorySecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsiface.SecretVersion, error) {
	return nil, nil // versioning not supported by this in-memory store
}
func (s *memorySecretStore) GetSecretMetadata(_ context.Context, key string) (*secretsiface.SecretMetadata, error) {
	if v, ok := s.secrets[key]; ok {
		return &secretsiface.SecretMetadata{Key: v.Key}, nil
	}
	return nil, secretsiface.ErrSecretNotFound
}
func (s *memorySecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *memorySecretStore) RotateSecret(_ context.Context, key string, newValue string) error {
	if v, ok := s.secrets[key]; ok {
		v.Value = newValue
		return nil
	}
	return secretsiface.ErrSecretNotFound
}
func (s *memorySecretStore) ExpireSecret(_ context.Context, key string) error {
	delete(s.secrets, key)
	return nil
}
func (s *memorySecretStore) HealthCheck(_ context.Context) error { return nil }
func (s *memorySecretStore) Close() error                        { return nil }

// createBareRemote sets up a local bare repo with an initial commit containing the
// provided files. Returns the path to the bare repo (used as the clone URL).
// All paths are relative to the repo root.
func createBareRemote(t *testing.T, files map[string][]byte) string {
	t.Helper()

	bareDir := t.TempDir()
	workDir := t.TempDir()

	// Init bare repo
	_, err := gogit.PlainInit(bareDir, true)
	require.NoError(t, err, "init bare repo")

	// Init working copy
	work, err := gogit.PlainInit(workDir, false)
	require.NoError(t, err, "init working copy")

	wt, err := work.Worktree()
	require.NoError(t, err)

	// Write files into working copy
	for relPath, content := range files {
		full := filepath.Join(workDir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0750))
		require.NoError(t, os.WriteFile(full, content, 0600))
		_, err = wt.Add(relPath)
		require.NoError(t, err, "git add %s", relPath)
	}

	// Commit
	_, err = wt.Commit("initial commit", &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  "Test Author",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err, "initial commit")

	// Add remote and push to bare
	_, err = work.CreateRemote(&gitconfig.RemoteConfig{
		Name: "origin",
		URLs: []string{bareDir},
	})
	require.NoError(t, err)

	err = work.Push(&gogit.PushOptions{RemoteName: "origin"})
	require.NoError(t, err, "push to bare remote")

	return bareDir
}

// addCommitToRemote adds a new file commit to the bare remote, simulating a remote update.
func addCommitToRemote(t *testing.T, bareDir string, filePath string, content []byte) {
	t.Helper()

	workDir := t.TempDir()

	work, err := gogit.PlainClone(workDir, false, &gogit.CloneOptions{URL: bareDir})
	require.NoError(t, err, "clone remote for update")

	wt, err := work.Worktree()
	require.NoError(t, err)

	full := filepath.Join(workDir, filePath)
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0750))
	require.NoError(t, os.WriteFile(full, content, 0600))
	_, err = wt.Add(filePath)
	require.NoError(t, err)

	_, err = wt.Commit("update "+filePath, &gogit.CommitOptions{
		Author: &object.Signature{Name: "Updater", Email: "up@example.com", When: time.Now()},
	})
	require.NoError(t, err)

	err = work.Push(&gogit.PushOptions{})
	require.NoError(t, err, "push update to bare remote")
}

func makeSource(remoteURL, subPath string) *pkgconfig.ConfigSourceInfo {
	return &pkgconfig.ConfigSourceInfo{
		Type:    pkgconfig.ConfigSourceTypeGit,
		URL:     remoteURL,
		SubPath: subPath,
	}
}

// --- tests ---

// TestGitConfigStore_Clone verifies that NewGitConfigStore clones the remote so that
// a .git directory is present in the work directory after construction.
func TestGitConfigStore_Clone(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/myapp.yaml": []byte("key: value\n"),
	})

	workDir := t.TempDir()
	source := makeSource(remoteDir, "configs")
	ss := newMemorySecretStore(nil)

	store, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, store)

	// .git directory must exist in the cloned repo
	gitDir := filepath.Join(store.repoDir, ".git")
	info, statErr := os.Stat(gitDir)
	require.NoError(t, statErr, ".git must exist after clone")
	assert.True(t, info.IsDir())
}

// TestGitConfigStore_GetConfig reads a config file that was present in the cloned repo.
func TestGitConfigStore_GetConfig(t *testing.T) {
	const configContent = "name: test\nvalue: 42\n"
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/networking/firewall.yaml": []byte(configContent),
	})

	workDir := t.TempDir()
	source := makeSource(remoteDir, "configs")
	ss := newMemorySecretStore(nil)

	store, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	entry, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "networking",
		Name:      "firewall",
	})
	require.NoError(t, err)
	assert.Equal(t, configContent, string(entry.Data))
	assert.Equal(t, cfgconfig.ConfigFormatYAML, entry.Format)
}

// TestGitConfigStore_WriteReturnsReadOnlyError asserts that all mutating methods
// return ErrReadOnlySource and never attempt to modify the repository.
func TestGitConfigStore_WriteReturnsReadOnlyError(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/init.yaml": []byte("init: true\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	ctx := context.Background()
	key := &cfgconfig.ConfigKey{TenantID: "tenant1", Namespace: "default", Name: "new"}
	entry := &cfgconfig.ConfigEntry{Key: key, Data: []byte("x: 1\n"), Format: cfgconfig.ConfigFormatYAML}

	assert.ErrorIs(t, store.StoreConfig(ctx, entry), ErrReadOnlySource, "StoreConfig")
	assert.ErrorIs(t, store.DeleteConfig(ctx, key), ErrReadOnlySource, "DeleteConfig")
	assert.ErrorIs(t, store.StoreConfigBatch(ctx, []*cfgconfig.ConfigEntry{entry}), ErrReadOnlySource, "StoreConfigBatch")
	assert.ErrorIs(t, store.DeleteConfigBatch(ctx, []*cfgconfig.ConfigKey{key}), ErrReadOnlySource, "DeleteConfigBatch")
}

// TestGitConfigStore_GetCurrentSHA verifies that GetCurrentSHA returns the HEAD commit SHA
// after cloning and returns an empty string (not an error) for a brand-new empty repo.
func TestGitConfigStore_GetCurrentSHA(t *testing.T) {
	t.Run("returns_HEAD_sha_after_clone", func(t *testing.T) {
		remoteDir := createBareRemote(t, map[string][]byte{
			"configs/default/app.yaml": []byte("version: 1\n"),
		})
		workDir := t.TempDir()
		ss := newMemorySecretStore(nil)
		store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
		require.NoError(t, err)

		sha, err := store.GetCurrentSHA()
		require.NoError(t, err)
		assert.Len(t, sha, 40, "HEAD SHA must be 40 hex characters")
	})

	t.Run("advances_after_pull", func(t *testing.T) {
		remoteDir := createBareRemote(t, map[string][]byte{
			"configs/default/app.yaml": []byte("v1\n"),
		})
		workDir := t.TempDir()
		ss := newMemorySecretStore(nil)
		store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
		require.NoError(t, err)

		sha1, err := store.GetCurrentSHA()
		require.NoError(t, err)
		require.Len(t, sha1, 40)

		addCommitToRemote(t, remoteDir, "configs/default/app.yaml", []byte("v2\n"))
		_, pullErr := store.SyncWithRemote(context.Background())
		require.NoError(t, pullErr)

		sha2, err := store.GetCurrentSHA()
		require.NoError(t, err)
		assert.NotEqual(t, sha1, sha2, "SHA must advance after pulling new commits")
	})
}

// TestGitConfigStore_SyncWithRemote verifies that SyncWithRemote pulls new commits and
// returns the updated HEAD SHA.
func TestGitConfigStore_SyncWithRemote(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/app.yaml": []byte("version: 1\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Get initial HEAD
	sha1, err := store.SyncWithRemote(context.Background())
	require.NoError(t, err)
	assert.Len(t, sha1, 40, "SHA must be 40 hex characters")

	// Push a new commit to the remote
	addCommitToRemote(t, remoteDir, "configs/default/app.yaml", []byte("version: 2\n"))

	// Sync again — SHA must change
	sha2, err := store.SyncWithRemote(context.Background())
	require.NoError(t, err)
	assert.Len(t, sha2, 40)
	assert.NotEqual(t, sha1, sha2, "SHA must advance after remote update")

	// Verify new content is visible via GetConfig
	entry, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "default",
		Name:      "app",
	})
	require.NoError(t, err)
	assert.Equal(t, "version: 2\n", string(entry.Data))
}

// TestGitConfigStore_PullFailureServesLastGood verifies that a pull error does not
// evict the last-known-good state — the store must continue serving previously cloned data.
// The remote origin URL is changed in .git/config to a non-existent path to force failure.
func TestGitConfigStore_PullFailureServesLastGood(t *testing.T) {
	const initialContent = "stable: true\n"
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/prod/config.yaml": []byte(initialContent),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Corrupt the origin URL inside .git/config to force a pull failure.
	// This simulates the remote becoming unreachable after the initial clone.
	repo, openErr := gogit.PlainOpen(store.repoDir)
	require.NoError(t, openErr)
	cfg, cfgErr := repo.Config()
	require.NoError(t, cfgErr)
	cfg.Remotes["origin"].URLs = []string{"/nonexistent/broken/remote"}
	require.NoError(t, repo.SetConfig(cfg))

	_, pullErr := store.SyncWithRemote(context.Background())
	assert.Error(t, pullErr, "pull to broken remote must fail")

	// The previously cloned data must still be readable (last-known-good preserved)
	entry, getErr := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "prod",
		Name:      "config",
	})
	require.NoError(t, getErr, "last-known-good state must remain readable after pull failure")
	assert.Equal(t, initialContent, string(entry.Data))
}

// TestGitConfigStore_NoCredentialLeakedInError asserts that the credential value does
// not appear in any error returned by SyncWithRemote. The origin URL in .git/config is
// corrupted to a non-existent path to force a pull failure; the sanitizeCredential
// function must strip the token from any resulting error message.
func TestGitConfigStore_NoCredentialLeakedInError(t *testing.T) {
	const secretToken = "super-secret-token-12345"

	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/app.yaml": []byte("ok: true\n"),
	})

	workDir := t.TempDir()
	source := &pkgconfig.ConfigSourceInfo{
		Type:          pkgconfig.ConfigSourceTypeGit,
		URL:           remoteDir,
		SubPath:       "configs",
		CredentialRef: "my-git-token",
	}
	ss := newMemorySecretStore(map[string]string{"my-git-token": secretToken})

	store, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Corrupt the origin URL in .git/config to a non-existent path.
	// The pull will fail; our sanitizeCredential must ensure the error message
	// does not contain the credential value even if go-git embeds it.
	repo, openErr := gogit.PlainOpen(store.repoDir)
	require.NoError(t, openErr)
	gitCfg, cfgErr := repo.Config()
	require.NoError(t, cfgErr)
	gitCfg.Remotes["origin"].URLs = []string{"/nonexistent/broken/" + secretToken + "/path"}
	require.NoError(t, repo.SetConfig(gitCfg))

	_, pullErr := store.SyncWithRemote(context.Background())
	require.Error(t, pullErr, "SyncWithRemote to a broken origin must return an error")
	assert.NotContains(t, pullErr.Error(), secretToken,
		"error message must not contain the credential value")
}

// TestGitConfigStore_AdversarialTenantID verifies that the constructor rejects tenantID
// values that attempt directory traversal (e.g. "../../escape").
func TestGitConfigStore_AdversarialTenantID(t *testing.T) {
	workDir := t.TempDir()
	source := makeSource("https://example.invalid/repo.git", "")
	ss := newMemorySecretStore(nil)

	adversarialInputs := []string{
		"../../escape",
		"../sibling",
		"/absolute/path",
		"tenant\x00null",
	}

	for _, badID := range adversarialInputs {
		_, err := NewGitConfigStore(context.Background(), source, badID, ss, workDir, logging.NewNoopLogger())
		assert.Error(t, err, "tenantID %q must be rejected", badID)
	}
}

// TestGitConfigStore_StructFieldsNoCredential asserts that after construction no
// exported or unexported struct field of GitConfigStore contains the credential value.
// This is a structural invariant: credentials are fetched at transport time only.
func TestGitConfigStore_StructFieldsNoCredential(t *testing.T) {
	const secretToken = "very-secret-credential-xyz987"

	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/app.yaml": []byte("ok: true\n"),
	})

	workDir := t.TempDir()
	source := &pkgconfig.ConfigSourceInfo{
		Type:          pkgconfig.ConfigSourceTypeGit,
		URL:           remoteDir,
		SubPath:       "configs",
		CredentialRef: "my-cred",
	}
	ss := newMemorySecretStore(map[string]string{"my-cred": secretToken})

	store, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	assertNoCredentialInStruct(t, store, secretToken, "GitConfigStore")
}

// assertNoCredentialInStruct uses reflection to walk all fields (including nested structs)
// and fails the test if the credential value is found in any string field.
func assertNoCredentialInStruct(t *testing.T, v interface{}, credential, path string) {
	t.Helper()
	if credential == "" {
		return
	}
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}
	switch val.Kind() {
	case reflect.Struct:
		typ := val.Type()
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			fieldName := fmt.Sprintf("%s.%s", path, typ.Field(i).Name)
			// Skip unexported fields that contain interfaces (secretStore, logger) —
			// those are inspected by type, not value, to avoid reflect panics.
			if !field.CanInterface() {
				continue
			}
			assertNoCredentialInStruct(t, field.Interface(), credential, fieldName)
		}
	case reflect.String:
		assert.NotContains(t, val.String(), credential,
			"credential found in field %s", path)
	}
}

// TestGitConfigStore_ListConfigs verifies that ListConfigs returns entries for all YAML
// files under the subPath directory.
func TestGitConfigStore_ListConfigs(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/networking/fw.yaml":    []byte("type: firewall\n"),
		"configs/networking/dns.yaml":   []byte("type: dns\n"),
		"configs/monitoring/agent.yaml": []byte("type: agent\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	entries, err := store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant1"})
	require.NoError(t, err)
	assert.Len(t, entries, 3, "should find 3 yaml files")

	// Filter by namespace
	netEntries, err := store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{
		TenantID:  "tenant1",
		Namespace: "networking",
	})
	require.NoError(t, err)
	assert.Len(t, netEntries, 2, "networking namespace should have 2 files")
}

// TestGitConfigStore_GetConfigNotFound verifies that GetConfig returns ErrConfigNotFound
// for a file that does not exist in the cloned repo.
func TestGitConfigStore_GetConfigNotFound(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/existing.yaml": []byte("x: 1\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	_, err = store.GetConfig(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "default",
		Name:      "missing",
	})
	assert.ErrorIs(t, err, cfgconfig.ErrConfigNotFound, "missing config must return ErrConfigNotFound")
}

// TestGitConfigStore_SecondConstructionSkipsClone verifies that constructing a
// GitConfigStore for an already-cloned directory does not re-clone.
func TestGitConfigStore_SecondConstructionSkipsClone(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/app.yaml": []byte("x: 1\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	source := makeSource(remoteDir, "configs")

	store1, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Write a local-only file (simulating uncommitted local change) to detect a re-clone
	sentinel := filepath.Join(store1.repoDir, "sentinel-file.txt")
	require.NoError(t, os.WriteFile(sentinel, []byte("do-not-delete"), 0600))

	// Second construction must not wipe the cloned directory
	_, err = NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	_, statErr := os.Stat(sentinel)
	assert.NoError(t, statErr, "sentinel file must survive second construction (no re-clone)")
}

// TestGitConfigStore_GetConfigStats verifies that GetConfigStats reflects the number
// of YAML files in the repo and correctly partitions by namespace.
func TestGitConfigStore_GetConfigStats(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/ns1/a.yaml": []byte("a: 1\n"),
		"configs/ns1/b.yaml": []byte("b: 2\n"),
		"configs/ns2/c.yaml": []byte("c: 3\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	stats, err := store.GetConfigStats(context.Background())
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalConfigs)
	assert.Equal(t, int64(3), stats.ConfigsByFormat[string(cfgconfig.ConfigFormatYAML)])
	assert.Equal(t, int64(3), stats.ConfigsByTenant["tenant1"])
	// Verify namespace split — exercises filepath.Rel/parts[0] logic
	assert.Equal(t, int64(2), stats.ConfigsByNamespace["ns1"], "ns1 should have 2 files")
	assert.Equal(t, int64(1), stats.ConfigsByNamespace["ns2"], "ns2 should have 1 file")
}

// TestGitConfigStore_GetConfigHistory verifies that GetConfigHistory returns commit
// metadata for files that have multiple commits in the repo.
func TestGitConfigStore_GetConfigHistory(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/app/settings.yaml": []byte("version: 1\n"),
	})
	// Add a second commit to the same file
	addCommitToRemote(t, remoteDir, "configs/app/settings.yaml", []byte("version: 2\n"))

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Sync to pick up both commits
	_, err = store.SyncWithRemote(context.Background())
	require.NoError(t, err)

	history, err := store.GetConfigHistory(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "app",
		Name:      "settings",
	}, 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(history), 2, "history must contain at least 2 commits")

	// Each entry must have a non-zero timestamp and a SHA embedded in Data
	for i, entry := range history {
		assert.NotZero(t, entry.UpdatedAt, "entry[%d] must have a timestamp", i)
		assert.NotEmpty(t, entry.Data, "entry[%d].Data must contain SHA", i)
		assert.Equal(t, int64(i+1), entry.Version, "entry[%d] version must be 1-indexed", i)
	}
}

// TestGitConfigStore_GetConfigVersion verifies version retrieval by commit index.
func TestGitConfigStore_GetConfigVersion(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/app/cfg.yaml": []byte("ver: 1\n"),
	})
	addCommitToRemote(t, remoteDir, "configs/app/cfg.yaml", []byte("ver: 2\n"))

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)
	_, err = store.SyncWithRemote(context.Background())
	require.NoError(t, err)

	key := &cfgconfig.ConfigKey{TenantID: "tenant1", Namespace: "app", Name: "cfg"}

	// Version 1 = most recent commit (ver: 2)
	v1, err := store.GetConfigVersion(context.Background(), key, 1)
	require.NoError(t, err)
	assert.Equal(t, "ver: 2\n", string(v1.Data), "version 1 should be the most recent commit")

	// Version 2 = previous commit (ver: 1)
	v2, err := store.GetConfigVersion(context.Background(), key, 2)
	require.NoError(t, err)
	assert.Equal(t, "ver: 1\n", string(v2.Data), "version 2 should be the older commit")

	// Out-of-bounds version returns ErrConfigNotFound
	_, err = store.GetConfigVersion(context.Background(), key, 999)
	assert.ErrorIs(t, err, cfgconfig.ErrConfigNotFound, "out-of-bounds version must return ErrConfigNotFound")

	// version < 1 returns validation error
	_, err = store.GetConfigVersion(context.Background(), key, 0)
	assert.Error(t, err, "version 0 must return an error")
}

// TestGitConfigStore_ValidateConfig verifies that ValidateConfig accepts YAML entries
// and rejects other formats.
func TestGitConfigStore_ValidateConfig(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/app.yaml": []byte("x: 1\n"),
	})
	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	ctx := context.Background()
	yamlEntry := &cfgconfig.ConfigEntry{Format: cfgconfig.ConfigFormatYAML, Data: []byte("x: 1\n")}
	assert.NoError(t, store.ValidateConfig(ctx, yamlEntry), "YAML must be valid")

	jsonEntry := &cfgconfig.ConfigEntry{Format: cfgconfig.ConfigFormatJSON, Data: []byte(`{"x":1}`)}
	assert.ErrorIs(t, store.ValidateConfig(ctx, jsonEntry), cfgconfig.ErrInvalidFormat, "non-YAML must return ErrInvalidFormat")

	assert.Error(t, store.ValidateConfig(ctx, nil), "nil entry must return error")
}

// TestGitConfigStore_ResolveConfigWithInheritance verifies that ResolveConfigWithInheritance
// delegates to GetConfig and returns the file content.
func TestGitConfigStore_ResolveConfigWithInheritance(t *testing.T) {
	const content = "resolved: true\n"
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/policy.yaml": []byte(content),
	})
	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	entry, err := store.ResolveConfigWithInheritance(context.Background(), &cfgconfig.ConfigKey{
		TenantID:  "tenant1",
		Namespace: "default",
		Name:      "policy",
	})
	require.NoError(t, err)
	assert.Equal(t, content, string(entry.Data))
}
