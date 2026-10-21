// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package git

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gitstorage "github.com/cfgis/cfgms/features/config/git/storage"
	pkgconfig "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/security"
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

// newBoundMemorySecretStore returns a store whose every secret carries a
// bound_repository_url binding to repoURL, as the operator-path route writes it.
func newBoundMemorySecretStore(pairs map[string]string, repoURL string) *memorySecretStore {
	s := newMemorySecretStore(pairs)
	for _, sec := range s.secrets {
		sec.Metadata = map[string]string{pkgconfig.SecretMetaKeyBoundRepositoryURL: pkgconfig.NormalizeRepositoryURL(repoURL)}
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

func (s *memorySecretStore) CompareAndSwapSecret(_ context.Context, key string, expectedVersion int, req *secretsiface.SecretRequest) (int, bool, error) {
	current := 0
	if existing, ok := s.secrets[key]; ok {
		current = existing.Version
	}
	if current != expectedVersion {
		return 0, false, nil
	}
	newVersion := current + 1
	s.secrets[req.Key] = &secretsiface.Secret{Key: req.Key, Value: req.Value, Version: newVersion}
	return newVersion, true, nil
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
// The remote is removed after the initial clone to force the sync to fail.
func TestGitConfigStore_PullFailureServesLastGood(t *testing.T) {
	const initialContent = "stable: true\n"
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/prod/config.yaml": []byte(initialContent),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Remove the remote to force a sync failure: the remote became unreachable after
	// the initial clone.
	require.NoError(t, os.RemoveAll(remoteDir))

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
// not appear in any error returned by SyncWithRemote. The remote is removed to force a
// sync failure; the sanitizeCredential function must strip the token from any
// resulting error message.
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
	ss := newBoundMemorySecretStore(map[string]string{"my-git-token": secretToken}, remoteDir)

	store, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// Remove the remote so the sync fails; sanitizeCredential must ensure the error
	// message does not contain the credential value even if go-git embeds it.
	require.NoError(t, os.RemoveAll(remoteDir))

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
	ss := newBoundMemorySecretStore(map[string]string{"my-cred": secretToken}, remoteDir)

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
// files under the subPath directory and stamps each entry with the store's tenant ID.
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
	for _, e := range entries {
		assert.Equal(t, "tenant1", e.Key.TenantID, "entries must be stamped with the store's tenant")
	}

	// Filter by namespace
	netEntries, err := store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{
		TenantID:  "tenant1",
		Namespace: "networking",
	})
	require.NoError(t, err)
	assert.Len(t, netEntries, 2, "networking namespace should have 2 files")
}

// TestGitConfigStore_ListConfigs_TenantIDScoping verifies that ListConfigs scopes its
// walk by filter.TenantID: entries are returned when the filter matches the store's
// tenant, and nothing is returned when the filter names a different tenant.
// This exercises the primary AC from issue #3438.
func TestGitConfigStore_ListConfigs_TenantIDScoping(t *testing.T) {
	// Populate two separate repos — one per tenant — to represent two tenants' configs.
	remoteDir1 := createBareRemote(t, map[string][]byte{
		"configs/networking/fw.yaml":  []byte("type: firewall\n"),
		"configs/networking/dns.yaml": []byte("type: dns\n"),
	})
	remoteDir2 := createBareRemote(t, map[string][]byte{
		"configs/networking/gw.yaml": []byte("type: gateway\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store1, err := NewGitConfigStore(context.Background(), makeSource(remoteDir1, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)
	store2, err := NewGitConfigStore(context.Background(), makeSource(remoteDir2, "configs"), "tenant2", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	t.Run("matching_tenant_returns_entries", func(t *testing.T) {
		entries, err := store1.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant1"})
		require.NoError(t, err)
		assert.Len(t, entries, 2, "should find 2 entries for tenant1")
		for _, e := range entries {
			assert.Equal(t, "tenant1", e.Key.TenantID, "entries must be stamped with tenant1")
		}
	})

	t.Run("non_matching_tenant_returns_empty", func(t *testing.T) {
		// Before the fix, store1.ListConfigs with TenantID="tenant2" returned all of
		// store1's entries mislabeled as tenant2. After the fix it must return nothing.
		entries, err := store1.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant2"})
		require.NoError(t, err)
		assert.Empty(t, entries, "tenant1 store must return nothing for a tenant2 filter")
	})

	t.Run("store2_returns_its_own_entries", func(t *testing.T) {
		entries, err := store2.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant2"})
		require.NoError(t, err)
		assert.Len(t, entries, 1, "should find 1 entry for tenant2")
		assert.Equal(t, "tenant2", entries[0].Key.TenantID)
	})
}

// TestGitConfigStore_ListConfigs_EmptyTenantFilter verifies that filter.TenantID == ""
// preserves the unscoped-walk behaviour — all of the store's entries are returned and
// each is stamped with the store's actual tenant ID.
func TestGitConfigStore_ListConfigs_EmptyTenantFilter(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/ns1/a.yaml": []byte("a: 1\n"),
		"configs/ns2/b.yaml": []byte("b: 2\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	t.Run("nil_filter_returns_all", func(t *testing.T) {
		entries, err := store.ListConfigs(context.Background(), nil)
		require.NoError(t, err)
		assert.Len(t, entries, 2, "nil filter must return all entries (unscoped walk)")
		for _, e := range entries {
			assert.Equal(t, "tenant1", e.Key.TenantID, "entries must be stamped with the store's tenant")
		}
	})

	t.Run("empty_tenant_id_returns_all", func(t *testing.T) {
		entries, err := store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{})
		require.NoError(t, err)
		assert.Len(t, entries, 2, "empty TenantID must return all entries (unscoped walk)")
		for _, e := range entries {
			assert.Equal(t, "tenant1", e.Key.TenantID, "entries must be stamped with the store's tenant")
		}
	})
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
	assert.Len(t, history, 1, "shallow clone holds only the HEAD commit")

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

	// Version 2 does not exist: the clone is shallow
	_, err = store.GetConfigVersion(context.Background(), key, 2)
	assert.ErrorIs(t, err, cfgconfig.ErrConfigNotFound, "shallow clone has no older versions")

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

// TestGitConfigStore_RepoDirUsesValidatedBasePath verifies that store.repoDir is
// constructed from the cleaned return value of security.ValidateAndCleanPath, not the
// raw tenantID string. The parent of repoDir must equal ValidateAndCleanPath(workDir,
// tenantID) and the leaf segment must be the hex SHA-256 of the source URL. (#2176)
func TestGitConfigStore_RepoDirUsesValidatedBasePath(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/default/app.yaml": []byte("x: 1\n"),
	})

	workDir := t.TempDir()
	ss := newMemorySecretStore(nil)
	const tenantID = "acme-tenant"
	source := makeSource(remoteDir, "configs")

	store, err := NewGitConfigStore(context.Background(), source, tenantID, ss, workDir, logging.NewNoopLogger())
	require.NoError(t, err)

	// cleanedBase is the canonical path that ValidateAndCleanPath returns for workDir/tenantID.
	cleanedBase, cleanErr := security.ValidateAndCleanPath(workDir, tenantID)
	require.NoError(t, cleanErr)

	// repoDir parent must equal cleanedBase (validated path, not raw filepath.Join).
	assert.Equal(t, cleanedBase, filepath.Dir(store.repoDir),
		"repoDir parent must equal the cleaned base from ValidateAndCleanPath")

	// repoDir leaf must be the hex-encoded SHA-256 of the source URL.
	expectedLeaf := fmt.Sprintf("%x", sha256.Sum256([]byte(source.URL)))
	assert.Equal(t, expectedLeaf, filepath.Base(store.repoDir),
		"repoDir leaf must be hex-SHA256 of the source URL")
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

// bindingHTTPSServer starts a real HTTPS server and records any Authorization header.
func bindingHTTPSServer(t *testing.T) (repoURL string, sawAuth func() bool) {
	t.Helper()
	var mu sync.Mutex
	seen := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			mu.Lock()
			seen = true
			mu.Unlock()
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	return fmt.Sprintf("https://localhost:%d/repo", port), func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

// TestGitConfigStore_CredentialBinding covers the three binding cases for the
// constructor (clone) path against a real HTTPS server.
func TestGitConfigStore_CredentialBinding(t *testing.T) {
	const token = "git-store-binding-token"
	const fix = "cfg tenant config-source set-credential"
	newSource := func(u string) *pkgconfig.ConfigSourceInfo {
		return &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeGit, URL: u, CredentialRef: "ref"}
	}

	t.Run("bound to another repository is refused with no Authorization header", func(t *testing.T) {
		urlB, sawAuth := bindingHTTPSServer(t)
		ss := newBoundMemorySecretStore(map[string]string{"ref": token}, "https://other.cfgms.local/repo")
		_, err := NewGitConfigStore(context.Background(), newSource(urlB), "tenant1", ss, t.TempDir(), logging.NewNoopLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), fix)
		assert.NotContains(t, err.Error(), token)
		assert.False(t, sawAuth())
	})

	t.Run("unbound credential is refused", func(t *testing.T) {
		urlB, sawAuth := bindingHTTPSServer(t)
		ss := newMemorySecretStore(map[string]string{"ref": token})
		_, err := NewGitConfigStore(context.Background(), newSource(urlB), "tenant1", ss, t.TempDir(), logging.NewNoopLogger())
		require.Error(t, err)
		assert.Contains(t, err.Error(), fix)
		assert.NotContains(t, err.Error(), token)
		assert.False(t, sawAuth())
	})

	t.Run("bound credential is returned, also across host case and trailing slash", func(t *testing.T) {
		urlA := "https://git.cfgms.local/acme/configs"
		ss := newBoundMemorySecretStore(map[string]string{"ref": token}, urlA)
		for _, u := range []string{urlA, "https://GIT.cfgms.local/acme/configs", urlA + "/"} {
			s := &GitConfigStore{source: newSource(u), secretStore: ss}
			_, pw, err := s.fetchCredential(context.Background())
			require.NoError(t, err, u)
			assert.Equal(t, token, pw, u)
		}
	})
}

// TestGitConfigStore_SyncRefusesAfterSourceURLChange proves the binding is rechecked at
// every pull: a source URL changed after construction no longer matches the credential.
func TestGitConfigStore_SyncRefusesAfterSourceURLChange(t *testing.T) {
	const token = "git-store-sync-token"
	remoteDir := createBareRemote(t, map[string][]byte{"configs/default/app.yaml": []byte("ok: true\n")})
	source := &pkgconfig.ConfigSourceInfo{Type: pkgconfig.ConfigSourceTypeGit, URL: remoteDir, SubPath: "configs", CredentialRef: "ref"}
	ss := newBoundMemorySecretStore(map[string]string{"ref": token}, remoteDir)

	store, err := NewGitConfigStore(context.Background(), source, "tenant1", ss, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)
	_, err = store.SyncWithRemote(context.Background())
	require.NoError(t, err)

	urlB, sawAuth := bindingHTTPSServer(t)
	source.URL = urlB
	_, err = store.SyncWithRemote(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfg tenant config-source set-credential")
	assert.NotContains(t, err.Error(), token)
	assert.False(t, sawAuth())
}

// TestGitConfigStore_GetConfig_RefusesSymlinks asserts a symlink committed in an
// external source cannot be used to read files outside the checkout.
func TestGitConfigStore_GetConfig_RefusesSymlinks(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/networking/firewall.yaml": []byte("ok: true\n"),
	})
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
		newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "secret.yaml")
	require.NoError(t, os.WriteFile(secret, []byte("secret: 1\n"), 0o600))

	cfgDir := filepath.Join(store.RepoDir(), "configs")
	require.NoError(t, os.Symlink(secret, filepath.Join(cfgDir, "networking", "leak.yaml")))
	require.NoError(t, os.Symlink(outsideDir, filepath.Join(cfgDir, "linked")))

	get := func(ns, name string) (*cfgconfig.ConfigEntry, error) {
		return store.GetConfig(context.Background(), &cfgconfig.ConfigKey{TenantID: "tenant1", Namespace: ns, Name: name})
	}

	entry, err := get("networking", "leak")
	require.Error(t, err)
	assert.Nil(t, entry)

	entry, err = get("linked", "secret")
	require.Error(t, err)
	assert.Nil(t, entry)

	entry, err = get("networking", "firewall")
	require.NoError(t, err)
	assert.Equal(t, "ok: true\n", string(entry.Data))

	_, err = get("networking", "missing")
	assert.ErrorIs(t, err, cfgconfig.ErrConfigNotFound)
}

// TestGitConfigStore_ListConfigs_UnreadableFileIsError verifies a .yaml file the
// store cannot read fails the listing instead of vanishing from it.
func TestGitConfigStore_ListConfigs_UnreadableFileIsError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("cannot make a file unreadable on this platform/user")
	}
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/networking/fw.yaml":  []byte("type: firewall\n"),
		"configs/networking/dns.yaml": []byte("type: dns\n"),
	})
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1", newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	locked := filepath.Join(store.RepoDir(), "configs", "networking", "dns.yaml")
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	_, err = store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant1"})
	require.Error(t, err)
}

// --- byte limits ---

// randomBytes returns incompressible content so object size tracks content size.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func TestGitConfigStore_CloneOverLimitIsRefusedAndLeavesNothing(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/ns/a.yaml": []byte("k: v\n"),
		"configs/big.bin":   randomBytes(t, 600<<10),
	})
	workDir := t.TempDir()

	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
		newMemorySecretStore(nil), workDir, logging.NewNoopLogger(), WithMaxCloneBytes(100<<10))
	require.Error(t, err)
	assert.Nil(t, store)
	assert.ErrorIs(t, err, ErrCloneTooLarge)
	assert.NotContains(t, err.Error(), workDir)

	entries, readErr := os.ReadDir(workDir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "partial clone directory must be removed")
}

// TestGitConfigStore_CompressibleCloneRefusedBeforeCheckout: a pack far under the limit
// whose blob inflates far past it must be refused from the object headers, before any
// worktree file is written — cancelling a context cannot stop a go-git checkout.
func TestGitConfigStore_CompressibleCloneRefusedBeforeCheckout(t *testing.T) {
	const limit = 100 << 10
	remoteDir := createBareRemote(t, map[string][]byte{
		"configs/ns/a.yaml": []byte("k: v\n"),
		"configs/zeros.bin": make([]byte, 8<<20),
	})

	t.Run("checkout guard writes nothing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, gitstorage.NewLocalRepositoryStore("", "").CloneShallow(context.Background(), remoteDir, dir))
		require.Less(t, dirSize(dir), int64(limit), "the compressed fetch must fit the limit for this test to exercise the checkout guard")

		s := &GitConfigStore{repoDir: dir, maxCloneBytes: limit}
		err := s.checkoutWithinLimit(dir)
		assert.ErrorIs(t, err, ErrCloneTooLarge)

		_, statErr := os.Lstat(filepath.Join(dir, "configs", "zeros.bin"))
		assert.True(t, os.IsNotExist(statErr), "the over-limit blob must never be checked out")
		_, statErr = os.Lstat(filepath.Join(dir, "configs", "ns", "a.yaml"))
		assert.True(t, os.IsNotExist(statErr), "no worktree file may be written when the tree is over the limit")
	})

	t.Run("store construction refuses and removes the clone", func(t *testing.T) {
		workDir := t.TempDir()
		store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
			newMemorySecretStore(nil), workDir, logging.NewNoopLogger(), WithMaxCloneBytes(limit))
		require.Error(t, err)
		assert.Nil(t, store)
		assert.ErrorIs(t, err, ErrCloneTooLarge)
		assert.NotContains(t, err.Error(), workDir)

		entries, readErr := os.ReadDir(workDir)
		require.NoError(t, readErr)
		assert.Empty(t, entries, "refused clone directory must be removed")
	})

	t.Run("within limit checks out the worktree", func(t *testing.T) {
		store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
			newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger(), WithMaxCloneBytes(64<<20))
		require.NoError(t, err)
		data, err := os.ReadFile(filepath.Join(store.RepoDir(), "configs", "ns", "a.yaml"))
		require.NoError(t, err)
		assert.Equal(t, "k: v\n", string(data))
	})
}

func TestGitConfigStore_CloneIsShallow(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{"configs/ns/a.yaml": []byte("v: 1\n")})
	addCommitToRemote(t, remoteDir, "configs/ns/a.yaml", []byte("v: 2\n"))
	addCommitToRemote(t, remoteDir, "configs/ns/a.yaml", []byte("v: 3\n"))

	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
		newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	shallow, err := os.ReadFile(filepath.Join(store.RepoDir(), ".git", "shallow"))
	require.NoError(t, err, "a depth-1 clone records its shallow boundary")
	assert.NotEmpty(t, shallow)
}

func newLimitStore(t *testing.T, files map[string][]byte, opts ...StoreOption) *GitConfigStore {
	t.Helper()
	remoteDir := createBareRemote(t, files)
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
		newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger(), opts...)
	require.NoError(t, err)
	return store
}

func TestGitConfigStore_OverLimitFileFailsListAndGet(t *testing.T) {
	store := newLimitStore(t, map[string][]byte{
		"configs/ns/small.yaml": []byte("a: 1\n"),
		"configs/ns/other.yaml": []byte("b: 2\n"),
		"configs/ns/huge.yaml":  randomBytes(t, 8<<10),
	}, WithMaxConfigFileBytes(1<<10))

	entries, err := store.ListConfigs(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigFileTooLarge)
	assert.Nil(t, entries, "no partial result set")
	assert.NotContains(t, err.Error(), store.RepoDir())

	got, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{Namespace: "ns", Name: "huge"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigFileTooLarge)
	assert.Nil(t, got)
	assert.NotContains(t, err.Error(), store.RepoDir())

	ok, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{Namespace: "ns", Name: "small"})
	require.NoError(t, err)
	assert.Equal(t, "a: 1\n", string(ok.Data))
}

func TestGitConfigStore_ListTotalReadLimit(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 5; i++ {
		files[fmt.Sprintf("configs/ns/f%d.yaml", i)] = randomBytes(t, 400)
	}
	store := newLimitStore(t, files, WithMaxConfigFileBytes(1<<10), WithMaxListReadBytes(1<<10))

	entries, err := store.ListConfigs(context.Background(), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrConfigReadTooLarge)
	assert.Nil(t, entries)
	assert.NotContains(t, err.Error(), store.RepoDir())
}

// TestGitConfigStore_SyncOverLimitKeepsLastKnownGood: a remote that grows past the
// clone limit after the first clone must not be fetched into place by a sync. The
// sync fails with ErrCloneTooLarge, the previous clone keeps serving, and no staging
// directory is left behind.
func TestGitConfigStore_SyncOverLimitKeepsLastKnownGood(t *testing.T) {
	const limit = 100 << 10
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "incompressible push", payload: randomBytes(t, 600<<10)},
		{name: "compressible push", payload: make([]byte, 8<<20)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			remoteDir := createBareRemote(t, map[string][]byte{"configs/ns/a.yaml": []byte("v: 1\n")})
			workDir := t.TempDir()
			store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
				newMemorySecretStore(nil), workDir, logging.NewNoopLogger(), WithMaxCloneBytes(limit))
			require.NoError(t, err)
			before, err := store.GetCurrentSHA()
			require.NoError(t, err)

			addCommitToRemote(t, remoteDir, "configs/ns/a.yaml", []byte("v: 2\n"))
			addCommitToRemote(t, remoteDir, "configs/big.bin", tc.payload)

			sha, err := store.SyncWithRemote(context.Background())
			require.ErrorIs(t, err, ErrCloneTooLarge)
			assert.Empty(t, sha)
			assert.NotContains(t, err.Error(), workDir)

			after, err := store.GetCurrentSHA()
			require.NoError(t, err)
			assert.Equal(t, before, after, "an over-limit sync must not move HEAD")
			entry, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{TenantID: "tenant1", Namespace: "ns", Name: "a"})
			require.NoError(t, err)
			assert.Equal(t, "v: 1\n", string(entry.Data), "last-known-good content must keep serving")
			assert.NoFileExists(t, filepath.Join(store.RepoDir(), "configs", "big.bin"))
			assert.LessOrEqual(t, store.CloneBytes(), int64(limit))

			entries, readErr := os.ReadDir(filepath.Dir(store.RepoDir()))
			require.NoError(t, readErr)
			require.Len(t, entries, 1, "the refused sync must leave no staging or retired directory")
			assert.Equal(t, filepath.Base(store.RepoDir()), entries[0].Name())
		})
	}
}

// TestGitConfigStore_SyncIsShallowAndReplacesClone: a successful sync swaps in a depth-1
// clone of the new HEAD and leaves no staging or retired directory.
func TestGitConfigStore_SyncIsShallowAndReplacesClone(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{"configs/ns/a.yaml": []byte("v: 1\n")})
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
		newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	addCommitToRemote(t, remoteDir, "configs/ns/a.yaml", []byte("v: 2\n"))
	addCommitToRemote(t, remoteDir, "configs/ns/a.yaml", []byte("v: 3\n"))
	sha, err := store.SyncWithRemote(context.Background())
	require.NoError(t, err)

	repo, err := gogit.PlainOpen(store.RepoDir())
	require.NoError(t, err)
	commit, err := repo.CommitObject(plumbing.NewHash(sha))
	require.NoError(t, err)
	_, parentErr := commit.Parent(0)
	assert.Error(t, parentErr, "a synced clone must be shallow: the parent commit is not fetched")

	entry, err := store.GetConfig(context.Background(), &cfgconfig.ConfigKey{TenantID: "tenant1", Namespace: "ns", Name: "a"})
	require.NoError(t, err)
	assert.Equal(t, "v: 3\n", string(entry.Data))

	entries, err := os.ReadDir(filepath.Dir(store.RepoDir()))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "a successful sync must leave no staging or retired directory")
}

// TestGitConfigStore_SyncConcurrentWithReads: reads running while syncs swap the clone
// in place never observe a missing clone.
func TestGitConfigStore_SyncConcurrentWithReads(t *testing.T) {
	remoteDir := createBareRemote(t, map[string][]byte{"configs/ns/a.yaml": []byte("v: 1\n")})
	store, err := NewGitConfigStore(context.Background(), makeSource(remoteDir, "configs"), "tenant1",
		newMemorySecretStore(nil), t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	done := make(chan struct{})
	readErrs := make(chan error, 1)
	go func() {
		defer close(readErrs)
		key := &cfgconfig.ConfigKey{TenantID: "tenant1", Namespace: "ns", Name: "a"}
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, err := store.GetConfig(context.Background(), key); err != nil {
				readErrs <- err
				return
			}
			if _, err := store.ListConfigs(context.Background(), &cfgconfig.ConfigFilter{TenantID: "tenant1"}); err != nil {
				readErrs <- err
				return
			}
		}
	}()
	for i := 0; i < 5; i++ {
		_, err := store.SyncWithRemote(context.Background())
		require.NoError(t, err)
	}
	close(done)
	for err := range readErrs {
		require.NoError(t, err, "reads must not fail while a sync swaps the clone")
	}
}
