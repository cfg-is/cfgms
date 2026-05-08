// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestMRM creates a ModuleRepositoryManager with an isolated cache directory under
// t.TempDir(). gitManager and store are nil because the methods under test
// (ensureModuleRepository, scanForModuleSpecs, loadModule, writeModuleSpec) do not
// invoke those interfaces.
func newTestMRM(t *testing.T) *ModuleRepositoryManager {
	t.Helper()
	mrm := NewModuleRepositoryManager(nil, nil, logging.NewNoopLogger())
	mrm.cacheDir = t.TempDir()
	return mrm
}

func initBareRepo(t *testing.T) string {
	t.Helper()
	barePath := t.TempDir()
	cmd := exec.Command("git", "init", "--bare", barePath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "failed to init bare repo: %s", string(out))
	return barePath
}

func TestEnsureModuleRepository_ClonesWhenMissing(t *testing.T) {
	barePath := initBareRepo(t)
	mrm := newTestMRM(t)
	repo := &Repository{
		ID:       "mod-a",
		CloneURL: "file://" + barePath,
	}

	clonePath, err := mrm.ensureModuleRepository(context.Background(), repo)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(mrm.cacheDir, "mod-a"), clonePath)

	// .git directory must exist in the cloned path
	_, statErr := os.Stat(filepath.Join(clonePath, ".git"))
	assert.NoError(t, statErr, ".git directory should exist after clone")
}

func TestEnsureModuleRepository_RejectsTraversalID(t *testing.T) {
	mrm := newTestMRM(t)
	for _, id := range []string{"../escape", "foo/bar", "foo\\bar", "a..b"} {
		repo := &Repository{ID: id, CloneURL: "file:///irrelevant"}
		_, err := mrm.ensureModuleRepository(context.Background(), repo)
		require.Error(t, err, "expected error for id %q", id)
		assert.Contains(t, err.Error(), "invalid repository ID", "id=%q", id)
	}
}

func TestEnsureModuleRepository_SkipsWhenPresent(t *testing.T) {
	barePath := initBareRepo(t)
	mrm := newTestMRM(t)
	repo := &Repository{
		ID:       "mod-b",
		CloneURL: "file://" + barePath,
	}

	// First call clones
	path1, err := mrm.ensureModuleRepository(context.Background(), repo)
	require.NoError(t, err)

	// Second call is idempotent — returns the same path without re-cloning
	path2, err := mrm.ensureModuleRepository(context.Background(), repo)
	require.NoError(t, err)
	assert.Equal(t, path1, path2)
}

func TestScanForModuleSpecs_FindsYAML(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "modules", "mod-a"), 0750))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "modules", "mod-b"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "modules", "mod-a", "module.yaml"), []byte("name: a"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "modules", "mod-b", "module.yaml"), []byte("name: b"), 0600))
	// A file that must NOT be returned
	require.NoError(t, os.WriteFile(filepath.Join(root, "modules", "mod-a", "other.yaml"), []byte("other"), 0600))

	mrm := newTestMRM(t)
	specs, err := mrm.scanForModuleSpecs(context.Background(), root)
	require.NoError(t, err)

	assert.Len(t, specs, 2)
	for _, spec := range specs {
		assert.Equal(t, "module.yaml", filepath.Base(spec), "each result must be a module.yaml path")
	}
}

func TestScanForModuleSpecs_EmptyDirectory(t *testing.T) {
	root := t.TempDir()
	mrm := newTestMRM(t)

	specs, err := mrm.scanForModuleSpecs(context.Background(), root)
	require.NoError(t, err)
	assert.Empty(t, specs)
}

func TestLoadModule_ValidYAML(t *testing.T) {
	root := t.TempDir()
	modDir := filepath.Join(root, "modules", "my-module")
	require.NoError(t, os.MkdirAll(modDir, 0750))

	specContent := []byte(`metadata:
  name: my-module
  version: 2.0.0
  description: Test module
  author: test-author
`)
	require.NoError(t, os.WriteFile(filepath.Join(modDir, "module.yaml"), specContent, 0600))

	mrm := newTestMRM(t)
	repo := &Repository{ID: "test-repo"}

	module, err := mrm.loadModule(context.Background(), repo, root, filepath.Join("modules", "my-module", "module.yaml"))
	require.NoError(t, err)

	assert.Equal(t, "my-module", module.Name)
	assert.Equal(t, "2.0.0", module.Version)
	assert.Equal(t, "Test module", module.Description)
	assert.Equal(t, "test-repo", module.Repository)
	assert.Equal(t, SecurityStatusPending, module.SecurityStatus.Status)
	assert.Equal(t, AccessLevelReadOnly, module.AccessLevel)
}

func TestLoadModule_MissingFile(t *testing.T) {
	root := t.TempDir()
	mrm := newTestMRM(t)
	repo := &Repository{ID: "test-repo"}

	_, err := mrm.loadModule(context.Background(), repo, root, "nonexistent/module.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read module spec")
}

func TestLoadModule_InvalidYAML(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "bad"), 0750))
	// A sequence where a struct is expected causes a YAML decode error
	require.NoError(t, os.WriteFile(filepath.Join(root, "bad", "module.yaml"),
		[]byte("metadata:\n  - this_is_a_list\n"), 0600))

	mrm := newTestMRM(t)
	repo := &Repository{ID: "test-repo"}

	_, err := mrm.loadModule(context.Background(), repo, root, "bad/module.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse module spec")
}

func TestWriteModuleSpec_RoundTrip(t *testing.T) {
	root := t.TempDir()
	original := &CustomModule{
		Name:       "round-trip-module",
		Version:    "1.0.0",
		Repository: "test-repo",
		Path:       filepath.Join("modules", "round-trip"),
		Spec: ModuleSpec{
			Metadata: ModuleMetadata{
				Name:    "round-trip-module",
				Version: "1.0.0",
				Author:  "tester",
			},
		},
		AccessLevel: AccessLevelReadOnly,
	}

	mrm := newTestMRM(t)
	repo := &Repository{ID: "test-repo"}

	specPath := filepath.Join("modules", "round-trip", "module.yaml")
	require.NoError(t, mrm.writeModuleSpec(context.Background(), root, specPath, original))

	// Read back via loadModule to verify the round-trip
	loaded, err := mrm.loadModule(context.Background(), repo, root, specPath)
	require.NoError(t, err)

	assert.Equal(t, "round-trip-module", loaded.Name)
	assert.Equal(t, "1.0.0", loaded.Version)
	assert.Equal(t, "tester", loaded.Spec.Metadata.Author)
}

func TestWriteModuleSpec_WriteError(t *testing.T) {
	// Place a regular file at a path where MkdirAll needs a directory. This blocks
	// directory creation on all OSes (including Windows, where chmod 0500 is not enforced).
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte(""), 0600))

	mrm := newTestMRM(t)
	module := &CustomModule{
		Spec: ModuleSpec{Metadata: ModuleMetadata{Name: "test"}},
	}

	// specPath descends through "blocker" (a file), so MkdirAll must fail.
	err := mrm.writeModuleSpec(context.Background(), root, filepath.Join("blocker", "sub", "module.yaml"), module)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create directory")
}
