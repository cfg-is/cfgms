// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package script

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func seedTenantScript(t *testing.T, repo *TenantScriptRepository, tenantID, id string) {
	t.Helper()
	gr, err := repo.ForTenant(tenantID)
	require.NoError(t, err)
	require.NoError(t, gr.Create(&VersionedScript{
		Metadata: &ScriptMetadata{
			ID:       id,
			Name:     id,
			Version:  &Version{Major: 1},
			Shell:    ShellBash,
			Platform: []string{"linux"},
		},
		Content: "echo " + id + "\n",
		Signature: &ScriptSignature{
			Algorithm: "rsa-sha256",
			Signature: "c2ln",
			PublicKey: "pem",
		},
	}))
}

func TestTenantScriptRepository_CrossTenantIsolation(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)

	seedTenantScript(t, repo, "tenant-a", "only-a")

	got, err := repo.GetForTenant("tenant-a", "only-a", "")
	require.NoError(t, err)
	assert.Equal(t, "only-a", got.Metadata.ID)
	require.NotNil(t, got.Signature, "the signature must round-trip through storage")
	assert.Equal(t, "rsa-sha256", got.Signature.Algorithm)

	_, err = repo.GetForTenant("tenant-b", "only-a", "")
	assert.Error(t, err, "tenant B must not resolve tenant A's script")

	listB, err := repo.ListForTenant("tenant-b", nil)
	require.NoError(t, err)
	assert.Empty(t, listB)

	listA, err := repo.ListForTenant("tenant-a", nil)
	require.NoError(t, err)
	assert.Len(t, listA, 1)

	_, err = repo.GetForTenant("", "only-a", "")
	assert.ErrorIs(t, err, ErrTenantRequired)
	_, err = repo.ListForTenant("", nil)
	assert.ErrorIs(t, err, ErrTenantRequired)
	_, err = repo.ForTenant("")
	assert.ErrorIs(t, err, ErrTenantRequired)
}

func TestTenantScriptRepository_TenantlessMethodsFailClosed(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)

	_, err = repo.Get("x", "")
	assert.ErrorIs(t, err, ErrTenantRequired)
	_, err = repo.List(nil)
	assert.ErrorIs(t, err, ErrTenantRequired)
	assert.ErrorIs(t, repo.Create(&VersionedScript{}), ErrTenantRequired)
	assert.ErrorIs(t, repo.Update(&VersionedScript{}), ErrTenantRequired)
	assert.ErrorIs(t, repo.Delete("x", ""), ErrTenantRequired)
	assert.ErrorIs(t, repo.Rollback("x", "1.0.0"), ErrTenantRequired)
	_, err = repo.ListVersions("x")
	assert.ErrorIs(t, err, ErrTenantRequired)
	_, err = repo.GetLatestVersion("x")
	assert.ErrorIs(t, err, ErrTenantRequired)
}

func TestTenantScriptRepository_CachesPerTenant(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	repo, err := NewTenantScriptRepository(sm.GetConfigStore())
	require.NoError(t, err)

	a1, err := repo.ForTenant("tenant-a")
	require.NoError(t, err)
	a2, err := repo.ForTenant("tenant-a")
	require.NoError(t, err)
	b, err := repo.ForTenant("tenant-b")
	require.NoError(t, err)
	assert.Same(t, a1, a2)
	assert.NotSame(t, a1, b)

	_, err = NewTenantScriptRepository(nil)
	assert.Error(t, err)
}
