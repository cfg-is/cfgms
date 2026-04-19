// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package flatfile_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	// blank import triggers init() registration
	_ "github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

func TestProviderRegistration(t *testing.T) {
	names := interfaces.GetRegisteredProviderNames()
	found := false
	for _, n := range names {
		if n == "flatfile" {
			found = true
			break
		}
	}
	assert.True(t, found, "flatfile provider must be registered after blank import")
}

func TestGetStorageProviderSucceeds(t *testing.T) {
	// GetStorageProvider calls Available() internally; flatfile is always available.
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	assert.Equal(t, "flatfile", p.Name())
}

func TestProviderAvailable(t *testing.T) {
	names := interfaces.GetRegisteredProviderNames()
	var p interfaces.StorageProvider
	for _, n := range names {
		if n == "flatfile" {
			pp, err := interfaces.GetStorageProvider("flatfile")
			require.NoError(t, err)
			p = pp
			break
		}
	}
	require.NotNil(t, p)

	ok, err := p.Available()
	assert.True(t, ok)
	assert.NoError(t, err)
}

func TestProviderCapabilities(t *testing.T) {
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)

	caps := p.GetCapabilities()
	assert.False(t, caps.SupportsVersioning, "flat-file must not claim versioning support")
	assert.False(t, caps.SupportsTransactions)
	assert.Greater(t, caps.MaxBatchSize, 0)
	assert.Greater(t, caps.MaxConfigSize, 0)
}

func TestProviderVersion(t *testing.T) {
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	assert.NotEmpty(t, p.GetVersion())
}

func TestProviderDescription(t *testing.T) {
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)
	assert.NotEmpty(t, p.Description())
}

func TestUnsupportedStoresReturnErrNotSupported(t *testing.T) {
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)

	cfg := map[string]interface{}{}

	t.Run("CreateClientTenantStore", func(t *testing.T) {
		store, err := p.CreateClientTenantStore(cfg)
		assert.Nil(t, store)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("CreateRBACStore", func(t *testing.T) {
		store, err := p.CreateRBACStore(cfg)
		assert.Nil(t, store)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("CreateTenantStore", func(t *testing.T) {
		store, err := p.CreateTenantStore(cfg)
		assert.Nil(t, store)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("CreateRegistrationTokenStore", func(t *testing.T) {
		store, err := p.CreateRegistrationTokenStore(cfg)
		assert.Nil(t, store)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("CreateCommandStore", func(t *testing.T) {
		store, err := p.CreateCommandStore(cfg)
		assert.Nil(t, store)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}

func TestCreateConfigStoreRequiresRoot(t *testing.T) {
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)

	store, err := p.CreateConfigStore(map[string]interface{}{})
	assert.Nil(t, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestCreateAuditStoreRequiresRoot(t *testing.T) {
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)

	store, err := p.CreateAuditStore(map[string]interface{}{})
	assert.Nil(t, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestCreateConfigStoreWithRoot(t *testing.T) {
	root := t.TempDir()
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)

	store, err := p.CreateConfigStore(map[string]interface{}{"root": root})
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestCreateAuditStoreWithRoot(t *testing.T) {
	root := t.TempDir()
	p, err := interfaces.GetStorageProvider("flatfile")
	require.NoError(t, err)

	store, err := p.CreateAuditStore(map[string]interface{}{"root": root})
	require.NoError(t, err)
	assert.NotNil(t, store)
}
