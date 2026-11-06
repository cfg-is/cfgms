// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newBareAPIServer builds a real api.Server with no optional dependencies, so
// every config-store consumer starts unwired.
func newBareAPIServer(t *testing.T) *api.Server {
	t.Helper()
	srv, err := api.New(
		config.DefaultConfig(),
		logging.NewNoopLogger(),
		nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		"",
		nil, nil, nil, nil, nil, nil, nil,
	)
	require.NoError(t, err)
	require.NotNil(t, srv)
	require.Nil(t, srv.RoleConfigStore())
	require.Nil(t, srv.PrivilegeStore())
	require.Nil(t, srv.HypervProfileConfigStore())
	require.Nil(t, srv.ContentApprovalStore())
	return srv
}

// TestWireConfigStoreConsumers covers the controller startup wiring of the
// config store into the API server's role-config, privilege, hyperv profile
// (Issue #3785) and script approval (Issue #5839) consumers.
func TestWireConfigStoreConsumers(t *testing.T) {
	t.Run("nil store wires nothing", func(t *testing.T) {
		srv := newBareAPIServer(t)

		require.NoError(t, wireHTTPConfigNamespaceStores(srv, nil))

		assert.Nil(t, srv.RoleConfigStore())
		assert.Nil(t, srv.PrivilegeStore())
		assert.Nil(t, srv.HypervProfileConfigStore())
		assert.Nil(t, srv.ContentApprovalStore())
	})

	t.Run("durable store wires all four consumers", func(t *testing.T) {
		srv := newBareAPIServer(t)
		cs := pkgtesting.SetupTestStorage(t).GetConfigStore()
		require.NotNil(t, cs)

		require.NoError(t, wireHTTPConfigNamespaceStores(srv, cs))

		assert.Same(t, cs, srv.RoleConfigStore())
		assert.Same(t, cs, srv.PrivilegeStore())
		assert.Same(t, cs, srv.HypervProfileConfigStore())
		require.NotNil(t, srv.ContentApprovalStore(),
			"script approval routes 503 when the content approval store is unwired")
	})

	t.Run("content approval store is built on the wired store", func(t *testing.T) {
		srv := newBareAPIServer(t)
		cs := pkgtesting.SetupTestStorage(t).GetConfigStore()
		require.NoError(t, wireHTTPConfigNamespaceStores(srv, cs))

		// The wired approval store reads the same durable store: a mode set
		// through it is visible through a second store built on cs.
		ctx := t.Context()
		require.NoError(t, srv.ContentApprovalStore().SetMode(ctx, "tenant-a", api.LibraryKindScript, api.ApprovalModeApprove, "operator-1"))
		other, err := api.NewContentApprovalStore(cs)
		require.NoError(t, err)
		mode, err := other.GetMode(ctx, "tenant-a", api.LibraryKindScript)
		require.NoError(t, err)
		assert.Equal(t, api.ApprovalModeApprove, mode)
	})

	t.Run("content approval store construction error is the case the nil guard excludes", func(t *testing.T) {
		// NewContentApprovalStore fails only for a nil config store. That is
		// exactly the input wireHTTPConfigNamespaceStores returns early on, so a
		// controller without a config store starts with the approval routes
		// unwired (503) instead of failing startup.
		_, err := api.NewContentApprovalStore(nil)
		require.Error(t, err)

		srv := newBareAPIServer(t)
		require.NoError(t, wireHTTPConfigNamespaceStores(srv, nil))
		assert.Nil(t, srv.ContentApprovalStore())
	})
}
