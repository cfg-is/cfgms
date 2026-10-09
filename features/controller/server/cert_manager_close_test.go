// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

type closeCounter struct{ n atomic.Int32 }

func (c *closeCounter) Close() error { c.n.Add(1); return nil }

// TestServerStop_ClosesCertManagerVaultConnection pins ownership of the vault
// connection a cluster-mode cert.Manager retains for its signing-key store
// (Issue #4689): the Server owns the Manager, so Stop releases the connection.
func TestServerStop_ClosesCertManagerVaultConnection(t *testing.T) {
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 30, KeySize: 2048},
	})
	require.NoError(t, err)
	vault := &closeCounter{}
	mgr.AttachCloser(vault)

	srv := &Server{certManager: mgr, logger: logging.NewNoopLogger()}
	require.NoError(t, srv.Stop())
	assert.EqualValues(t, 1, vault.n.Load(), "Stop must close the retained vault connection")

	require.NoError(t, srv.Stop())
	assert.EqualValues(t, 1, vault.n.Load(), "closing is idempotent")
}
