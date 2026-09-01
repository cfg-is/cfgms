// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServer_New_WiresNonceStoreIntoAPIServer is the composition-root wiring
// test for the durable registration-refresh nonce store (Issue #3755, ADR-031
// amendment to ADR-011). The real startup path in New() must leave
// Server.nonceStore non-nil when storageManager.GetNonceStore() returns a store.
//
// Every handler-level test in features/controller/api calls SetNonceStore
// directly, so none of them can observe a composition root that never calls the
// setter. That exact gap shipped twice before — the ip-trust store (Issue #3096)
// and the tag/role store (Issue #2548) both 503'd indefinitely in production
// while their handler tests passed. This test closes it for the nonce store, in
// the same shape as TestServer_New_WiresCasesStoreIntoAPIServer (Issue #3605).
func TestServer_New_WiresNonceStoreIntoAPIServer(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Nonce Store Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "nonce-wiring-controller",
				Organization: "Nonce Store Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		// FlatfileRoot causes CreateOSSStorageManager to build the flatfile
		// NonceStore (the OSS deployment sources nonces from flatfile, like
		// IPTrustStore and AlertStore); SQLitePath is required for the rest of
		// the composite. Without both, GetNonceStore returns nil and this test
		// would be a false positive.
		Storage: createTestStorageConfig(tempDir, "nonce-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })

	require.NotNil(t, srv.httpServer, "API server must be initialized")

	store := srv.httpServer.NonceStore()
	require.NotNil(t, store,
		"nonce store must be wired into the API server (else the registration-refresh challenge and complete endpoints 503 at runtime)")

	// The wired store must be usable, not merely non-nil: a store that errors on
	// every call would 500 the refresh endpoints just as surely as a nil one.
	ctx := context.Background()
	const key = "nonce-wiring-test-key"
	require.NoError(t, store.PutNonce(ctx, key, []byte("challenge-payload"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, key)
	require.NoError(t, err)
	require.True(t, found, "nonce stored through the wired store must be retrievable")
	assert.Equal(t, []byte("challenge-payload"), entry)

	_, found, err = store.GetAndConsumeNonce(ctx, key)
	require.NoError(t, err)
	assert.False(t, found, "consumed nonce must not be retrievable a second time")
}
