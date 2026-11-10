// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Tests for wireRolloutStore (Issue #5976): the controller-startup call site that
// hands the shared rollout store to the HTTP API server and halts the rollouts
// this node left in progress.
package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const rolloutWiringTenant = "fleet-root/fleet-child-a"

// rolloutWiringServer builds a real controller Server on the flatfile provider (which
// implements no RolloutStoreCreator) plus a seeded API key allowed to start rollouts.
func rolloutWiringServer(t *testing.T) (*Server, string) {
	t.Helper()
	keyBytes := make([]byte, 16)
	_, err := rand.Read(keyBytes)
	require.NoError(t, err)
	key := "rollout-wiring-" + hex.EncodeToString(keyBytes)
	t.Setenv("CFGMS_SEED_TEST_API_KEYS", "1")
	t.Setenv("CFGMS_API_KEY_UPGRADE_TEST", key)

	srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())
	require.NotNil(t, srv.httpServer)
	// The permission check resolves the key's tenant for its assurance policy.
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), "fleet-root", "fleet-root", "")
	mustCreateTenantForWiring(t, srv.storageManager.GetTenantStore(), rolloutWiringTenant, "fleet-child-a", "fleet-root")
	return srv, key
}

// postStartRollout calls POST /api/v1/rollout through the server's real router and
// returns the status code and body.
func postStartRollout(t *testing.T, srv *Server, key string) (int, string) {
	t.Helper()
	body := []byte(`{"target_version":"v1.2.3","tenant_id":"` + rolloutWiringTenant + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/rollout", bytes.NewReader(body))
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.httpServer.GetRouter().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestWireRolloutStore_ProviderWithoutCreatorLeavesEndpointAt503(t *testing.T) {
	srv, key := rolloutWiringServer(t)

	require.Nil(t, srv.storageManager.GetRolloutStore(),
		"the flatfile provider implements no RolloutStoreCreator, so no store is created")
	assert.Nil(t, srv.httpServer.RolloutStore(), "New wires nothing when the manager holds no rollout store")

	wireRolloutStore(srv.httpServer, srv.storageManager, logging.NewNoopLogger())
	assert.Nil(t, srv.httpServer.RolloutStore(), "wiring a manager without a store must not set a (typed) nil")

	code, body := postStartRollout(t, srv, key)
	assert.Equal(t, http.StatusServiceUnavailable, code, body)
	assert.Contains(t, body, "ROLLOUT_STORE_UNAVAILABLE")
}

func TestWireRolloutStore_StorePresentWiresServerAndEndpoint(t *testing.T) {
	srv, key := rolloutWiringServer(t)
	store := newMemoryRolloutStore()
	srv.storageManager.SetRolloutStore(store)

	wireRolloutStore(srv.httpServer, srv.storageManager, logging.NewNoopLogger())

	assert.Same(t, store, srv.httpServer.RolloutStore())
	code, body := postStartRollout(t, srv, key)
	assert.NotContains(t, body, "ROLLOUT_STORE_UNAVAILABLE", "status %d", code)
	assert.NotEqual(t, http.StatusServiceUnavailable, code, body)
}

func TestWireRolloutStore_NilArgumentsAreNoops(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/rollout-wiring-nil.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	sm.SetRolloutStore(newMemoryRolloutStore())

	assert.NotPanics(t, func() { wireRolloutStore(nil, sm, logging.NewNoopLogger()) })
	httpServer := newBareAPIServer(t)
	assert.NotPanics(t, func() { wireRolloutStore(httpServer, nil, logging.NewNoopLogger()) })
	assert.Nil(t, httpServer.RolloutStore())
}

// TestWireRolloutStore_SweepsOrphanedRollouts is the [REQUIRED TEST] for the startup
// sweep: after wiring, an in-progress rollout owned by this node is halted with the
// recorded reason and a HaltedAt, while an in-progress rollout owned by a peer and a
// completed rollout owned by this node are unchanged. The bare API server has no HA
// manager, so this node's owner ID is empty.
func TestWireRolloutStore_SweepsOrphanedRollouts(t *testing.T) {
	ctx := context.Background()
	store := newMemoryRolloutStore()
	seed := func(id, owner string, status business.RolloutStatus) {
		require.NoError(t, store.CreateRollout(ctx, &business.RolloutRecord{
			ID: id, TenantID: "tenant-" + id, TargetVersion: "v2.0.0", CurrentRing: "early",
			RingsCompleted: 1, RingsTotal: 3, Status: status, StartedAt: time.Now().UTC().Add(-time.Minute),
			OwnerNodeID: owner,
		}))
	}
	seed("local-active", "", business.RolloutStatusInProgress)
	seed("peer-active", "node-b-0002", business.RolloutStatusInProgress)
	seed("local-done", "", business.RolloutStatusCompleted)

	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/rollout-sweep.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	sm.SetRolloutStore(store)
	httpServer := newBareAPIServer(t)

	wireRolloutStore(httpServer, sm, logging.NewNoopLogger())

	local, err := store.GetRollout(ctx, "local-active")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusHalted, local.Status)
	assert.Equal(t, "advancing node stopped", local.Error)
	require.NotNil(t, local.HaltedAt)

	peer, err := store.GetRollout(ctx, "peer-active")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusInProgress, peer.Status)
	assert.Nil(t, peer.HaltedAt)
	assert.Empty(t, peer.Error)

	done, err := store.GetRollout(ctx, "local-done")
	require.NoError(t, err)
	assert.Equal(t, business.RolloutStatusCompleted, done.Status)
	assert.Nil(t, done.HaltedAt)
}

// rolloutListFailStore fails the cross-tenant listing the sweep depends on.
type rolloutListFailStore struct{ business.RolloutStore }

func (rolloutListFailStore) ListInProgressRollouts(context.Context) ([]*business.RolloutRecord, error) {
	return nil, errors.New("store unavailable")
}

// TestWireRolloutStore_FailedSweepDoesNotBlockWiring proves a sweep failure is a
// warning: the store is still wired and wireRolloutStore returns.
func TestWireRolloutStore_FailedSweepDoesNotBlockWiring(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), t.TempDir()+"/rollout-sweep-fail.db")
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })
	store := rolloutListFailStore{newMemoryRolloutStore()}
	sm.SetRolloutStore(store)
	httpServer := newBareAPIServer(t)
	logger := &recordingLogger{}

	wireRolloutStore(httpServer, sm, logger)

	assert.NotNil(t, httpServer.RolloutStore(), "the store is wired even when the sweep fails")
	assert.True(t, logger.containsAny("Startup rollout sweep did not finish; continuing"))
}
