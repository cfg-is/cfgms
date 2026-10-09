// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// countingStewardStore wraps a real StewardStore, counting UpdateHeartbeat
// calls and optionally substituting an error for them.
type countingStewardStore struct {
	business.StewardStore
	calls   atomic.Int32
	failErr error
}

func (c *countingStewardStore) UpdateHeartbeat(ctx context.Context, id, version string) error {
	c.calls.Add(1)
	if c.failErr != nil {
		return c.failErr
	}
	return c.StewardStore.UpdateHeartbeat(ctx, id, version)
}

func registerLiveSteward(t *testing.T, svc *ControllerService, id string) {
	t.Helper()
	svc.mu.Lock()
	svc.stewards[id] = &StewardInfo{ID: id, TenantID: "tenant-a", Status: "registered", Metrics: map[string]string{}}
	svc.mu.Unlock()
}

func newSharedStewardStore(t *testing.T, id string) business.StewardStore {
	t.Helper()
	store := pkgtesting.SetupTestStorage(t).GetStewardStore()
	require.NotNil(t, store)
	require.NoError(t, store.RegisterSteward(context.Background(), &business.StewardRecord{
		ID:           id,
		TenantID:     "tenant-a",
		Status:       business.StewardStatusActive,
		RegisteredAt: time.Now().UTC().Add(-72 * time.Hour),
		LastSeen:     time.Now().UTC().Add(-72 * time.Hour),
	}))
	return store
}

func TestRecordHeartbeat_PersistsToSharedStoreAcrossInstances(t *testing.T) {
	store := newSharedStewardStore(t, "dev-1")
	svcA := NewControllerService(logging.NewNoopLogger())
	svcA.SetStewardStore(store)
	svcB := NewControllerService(logging.NewNoopLogger())
	svcB.SetStewardStore(store)
	registerLiveSteward(t, svcA, "dev-1")

	before := time.Now().UTC().Add(-time.Second)
	require.True(t, svcA.RecordHeartbeat("dev-1", "v1.2.3", time.Now()))

	rec, err := store.GetSteward(context.Background(), "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "v1.2.3", rec.Version)
	assert.True(t, rec.LastSeen.After(before), "LastSeen must be refreshed")
	assert.Equal(t, "tenant-a", rec.TenantID, "tenant must never change")

	// Instance B holds no session: the fleet read path serves the shared
	// store's records (fleet_view.go reads StewardStore.ListStewards).
	recs, err := svcB.stewardStore.ListStewards(context.Background())
	require.NoError(t, err)
	var found *business.StewardRecord
	for _, r := range recs {
		if r.ID == "dev-1" {
			found = r
		}
	}
	require.NotNil(t, found, "instance B must see the steward in the shared store")
	assert.Equal(t, "v1.2.3", found.Version)
	assert.True(t, found.LastSeen.After(before))
}

func TestRecordHeartbeat_PersistRateLimit(t *testing.T) {
	counting := &countingStewardStore{StewardStore: newSharedStewardStore(t, "dev-1")}
	svc := NewControllerService(logging.NewNoopLogger())
	svc.SetStewardStore(counting)
	registerLiveSteward(t, svc, "dev-1")

	require.True(t, svc.RecordHeartbeat("dev-1", "v1", time.Now()))
	require.True(t, svc.RecordHeartbeat("dev-1", "v1", time.Now()))
	require.True(t, svc.RecordHeartbeat("dev-1", "", time.Now()))
	assert.EqualValues(t, 1, counting.calls.Load(), "same version inside the interval writes once")

	require.True(t, svc.RecordHeartbeat("dev-1", "v2", time.Now()))
	assert.EqualValues(t, 2, counting.calls.Load(), "changed version writes immediately")
	rec, err := counting.GetSteward(context.Background(), "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "v2", rec.Version)

	// After the interval elapses a same-version heartbeat writes again.
	svc.heartbeatPersistMu.Lock()
	st := svc.heartbeatPersist["dev-1"]
	st.at = time.Now().Add(-heartbeatPersistInterval - time.Second)
	svc.heartbeatPersist["dev-1"] = st
	svc.heartbeatPersistMu.Unlock()
	require.True(t, svc.RecordHeartbeat("dev-1", "v2", time.Now()))
	assert.EqualValues(t, 3, counting.calls.Load())
}

func TestRecordHeartbeat_StoreErrorsDoNotAffectResult(t *testing.T) {
	for name, failErr := range map[string]error{
		"store failure":   errors.New("disk on fire"),
		"steward missing": business.ErrStewardNotFound,
	} {
		t.Run(name, func(t *testing.T) {
			counting := &countingStewardStore{StewardStore: newSharedStewardStore(t, "dev-1"), failErr: failErr}
			svc := NewControllerService(logging.NewNoopLogger())
			svc.SetStewardStore(counting)
			registerLiveSteward(t, svc, "dev-1")

			assert.NotPanics(t, func() {
				assert.True(t, svc.RecordHeartbeat("dev-1", "v1", time.Now()))
			})
			assert.EqualValues(t, 1, counting.calls.Load())
			info, ok := svc.GetStewardInfo("dev-1")
			require.True(t, ok)
			assert.Equal(t, "active", info.Status)
		})
	}
}
