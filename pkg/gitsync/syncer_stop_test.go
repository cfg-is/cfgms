// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// heldWriteStore is a real ConfigStore whose StoreConfig holds the first
// write until release is closed. It stands for a sync that is still writing
// when the syncer is stopped.
type heldWriteStore struct {
	cfgconfig.ConfigStore
	entered     chan struct{}
	enteredOnce sync.Once
	release     chan struct{}
}

func (s *heldWriteStore) StoreConfig(ctx context.Context, entry *cfgconfig.ConfigEntry) error {
	s.enteredOnce.Do(func() { close(s.entered) })
	<-s.release
	return s.ConfigStore.StoreConfig(ctx, entry)
}

// Issue #5096: Stop must not return while a polling goroutine is still inside
// a sync. Callers tear down what the sync writes into (the work directory, the
// store) as soon as Stop returns; on Windows a goroutine still writing
// repos/<scope>/.git made the test's TempDir cleanup fail with "The directory
// is not empty".
func TestSyncer_StopWaitsForInFlightSync(t *testing.T) {
	requireGit(t)
	bareDir, _, _ := newTestRepo(t, map[string]string{"policy1.yaml": "key: value\n"})

	root := t.TempDir()
	store := &heldWriteStore{
		ConfigStore: pkgtesting.SetupTestStorage(t).GetConfigStore(),
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
	}
	var releaseOnce sync.Once
	releaseWrite := func() { releaseOnce.Do(func() { close(store.release) }) }
	t.Cleanup(releaseWrite) // never leave the sync blocked if an assertion fails

	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)
	tick := make(chan time.Time, 1)
	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logging.NewNoopLogger(),
		gitsync.WithTickerFunc(func(time.Duration) (<-chan time.Time, func()) { return tick, func() {} }),
	)
	require.NoError(t, err)
	require.NoError(t, syncer.AddBinding(gitsync.ScopeBinding{
		TenantPath:      "root/stop-tenant",
		Namespace:       "policies",
		OriginURL:       bareDir,
		Branch:          "main",
		PollingInterval: gitsync.MinPollingInterval,
	}))

	tick <- time.Now()
	select {
	case <-store.entered:
	case <-time.After(10 * time.Second): // failure bound only; the passing path waits on the event
		t.Fatal("polling sync never reached the store")
	}

	stopped := make(chan struct{})
	go func() {
		syncer.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned while a polling sync was still writing")
	case <-time.After(200 * time.Millisecond):
	}

	releaseWrite()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second): // failure bound only
		t.Fatal("Stop did not return after the in-flight sync finished")
	}
}
