// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Regression tests for the heartbeat / DNA-sync lock-order inversion
// (Issue #6275): heartbeat.Service.mu and ControllerService.mu were each held
// while a callback took the other.
package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	fleetStorage "github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	"github.com/cfgis/cfgms/features/controller/service"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	sdna "github.com/cfgis/cfgms/pkg/dna"
	"github.com/cfgis/cfgms/pkg/logging"
)

// deadlockBound is how long a single call may take before the test declares a
// deadlock. The calls are in-process and complete in microseconds when the
// locks are not inverted.
const deadlockBound = 10 * time.Second

// callWithinBound runs fn and reports whether it returned within deadlockBound.
// It is safe to call from any goroutine.
func callWithinBound(fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(deadlockBound):
		return false
	}
}

// returnsWithinBound runs fn and fails the test if it does not return within
// deadlockBound, so a lock deadlock fails the test instead of hanging it.
func returnsWithinBound(t *testing.T, name string, fn func()) {
	t.Helper()
	if !callWithinBound(fn) {
		t.Fatalf("%s did not return within %s: heartbeat and DNA-sync locks are deadlocked", name, deadlockBound)
	}
}

// deadlockFixture wires a real heartbeat.Service and ControllerService the way
// server.go does: the heartbeat-received hook records health reasons on the
// ControllerService (newHeartbeatReceivedHook), and the post-DNA-sync hook sets
// the expected DNA hash on the heartbeat service (wirePostDNASyncExpectedHash).
// The tests wrap each hook to force the interleaving.
type deadlockFixture struct {
	cp  *hbTestControlPlane
	hb  *heartbeat.Service
	svc *service.ControllerService
}

type deadlockFixtureOpts struct {
	// beforeRecordHealthReasons runs inside the heartbeat-received hook before
	// it calls RecordHealthReasons. Optional.
	beforeRecordHealthReasons func()
	// beforeSetExpectedHash runs inside the post-DNA-sync hook before it calls
	// SetExpectedDNAHash. Optional.
	beforeSetExpectedHash func()
	// onStatusChange is the heartbeat status-change callback. Optional.
	onStatusChange heartbeat.StatusChangeCallback
	// offlineTimeout and checkInterval configure the stale monitor.
	offlineTimeout time.Duration
	checkInterval  time.Duration
}

func newDeadlockFixture(t *testing.T, opts deadlockFixtureOpts) *deadlockFixture {
	t.Helper()
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	fleetCfg := fleetStorage.DefaultConfig()
	fleetCfg.DataDir = t.TempDir()
	fleetCfg.EnableDeduplication = false
	mgr, err := fleetStorage.NewManager(fleetCfg, logger)
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	svc := service.NewControllerServiceWithStorage(logger, mgr)

	if opts.offlineTimeout == 0 {
		opts.offlineTimeout = time.Minute
	}
	if opts.checkInterval == 0 {
		opts.checkInterval = time.Minute
	}
	cp := &hbTestControlPlane{}
	hb, err := heartbeat.New(&heartbeat.Config{
		ControlPlane:          cp,
		StewardOfflineTimeout: opts.offlineTimeout,
		CheckInterval:         opts.checkInterval,
		OnStatusChange:        opts.onStatusChange,
		OnHeartbeatReceived: func(stewardID string, reasons []controlplaneTypes.HealthReason) {
			if opts.beforeRecordHealthReasons != nil {
				opts.beforeRecordHealthReasons()
			}
			svc.RecordHealthReasons(stewardID, reasons)
		},
		Logger: logger,
	})
	require.NoError(t, err)

	svc.SetPostDNASyncHook(func(stewardID string, dna *commonpb.DNA) {
		if opts.beforeSetExpectedHash != nil {
			opts.beforeSetExpectedHash()
		}
		hash, hashErr := fleetStorage.ContentHash(dna)
		if hashErr != nil {
			t.Errorf("content hash for %s: %v", stewardID, hashErr)
			return
		}
		hb.SetExpectedDNAHash(stewardID, hash)
	})

	require.NoError(t, hb.Start(ctx))
	t.Cleanup(func() { _ = hb.Stop(context.Background()) })
	return &deadlockFixture{cp: cp, hb: hb, svc: svc}
}

// heartbeat sends one healthy heartbeat. It is safe to call from any goroutine.
func (f *deadlockFixture) heartbeat(t *testing.T, stewardID string) {
	if err := f.cp.sendHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID: stewardID,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}); err != nil {
		t.Errorf("heartbeat %s: %v", stewardID, err)
	}
}

// validDNA builds a DNA snapshot that passes the controller's integrity check.
// It is called from worker goroutines, so it panics instead of using
// require.
func validDNA(id string, revision int) *commonpb.DNA {
	frag := func(kind string, fields map[string]interface{}) *commonpb.Fragment {
		f, err := sdna.NewFragment(kind, "test", sdna.MapState(fields))
		if err != nil {
			panic(fmt.Sprintf("validDNA fragment %q: %v", kind, err))
		}
		return f
	}
	return &commonpb.DNA{
		Id:              id,
		SyncFingerprint: fmt.Sprintf("fp-%s-%d", id, revision),
		Fragments: []*commonpb.Fragment{
			frag("hostname", map[string]interface{}{"hostname": id + "-host"}),
			frag("host:os", map[string]interface{}{"os": "linux"}),
			frag("host:test", map[string]interface{}{"revision": fmt.Sprintf("%d", revision)}),
		},
	}
}

// TestHeartbeatAndDNASync_NoLockOrderInversion forces the exact interleaving
// that deadlocked the controller: the heartbeat-received hook is parked until
// the post-DNA-sync hook has been entered, and only then takes
// ControllerService.mu. With either callback invoked under its owner's mutex
// this deadlocks every time.
func TestHeartbeatAndDNASync_NoLockOrderInversion(t *testing.T) {
	const stewardID = "deadlock-steward-1"

	syncHookEntered := make(chan struct{})
	heartbeatInHook := make(chan struct{})
	var heartbeatOnce, syncOnce sync.Once

	f := newDeadlockFixture(t, deadlockFixtureOpts{
		beforeRecordHealthReasons: func() {
			heartbeatOnce.Do(func() { close(heartbeatInHook) })
			// Park until the SyncDNA hook is in flight. Bounded so a regression
			// that stops SyncDNA from reaching its hook fails rather than leaks.
			select {
			case <-syncHookEntered:
			case <-time.After(deadlockBound):
			}
		},
		beforeSetExpectedHash: func() {
			syncOnce.Do(func() { close(syncHookEntered) })
		},
	})
	require.NoError(t, f.svc.RegisterSteward(stewardID, "tenant-1", "", "active"))

	var hbErr, syncErr error
	var syncStatus *commonpb.Status
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		hbErr = f.cp.sendHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
			StewardID: stewardID,
			Status:    controlplaneTypes.StatusHealthy,
			Timestamp: time.Now(),
		})
	}()
	go func() {
		defer wg.Done()
		<-heartbeatInHook
		syncStatus, syncErr = f.svc.SyncDNA(context.Background(), validDNA(stewardID, 0))
	}()

	returnsWithinBound(t, "concurrent heartbeat and SyncDNA", wg.Wait)

	require.NoError(t, hbErr)
	require.NoError(t, syncErr)
	require.Equal(t, commonpb.Status_OK, syncStatus.Code)
	require.Equal(t, "DNA synchronized", syncStatus.Message)

	// The hook ran after unlock and still did its job.
	got, ok := f.hb.GetStatus(stewardID)
	require.True(t, ok)
	require.True(t, got.Healthy)
}

// TestStaleMonitor_StatusChangeMayCallControllerService verifies the stale
// monitor does not hold heartbeat.Service.mu while onStatusChange runs: a
// callback that calls back into a lock-taking ControllerService method must
// complete even while a SyncDNA holds ControllerService.mu and waits on
// heartbeat.Service.mu through its post-sync hook.
func TestStaleMonitor_StatusChangeMayCallControllerService(t *testing.T) {
	const stewardID = "deadlock-steward-stale"

	syncHookEntered := make(chan struct{})
	staleInCallback := make(chan struct{})
	staleCallbackDone := make(chan struct{})
	var syncOnce, staleOnce, doneOnce sync.Once
	var svc atomic.Pointer[service.ControllerService]

	f := newDeadlockFixture(t, deadlockFixtureOpts{
		offlineTimeout: 50 * time.Millisecond,
		checkInterval:  10 * time.Millisecond,
		onStatusChange: func(_ string, healthy bool, _ heartbeat.StewardStatus) {
			if healthy {
				return
			}
			staleOnce.Do(func() { close(staleInCallback) })
			select {
			case <-syncHookEntered:
			case <-time.After(deadlockBound):
			}
			// A lock-taking ControllerService method, as makeHeartbeatStatusChangeCallback
			// and the heartbeat hooks reach in server.go.
			_ = svc.Load().GetStewardCount()
			doneOnce.Do(func() { close(staleCallbackDone) })
		},
		beforeSetExpectedHash: func() {
			syncOnce.Do(func() { close(syncHookEntered) })
		},
	})
	svc.Store(f.svc)
	require.NoError(t, f.svc.RegisterSteward(stewardID, "tenant-1", "", "active"))

	// One heartbeat registers the steward; with no further heartbeats the
	// monitor marks it stale ~50 ms later and invokes onStatusChange(false).
	f.heartbeat(t, stewardID)

	select {
	case <-staleInCallback:
	case <-time.After(deadlockBound):
		t.Fatal("stale monitor never reported the steward offline")
	}

	// SyncDNA now runs while the stale monitor is inside its callback.
	var syncErr error
	returnsWithinBound(t, "SyncDNA during stale callback", func() {
		_, syncErr = f.svc.SyncDNA(context.Background(), validDNA(stewardID, 0))
	})
	require.NoError(t, syncErr)

	select {
	case <-staleCallbackDone:
	case <-time.After(deadlockBound):
		t.Fatal("stale monitor onStatusChange callback did not complete: lock deadlock")
	}

	// Heartbeats are still served while the monitor keeps running.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !callWithinBound(func() { f.heartbeat(t, stewardID) }) {
				t.Errorf("heartbeat did not return within %s alongside the stale monitor", deadlockBound)
			}
		}()
	}
	wg.Wait()
}

// TestHeartbeatAndDNASync_ConcurrentStress runs many concurrent heartbeats and
// DNA syncs across several stewards with the production hook wiring and a fast
// stale monitor whose status-change callback reaches into ControllerService.
// Each call is bounded by deadlockBound. Run under -race.
func TestHeartbeatAndDNASync_ConcurrentStress(t *testing.T) {
	const (
		stewards   = 4
		iterations = 100
	)
	var svc atomic.Pointer[service.ControllerService]
	f := newDeadlockFixture(t, deadlockFixtureOpts{
		offlineTimeout: 20 * time.Millisecond,
		checkInterval:  5 * time.Millisecond,
		onStatusChange: func(_ string, _ bool, _ heartbeat.StewardStatus) {
			if s := svc.Load(); s != nil {
				_ = s.GetStewardCount()
			}
		},
	})
	svc.Store(f.svc)
	ids := make([]string, stewards)
	for i := range ids {
		ids[i] = fmt.Sprintf("stress-steward-%d", i)
		require.NoError(t, f.svc.RegisterSteward(ids[i], "tenant-1", "", "active"))
	}

	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if !callWithinBound(func() { f.heartbeat(t, id) }) {
					t.Errorf("heartbeat for %s did not return within %s", id, deadlockBound)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				ok := callWithinBound(func() {
					if _, err := f.svc.SyncDNA(context.Background(), validDNA(id, i)); err != nil {
						t.Errorf("SyncDNA %s: %v", id, err)
					}
				})
				if !ok {
					t.Errorf("SyncDNA for %s did not return within %s", id, deadlockBound)
					return
				}
			}
		}()
	}
	wg.Wait()
}
