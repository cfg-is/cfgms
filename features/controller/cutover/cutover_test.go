// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeHandle records lifecycle calls so tests can assert subprocess
// effects without spawning anything.
type fakeHandle struct {
	mu         sync.Mutex
	binary     string
	startCalls int
	drainCalls int
	stopCalls  int
	startErr   error
	stopped    bool
}

func newFakeHandle(binary string) *fakeHandle { return &fakeHandle{binary: binary} }

func (f *fakeHandle) Start(_ context.Context, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	return f.startErr
}
func (f *fakeHandle) Drain(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.drainCalls++
	return nil
}
func (f *fakeHandle) Stop(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls++
	f.stopped = true
	return nil
}
func (f *fakeHandle) BinaryPath() string { return f.binary }

type stubValidator struct{ err error }

func (s stubValidator) Validate(context.Context, string) error { return s.err }

type stubSmoke struct{ err error }

func (s stubSmoke) Probe(context.Context, ProcessHandle, string, string) error { return s.err }

type stubSwap struct {
	mu        sync.Mutex
	calls     int
	swapErr   error
	lastFrom  ProcessHandle
	lastTo    ProcessHandle
	canonAPI  string
	canonGRPC string
}

func (s *stubSwap) Swap(_ context.Context, from, to ProcessHandle, canonAPIAddr, canonTransportAddr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.lastFrom = from
	s.lastTo = to
	s.canonAPI = canonAPIAddr
	s.canonGRPC = canonTransportAddr
	return s.swapErr
}

// newOrchForTest is the standard test orchestrator: blue is canonical
// starting from path "blue.exe"; the spawn factory returns a new fake
// for whatever path it's asked for. Callers override individual deps as
// needed.
func newOrchForTest(t *testing.T) (*Orchestrator, *fakeHandle, *stubSwap, *atomic.Pointer[fakeHandle]) {
	t.Helper()
	blue := newFakeHandle("blue.exe")
	swap := &stubSwap{}
	lastSpawned := &atomic.Pointer[fakeHandle]{}
	spawn := func(p string) ProcessHandle {
		fh := newFakeHandle(p)
		lastSpawned.Store(fh)
		return fh
	}
	o := NewOrchestrator(
		Config{
			CanonicalAPIAddr:       ":9080",
			CanonicalTransportAddr: ":4433",
			CandidateAPIAddr:       ":9081",
			CandidateTransportAddr: ":4434",
			QuarantineWindow:       1 * time.Hour,
			SmoketestTimeout:       100 * time.Millisecond,
		},
		blue,
		stubValidator{},
		stubSmoke{},
		swap,
		spawn,
	)
	return o, blue, swap, lastSpawned
}

func TestOrchestrator_HappyPath_BlueToGreen(t *testing.T) {
	o, blue, swap, spawned := newOrchForTest(t)
	require.Equal(t, StateIdle, o.Status().State)
	require.Equal(t, "blue.exe", o.Status().CanonicalBinary)

	err := o.Upgrade(context.Background(), "green.exe")
	require.NoError(t, err)

	snap := o.Status()
	assert.Equal(t, StateQuarantined, snap.State)
	assert.Equal(t, "green.exe", snap.CanonicalBinary)
	assert.Equal(t, "blue.exe", snap.QuarantinedBinary)
	assert.False(t, snap.QuarantineExpiresAt.IsZero())

	assert.Equal(t, 1, swap.calls)
	assert.Equal(t, blue, swap.lastFrom)
	assert.Equal(t, ":9080", swap.canonAPI)
	assert.Equal(t, ":4433", swap.canonGRPC)

	// The candidate that was spawned IS now canonical, so it should
	// have been started exactly once and never stopped.
	green := spawned.Load()
	require.NotNil(t, green)
	assert.Equal(t, "green.exe", green.binary)
	assert.Equal(t, 1, green.startCalls)
	assert.Equal(t, 0, green.stopCalls, "newly canonical green must NOT have been stopped")
}

func TestOrchestrator_ConcurrentUpgrade_SecondReturnsInProgress(t *testing.T) {
	o, _, _, _ := newOrchForTest(t)

	// Block the validator on a channel so the first Upgrade holds the
	// state machine in StatePreparing while we race a second one in.
	release := make(chan struct{})
	o.validator = blockingValidator{release: release}

	var firstErr, secondErr error
	var firstDone, secondDone sync.WaitGroup
	firstDone.Add(1)
	go func() {
		defer firstDone.Done()
		firstErr = o.Upgrade(context.Background(), "green.exe")
	}()

	// Wait until the orchestrator has entered StatePreparing — that's
	// when the second attempt should be rejected.
	require.Eventually(t, func() bool {
		return o.Status().State == StatePreparing
	}, 1*time.Second, 5*time.Millisecond)

	secondDone.Add(1)
	go func() {
		defer secondDone.Done()
		secondErr = o.Upgrade(context.Background(), "blue-rev2.exe")
	}()
	secondDone.Wait()

	assert.ErrorIs(t, secondErr, ErrUpgradeInProgress,
		"second concurrent Upgrade must reject with ErrUpgradeInProgress")

	close(release)
	firstDone.Wait()
	assert.NoError(t, firstErr)
}

type blockingValidator struct {
	release chan struct{}
}

func (b blockingValidator) Validate(ctx context.Context, _ string) error {
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestOrchestrator_ValidatorRejects_NoSideEffects(t *testing.T) {
	o, blue, swap, spawned := newOrchForTest(t)
	o.validator = stubValidator{err: errors.New("bad signature")}

	err := o.Upgrade(context.Background(), "tampered.exe")
	require.ErrorIs(t, err, ErrValidationFailed)
	assert.Contains(t, err.Error(), "bad signature")

	// Validation runs BEFORE spawning, so no candidate handle should
	// have been created; swap must not have been called; blue is still
	// canonical and untouched.
	assert.Nil(t, spawned.Load())
	assert.Equal(t, 0, swap.calls)
	assert.Equal(t, "blue.exe", o.Status().CanonicalBinary)
	assert.Equal(t, StateIdle, o.Status().State)
	assert.Equal(t, 0, blue.stopCalls, "validator failure must not touch blue")
}

func TestOrchestrator_SmoketestFails_CandidateStopped(t *testing.T) {
	o, blue, swap, spawned := newOrchForTest(t)
	o.smoke = stubSmoke{err: errors.New("control plane unreachable")}

	err := o.Upgrade(context.Background(), "broken.exe")
	require.ErrorIs(t, err, ErrSmoketestFailed)
	assert.Contains(t, err.Error(), "control plane unreachable")

	// Candidate was started — smoketest failure must stop it cleanly.
	candidate := spawned.Load()
	require.NotNil(t, candidate)
	assert.Equal(t, 1, candidate.startCalls)
	assert.Equal(t, 1, candidate.stopCalls, "failed-smoketest candidate must be stopped")

	// No cutover should have happened.
	assert.Equal(t, 0, swap.calls)
	assert.Equal(t, "blue.exe", o.Status().CanonicalBinary)
	assert.Equal(t, StateIdle, o.Status().State)
	assert.Equal(t, 0, blue.stopCalls, "smoketest failure must not stop blue")
}

func TestOrchestrator_SwapFails_CandidateStopped_StateReturnsToIdle(t *testing.T) {
	o, blue, swap, spawned := newOrchForTest(t)
	swap.swapErr = errors.New("port handoff timed out")

	err := o.Upgrade(context.Background(), "green.exe")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port handoff timed out")

	candidate := spawned.Load()
	require.NotNil(t, candidate)
	assert.Equal(t, 1, candidate.stopCalls, "failed-swap candidate must be stopped")

	// Blue remains canonical; the state machine returned to idle so a
	// retry is possible.
	assert.Equal(t, "blue.exe", o.Status().CanonicalBinary)
	assert.Equal(t, StateIdle, o.Status().State)
	assert.Equal(t, 0, blue.stopCalls)
}

func TestOrchestrator_Rollback_FromQuarantine_RestoresPrevious(t *testing.T) {
	o, blue, swap, spawned := newOrchForTest(t)

	require.NoError(t, o.Upgrade(context.Background(), "green.exe"))
	require.Equal(t, StateQuarantined, o.Status().State)

	green := spawned.Load()
	require.NotNil(t, green)

	require.NoError(t, o.Rollback(context.Background()))

	snap := o.Status()
	assert.Equal(t, StateIdle, snap.State)
	assert.Equal(t, "blue.exe", snap.CanonicalBinary,
		"after rollback the original blue must be canonical again")
	assert.Empty(t, snap.QuarantinedBinary)

	// Two swap calls total: the upgrade + the rollback.
	assert.Equal(t, 2, swap.calls)

	// Green (the rolled-back binary) must be stopped.
	assert.Equal(t, 1, green.stopCalls,
		"rolled-back green must be stopped exactly once")
	// Blue was never stopped during the cycle.
	assert.Equal(t, 0, blue.stopCalls)
}

func TestOrchestrator_Rollback_WithoutQuarantine_ReturnsError(t *testing.T) {
	o, _, _, _ := newOrchForTest(t)
	require.Equal(t, StateIdle, o.Status().State)

	err := o.Rollback(context.Background())
	assert.ErrorIs(t, err, ErrNoQuarantinedBinary)
}

func TestOrchestrator_FinalizeQuarantine_StopsParkedBinary(t *testing.T) {
	o, _, _, spawned := newOrchForTest(t)
	require.NoError(t, o.Upgrade(context.Background(), "green.exe"))
	green := spawned.Load() // candidate that became canonical
	_ = green

	// At this point blue is parked in the quarantine slot.
	snap := o.Status()
	require.Equal(t, "blue.exe", snap.QuarantinedBinary)

	o.FinalizeQuarantine(context.Background())

	snap = o.Status()
	assert.Equal(t, StateIdle, snap.State)
	assert.Empty(t, snap.QuarantinedBinary)
}

func TestOrchestrator_FinalizeQuarantine_Idempotent(t *testing.T) {
	o, _, _, _ := newOrchForTest(t)
	// In StateIdle with no quarantine, FinalizeQuarantine must be a no-op.
	o.FinalizeQuarantine(context.Background())
	assert.Equal(t, StateIdle, o.Status().State)
}

func TestOrchestrator_CandidateStartFailure_BlueUntouched(t *testing.T) {
	blue := newFakeHandle("blue.exe")
	swap := &stubSwap{}
	spawnedFake := &atomic.Pointer[fakeHandle]{}
	spawn := func(p string) ProcessHandle {
		fh := newFakeHandle(p)
		fh.startErr = errors.New("binary missing")
		spawnedFake.Store(fh)
		return fh
	}
	o := NewOrchestrator(
		Config{
			CanonicalAPIAddr:       ":9080",
			CanonicalTransportAddr: ":4433",
			CandidateAPIAddr:       ":9081",
			CandidateTransportAddr: ":4434",
		},
		blue, stubValidator{}, stubSmoke{}, swap, spawn,
	)

	err := o.Upgrade(context.Background(), "ghost.exe")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binary missing")

	// State must return to idle; blue is still canonical and not stopped.
	assert.Equal(t, StateIdle, o.Status().State)
	assert.Equal(t, "blue.exe", o.Status().CanonicalBinary)
	assert.Equal(t, 0, blue.stopCalls)

	// Swap must not have been called.
	assert.Equal(t, 0, swap.calls)
}
