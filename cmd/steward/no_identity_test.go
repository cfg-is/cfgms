// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/subscribers/systemlog"
)

// recordingSink is the system log sink the loop writes its reasons to.
type recordingSink struct {
	mu    sync.Mutex
	calls []string
}

func (r *recordingSink) WriteOnce(_ systemlog.Level, key, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, key)
	return nil
}

func (r *recordingSink) keys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// fakeClock advances only when the loop sleeps. onSleep runs after each sleep
// with the number of sleeps so far and may return an error to end the wait.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	delays  []time.Duration
	onSleep func(n int) error
}

func (f *fakeClock) waiter(sink systemLogWriter) enrollmentWaiter {
	return enrollmentWaiter{
		sleep: func(ctx context.Context, d time.Duration) error {
			f.mu.Lock()
			f.delays = append(f.delays, d)
			f.now = f.now.Add(d)
			n := len(f.delays)
			f.mu.Unlock()
			if err := ctx.Err(); err != nil {
				return err
			}
			if f.onSleep != nil {
				return f.onSleep(n)
			}
			return nil
		},
		now: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.now
		},
		jitter: func(n time.Duration) time.Duration { return n / 2 },
		sink:   sink,
	}
}

func emptyCertStore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	prev := certStoreDirResolver
	certStoreDirResolver = func() string { return dir }
	t.Cleanup(func() { certStoreDirResolver = prev })
	return dir
}

func stopAfter(n int) func(int) error {
	return func(i int) error {
		if i >= n {
			return context.Canceled
		}
		return nil
	}
}

func TestWaitForEnrollment_NoToken_RetriesWithCappedBackoffAndLogsReasonOnce(t *testing.T) {
	emptyCertStore(t)
	sink := &recordingSink{}
	clock := &fakeClock{now: time.Unix(0, 0)}

	// Released one cycle at a time so the test can see the function has not returned.
	step := make(chan struct{})
	slept := make(chan struct{})
	clock.onSleep = func(int) error {
		slept <- struct{}{}
		<-step
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := waitForEnrollment(ctx, "", clock.waiter(sink), logging.NewNoopLogger())
		done <- err
	}()
	const cycles = 12
	for i := 0; i < cycles; i++ {
		<-slept
		select {
		case err := <-done:
			t.Fatalf("waitForEnrollment returned after %d cycles: %v", i, err)
		default:
		}
		step <- struct{}{}
	}
	<-slept
	cancel()
	step <- struct{}{}
	require.ErrorIs(t, <-done, context.Canceled)

	require.GreaterOrEqual(t, len(clock.delays), 4)
	for i, d := range clock.delays {
		assert.LessOrEqual(t, d, noIdentityMaxBackoff, "delay %d is capped", i)
		assert.GreaterOrEqual(t, d, noIdentityInitialBackoff)
		if i > 0 {
			assert.GreaterOrEqual(t, d, clock.delays[i-1], "delays never decrease")
		}
	}
	assert.Equal(t, noIdentityMaxBackoff, clock.delays[len(clock.delays)-1], "the backoff reaches the cap")
	// 13 cycles elapse in well under the repeat interval, so one reason is one write.
	assert.Equal(t, []string{reasonNoToken}, sink.keys())
}

func TestWaitForEnrollment_RepeatsReasonAfterRepeatInterval(t *testing.T) {
	emptyCertStore(t)
	sink := &recordingSink{}
	clock := &fakeClock{now: time.Unix(0, 0), onSleep: stopAfter(40)}
	_, err := waitForEnrollment(context.Background(), "", clock.waiter(sink), logging.NewNoopLogger())
	require.ErrorIs(t, err, context.Canceled)
	// 40 cycles of up to 5 minutes span more than three hours.
	assert.GreaterOrEqual(t, len(sink.keys()), 3)
	assert.Less(t, len(sink.keys()), len(clock.delays), "not one write per cycle")
}

func TestWaitForEnrollment_WritesEachDistinctReason(t *testing.T) {
	emptyCertStore(t)
	path := filepath.Join(t.TempDir(), "registration-token")
	sink := &recordingSink{}
	clock := &fakeClock{now: time.Unix(0, 0)}
	clock.onSleep = func(n int) error {
		switch n {
		case 2:
			writeSafeTokenFile(t, path, "")
		case 4:
			return context.Canceled
		}
		return nil
	}
	_, err := waitForEnrollment(context.Background(), path, clock.waiter(sink), logging.NewNoopLogger())
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"token_file.missing", "token_file.empty"}, sink.keys())
}

func TestWaitForEnrollment_TokenAppears_ReturnsItWithoutRestart(t *testing.T) {
	emptyCertStore(t)
	path := filepath.Join(t.TempDir(), "registration-token")
	clock := &fakeClock{now: time.Unix(0, 0)}
	clock.onSleep = func(n int) error {
		if n == 3 {
			writeSafeTokenFile(t, path, "tok_appeared_123")
		}
		return nil
	}
	token, err := waitForEnrollment(context.Background(), path, clock.waiter(nil), logging.NewNoopLogger())
	require.NoError(t, err)
	assert.Equal(t, "tok_appeared_123", token)
	assert.Len(t, clock.delays, 3)
}

func TestWaitForEnrollment_IdentityAppears_ReturnsEmptyToken(t *testing.T) {
	dir := emptyCertStore(t)
	clock := &fakeClock{now: time.Unix(0, 0)}
	clock.onSleep = func(n int) error {
		if n == 2 {
			require.NoError(t, saveIdentity(dir, StewardIdentity{StewardID: "s-1", TransportAddress: "127.0.0.1:1"}))
		}
		return nil
	}
	token, err := waitForEnrollment(context.Background(), "", clock.waiter(nil), logging.NewNoopLogger())
	require.NoError(t, err)
	assert.Empty(t, token)
}

func TestWaitForEnrollment_NoToken_NeverCreatesIdentity(t *testing.T) {
	dir := emptyCertStore(t)
	sink := &recordingSink{}
	clock := &fakeClock{now: time.Unix(0, 0), onSleep: stopAfter(20)}
	_, err := waitForEnrollment(context.Background(), filepath.Join(t.TempDir(), "absent"), clock.waiter(sink), logging.NewNoopLogger())
	require.ErrorIs(t, err, context.Canceled)

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "only log entries are produced: no identity, key or registration state")
	assert.NotEmpty(t, sink.keys())
}

func TestWaitForEnrollment_CancellationEndsLoopPromptly(t *testing.T) {
	emptyCertStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := waitForEnrollment(ctx, "", defaultEnrollmentWaiter(nil), logging.NewNoopLogger())
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("returned before cancellation: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not end after cancellation")
	}
}

func TestWaitForEnrollment_UnsafeTokenFile_NeverUsed(t *testing.T) {
	emptyCertStore(t)
	path := filepath.Join(t.TempDir(), "registration-token")
	writeSafeTokenFile(t, path, unsafeTokenContent)
	makeReadableByOthers(t, path)
	sink := &recordingSink{}
	clock := &fakeClock{now: time.Unix(0, 0), onSleep: stopAfter(5)}
	token, err := waitForEnrollment(context.Background(), path, clock.waiter(sink), logging.NewNoopLogger())
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, token)
	assert.Equal(t, []string{"token_file.permissions"}, sink.keys())
}

func TestWaitForEnrollment_CorruptIdentityNoToken_StaysWaitingAndCreatesNothing(t *testing.T) {
	dir := emptyCertStore(t)
	corrupt := filepath.Join(dir, identityFileName)
	require.NoError(t, os.WriteFile(corrupt, []byte("{not json"), 0o600))
	sink := &recordingSink{}
	clock := &fakeClock{now: time.Unix(0, 0), onSleep: stopAfter(6)}
	token, err := waitForEnrollment(context.Background(), "", clock.waiter(sink), logging.NewNoopLogger())
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, token)
	assert.Equal(t, []string{reasonIdentityUnusable}, sink.keys())

	entries, readErr := os.ReadDir(dir)
	require.NoError(t, readErr)
	require.Len(t, entries, 1, "no identity or key is created next to the corrupt one")
	b, readErr := os.ReadFile(corrupt)
	require.NoError(t, readErr)
	assert.Equal(t, "{not json", string(b))
}

// TestRunStewardInternal_NoTokenNoIdentityNoConfig_KeepsRunning fails if the old
// immediate `return nil` is restored.
func TestRunStewardInternal_NoTokenNoIdentityNoConfig_KeepsRunning(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	emptyCertStore(t)
	prevSink := newSystemLogSink
	newSystemLogSink = func() systemLogWriter { return nil }
	t.Cleanup(func() { newSystemLogSink = prevSink })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runStewardInternal(ctx, "", "", "", nil) }()
	select {
	case err := <-done:
		t.Fatalf("steward exited with no identity and no token: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "cancellation is a clean shutdown")
	case <-time.After(5 * time.Second):
		t.Fatal("steward did not stop after cancellation")
	}
}

// TestRunStewardInternal_TokenFileAppears_EnrollsWithRealController starts with
// no token, then writes a valid registration token file: the same process
// registers with the real controller API without a restart.
func TestRunStewardInternal_TokenFileAppears_EnrollsWithRealController(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())
	emptyCertStore(t)
	skipWithoutHostAttributes(t)
	controller := newCloneTestController(t, "steward-unrelated")

	saved := ControllerURL
	ControllerURL = controller.server.URL
	t.Cleanup(func() { ControllerURL = saved })
	prevSink := newSystemLogSink
	newSystemLogSink = func() systemLogWriter { return nil }
	prevWaiter := newEnrollmentWaiter
	newEnrollmentWaiter = func(sink systemLogWriter) enrollmentWaiter {
		w := defaultEnrollmentWaiter(sink)
		w.sleep = func(ctx context.Context, _ time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
				return nil
			}
		}
		return w
	}
	t.Cleanup(func() { newSystemLogSink, newEnrollmentWaiter = prevSink, prevWaiter })

	path := filepath.Join(t.TempDir(), "registration-token")
	ctx, cancel := context.WithCancel(withRegTokenFile(context.Background(), path))
	done := make(chan error, 1)
	go func() { done <- runStewardInternal(ctx, "", "", "", nil) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			assert.NoError(t, err, "cancellation is a clean shutdown")
		case <-time.After(10 * time.Second):
			t.Error("steward did not stop after cancellation")
		}
	})

	time.Sleep(300 * time.Millisecond)
	assert.Zero(t, controller.registerHits.Load(), "no registration without a token")
	writeSafeTokenFile(t, path, "cfgms_reg_clone_test")

	require.Eventually(t, func() bool { return controller.registerHits.Load() > 0 }, 30*time.Second, 50*time.Millisecond,
		"the steward must register once the token file appears")
	select {
	case err := <-done:
		t.Fatalf("steward exited: %v", err)
	default:
	}
}
