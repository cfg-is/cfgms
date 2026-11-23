// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config_test

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	// queueTestAcquireTimeout mirrors the unexported atomicLockAcquireTimeout (5s).
	queueTestAcquireTimeout = 5 * time.Second
	lockTimeoutText         = "timed out waiting for atomic-update lock"
)

func incrementFn(key *cfgconfig.ConfigKey, hold time.Duration) func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
	return func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		n := 0
		if cur != nil {
			n, _ = strconv.Atoi(string(cur.Data))
		}
		time.Sleep(hold)
		return &cfgconfig.ConfigEntry{Key: key, Data: []byte(strconv.Itoa(n + 1)),
			Format: cfgconfig.ConfigFormatJSON, CreatedBy: "t", UpdatedBy: "t"}, nil
	}
}

// A queue of live holders that each make progress is not a timeout: the total
// wait exceeds atomicLockAcquireTimeout, yet every writer succeeds. Under the
// former per-call deadline the last writers failed with the timeout error.
func TestAtomicLock_QueueLongerThanTimeoutSucceeds(t *testing.T) {
	store := newFlatfile(t)
	ctx := context.Background()
	key := uniqueKey(t)
	const hold = 300 * time.Millisecond

	start := time.Now()
	var wg sync.WaitGroup
	errs := make([]error, concurrentWriters)
	for i := 0; i < concurrentWriters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = cfgconfig.AtomicUpdate(ctx, store, key, incrementFn(key, hold))
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		require.NoError(t, err, "writer %d", i)
	}
	got, err := store.GetConfig(ctx, key)
	require.NoError(t, err)
	assert.Equal(t, strconv.Itoa(concurrentWriters), string(got.Data))
	assert.Greater(t, elapsed, queueTestAcquireTimeout,
		"the queue must outlast the acquire timeout for this test to prove anything")
}

// A holder that never releases makes the next waiter fail closed within the
// acquire timeout, and the waiter writes nothing.
func TestAtomicLock_StuckHolderFailsClosed(t *testing.T) {
	store := newFlatfile(t)
	ctx := context.Background()
	key := uniqueKey(t)

	inFn := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- cfgconfig.AtomicUpdate(ctx, store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			close(inFn)
			<-release
			return &cfgconfig.ConfigEntry{Key: key, Data: []byte("holder"), Format: cfgconfig.ConfigFormatJSON}, nil
		})
	}()
	<-inFn

	start := time.Now()
	called := false
	err := cfgconfig.AtomicUpdate(ctx, store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		called = true
		return &cfgconfig.ConfigEntry{Key: key, Data: []byte("waiter"), Format: cfgconfig.ConfigFormatJSON}, nil
	})
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Contains(t, err.Error(), lockTimeoutText)
	assert.Less(t, elapsed, queueTestAcquireTimeout+2*time.Second)
	assert.False(t, called, "fn must not run without the lock")

	close(release)
	require.NoError(t, <-holderDone)
	got, getErr := store.GetConfig(ctx, key)
	require.NoError(t, getErr)
	assert.Equal(t, "holder", string(got.Data), "the timed-out waiter writes nothing")
}

// A queued waiter whose context is cancelled returns the context error, writes
// nothing, and does not stall the waiter behind it.
func TestAtomicLock_CancelledContextReturnsCtxErr(t *testing.T) {
	store := newFlatfile(t)
	ctx := context.Background()
	key := uniqueKey(t)

	inFn := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- cfgconfig.AtomicUpdate(ctx, store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			close(inFn)
			<-release
			return &cfgconfig.ConfigEntry{Key: key, Data: []byte("1"), Format: cfgconfig.ConfigFormatJSON}, nil
		})
	}()
	<-inFn

	cancelCtx, cancel := context.WithCancel(ctx)
	cancelledDone := make(chan error, 1)
	cancelledCalled := false
	go func() {
		cancelledDone <- cfgconfig.AtomicUpdate(cancelCtx, store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			cancelledCalled = true
			return &cfgconfig.ConfigEntry{Key: key, Data: []byte("cancelled"), Format: cfgconfig.ConfigFormatJSON}, nil
		})
	}()
	time.Sleep(100 * time.Millisecond) // let it queue behind the holder

	// A third waiter queued behind the one that will be cancelled.
	thirdDone := make(chan error, 1)
	go func() {
		thirdDone <- cfgconfig.AtomicUpdate(ctx, store, key, incrementFn(key, 0))
	}()
	time.Sleep(100 * time.Millisecond)

	cancel()
	err := <-cancelledDone
	assert.ErrorIs(t, err, context.Canceled)
	assert.False(t, cancelledCalled)

	close(release)
	require.NoError(t, <-holderDone)
	require.NoError(t, <-thirdDone, "a cancelled waiter must not stall the one behind it")
	got, getErr := store.GetConfig(ctx, key)
	require.NoError(t, getErr)
	assert.Equal(t, "2", string(got.Data))
}

// An already-cancelled context takes no lock and writes nothing.
func TestAtomicLock_AlreadyCancelledContext(t *testing.T) {
	store := newFlatfile(t)
	key := uniqueKey(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := cfgconfig.AtomicUpdate(ctx, store, key, incrementFn(key, 0))
	assert.ErrorIs(t, err, context.Canceled)
	_, getErr := store.GetConfig(context.Background(), key)
	assert.ErrorIs(t, getErr, cfgconfig.ErrConfigNotFound)
}
