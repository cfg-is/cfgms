// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
)

const atomicMaxAttempts = 16

var (
	// ErrNotClusterAtomic is returned when the controller is configured as a
	// multi-node cluster and the store cannot make a read-modify-write atomic
	// across nodes. The operation never proceeds.
	ErrNotClusterAtomic = errors.New(
		"config store is not cluster-atomic: multi-node controllers require the database provider")

	// ErrAtomicRetryExhausted is returned when compare-and-swap kept losing the
	// race. Nothing was written.
	ErrAtomicRetryExhausted = errors.New("atomic update retries exhausted")

	// ErrAlreadyExists is returned by CreateIfAbsent when an entry exists.
	ErrAlreadyExists = errors.New("config entry already exists")
)

var clusterConfigured atomic.Bool

// SetClusterConfigured records whether the controller is configured as a
// multi-node cluster (pkg/ha Config.IsClusterMode()). It is decided from
// configuration, never from live peer count. Call once at controller startup.
func SetClusterConfigured(v bool) { clusterConfigured.Store(v) }

// ClusterConfigured reports the value last passed to SetClusterConfigured.
func ClusterConfigured() bool { return clusterConfigured.Load() }

// ClusterAtomic reports whether store's atomic updates hold across controller
// nodes: true only for a store implementing ConditionalConfigStore. A per-key
// file lock serializes processes on one host only.
func ClusterAtomic(store ConfigStore) bool {
	_, ok := store.(ConditionalConfigStore)
	return ok
}

func checkCluster(store ConfigStore) error {
	if ClusterConfigured() && !ClusterAtomic(store) {
		return ErrNotClusterAtomic
	}
	return nil
}

// AtomicUpdate performs a read-modify-write on key. fn receives the current
// entry (nil if absent) and returns the entry to store; returning an error
// aborts without writing. With a ConditionalConfigStore it uses
// CompareAndSwapConfig with bounded retry (fn may run more than once); otherwise
// it holds a per-key file lock in the store's own directory.
func AtomicUpdate(ctx context.Context, store ConfigStore, key *ConfigKey, fn func(current *ConfigEntry) (*ConfigEntry, error)) error {
	if store == nil || key == nil || fn == nil {
		return errors.New("atomic update requires a store, key and function")
	}
	if err := checkCluster(store); err != nil {
		return err
	}
	if cond, ok := store.(ConditionalConfigStore); ok {
		return atomicUpdateCAS(ctx, cond, key, fn)
	}
	dir, err := atomicLockDir(store)
	if err != nil {
		return err
	}
	release, err := acquireAtomicLock(ctx, dir, key)
	if err != nil {
		return err
	}
	defer release()

	current, err := readCurrent(ctx, store, key)
	if err != nil {
		return err
	}
	next, err := fn(current)
	if err != nil {
		return err
	}
	if next == nil {
		return errors.New("atomic update function returned no entry")
	}
	next.Key = key
	return store.StoreConfig(ctx, next)
}

func atomicUpdateCAS(ctx context.Context, store ConditionalConfigStore, key *ConfigKey, fn func(*ConfigEntry) (*ConfigEntry, error)) error {
	for attempt := 0; attempt < atomicMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		current, err := readCurrent(ctx, store, key)
		if err != nil {
			return err
		}
		var expected int64
		if current != nil {
			expected = current.Version
		}
		next, err := fn(current)
		if err != nil {
			return err
		}
		if next == nil {
			return errors.New("atomic update function returned no entry")
		}
		next.Key = key
		_, ok, err := store.CompareAndSwapConfig(ctx, next, expected)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrAtomicRetryExhausted
}

// readCurrent returns the stored entry, or nil if none exists.
func readCurrent(ctx context.Context, store ConfigStore, key *ConfigKey) (*ConfigEntry, error) {
	entry, err := store.GetConfig(ctx, key)
	if err != nil {
		if errors.Is(err, ErrConfigNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read current config: %w", err)
	}
	return entry, nil
}

// CreateIfAbsent stores entry only if nothing exists under entry.Key; otherwise
// it returns ErrAlreadyExists. Exactly one concurrent creator wins.
func CreateIfAbsent(ctx context.Context, store ConfigStore, entry *ConfigEntry) error {
	if entry == nil || entry.Key == nil {
		return errors.New("create-if-absent requires an entry with a key")
	}
	return AtomicUpdate(ctx, store, entry.Key, func(current *ConfigEntry) (*ConfigEntry, error) {
		if current != nil {
			return nil, ErrAlreadyExists
		}
		return entry, nil
	})
}
