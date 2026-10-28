// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ha"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const concurrentWriters = 24

type storeCase struct {
	name string
	new  func(t *testing.T) cfgconfig.ConfigStore
}

func lockingStores() []storeCase {
	return []storeCase{{"flatfile", newFlatfile}}
}

func allStores() []storeCase {
	return append(lockingStores(), storeCase{"database", newDatabase})
}

func uniqueKey(t *testing.T) *cfgconfig.ConfigKey {
	var b [6]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return &cfgconfig.ConfigKey{TenantID: "tenant-atomic", Namespace: "atomic", Name: hex.EncodeToString(b[:])}
}

func setCluster(t *testing.T, v bool) {
	cfgconfig.SetClusterConfigured(v)
	t.Cleanup(func() { cfgconfig.SetClusterConfigured(false) })
}

func TestAtomicUpdate_ConcurrentWritersLoseNoUpdate(t *testing.T) {
	for _, tc := range allStores() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.new(t)
			ctx := context.Background()
			key := uniqueKey(t)

			var wg sync.WaitGroup
			errs := make([]error, concurrentWriters)
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					errs[i] = cfgconfig.AtomicUpdate(ctx, store, key, func(cur *cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
						n := 0
						if cur != nil {
							n, _ = strconv.Atoi(string(cur.Data))
						}
						return &cfgconfig.ConfigEntry{Key: key, Data: []byte(strconv.Itoa(n + 1)),
							Format: cfgconfig.ConfigFormatJSON, CreatedBy: "t", UpdatedBy: "t"}, nil
					})
				}(i)
			}
			wg.Wait()
			for i, err := range errs {
				require.NoError(t, err, "writer %d", i)
			}
			got, err := store.GetConfig(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, strconv.Itoa(concurrentWriters), string(got.Data), "no increment may be lost")
		})
	}
}

func TestCreateIfAbsent_OnlyOneConcurrentCreatorWins(t *testing.T) {
	for _, tc := range allStores() {
		t.Run(tc.name, func(t *testing.T) {
			store := tc.new(t)
			ctx := context.Background()
			key := uniqueKey(t)

			var wins, exists int64
			var wg sync.WaitGroup
			for i := 0; i < concurrentWriters; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					err := cfgconfig.CreateIfAbsent(ctx, store, &cfgconfig.ConfigEntry{Key: key,
						Data: []byte(strconv.Itoa(i)), Format: cfgconfig.ConfigFormatJSON, CreatedBy: "t", UpdatedBy: "t"})
					switch {
					case err == nil:
						atomic.AddInt64(&wins, 1)
					case errors.Is(err, cfgconfig.ErrAlreadyExists):
						atomic.AddInt64(&exists, 1)
					default:
						t.Errorf("unexpected error: %v", err)
					}
				}(i)
			}
			wg.Wait()
			assert.Equal(t, int64(1), wins)
			assert.Equal(t, int64(concurrentWriters-1), exists)
		})
	}
}

func TestAtomicUpdate_FnErrorWritesNothing(t *testing.T) {
	store := newFlatfile(t)
	key := uniqueKey(t)
	boom := errors.New("boom")
	err := cfgconfig.AtomicUpdate(context.Background(), store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		return nil, boom
	})
	assert.ErrorIs(t, err, boom)
	_, getErr := store.GetConfig(context.Background(), key)
	assert.ErrorIs(t, getErr, cfgconfig.ErrConfigNotFound)
}

func TestAtomicUpdate_NilArguments(t *testing.T) {
	store := newFlatfile(t)
	assert.Error(t, cfgconfig.AtomicUpdate(context.Background(), nil, uniqueKey(t), nil))
	assert.Error(t, cfgconfig.AtomicUpdate(context.Background(), store, nil, nil))
	assert.Error(t, cfgconfig.CreateIfAbsent(context.Background(), store, nil))
}

// SQLite has no ConfigStore (config data uses flatfile or the database provider),
// so there is no sqlite store to take a lock on; pin that so the gap is visible.
func TestAtomicUpdate_SQLiteHasNoConfigStore(t *testing.T) {
	_, err := newSQLiteConfigStore(filepath.Join(t.TempDir(), "x.db"))
	assert.Error(t, err)
}

func TestClusterAtomic(t *testing.T) {
	assert.False(t, cfgconfig.ClusterAtomic(newFlatfile(t)))
	assert.True(t, cfgconfig.ClusterAtomic(newDatabase(t)))
}

func TestAtomicUpdate_ClusterModeWithFlatfile_RefusesWithTypedError(t *testing.T) {
	setCluster(t, true)
	store := newFlatfile(t)
	key := uniqueKey(t)
	called := false
	err := cfgconfig.AtomicUpdate(context.Background(), store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		called = true
		return &cfgconfig.ConfigEntry{Key: key, Data: []byte("x")}, nil
	})
	assert.ErrorIs(t, err, cfgconfig.ErrNotClusterAtomic)
	assert.False(t, called)
	err = cfgconfig.CreateIfAbsent(context.Background(), store, &cfgconfig.ConfigEntry{Key: key, Data: []byte("x")})
	assert.ErrorIs(t, err, cfgconfig.ErrNotClusterAtomic)
	_, getErr := store.GetConfig(context.Background(), key)
	assert.ErrorIs(t, getErr, cfgconfig.ErrConfigNotFound)
}

// The signal is configuration (ha.Config.IsClusterMode), never the live peer
// count: a cluster with a single live node must still refuse.
func TestAtomicUpdate_ClusterConfiguredSingleLiveNode_StillRefuses(t *testing.T) {
	haCfg := ha.DefaultConfig()
	haCfg.Mode = ha.ClusterMode
	require.True(t, haCfg.IsClusterMode())
	setCluster(t, haCfg.IsClusterMode())

	key := uniqueKey(t)
	err := cfgconfig.CreateIfAbsent(context.Background(), newFlatfile(t), &cfgconfig.ConfigEntry{Key: key, Data: []byte("x")})
	assert.ErrorIs(t, err, cfgconfig.ErrNotClusterAtomic)

	setCluster(t, false)
	err = cfgconfig.CreateIfAbsent(context.Background(), newFlatfile(t), &cfgconfig.ConfigEntry{Key: key, Data: []byte("x")})
	assert.NoError(t, err, "single-server mode may use the file lock")
}

// losingCAS is a real flatfile store whose CompareAndSwapConfig always loses the
// race to a rival writer, which commits its own value first.
type losingCAS struct {
	cfgconfig.ConfigStore
	cas int32
}

func (l *losingCAS) CompareAndSwapConfig(ctx context.Context, c *cfgconfig.ConfigEntry, _ int64) (int64, bool, error) {
	atomic.AddInt32(&l.cas, 1)
	rival := &cfgconfig.ConfigEntry{Key: c.Key, Data: []byte("rival"), Format: cfgconfig.ConfigFormatJSON, CreatedBy: "rival", UpdatedBy: "rival"}
	if err := l.StoreConfig(ctx, rival); err != nil {
		return 0, false, err
	}
	return 0, false, nil
}

func TestAtomicUpdate_RetryExhausted_NoBlindWrite(t *testing.T) {
	store := &losingCAS{ConfigStore: newFlatfile(t)}
	key := uniqueKey(t)
	err := cfgconfig.AtomicUpdate(context.Background(), store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
		return &cfgconfig.ConfigEntry{Key: key, Data: []byte("mine"), Format: cfgconfig.ConfigFormatJSON}, nil
	})
	assert.ErrorIs(t, err, cfgconfig.ErrAtomicRetryExhausted)
	assert.Greater(t, atomic.LoadInt32(&store.cas), int32(1), "must retry")
	got, getErr := store.GetConfig(context.Background(), key)
	require.NoError(t, getErr)
	assert.Equal(t, "rival", string(got.Data), "the helper must never write blindly")
}

func TestAtomicLock_DirectoryModeAndLocation(t *testing.T) {
	root := t.TempDir()
	store, err := newFlatfileAt(root)
	require.NoError(t, err)
	key := uniqueKey(t)
	require.NoError(t, cfgconfig.CreateIfAbsent(context.Background(), store,
		&cfgconfig.ConfigEntry{Key: key, Data: []byte("x"), Format: cfgconfig.ConfigFormatJSON}))

	dir := filepath.Join(root, ".atomic-locks")
	info, err := os.Stat(dir)
	require.NoError(t, err, "lock directory must live inside the store's own directory")
	assert.True(t, info.IsDir())
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "lock files are released")
	assert.True(t, strings.HasPrefix(dir, root))
}

// A store without a conditional write and without a private directory cannot be
// locked safely; the helper must refuse rather than fall back to os.TempDir().
type bareStore struct{ cfgconfig.ConfigStore }

func TestAtomicUpdate_NoLockDirRefuses(t *testing.T) {
	store := &bareStore{newFlatfile(t)}
	err := cfgconfig.CreateIfAbsent(context.Background(), store, &cfgconfig.ConfigEntry{Key: uniqueKey(t), Data: []byte("x")})
	assert.ErrorIs(t, err, cfgconfig.ErrNoAtomicLockDir)
}
