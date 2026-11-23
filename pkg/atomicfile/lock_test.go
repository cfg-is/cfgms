// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package atomicfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockFile_ExcludesSecondLockOnSamePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	unlock, err := LockFile(context.Background(), path)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	second, err := LockFile(ctx, path)
	assert.Nil(t, second)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond, "must wait for the context, not fail at once")

	unlock()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	unlock2, err := LockFile(ctx2, path)
	require.NoError(t, err)
	unlock2()

	_, statErr := os.Stat(path)
	assert.NoError(t, statErr, "the lock file persists after unlock")
}

func TestLockFile_CancelledContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unlock, err := LockFile(ctx, path)
	assert.Nil(t, unlock)
	assert.ErrorIs(t, err, context.Canceled)

	// Cancelled while waiting on a held lock.
	held, err := LockFile(context.Background(), path)
	require.NoError(t, err)
	defer held()
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel2)
	_, err = LockFile(ctx2, path)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLockFile_UnlockIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	unlock, err := LockFile(context.Background(), path)
	require.NoError(t, err)
	unlock()
	unlock()

	again, err := LockFile(context.Background(), path)
	require.NoError(t, err)
	again()
}

func TestLockFile_MissingDirectoryFailsAtOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "k.lock")
	unlock, err := LockFile(context.Background(), path)
	assert.Nil(t, unlock)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, context.DeadlineExceeded)
}
