// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config_test

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

const (
	lockHelperEnv     = "CFGMS_ATOMIC_LOCK_HELPER"
	lockHelperRoot    = "CFGMS_ATOMIC_LOCK_ROOT"
	lockHelperCount   = "CFGMS_ATOMIC_LOCK_COUNT"
	lockHelperTenant  = "tenant-lock-process"
	lockHelperNs      = "atomic"
	lockHelperName    = "shared"
	lockHelperHolding = "HOLDING"
)

func lockHelperKey() *cfgconfig.ConfigKey {
	return &cfgconfig.ConfigKey{TenantID: lockHelperTenant, Namespace: lockHelperNs, Name: lockHelperName}
}

// TestAtomicLockHelperProcess is the child side of TestAtomicLock_CrossProcess.
// It is not a real test: the parent re-executes this binary with
// CFGMS_ATOMIC_LOCK_HELPER set to "increment" or "hold".
//
//	increment  performs CFGMS_ATOMIC_LOCK_COUNT increments of the shared key.
//	hold       prints HOLDING from inside fn, then blocks until killed.
func TestAtomicLockHelperProcess(t *testing.T) {
	mode := os.Getenv(lockHelperEnv)
	if mode == "" {
		return
	}
	store, err := newFlatfileAt(os.Getenv(lockHelperRoot))
	if err != nil {
		_, _ = os.Stderr.WriteString("helper: store: " + err.Error() + "\n")
		os.Exit(2)
	}
	key := lockHelperKey()
	ctx := context.Background()
	switch mode {
	case "increment":
		n, _ := strconv.Atoi(os.Getenv(lockHelperCount))
		for i := 0; i < n; i++ {
			if err := cfgconfig.AtomicUpdate(ctx, store, key, incrementFn(key, 0)); err != nil {
				_, _ = os.Stderr.WriteString("helper: increment: " + err.Error() + "\n")
				os.Exit(3)
			}
		}
		os.Exit(0)
	case "hold":
		err := cfgconfig.AtomicUpdate(ctx, store, key, func(*cfgconfig.ConfigEntry) (*cfgconfig.ConfigEntry, error) {
			_, _ = os.Stdout.WriteString(lockHelperHolding + "\n")
			select {} // hold the lock until the parent kills this process
		})
		_, _ = os.Stderr.WriteString("helper: hold returned: " + errString(err) + "\n")
		os.Exit(4)
	default:
		os.Exit(2)
	}
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

func spawnLockHelper(t *testing.T, mode, root string, count int) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run=^TestAtomicLockHelperProcess$") //nolint:gosec // re-exec of this test binary
	cmd.Env = append(os.Environ(),
		lockHelperEnv+"="+mode,
		lockHelperRoot+"="+root,
		lockHelperCount+"="+strconv.Itoa(count),
	)
	cmd.Stderr = os.Stderr
	return cmd
}

func TestAtomicLock_CrossProcess(t *testing.T) {
	t.Run("two processes lose no increment", func(t *testing.T) {
		root := t.TempDir()
		store, err := newFlatfileAt(root)
		require.NoError(t, err)
		const perChild = 20

		a := spawnLockHelper(t, "increment", root, perChild)
		b := spawnLockHelper(t, "increment", root, perChild)
		require.NoError(t, a.Start())
		require.NoError(t, b.Start())
		assert.NoError(t, a.Wait())
		assert.NoError(t, b.Wait())

		got, err := store.GetConfig(context.Background(), lockHelperKey())
		require.NoError(t, err)
		assert.Equal(t, strconv.Itoa(2*perChild), string(got.Data), "no increment may be lost across processes")
	})

	t.Run("killed holder releases the lock", func(t *testing.T) {
		root := t.TempDir()
		store, err := newFlatfileAt(root)
		require.NoError(t, err)

		child := spawnLockHelper(t, "hold", root, 0)
		stdout, err := child.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, child.Start())
		killed := false
		t.Cleanup(func() {
			if !killed {
				_ = child.Process.Kill()
				_ = child.Wait()
			}
		})

		line, err := bufio.NewReader(stdout).ReadString('\n')
		require.NoError(t, err, "child must report that it holds the lock")
		require.Equal(t, lockHelperHolding+"\n", line)

		require.NoError(t, child.Process.Kill())
		killed = true
		_ = child.Wait() // a killed child reports a non-nil exit error

		key := lockHelperKey()
		start := time.Now()
		err = cfgconfig.AtomicUpdate(context.Background(), store, key, incrementFn(key, 0))
		require.NoError(t, err, "the kernel releases a dead holder's lock; no stale wait")
		assert.Less(t, time.Since(start), queueTestAcquireTimeout)

		got, err := store.GetConfig(context.Background(), key)
		require.NoError(t, err)
		assert.Equal(t, "1", string(got.Data))
	})
}
