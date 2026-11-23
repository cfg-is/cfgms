// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sops

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	casHelperEnv     = "CFGMS_CAS_LOCK_HELPER"
	casHelperDir     = "CFGMS_CAS_LOCK_DIR"
	casHelperCounter = "CFGMS_CAS_LOCK_COUNTER"
	casHelperCount   = "CFGMS_CAS_LOCK_COUNT"
	casHelperTenant  = "tenant-cas-process"
	casHelperKey     = "shared"
	casHelperHolding = "HOLDING"
)

// TestCASLockHelperProcess is the child side of TestCASLock_CrossProcess. It is
// not a real test: the parent re-executes this binary with CFGMS_CAS_LOCK_HELPER
// set to "increment" or "hold".
//
//	increment  performs CFGMS_CAS_LOCK_COUNT increments of the counter file.
//	hold       prints HOLDING while holding the lock, then blocks until killed.
func TestCASLockHelperProcess(t *testing.T) {
	mode := os.Getenv(casHelperEnv)
	if mode == "" {
		return
	}
	fail := func(code int, msg string) {
		_, _ = os.Stderr.WriteString("helper: " + msg + "\n")
		os.Exit(code)
	}
	dir := os.Getenv(casHelperDir)
	ctx := context.Background()
	switch mode {
	case "increment":
		counter := os.Getenv(casHelperCounter)
		n, _ := strconv.Atoi(os.Getenv(casHelperCount))
		for i := 0; i < n; i++ {
			release, err := acquireCASLock(ctx, dir, casHelperTenant, casHelperKey)
			if err != nil {
				fail(3, "acquire: "+err.Error())
			}
			cur, err := readCounter(counter)
			if err != nil {
				fail(4, "read: "+err.Error())
			}
			time.Sleep(time.Millisecond) // widen the read-modify-write window
			if err := os.WriteFile(counter, []byte(strconv.Itoa(cur+1)), 0o600); err != nil {
				fail(5, "write: "+err.Error())
			}
			release()
		}
		os.Exit(0)
	case "hold":
		if _, err := acquireCASLock(ctx, dir, casHelperTenant, casHelperKey); err != nil {
			fail(3, "acquire: "+err.Error())
		}
		_, _ = os.Stdout.WriteString(casHelperHolding + "\n")
		select {} // hold the lock until the parent kills this process
	default:
		os.Exit(2)
	}
}

func readCounter(path string) (int, error) {
	b, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

func spawnCASLockHelper(t *testing.T, mode, dir, counter string, count int) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run=^TestCASLockHelperProcess$") //nolint:gosec // re-exec of this test binary
	cmd.Env = append(os.Environ(),
		casHelperEnv+"="+mode,
		casHelperDir+"="+dir,
		casHelperCounter+"="+counter,
		casHelperCount+"="+strconv.Itoa(count),
	)
	cmd.Stderr = os.Stderr
	return cmd
}

// startHoldingHelper starts a child that holds the lock on the helper key and
// returns once it has reported HOLDING. The child is killed on cleanup.
func startHoldingHelper(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	child := spawnCASLockHelper(t, "hold", dir, "", 0)
	stdout, err := child.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, child.Start())
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err, "child must report that it holds the lock")
	require.Equal(t, casHelperHolding+"\n", line)
	return child
}

func TestCASLock_CrossProcess(t *testing.T) {
	t.Run("two processes lose no increment", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), casLockSubdir)
		counter := filepath.Join(t.TempDir(), "counter")
		const perChild = 20

		a := spawnCASLockHelper(t, "increment", dir, counter, perChild)
		b := spawnCASLockHelper(t, "increment", dir, counter, perChild)
		require.NoError(t, a.Start())
		require.NoError(t, b.Start())
		assert.NoError(t, a.Wait())
		assert.NoError(t, b.Wait())

		got, err := readCounter(counter)
		require.NoError(t, err)
		assert.Equal(t, 2*perChild, got, "no increment may be lost across processes")
	})

	t.Run("killed holder releases the lock", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), casLockSubdir)
		child := startHoldingHelper(t, dir)

		require.NoError(t, child.Process.Kill())
		_ = child.Wait() // a killed child reports a non-nil exit error

		start := time.Now()
		release, err := acquireCASLock(context.Background(), dir, casHelperTenant, casHelperKey)
		require.NoError(t, err, "the kernel releases a dead holder's lock; no stale wait")
		release()
		assert.Less(t, time.Since(start), casLockAcquireTimeout)
	})
}
