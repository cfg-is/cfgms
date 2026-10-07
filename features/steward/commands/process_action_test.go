// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const processHelperEnv = "CFGMS_PROCESS_ACTION_HELPER"

// TestMain lets the test binary double as the child process the tests act on.
func TestMain(m *testing.M) {
	if os.Getenv(processHelperEnv) == "1" {
		time.Sleep(10 * time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type testChild struct {
	pid   int
	image string
	done  chan struct{}
}

// spawnChild starts a real child process (this test binary in helper mode).
func spawnChild(t *testing.T) *testChild {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skipf("process control is unsupported on %s", runtime.GOOS)
	}
	exe, err := os.Executable()
	require.NoError(t, err)
	p, err := os.StartProcess(exe, []string{exe}, &os.ProcAttr{
		Env:   append(os.Environ(), processHelperEnv+"=1"),
		Files: []*os.File{nil, nil, nil},
	})
	require.NoError(t, err)
	c := &testChild{pid: p.Pid, image: filepath.Base(exe), done: make(chan struct{})}
	go func() { _, _ = p.Wait(); close(c.done) }()
	t.Cleanup(func() { _ = p.Kill() })
	return c
}

func (c *testChild) exited(d time.Duration) bool {
	select {
	case <-c.done:
		return true
	case <-time.After(d):
		return false
	}
}

func processParams(image string) map[string]string { return map[string]string{"image": image} }

func TestProcessAction_EndSuspendResumeChild(t *testing.T) {
	f := newActionFixture(t)
	child := spawnChild(t)
	name := strconv.Itoa(child.pid)

	require.NoError(t, f.run(f.signedAction(t, "process.suspend", "process", name, processParams(child.image))))
	assert.Equal(t, "ok", f.lastEvent(t).Details["result_code"])
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/" + name + "/stat")
		require.NoError(t, err)
		s := string(b)
		assert.Equal(t, byte('T'), s[strings.LastIndexByte(s, ')')+2], "child must be stopped")
	}

	require.NoError(t, f.run(f.signedAction(t, "process.resume", "process", name, processParams(child.image))))
	assert.Equal(t, "ok", f.lastEvent(t).Details["result_code"])
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile("/proc/" + name + "/stat")
		require.NoError(t, err)
		s := string(b)
		assert.NotEqual(t, byte('T'), s[strings.LastIndexByte(s, ')')+2], "child must be running")
	}
	assert.False(t, child.exited(100*time.Millisecond))

	require.NoError(t, f.run(f.signedAction(t, "process.end", "process", name, processParams(child.image))))
	assert.Equal(t, "ok", f.lastEvent(t).Details["result_code"])
	assert.True(t, child.exited(10*time.Second), "child must be gone")
}

func TestProcessAction_EndEscalatesPastSuspendedChild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SIGSTOP/SIGKILL escalation is Linux-specific")
	}
	f := newActionFixture(t)
	child := spawnChild(t)
	name := strconv.Itoa(child.pid)
	require.NoError(t, f.run(f.signedAction(t, "process.suspend", "process", name, processParams(child.image))))
	require.NoError(t, f.run(f.signedAction(t, "process.end", "process", name, processParams(child.image))))
	assert.True(t, child.exited(15*time.Second))
}

func TestProcessAction_OwnPIDSelfProtect(t *testing.T) {
	f := newActionFixture(t)
	exe, err := os.Executable()
	require.NoError(t, err)
	for _, verb := range []string{"process.end", "process.suspend", "process.resume"} {
		require.NoError(t, f.run(f.signedAction(t, verb, "process", strconv.Itoa(os.Getpid()), processParams(filepath.Base(exe)))))
		ev := f.lastEvent(t)
		assert.Equal(t, "self_protect", ev.Details["result_code"], verb)
		assert.Equal(t, 1, ev.Details["exit_code"])
	}
	// The steward (this process) is still running and responsive.
	require.NoError(t, f.run(f.signedAction(t, "process.suspend", "process", strconv.Itoa(os.Getppid()), processParams("x"))))
	assert.Equal(t, "self_protect", f.lastEvent(t).Details["result_code"], "parent must be protected")
}

func TestProcessAction_SystemPIDsRefused(t *testing.T) {
	pids := []string{"0", "1"}
	if runtime.GOOS == "windows" {
		pids = []string{"0", "4"}
	}
	for _, pid := range pids {
		f := newActionFixture(t)
		require.NoError(t, f.run(f.signedAction(t, "process.end", "process", pid, processParams("init"))))
		assert.Equal(t, "self_protect", f.lastEvent(t).Details["result_code"], pid)
	}
}

func TestProcessAction_ImageMismatchProcessChanged(t *testing.T) {
	f := newActionFixture(t)
	child := spawnChild(t)
	for _, verb := range []string{"process.end", "process.suspend", "process.resume"} {
		require.NoError(t, f.run(f.signedAction(t, verb, "process", strconv.Itoa(child.pid), processParams("not-the-image.exe"))))
		assert.Equal(t, "process_changed", f.lastEvent(t).Details["result_code"], verb)
	}
	assert.False(t, child.exited(300*time.Millisecond), "mismatched image must leave the process untouched")
}

func TestProcessAction_NotFound(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skipf("process control is unsupported on %s", runtime.GOOS)
	}
	f := newActionFixture(t)
	child := spawnChild(t)
	_ = child
	require.NoError(t, f.run(f.signedAction(t, "process.end", "process", "2147483646", processParams("x"))))
	assert.Equal(t, "not_found", f.lastEvent(t).Details["result_code"])
}

func TestProcessAction_InvalidRequestRejected(t *testing.T) {
	cases := map[string]struct {
		name       string
		parameters map[string]string
	}{
		"non numeric pid":  {"abc", processParams("x")},
		"no image":         {"123", nil},
		"extra parameter":  {"123", map[string]string{"image": "x", "force": "1"}},
		"image with slash": {"123", processParams("../bin/sh")},
		"empty image":      {"123", processParams("")},
		"pid out of range": {"99999999999", processParams("x")},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newActionFixture(t)
			before := f.eventCount()
			require.Error(t, f.run(f.signedAction(t, "process.end", "process", tc.name, tc.parameters)))
			assert.Equal(t, before, f.eventCount())
		})
	}
	f := newActionFixture(t)
	require.Error(t, f.run(f.signedAction(t, "process.end", "service", "123", processParams("x"))), "wrong target kind")
}
