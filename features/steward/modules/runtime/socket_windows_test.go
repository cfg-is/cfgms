// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package runtime

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/modules/contract"
)

// idleProcessPID is process 0, the System Idle Process, which can never be a
// named pipe server. It stands in for "some process other than the module this
// runtime fork/exec'd" without the test having to spawn a second process: the
// verification compares the pipe's real server pid against the one the runtime
// expects, so any non-matching value exercises the same branch a real squatter
// would.
const idleProcessPID = 0

// startTestPipeServer creates a module pipe at addr using the real module-side
// listener (contract.Listen, owner-only DACL) and keeps accepting on it until
// the test ends.
//
// The accept loop is required for a client to connect at all: go-winio creates a
// listener's first instance without read/write access, so every client open
// fails with ERROR_PIPE_BUSY until something calls Accept.
func startTestPipeServer(t *testing.T, addr string) {
	t.Helper()

	lis, err := contract.Listen(addr)
	require.NoError(t, err, "create test module pipe %s", addr)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, acceptErr := lis.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = lis.Close()
		<-done
	})
}

// testPipePath returns a pipe path for this test, built by the code under test
// so the tests exercise the real naming scheme.
func testPipePath(t *testing.T) string {
	t.Helper()
	path, err := makeSocketPath("", t.Name(), 1)
	require.NoError(t, err)
	return path
}

// TestMakeSocketPath_NameIsUnguessable asserts the module pipe name carries
// crypto/rand entropy and is therefore not derivable from the module name and
// the per-process counter.
//
// This is the regression test for local pipe squatting: with the old
// `\\.\pipe\cfgms-module-<name>-<id>` scheme every stdlib module's pipe name
// was known ahead of time, so any local user could pre-create it, take
// ownership of the name (the module's own contract.Listen then fails closed and
// the module exits) and serve the steward's Apply payloads itself.
func TestMakeSocketPath_NameIsUnguessable(t *testing.T) {
	const prefix = `\\.\pipe\cfgms-module-file-1-`

	first, err := makeSocketPath("", "file", 1)
	require.NoError(t, err)
	second, err := makeSocketPath("", "file", 1)
	require.NoError(t, err)

	assert.NotEqual(t, `\\.\pipe\cfgms-module-file-1`, first,
		"pipe name must not be the fully deterministic module-name+id form")
	require.True(t, strings.HasPrefix(first, prefix),
		"pipe name %q must keep the %q prefix for diagnosability", first, prefix)
	assert.NotEqual(t, first, second,
		"two instances of the same module and id must not share a pipe name")

	nonce := strings.TrimPrefix(first, prefix)
	assert.Len(t, nonce, 2*pipeNonceBytes,
		"pipe name %q must end in %d hex chars of entropy", first, 2*pipeNonceBytes)
	_, decodeErr := hex.DecodeString(nonce)
	assert.NoError(t, decodeErr, "pipe name suffix %q must be hex", nonce)
}

// TestDialVerifiedPipe_AcceptsServerProcess verifies the happy path: a pipe
// served by the expected process is dialable and the connection is returned.
func TestDialVerifiedPipe_AcceptsServerProcess(t *testing.T) {
	addr := testPipePath(t)
	startTestPipeServer(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialVerifiedPipe(ctx, addr, os.Getpid())
	require.NoError(t, err, "dial must succeed when the pipe server is the expected process")
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())
}

// TestDialVerifiedPipe_RejectsForeignServerProcess verifies that a pipe served
// by any other process is refused, which is what stops a local squatter that
// holds the name from receiving module payloads.
func TestDialVerifiedPipe_RejectsForeignServerProcess(t *testing.T) {
	addr := testPipePath(t)
	startTestPipeServer(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialVerifiedPipe(ctx, addr, idleProcessPID)
	require.Error(t, err, "dial must fail when the pipe server is not the module process")
	assert.Nil(t, conn, "no connection may be handed back on a server mismatch")
	assert.ErrorIs(t, err, errPipeServerMismatch)
	assert.Contains(t, err.Error(), "want module process",
		"error must name the process the runtime expected; got %v", err)
}

// TestVerifyPipeServer_RejectsConnectionWithoutHandle asserts the check fails
// closed when the connection exposes no OS handle to identify the server with,
// rather than treating an unverifiable peer as verified.
func TestVerifyPipeServer_RejectsConnectionWithoutHandle(t *testing.T) {
	client, server := net.Pipe()
	defer func() {
		_ = client.Close()
		_ = server.Close()
	}()

	err := verifyPipeServer(client, os.Getpid())
	require.Error(t, err)
	assert.ErrorIs(t, err, errPipeServerMismatch)
}

// TestWaitForSocket_ForeignServerDoesNotSatisfyWait asserts that a pipe held by
// another process does not count as "the module is listening", and that the wait
// says so at once instead of running to its deadline.
//
// This is the second half of the squatting fix: waitForSocket previously
// returned as soon as *anything* accepted a connection on the name, so a
// squatter satisfied the wait and went on to answer the handshake.
func TestWaitForSocket_ForeignServerDoesNotSatisfyWait(t *testing.T) {
	addr := testPipePath(t)
	startTestPipeServer(t, addr)

	const ctxTimeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	// waitForSocket runs on its own goroutine, raced here against a watchdog
	// well past ctxTimeout: dialVerifiedPipe's ctx.Done race (socket_windows.go)
	// is what makes waitForSocket honor ctxTimeout even when the underlying pipe
	// dial stalls, but if that guarantee ever regresses this bound turns the
	// symptom back into a test failure instead of the full go test -timeout
	// panic that surfaced it (a 10-minute hang with no assertion output).
	const watchdogBound = 2 * ctxTimeout
	type result struct {
		err     error
		elapsed time.Duration
	}
	resultCh := make(chan result, 1)
	start := time.Now()
	go func() {
		err := waitForSocket(ctx, addr, idleProcessPID)
		resultCh <- result{err: err, elapsed: time.Since(start)}
	}()

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(watchdogBound):
		t.Fatalf("waitForSocket did not return within %s of its %s ctx deadline", watchdogBound, ctxTimeout)
	}

	require.Error(t, res.err, "a pipe served by another process must not satisfy the wait")
	assert.ErrorIs(t, res.err, errPipeServerMismatch)
	assert.Contains(t, res.err.Error(), "not served by the module",
		"error must explain that another process holds the name; got %v", res.err)
	assert.Less(t, res.elapsed, 5*time.Second,
		"a foreign server is terminal and must be reported at once, not after the deadline (took %s)", res.elapsed)
}

// TestWaitForSocket_ReturnsOnceExpectedServerListens verifies the wait succeeds
// against a pipe served by the expected process.
func TestWaitForSocket_ReturnsOnceExpectedServerListens(t *testing.T) {
	addr := testPipePath(t)
	startTestPipeServer(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, waitForSocket(ctx, addr, os.Getpid()))
}
