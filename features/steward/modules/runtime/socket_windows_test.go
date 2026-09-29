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

// pipeCloseTimeout bounds how long a test's cleanup waits for
// win32PipeListener.Close (go-winio) to return.
//
// Root cause (Issue #4438): go-winio v0.6.2's win32PipeListener has a
// state-tracking gap between Close and its listenerRoutine goroutine. Close
// aborts a pending connect by closing the in-flight server pipe instance and
// reading the aborted connect's error (pipe.go's makeConnectedServerPipe);
// that error is only translated to the ErrPipeListenerClosed sentinel when it
// is exactly nil or ErrFileClosed. An abort mid-ConnectNamedPipe can surface
// as a different error (observed: the goroutine that owns the pending accept
// exits, but listenerRoutine's own `closed = err == ErrPipeListenerClosed`
// check evaluates false), so listenerRoutine loops back to its idle select
// forever instead of exiting and closing its internal doneCh — leaving
// Close's own `<-l.doneCh` wait (pipe.go:578) blocked permanently. Close
// takes no context, so nothing above it in the call chain can bound it either
// — this is not a ctx violation in our code, it is an unbounded call in a
// dependency with no ctx parameter at all.
//
// Confirmed from the goroutine dump attached to CI run 36578160588, job
// 109439103141 (gh api repos/cfg-is/cfgms/actions/jobs/109439103141/logs):
// at the 10-minute panic, the test's own accept-loop goroutine (below) had
// already exited — proving it received the abort's error and returned — while
// win32PipeListener.Close sat parked on <-l.doneCh (pipe.go:578) and
// listenerRoutine sat parked back in its idle select (pipe.go:462), exactly
// the shape above. This is what actually hung, not dialVerifiedPipe or
// waitForSocket in socket_windows.go: those already bound every syscall on
// their own path by ctx as of commit 470bf8f38, which is unrelated to this
// gap in go-winio's own Close/Accept rendezvous. Racing Close on its own
// goroutine here — the only place client code can intervene, since Close has
// no ctx parameter to honor — turns an indefinite hang of the whole test
// binary into a bounded, loud test failure instead.
const pipeCloseTimeout = 5 * time.Second

// closeTestPipeListener closes lis with a hard bound; see pipeCloseTimeout.
func closeTestPipeListener(t *testing.T, addr string, lis net.Listener) {
	t.Helper()
	closed := make(chan struct{})
	go func() {
		_ = lis.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(pipeCloseTimeout):
		t.Errorf("pipe listener for %s did not close within %s (see pipeCloseTimeout)", addr, pipeCloseTimeout)
	}
}

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
		closeTestPipeListener(t, addr, lis)
		select {
		case <-done:
		case <-time.After(pipeCloseTimeout):
			t.Errorf("test pipe accept loop for %s did not exit within %s of Close returning", addr, pipeCloseTimeout)
		}
	})
}

// startStallingTestPipeServer creates the test module pipe at addr, accepts
// exactly one connection — so the client's dial succeeds — and then does
// nothing further with it: no read, no write, no close until cleanup.
//
// Unlike startTestPipeServer, this never calls Accept a second time, so it
// never puts the listener into the pending-second-instance-connect state that
// pipeCloseTimeout's doc comment describes; Close on this listener is not
// expected to need its own bound, but it is routed through the same
// closeTestPipeListener regardless, since the point of this test is to prove
// a hang-free dial, not to also prove a particular cleanup path.
func startStallingTestPipeServer(t *testing.T, addr string) {
	t.Helper()

	lis, err := contract.Listen(addr)
	require.NoError(t, err, "create test module pipe %s", addr)

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := lis.Accept()
		if acceptErr == nil {
			acceptedCh <- conn
		}
	}()

	t.Cleanup(func() {
		closeTestPipeListener(t, addr, lis)
		select {
		case conn := <-acceptedCh:
			_ = conn.Close()
		default:
		}
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

// TestDialVerifiedPipe_ServerAcceptsThenStalls_ReturnsWithinContextDeadline is
// a [REQUIRED TEST] for Issue #4438. It proves dialVerifiedPipe does not
// depend on the server doing anything past accepting the connection:
// verifyPipeServer reads the server's process id straight from the kernel
// (windows.GetNamedPipeServerProcessId), not from the server, so a server
// that accepts and then never reads, writes, or closes must not be able to
// hang the dial. This guards against a future change adding a post-accept
// read or handshake to dialAndVerifyPipe without also bounding it by ctx —
// today, per the root-cause investigation in pipeCloseTimeout's doc comment,
// the dial+verify path in socket_windows.go was already correctly bounded by
// ctx as of commit 470bf8f38; the CI hangs this issue fixes were in the test
// fixture's unbounded lis.Close(), not here.
func TestDialVerifiedPipe_ServerAcceptsThenStalls_ReturnsWithinContextDeadline(t *testing.T) {
	addr := testPipePath(t)
	startStallingTestPipeServer(t, addr)

	const ctxTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	const watchdogBound = 2 * ctxTimeout
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	start := time.Now()
	go func() {
		conn, err := dialVerifiedPipe(ctx, addr, os.Getpid())
		resultCh <- result{conn, err}
	}()

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(watchdogBound):
		t.Fatalf("dialVerifiedPipe did not return within %s of its %s ctx deadline against a stalling server", watchdogBound, ctxTimeout)
	}
	if res.conn != nil {
		_ = res.conn.Close()
	}
	assert.Less(t, time.Since(start), watchdogBound,
		"dialVerifiedPipe must return well before the watchdog even when the server never completes anything past accept")
}

// TestDialVerifiedPipe_ServerNeverAcceptsConnection_ReturnsWithinContextDeadline
// is a [REQUIRED TEST] for Issue #4438. It proves dialVerifiedPipe is bounded
// by ctx even when nobody ever answers the pipe: the module process created
// its listener (the pipe name exists) but hung before its serve loop reached
// Accept — the state a module binary is in from process start until
// contract.Listen's Accept first runs. Without an Accept, go-winio's first
// pipe instance has no read/write access (see startTestPipeServer's doc
// comment), so every client CreateFile keeps returning ERROR_PIPE_BUSY and
// winio.DialPipeContext keeps retrying — exactly the retry loop
// dialVerifiedPipe's ctx race (see its doc comment in socket_windows.go)
// exists to bound. Unlike the stall test above, this scenario genuinely
// exercises that bound and returns an error attributable to the deadline.
func TestDialVerifiedPipe_ServerNeverAcceptsConnection_ReturnsWithinContextDeadline(t *testing.T) {
	addr := testPipePath(t)
	lis, err := contract.Listen(addr)
	require.NoError(t, err, "create test module pipe %s", addr)
	t.Cleanup(func() { closeTestPipeListener(t, addr, lis) })

	const ctxTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()

	const watchdogBound = 2 * ctxTimeout
	type result struct {
		err     error
		elapsed time.Duration
	}
	resultCh := make(chan result, 1)
	start := time.Now()
	go func() {
		_, dialErr := dialVerifiedPipe(ctx, addr, os.Getpid())
		resultCh <- result{err: dialErr, elapsed: time.Since(start)}
	}()

	var res result
	select {
	case res = <-resultCh:
	case <-time.After(watchdogBound):
		t.Fatalf("dialVerifiedPipe did not return within %s of its %s ctx deadline against a server that never accepts", watchdogBound, ctxTimeout)
	}

	require.Error(t, res.err, "dial must fail once ctx expires against a pipe nobody is servicing")
	assert.ErrorIs(t, res.err, context.DeadlineExceeded,
		"error must be attributable to the ctx deadline, not a different failure; got %v", res.err)
	assert.Less(t, res.elapsed, watchdogBound,
		"dialVerifiedPipe must return once ctx fires, not after the watchdog (took %s)", res.elapsed)
}
