// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

//go:build windows

package contract_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/cfgis/cfgms/pkg/modules/contract"
)

// gracefulStopTimeout bounds how long this file's tests wait for
// grpc.Server.GracefulStop/Stop, or a raw Close, to return while an Accept is
// in flight. See pipeCloseTimeout in listen_test.go for why a bound is
// needed at all for a Windows named-pipe listener. Separate constant because
// GracefulStop does strictly more work than a bare Close (it also waits for
// serveWG), so it gets its own named budget rather than reusing
// pipeCloseTimeout and implying the two calls are equivalent.
const gracefulStopTimeout = 5 * time.Second

// TestListen_GracefulStopWithPendingAccept reproduces the production shutdown
// shape every contract.Listen caller uses (see e.g.
// features/modules/stdlib/script/cmd/main.go): a grpc.Server Serving a
// contract.Listen listener, stopped from another goroutine while Serve's
// Accept loop is blocked waiting for a dial that never comes. Every managed
// module sits idle this way for nearly its whole life, so this is the
// steady-state shutdown case, not an edge case.
//
// Before the go-winio upgrade in this change, win32PipeListener.Close could
// leave Accept's win32PipeListener.Close blocked on <-l.doneCh forever
// whenever Close raced a pending Accept (#4438, #4451, #4459): the Accept
// goroutine's makeConnectedServerPipe could observe a non-nil, non-ErrFileClosed
// error (e.g. ERROR_NO_DATA) from the aborted connect and retry instead of
// treating the close as authoritative, consuming the one-shot closeCh
// rendezvous value without ever reaching close(l.doneCh). grpc-go's
// (*Server).stop holds s.mu for the whole of that Close call
// (google.golang.org/grpc@v1.83.2/server.go), so the hang took the entire
// shutdown path with it, not just the listener.
func TestListen_GracefulStopWithPendingAccept(t *testing.T) {
	addr := listenTestAddr(t)
	lis, err := contract.Listen(addr)
	require.NoError(t, err)

	srv := grpc.NewServer()
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(lis)
	}()

	// Give Serve's Accept loop time to actually enter Accept before racing
	// GracefulStop against it; without this the test would sometimes assert
	// nothing because Stop won the race against a not-yet-started Accept.
	time.Sleep(100 * time.Millisecond)

	stopDone := make(chan struct{})
	go func() {
		defer close(stopDone)
		srv.GracefulStop()
	}()

	select {
	case <-stopDone:
	case <-time.After(gracefulStopTimeout):
		t.Fatalf("srv.GracefulStop did not return within %s with a pending Accept (go-winio Close/Accept rendezvous regression)", gracefulStopTimeout)
	}

	select {
	case <-serveDone:
	case <-time.After(gracefulStopTimeout):
		t.Fatalf("srv.Serve did not return within %s after GracefulStop", gracefulStopTimeout)
	}
}

// TestListen_CloseWithPendingAccept_Loop runs the Close/Accept race 50 times
// in one test so an intermittent regression of the go-winio rendezvous fix
// shows up as a failure here instead of resurfacing as sporadic flakes on
// unrelated PRs, which is how #4438 and #4451 were first found. Every
// iteration uses closeTestPipeListener, the same bounded-close safety net the
// rest of this package and the steward/workflow runtime tests use (see
// pipeCloseTimeout in listen_test.go): a single timeout anywhere in the 50
// iterations fails the test via t.Errorf.
func TestListen_CloseWithPendingAccept_Loop(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		addr := listenTestAddr(t) + "-" + strconv.Itoa(i)
		lis, err := contract.Listen(addr)
		require.NoError(t, err)

		acceptDone := make(chan struct{})
		go func() {
			defer close(acceptDone)
			_, _ = lis.Accept()
		}()

		// Give Accept time to register with the listener's internal routine
		// before racing Close against it.
		time.Sleep(10 * time.Millisecond)

		closeTestPipeListener(t, addr, lis)
		<-acceptDone
	}
}
