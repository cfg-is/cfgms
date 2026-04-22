// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build windows

package main

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockingServer is a Server whose Start() blocks until Stop() is called.
// This allows signal-path tests to exercise the signal branch of
// runControllerServer without a race between signal delivery and Start() return.
type blockingServer struct {
	mu        sync.Mutex
	stopCalls int
	done      chan struct{}
}

func newBlockingServer() *blockingServer {
	return &blockingServer{done: make(chan struct{})}
}

func (b *blockingServer) Start() error {
	<-b.done
	return nil
}

func (b *blockingServer) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopCalls++
	if b.stopCalls == 1 {
		close(b.done)
	}
	return nil
}

func (b *blockingServer) StopCallCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopCalls
}

// TestSignalHandling verifies that runControllerServer shuts down when a signal
// arrives on sigChan, calls srv.Stop() exactly once, and returns nil.
// On Windows there is no syscall.Kill equivalent, so we test via the sigChan
// seam directly — the OS signal wiring is tested by the integration build.
func TestSignalHandling(t *testing.T) {
	srv := newBlockingServer()
	logger := logging.NewNoopLogger()
	sigChan := make(chan os.Signal, 1)

	// Pre-buffer the signal so runControllerServer's select fires the signal
	// path before srv.Start() can return on its own.
	sigChan <- os.Interrupt

	result := make(chan error, 1)
	go func() {
		result <- runControllerServer(srv, logger, sigChan)
	}()

	select {
	case err := <-result:
		require.NoError(t, err)
		assert.Equal(t, 1, srv.StopCallCount(), "srv.Stop() must be called exactly once on signal")
	case <-time.After(1 * time.Second):
		t.Fatal("TestSignalHandling timed out — runControllerServer did not return after signal")
	}
}
