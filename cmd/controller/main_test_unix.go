// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignalHandling(t *testing.T) {
	done := make(chan struct{})
	// ready is closed after signal.Notify is registered, ensuring the sender
	// does not fire SIGINT before the receiver goroutine is listening.
	ready := make(chan struct{})

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		// Signal that registration is complete before waiting.
		close(ready)

		sig := <-sigChan
		assert.Equal(t, syscall.SIGINT, sig)
		close(done)
	}()

	// Wait until signal.Notify is registered before sending the signal.
	<-ready
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("Failed to send SIGINT: %v", err)
	}

	select {
	case <-done:
		// Test completed successfully
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out")
	}
}
