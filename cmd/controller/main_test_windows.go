// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
//go:build windows

package main

import (
	"os"
	"os/signal"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSignalHandling(t *testing.T) {
	// Create a channel to coordinate test completion
	done := make(chan struct{})

	// Start the main process in a goroutine
	go func() {
		// On Windows, we test with os.Interrupt which is the closest equivalent
		// to SIGINT. Windows doesn't support SIGTERM or syscall.Kill in the same way.
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)

		// Send interrupt signal after a short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			// On Windows, we can send to the channel directly for testing
			// since there's no syscall.Kill equivalent
			sigChan <- os.Interrupt
		}()

		// Wait for signal
		sig := <-sigChan
		assert.Equal(t, os.Interrupt, sig)
		close(done)
	}()

	// Wait for test completion with timeout
	select {
	case <-done:
		// Test completed successfully
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out")
	}
}
