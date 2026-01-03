// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
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
	// Create a channel to coordinate test completion
	done := make(chan struct{})

	// Start the main process in a goroutine
	go func() {
		// Simulate the main process
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Send a signal after a short delay
		go func() {
			time.Sleep(100 * time.Millisecond)
			if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
				t.Logf("Failed to send SIGINT: %v", err)
			}
		}()

		// Wait for signal
		sig := <-sigChan
		assert.Equal(t, syscall.SIGINT, sig)
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
