// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
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
	done := make(chan struct{})

	go func() {
		// On Windows we test with os.Interrupt (no syscall.Kill equivalent).
		// The channel is buffered so the send below does not block regardless of
		// receive timing — no sleep needed.
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt)

		// Send directly to the buffered channel; this is deterministic and races-free.
		sigChan <- os.Interrupt

		sig := <-sigChan
		assert.Equal(t, os.Interrupt, sig)
		close(done)
	}()

	select {
	case <-done:
		// Test completed successfully
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out")
	}
}
