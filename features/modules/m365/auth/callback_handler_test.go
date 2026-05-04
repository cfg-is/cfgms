// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package auth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// TestCallbackHandler_WithLogger_routesError verifies that server errors in the
// callback server goroutine are routed through the injected logger.
func TestCallbackHandler_WithLogger_routesError(t *testing.T) {
	mockLog := pkgtesting.NewMockLogger(false)

	handler := NewCallbackHandler()
	handler.WithLogger(mockLog)

	ctx := context.Background()
	err := handler.StartCallbackServer(ctx, "0")
	require.NoError(t, err)

	// Forcefully close the underlying listener (not via Shutdown) so that
	// server.Serve returns a non-ErrServerClosed error, triggering the log path.
	require.NotNil(t, handler.listener)
	require.NoError(t, handler.listener.Close())

	// Give the goroutine time to react and log the error.
	deadline := time.Now().Add(2 * time.Second)
	var errLogs []pkgtesting.LogEntry
	for time.Now().Before(deadline) {
		errLogs = mockLog.GetLogs("error")
		if len(errLogs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	require.NotEmpty(t, errLogs, "expected error log when listener is closed externally")
	assert.Equal(t, "callback server error", errLogs[0].Message)
}

// TestCallbackHandler_WithLogger_chainsReturn verifies that WithLogger returns
// the handler itself for chaining.
func TestCallbackHandler_WithLogger_chainsReturn(t *testing.T) {
	h := NewCallbackHandler()
	mockLog := pkgtesting.NewMockLogger(false)
	returned := h.WithLogger(mockLog)
	assert.Same(t, h, returned, "WithLogger must return the receiver for chaining")
}

// TestCallbackHandler_WithLogger_nilIsIgnored verifies that passing nil to
// WithLogger does not replace the existing logger.
func TestCallbackHandler_WithLogger_nilIsIgnored(t *testing.T) {
	h := NewCallbackHandler()
	original := h.logger
	h.WithLogger(nil)
	assert.Equal(t, original, h.logger, "nil logger should not replace the existing logger")
}

// TestCallbackHandler_defaultLogger_isNoopLogger verifies that a freshly
// constructed CallbackHandler has a non-nil logger.
func TestCallbackHandler_defaultLogger_isNoopLogger(t *testing.T) {
	h := NewCallbackHandler()
	assert.NotNil(t, h.logger, "default logger must be non-nil")
}
