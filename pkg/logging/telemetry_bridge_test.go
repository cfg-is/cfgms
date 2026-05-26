// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package logging

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTelemetryBridgeInitialize_EndToEnd(t *testing.T) {
	// Save and restore global state so tests don't pollute each other.
	prev := globalTelemetryBridge.Load()
	t.Cleanup(func() { globalTelemetryBridge.Store(prev) })
	globalTelemetryBridge.Store(nil)

	// Bridge is not yet wired — UpdatedExtractCorrelationID falls back to
	// direct key read and must still find the value.
	ctx := WithCorrelation(context.Background(), "e2e-id")
	assert.Equal(t, "e2e-id", UpdatedExtractCorrelationID(ctx), "direct key read before bridge init")

	// Wire the bridge.
	(&TelemetryBridge{}).Initialize()
	assert.NotNil(t, globalTelemetryBridge.Load(), "bridge must be set after Initialize")

	// After Initialize the bridge code path is exercised and must return the same value.
	assert.Equal(t, "e2e-id", UpdatedExtractCorrelationID(ctx), "bridge code path after Initialize")
}

func TestTelemetryBridgeInitialize_Idempotent(t *testing.T) {
	prev := globalTelemetryBridge.Load()
	t.Cleanup(func() { globalTelemetryBridge.Store(prev) })
	globalTelemetryBridge.Store(nil)

	ctx := WithCorrelation(context.Background(), "id-idem")

	(&TelemetryBridge{}).Initialize()
	result1 := UpdatedExtractCorrelationID(ctx)

	(&TelemetryBridge{}).Initialize()
	result2 := UpdatedExtractCorrelationID(ctx)

	assert.NotNil(t, globalTelemetryBridge.Load(), "bridge non-nil after repeated Initialize calls")
	assert.Equal(t, result1, result2, "successive Initialize calls produce identical observable behavior")
	assert.Equal(t, "id-idem", result2, "correlation ID correct after second Initialize")
}

func TestTelemetryBridgeInitialize_EmptyContext(t *testing.T) {
	prev := globalTelemetryBridge.Load()
	t.Cleanup(func() { globalTelemetryBridge.Store(prev) })
	globalTelemetryBridge.Store(nil)

	// Verify fallback (no bridge) returns empty for a context with no correlation ID.
	assert.Equal(t, "", UpdatedExtractCorrelationID(context.Background()), "no bridge, no value → empty")

	(&TelemetryBridge{}).Initialize()

	// After wiring, context with no correlation ID still returns empty.
	assert.Equal(t, "", UpdatedExtractCorrelationID(context.Background()), "bridge wired, no value → empty")
}
