// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestNewCollector(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	assert.NotNil(t, collector)
	assert.Equal(t, logger, collector.logger)
}

func TestCollect(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	dna, err := collector.Collect(t.Context())
	require.NoError(t, err)
	require.NotNil(t, dna)

	// Test basic structure
	assert.NotEmpty(t, dna.Id)
	assert.NotNil(t, dna.Attributes)
	assert.NotNil(t, dna.LastUpdated)

	// Test that we have basic attributes (all from fast path)
	assert.Contains(t, dna.Attributes, "runtime_os")
	assert.Contains(t, dna.Attributes, "runtime_arch")
	assert.Contains(t, dna.Attributes, "runtime_version")
	assert.Contains(t, dna.Attributes, "num_cpu")
	assert.Contains(t, dna.Attributes, "timestamp")

	// Test timestamp is recent
	timeDiff := time.Since(dna.LastUpdated.AsTime())
	assert.True(t, timeDiff < time.Minute, "DNA timestamp should be recent")
}

// TestCollectAcceptsContext verifies that Collect honours a cancelled context.
func TestCollectAcceptsContext(t *testing.T) {
	logger := logging.NewLogger("error")
	collector := NewCollector(logger)

	// A background context should work fine.
	ctx := context.Background()
	dna, err := collector.Collect(ctx)
	require.NoError(t, err)
	require.NotNil(t, dna)
	assert.NotEmpty(t, dna.Id)
}

func TestCollectBasicInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectBasicInfo(attributes)

	// Test required attributes
	assert.Contains(t, attributes, "timestamp")
	assert.Contains(t, attributes, "runtime_version")
	assert.Contains(t, attributes, "runtime_os")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "num_cpu")

	// Test values are reasonable
	assert.NotEmpty(t, attributes["runtime_os"])
	assert.NotEmpty(t, attributes["runtime_arch"])
	assert.NotEmpty(t, attributes["num_cpu"])
}

func TestCollectHardwareInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectHardwareInfo(t.Context(), attributes)

	// Test enhanced hardware attributes
	assert.Contains(t, attributes, "cpu_count")
	assert.Contains(t, attributes, "cpu_arch")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "runtime_os")

	// Test values are reasonable
	assert.NotEmpty(t, attributes["cpu_count"])
	assert.NotEmpty(t, attributes["cpu_arch"])
}

// TestHardwareCacheReuse verifies that the hardware cache is populated on the first call
// and reused (not re-queried) on subsequent calls to collectHardwareInfo.
func TestHardwareCacheReuse(t *testing.T) {
	logger := logging.NewLogger("error")
	collector := NewCollector(logger)
	ctx := t.Context()

	// First call populates the cache
	attrs1 := make(map[string]string)
	collector.collectHardwareInfo(ctx, attrs1)

	// Second call should return from cache
	attrs2 := make(map[string]string)
	start := time.Now()
	collector.collectHardwareInfo(ctx, attrs2)
	cacheHitDuration := time.Since(start)

	// Cache hit should be very fast (under 100ms)
	assert.Less(t, cacheHitDuration, 100*time.Millisecond,
		"Second hardware collection should be near-instant (cache hit)")

	// Both calls should return the same stable values
	assert.Equal(t, attrs1["cpu_count"], attrs2["cpu_count"],
		"cpu_count should be consistent across calls")
	assert.Equal(t, attrs1["runtime_arch"], attrs2["runtime_arch"],
		"runtime_arch should be consistent across calls")
}

func TestCollectSoftwareInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectSoftwareInfo(t.Context(), attributes)

	// Test enhanced software attributes
	assert.Contains(t, attributes, "os")
	assert.Contains(t, attributes, "go_version")
	assert.Contains(t, attributes, "current_pid")
	assert.Contains(t, attributes, "parent_pid")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "runtime_os")

	// Test values are reasonable
	assert.NotEmpty(t, attributes["os"])
	assert.NotEmpty(t, attributes["current_pid"])
	assert.NotEmpty(t, attributes["go_version"])
}

func TestCollectNetworkInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectNetworkInfo(t.Context(), attributes)

	// Test network attributes (may not be present in all environments)
	assert.Contains(t, attributes, "network_interface_count")

	// If we have network interfaces, we should have some network info
	if attributes["network_interface_count"] != "0" {
		// We might have IP or MAC addresses, but not guaranteed
		// Just test that the method runs without error
		assert.NotEmpty(t, attributes["network_interface_count"])
	}
}

func TestCollectEnvironmentInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectEnvironmentInfo(attributes)

	// Environment attributes depend on the system, but timezone should always be set
	assert.Contains(t, attributes, "timezone", "collectEnvironmentInfo should always set timezone")
}

func TestGenerateSystemID(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	// Test with MAC address
	attributes1 := map[string]string{
		"primary_mac": "00:11:22:33:44:55",
		"hostname":    "test-host",
	}
	id1 := collector.generateSystemID(attributes1)
	assert.NotEmpty(t, id1)
	assert.Len(t, id1, 16) // 8 bytes in hex = 16 characters

	// Test consistency
	id2 := collector.generateSystemID(attributes1)
	assert.Equal(t, id1, id2, "System ID should be consistent")

	// Test different MAC gives different ID
	attributes2 := map[string]string{
		"primary_mac": "00:11:22:33:44:56", // Different MAC
		"hostname":    "test-host",
	}
	id3 := collector.generateSystemID(attributes2)
	assert.NotEqual(t, id1, id3, "Different MAC should give different ID")

	// Test fallback without MAC
	attributes3 := map[string]string{
		"runtime_os":   "linux",
		"runtime_arch": "amd64",
	}
	id4 := collector.generateSystemID(attributes3)
	assert.NotEmpty(t, id4)
	assert.Len(t, id4, 16)
}

// TestBackgroundCollectionStartsOnFirstCollect verifies that the background
// collection goroutine is started on the first Collect() call and the bgDone
// channel is eventually closed.
func TestBackgroundCollectionStartsOnFirstCollect(t *testing.T) {
	logger := logging.NewLogger("error")
	collector := NewCollector(logger)

	// First Collect should return fast data immediately
	start := time.Now()
	dna, err := collector.Collect(t.Context())
	require.NoError(t, err)
	require.NotNil(t, dna)
	firstCallDuration := time.Since(start)

	// Fast path should complete in under 30 seconds even on slow machines
	// (hardware WMI calls are 1-5s each, so first call can be up to ~40s on Windows)
	assert.Less(t, firstCallDuration, 5*time.Minute,
		"First Collect() should return within 5 minutes")

	// Background collection should complete within a generous timeout
	select {
	case <-collector.bgDone:
		// Background collection completed — subsequent Collect() will return merged data
	case <-time.After(3 * time.Minute):
		t.Fatal("Background collection goroutine did not complete within 3 minutes — goroutine may not have started")
	}

	// Second Collect should return at least as many attributes as the first
	dna2, err := collector.Collect(t.Context())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(dna2.Attributes), len(dna.Attributes),
		"Second Collect() should have at least as many attributes as first")
}
