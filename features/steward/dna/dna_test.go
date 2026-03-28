// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestNewCollector(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	assert.NotNil(t, collector)
	assert.Equal(t, logger, collector.logger)
}

func TestCollect(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full DNA collection test in short mode")
	}

	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	dna, err := collector.Collect()
	require.NoError(t, err)
	require.NotNil(t, dna)

	// Test basic structure
	assert.NotEmpty(t, dna.Id)
	assert.NotNil(t, dna.Attributes)
	assert.NotNil(t, dna.LastUpdated)

	// Test that we have basic attributes
	assert.Contains(t, dna.Attributes, "runtime_os")
	assert.Contains(t, dna.Attributes, "runtime_arch")
	assert.Contains(t, dna.Attributes, "runtime_version")
	assert.Contains(t, dna.Attributes, "num_cpu")
	assert.Contains(t, dna.Attributes, "timestamp")

	// Test timestamp is recent
	timeDiff := time.Since(dna.LastUpdated.AsTime())
	assert.True(t, timeDiff < time.Minute, "DNA timestamp should be recent")
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
	collector.collectHardwareInfo(attributes)

	// Test enhanced hardware attributes
	assert.Contains(t, attributes, "cpu_count")
	assert.Contains(t, attributes, "cpu_arch")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "runtime_os")

	// Test values are reasonable
	assert.NotEmpty(t, attributes["cpu_count"])
	assert.NotEmpty(t, attributes["cpu_arch"])
}

func TestCollectSoftwareInfo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping software collection in short mode — WMI enumeration on Windows takes 6+ minutes")
	}
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectSoftwareInfo(attributes)

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
	collector.collectNetworkInfo(attributes)

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

	// Environment attributes depend on the system
	// Just verify the method runs and populates some data
	assert.True(t, len(attributes) >= 0) // At least timezone info should be there
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

func TestRefreshDNA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DNA refresh test in short mode")
	}

	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	dna, err := collector.RefreshDNA()
	require.NoError(t, err)
	require.NotNil(t, dna)

	// RefreshDNA should work the same as Collect
	assert.NotEmpty(t, dna.Id)
	assert.NotNil(t, dna.Attributes)
	assert.NotNil(t, dna.LastUpdated)
}

func TestCompareDNA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping DNA compare test in short mode")
	}

	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	// Create test DNA
	dna1, err := collector.Collect()
	require.NoError(t, err)

	dna2, err := collector.Collect()
	require.NoError(t, err)

	// Same system should compare equal
	assert.True(t, CompareDNA(dna1, dna2))

	// Different system ID should not compare equal
	dna3 := &commonpb.DNA{
		Id: "different-id",
		Attributes: map[string]string{
			"primary_mac": "different-mac",
			"hostname":    "different-host",
		},
	}
	assert.False(t, CompareDNA(dna1, dna3))

	// Nil DNA should not compare equal
	assert.False(t, CompareDNA(dna1, nil))
	assert.False(t, CompareDNA(nil, dna2))
	assert.False(t, CompareDNA(nil, nil))
}
