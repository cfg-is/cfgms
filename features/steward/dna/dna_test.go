// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
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
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	dna, err := collector.Collect(context.Background())
	require.NoError(t, err)
	require.NotNil(t, dna)

	assert.NotEmpty(t, dna.Id)
	assert.NotNil(t, dna.Attributes)
	assert.NotNil(t, dna.LastUpdated)

	assert.Contains(t, dna.Attributes, "runtime_os")
	assert.Contains(t, dna.Attributes, "runtime_arch")
	assert.Contains(t, dna.Attributes, "runtime_version")
	assert.Contains(t, dna.Attributes, "num_cpu")
	assert.Contains(t, dna.Attributes, "timestamp")

	timeDiff := time.Since(dna.LastUpdated.AsTime())
	assert.True(t, timeDiff < time.Minute, "DNA timestamp should be recent")
}

func TestCollectBasicInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectBasicInfo(attributes)

	assert.Contains(t, attributes, "timestamp")
	assert.Contains(t, attributes, "runtime_version")
	assert.Contains(t, attributes, "runtime_os")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "num_cpu")

	assert.NotEmpty(t, attributes["runtime_os"])
	assert.NotEmpty(t, attributes["runtime_arch"])
	assert.NotEmpty(t, attributes["num_cpu"])
}

func TestCollectHardwareInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectHardwareInfo(context.Background(), attributes)

	assert.Contains(t, attributes, "cpu_count")
	assert.Contains(t, attributes, "cpu_arch")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "runtime_os")

	assert.NotEmpty(t, attributes["cpu_count"])
	assert.NotEmpty(t, attributes["cpu_arch"])
}

func TestHardwareCaching(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	// First collect populates the cache
	attrs1 := make(map[string]string)
	collector.collectHardwareInfoCached(context.Background(), attrs1)

	assert.True(t, collector.hardwareCached, "hardware cache should be populated after first call")
	assert.NotEmpty(t, collector.cachedHardware)

	// Second collect reuses the cache for static hardware
	attrs2 := make(map[string]string)
	collector.collectHardwareInfoCached(context.Background(), attrs2)

	// CPU count should be consistent across both calls
	assert.Equal(t, attrs1["cpu_count"], attrs2["cpu_count"],
		"cpu_count should be consistent when served from cache")
}

func TestCollectSoftwareInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectSoftwareInfo(context.Background(), attributes)

	assert.Contains(t, attributes, "os")
	assert.Contains(t, attributes, "go_version")
	assert.Contains(t, attributes, "current_pid")
	assert.Contains(t, attributes, "parent_pid")
	assert.Contains(t, attributes, "runtime_arch")
	assert.Contains(t, attributes, "runtime_os")

	assert.NotEmpty(t, attributes["os"])
	assert.NotEmpty(t, attributes["current_pid"])
	assert.NotEmpty(t, attributes["go_version"])
}

func TestCollectNetworkInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectNetworkInfo(context.Background(), attributes)

	assert.Contains(t, attributes, "network_interface_count")

	if attributes["network_interface_count"] != "0" {
		assert.NotEmpty(t, attributes["network_interface_count"])
	}
}

func TestCollectEnvironmentInfo(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes := make(map[string]string)
	collector.collectEnvironmentInfo(attributes)

	// Timezone is always populated from system clock even when TZ env var is absent
	assert.Contains(t, attributes, "timezone", "timezone must always be populated from system clock")
	assert.NotEmpty(t, attributes["timezone"])
}

func TestGenerateSystemID(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	attributes1 := map[string]string{
		"primary_mac": "00:11:22:33:44:55",
		"hostname":    "test-host",
	}
	id1 := collector.generateSystemID(attributes1)
	assert.NotEmpty(t, id1)
	assert.Len(t, id1, 16)

	id2 := collector.generateSystemID(attributes1)
	assert.Equal(t, id1, id2, "System ID should be consistent")

	attributes2 := map[string]string{
		"primary_mac": "00:11:22:33:44:56",
		"hostname":    "test-host",
	}
	id3 := collector.generateSystemID(attributes2)
	assert.NotEqual(t, id1, id3, "Different MAC should give different ID")

	attributes3 := map[string]string{
		"runtime_os":   "linux",
		"runtime_arch": "amd64",
	}
	id4 := collector.generateSystemID(attributes3)
	assert.NotEmpty(t, id4)
	assert.Len(t, id4, 16)
}

func TestRefreshDNA(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	dna, err := collector.RefreshDNA(context.Background())
	require.NoError(t, err)
	require.NotNil(t, dna)

	assert.NotEmpty(t, dna.Id)
	assert.NotNil(t, dna.Attributes)
	assert.NotNil(t, dna.LastUpdated)
}

func TestCompareDNA(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	dna1, err := collector.Collect(context.Background())
	require.NoError(t, err)

	dna2, err := collector.Collect(context.Background())
	require.NoError(t, err)

	assert.True(t, CompareDNA(dna1, dna2))

	dna3 := &commonpb.DNA{
		Id: "different-id",
		Attributes: map[string]string{
			"primary_mac": "different-mac",
			"hostname":    "different-host",
		},
	}
	assert.False(t, CompareDNA(dna1, dna3))

	assert.False(t, CompareDNA(dna1, nil))
	assert.False(t, CompareDNA(nil, dna2))
	assert.False(t, CompareDNA(nil, nil))
}
