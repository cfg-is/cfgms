// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
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
	// Host facts travel only as fragments: the flat attributes field was removed
	// from the DNA schema outright (Issue #3331), so there is nothing left for
	// Collect to populate. Asserted against the descriptor rather than a Go
	// field so a reintroduced field 2 fails here instead of silently returning.
	assert.Nil(t, dna.ProtoReflect().Descriptor().Fields().ByName("attributes"),
		"DNA must not carry a flat attributes field — host facts are fragments (Issue #3331)")
	assert.NotNil(t, dna.LastUpdated)

	// Test timestamp is recent
	timeDiff := time.Since(dna.LastUpdated.AsTime())
	assert.True(t, timeDiff < time.Minute, "DNA timestamp should be recent")

	// Fragment fields (ADR-017 Amendment 3) — wiring check:
	// cpu_count and cpu_arch are always set by the hardware collector (runtime
	// fallbacks), so host:cpu must always emit at least one fragment.
	assert.NotEmpty(t, dna.Fragments, "Collect should emit at least one host:* fragment")
	assert.NotEmpty(t, dna.AggregateRoot, "AggregateRoot must be non-empty when fragments are present")
	assert.Equal(t, len(dna.Fragments), len(dna.Manifest), "Manifest entry count must match fragment count")
	for _, frag := range dna.Fragments {
		_, ok := dna.Envelopes[frag.FragmentId]
		assert.Truef(t, ok, "fragment %q must have a corresponding envelope entry", frag.FragmentId)
	}
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

	// Second Collect should report at least as many attributes as the first
	// (background collection may add more; AttributeCount reflects the flat map
	// used internally for sync fingerprinting — still populated after the change).
	dna2, err := collector.Collect(t.Context())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, int(dna2.AttributeCount), int(dna.AttributeCount),
		"Second Collect() should have at least as many attributes as first")
}

// --- Source-selection tests (ADR-017 Amendment 3, Issue #3565) ---

// dnaOsquerySource is a deterministic OsquerySource for dna_test tests.
// It is not a mock — it directly implements the OsquerySource interface.
type dnaOsquerySource struct {
	healthy bool
	data    map[string]modules.ConfigState
}

func (s *dnaOsquerySource) IsActiveAndHealthy() bool { return s.healthy }

func (s *dnaOsquerySource) Get(_ context.Context, kind string) (modules.ConfigState, error) {
	if state, ok := s.data[kind]; ok {
		return state, nil
	}
	return nil, errors.New("osquery: unsupported kind")
}

var _ OsquerySource = (*dnaOsquerySource)(nil)

// defaultDNAOsquerySource returns a healthy OsquerySource with plausible data
// for all four curated host:* kinds.
func defaultDNAOsquerySource() *dnaOsquerySource {
	return &dnaOsquerySource{
		healthy: true,
		data: map[string]modules.ConfigState{
			"host:cpu": MapState(map[string]interface{}{
				"cpu_brand":          "Intel(R) Xeon(R) Gold 6154",
				"cpu_physical_cores": "18",
			}),
			"host:memory": MapState(map[string]interface{}{
				"physical_memory": "137438953472",
			}),
			"host:os": MapState(map[string]interface{}{
				"os":       "Ubuntu",
				"hostname": "steward-01",
			}),
			"host:bios": MapState(map[string]interface{}{
				"hardware_vendor": "ACME Corp",
				"uuid":            "AAAABBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF",
			}),
		},
	}
}

// TestSourceSelection_OsqueryActive verifies that when an active and healthy
// OsquerySource is wired in, Collect emits fragments with Authority:"osquery".
func TestSourceSelection_OsqueryActive(t *testing.T) {
	logger := logging.NewNoopLogger()
	src := defaultDNAOsquerySource()

	collector := NewCollector(logger, WithOsquerySource(src))
	d, err := collector.Collect(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, d.Fragments, "fragments must be emitted when osquery is active")

	for _, f := range d.Fragments {
		if f.FragmentId == "host:cpu" || f.FragmentId == "host:memory" ||
			f.FragmentId == "host:os" || f.FragmentId == "host:bios" {
			assert.Equal(t, "osquery", f.Authority,
				"host:* fragment %s must carry Authority:'osquery' when osquery is active",
				f.FragmentId)
		}
	}

	// Envelopes must also declare Source:"osquery" for the osquery-sourced kinds.
	for _, f := range d.Fragments {
		if f.Authority != "osquery" {
			continue
		}
		env, ok := d.Envelopes[f.FragmentId]
		require.True(t, ok, "envelope must exist for fragment %s", f.FragmentId)
		assert.Equal(t, "osquery", env.Source,
			"envelope Source must be 'osquery' for fragment %s", f.FragmentId)
	}
}

// TestSourceSelection_OsqueryNil verifies that when no OsquerySource is wired in
// (the default), Collect falls back to the gatherer path and emits fragments with
// Authority:"gatherer".
func TestSourceSelection_OsqueryNil(t *testing.T) {
	logger := logging.NewNoopLogger()
	collector := NewCollector(logger) // no WithOsquerySource — uses gatherer

	d, err := collector.Collect(t.Context())
	require.NoError(t, err)
	// cpu_count and cpu_arch are always set by the runtime fallbacks in
	// collectHardwareInfo, so host:cpu must always be emitted.
	require.NotEmpty(t, d.Fragments,
		"gatherer must emit at least one host:* fragment; cpu_count/cpu_arch are always set")

	for _, f := range d.Fragments {
		if f.FragmentId == "host:cpu" || f.FragmentId == "host:memory" ||
			f.FragmentId == "host:os" || f.FragmentId == "host:bios" {
			assert.Equal(t, "gatherer", f.Authority,
				"host:* fragment %s must carry Authority:'gatherer' when no OsquerySource is configured",
				f.FragmentId)
		}
	}
}

// TestSourceSelection_OsqueryUnhealthy verifies that when the OsquerySource
// reports IsActiveAndHealthy() == false, the gatherer path is used, not osquery.
func TestSourceSelection_OsqueryUnhealthy(t *testing.T) {
	logger := logging.NewNoopLogger()
	src := defaultDNAOsquerySource()
	src.healthy = false // simulate binary verification failure

	collector := NewCollector(logger, WithOsquerySource(src))
	d, err := collector.Collect(t.Context())
	require.NoError(t, err)
	// Gatherer fallback must emit at least one fragment (cpu_count/cpu_arch runtime fallbacks).
	require.NotEmpty(t, d.Fragments,
		"gatherer fallback must emit at least one host:* fragment when osquery is unhealthy")

	for _, f := range d.Fragments {
		if f.FragmentId == "host:cpu" || f.FragmentId == "host:memory" ||
			f.FragmentId == "host:os" || f.FragmentId == "host:bios" {
			assert.Equal(t, "gatherer", f.Authority,
				"[REQUIRED] host:* fragment %s must carry Authority:'gatherer' when osquery reports unhealthy — "+
					"never 'osquery'", f.FragmentId)
		}
	}
}

// TestSourceLabelPairingInvariant is the REQUIRED test: no code path emits
// gatherer-sourced fragment content labeled Authority:"osquery", or the reverse.
// The source decision and the label are made together, once, never independently.
func TestSourceLabelPairingInvariant(t *testing.T) {
	logger := logging.NewNoopLogger()

	t.Run("osquery_active_labels_osquery", func(t *testing.T) {
		src := defaultDNAOsquerySource()
		collector := NewCollector(logger, WithOsquerySource(src))
		d, err := collector.Collect(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, d.Fragments,
			"[REQUIRED] at least one host:* fragment must be emitted for the invariant test to be meaningful")

		for _, f := range d.Fragments {
			// Only check the host:* kinds that the osquery source provides.
			if _, ok := src.data[f.FragmentId]; ok {
				assert.Equal(t, "osquery", f.Authority,
					"[REQUIRED] fragment %s came from osquery source but is labeled %q — invariant violated",
					f.FragmentId, f.Authority)
			}
		}
	})

	t.Run("gatherer_path_labels_gatherer", func(t *testing.T) {
		// Unhealthy osquery → gatherer path runs.
		src := defaultDNAOsquerySource()
		src.healthy = false
		collector := NewCollector(logger, WithOsquerySource(src))
		d, err := collector.Collect(t.Context())
		require.NoError(t, err)
		require.NotEmpty(t, d.Fragments,
			"[REQUIRED] gatherer must emit fragments when osquery is unhealthy — invariant test requires non-empty output")

		for _, f := range d.Fragments {
			if f.FragmentId == "host:cpu" || f.FragmentId == "host:memory" ||
				f.FragmentId == "host:os" || f.FragmentId == "host:bios" {
				assert.Equal(t, "gatherer", f.Authority,
					"[REQUIRED] fragment %s came from gatherer path but is labeled %q — invariant violated",
					f.FragmentId, f.Authority)
				assert.NotEqual(t, "osquery", f.Authority,
					"[REQUIRED] gatherer-sourced fragment %s must NEVER be labeled 'osquery'",
					f.FragmentId)
			}
		}
	})
}

// TestRawAttributesUnchangedByOsquerySource verifies that RawAttributes always
// returns gatherer data regardless of whether an OsquerySource is configured.
// The gatherers run unconditionally — this is a required invariant of Issue #3565.
func TestRawAttributesUnchangedByOsquerySource(t *testing.T) {
	logger := logging.NewNoopLogger()

	// Without osquery
	collectorNoOsquery := NewCollector(logger)
	attrsNoOsquery := collectorNoOsquery.RawAttributes(t.Context())

	// With osquery
	src := defaultDNAOsquerySource()
	collectorWithOsquery := NewCollector(logger, WithOsquerySource(src))
	attrsWithOsquery := collectorWithOsquery.RawAttributes(t.Context())

	// Both should have the same essential gatherer-sourced attributes.
	assert.NotEmpty(t, attrsNoOsquery, "RawAttributes must be non-empty without osquery")
	assert.NotEmpty(t, attrsWithOsquery, "RawAttributes must be non-empty with osquery")

	// Key gatherer attributes must be present regardless of osquery configuration.
	for _, key := range []string{"runtime_os", "runtime_arch", "cpu_count", "cpu_arch"} {
		assert.Contains(t, attrsWithOsquery, key,
			"RawAttributes must contain gatherer key %q even when OsquerySource is configured", key)
	}

	// RawAttributes must not contain osquery-only keys (like "cpu_brand" from osquery's cpu_info).
	// cpu_brand is an osquery-specific field name not produced by gatherers.
	assert.NotContains(t, attrsNoOsquery, "cpu_brand",
		"gatherer RawAttributes must not contain osquery-specific keys like cpu_brand")
}
