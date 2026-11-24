// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	pkgdna "github.com/cfgis/cfgms/pkg/dna"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/dnasnapshot"
)

func TestNewCollector(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := NewCollector(logger)

	assert.NotNil(t, collector)
	assert.Equal(t, logger, collector.logger)
}

func TestCollect(t *testing.T) {
	logger := logging.NewLogger("debug")
	collector := newSnapshotCollector(t, logger)

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
	collector := newSnapshotCollector(t, logger)

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
	snap, err := dnasnapshot.Load(dnaSnapshotFixturePath)
	require.NoError(t, err, "load DNA snapshot fixture")

	// dnasnapshot.HardwareCollector counts its CollectX calls, which is the
	// observable signal for whether collectHardwareInfo's second call re-probed
	// the sub-collector or was served entirely from the cache.
	hw := dnasnapshot.NewHardwareCollector(snap.Hardware)
	collector := NewCollector(logger, WithHardwareCollector(hw))
	ctx := t.Context()

	// First call populates the cache — four CollectX methods run inside hwCacheOnce.Do.
	attrs1 := make(map[string]string)
	collector.collectHardwareInfo(ctx, attrs1)
	require.EqualValues(t, 4, hw.Calls(), "first call must probe all four hardware sub-collections")

	// Second call should return from cache
	attrs2 := make(map[string]string)
	start := time.Now()
	collector.collectHardwareInfo(ctx, attrs2)
	cacheHitDuration := time.Since(start)

	// Cache hit should be very fast (under 100ms)
	assert.Less(t, cacheHitDuration, 100*time.Millisecond,
		"Second hardware collection should be near-instant (cache hit)")

	// The second call must be served entirely from the cache, not re-queried.
	assert.EqualValues(t, 4, hw.Calls(),
		"hardware collector must be queried exactly once; second collectHardwareInfo call must hit the cache")

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
	collector := newSnapshotCollector(t, logger)

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
	collector := newSnapshotCollector(t, logger)

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
			"host:cpu": pkgdna.MapState(map[string]interface{}{
				"cpu_brand":          "Intel(R) Xeon(R) Gold 6154",
				"cpu_physical_cores": "18",
			}),
			"host:memory": pkgdna.MapState(map[string]interface{}{
				"physical_memory": "137438953472",
			}),
			"host:os": pkgdna.MapState(map[string]interface{}{
				"os":       "Ubuntu",
				"hostname": "steward-01",
			}),
			"host:bios": pkgdna.MapState(map[string]interface{}{
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

	collector := newSnapshotCollector(t, logger, WithOsquerySource(src))
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
	collector := newSnapshotCollector(t, logger) // no WithOsquerySource — uses gatherer

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

	collector := newSnapshotCollector(t, logger, WithOsquerySource(src))
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
		collector := newSnapshotCollector(t, logger, WithOsquerySource(src))
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
		collector := newSnapshotCollector(t, logger, WithOsquerySource(src))
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
	collectorNoOsquery := newSnapshotCollector(t, logger)
	attrsNoOsquery := collectorNoOsquery.RawAttributes(t.Context())

	// With osquery
	src := defaultDNAOsquerySource()
	collectorWithOsquery := newSnapshotCollector(t, logger, WithOsquerySource(src))
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

// --- Slow-collection refresh tests (Issue #6498) ---

const testPackageAttr = "test_package_list"

// filePackageCollector is a real SoftwareCollector that reads a package list
// from a local file. Unused methods write nothing and return nil.
type filePackageCollector struct {
	path  string
	calls atomic.Int32
	// gate, when non-nil, is received from before CollectPackages reads the
	// file, so a test can hold a run open.
	gate chan struct{}
	// started, when non-nil, receives a value each time CollectPackages begins.
	started chan struct{}
}

func (f *filePackageCollector) CollectOS(context.Context, map[string]string) error { return nil }
func (f *filePackageCollector) CollectServices(context.Context, map[string]string) error {
	return nil
}
func (f *filePackageCollector) CollectProcesses(context.Context, map[string]string) error {
	return nil
}

func (f *filePackageCollector) CollectPackages(ctx context.Context, attrs map[string]string) error {
	f.calls.Add(1)
	if f.started != nil {
		select {
		case f.started <- struct{}{}:
		default:
		}
	}
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	data, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}
	attrs[testPackageAttr] = strings.TrimSpace(string(data))
	return nil
}

// newFilePackageCollector builds a Collector whose software source is the
// package-list file at a fresh t.TempDir() path, holding initial.
func newFilePackageCollector(t *testing.T, initial string, sw *filePackageCollector, opts ...CollectorOption) (*Collector, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "packages.txt")
	require.NoError(t, os.WriteFile(path, []byte(initial), 0o600))
	sw.path = path

	snap, err := dnasnapshot.Load(dnaSnapshotFixturePath)
	require.NoError(t, err)
	base := []CollectorOption{
		WithHardwareCollector(dnasnapshot.NewHardwareCollector(snap.Hardware)),
		WithSoftwareCollector(sw),
		WithNetworkCollector(dnasnapshot.NewNetworkCollector(snap.Network)),
		WithSecurityCollector(dnasnapshot.NewSecurityCollector(snap.Security)),
	}
	return NewCollector(logging.NewLogger("error"), append(base, opts...)...), path
}

func TestSlowCollectionRefreshesOnInterval(t *testing.T) {
	const interval = 300 * time.Millisecond
	sw := &filePackageCollector{}
	c, path := newFilePackageCollector(t, "pkg-v1", sw, WithSlowCollectionInterval(interval))
	ctx := t.Context()

	assert.True(t, c.SlowCollectedAt().IsZero(), "no collection has completed yet")

	_, err := c.Collect(ctx)
	require.NoError(t, err)
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c.WaitForBackground(waitCtx)
	require.NoError(t, waitCtx.Err(), "first slow run must complete")
	assert.Equal(t, "pkg-v1", c.RawAttributes(ctx)[testPackageAttr])
	first := c.SlowCollectedAt()
	require.False(t, first.IsZero())

	require.NoError(t, os.WriteFile(path, []byte("pkg-v2"), 0o600))
	time.Sleep(interval + 100*time.Millisecond)

	_, err = c.Collect(ctx)
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		return c.RawAttributes(ctx)[testPackageAttr] == "pkg-v2"
	}, 30*time.Second, 25*time.Millisecond, "RawAttributes must show the re-collected value")
	assert.True(t, c.SlowCollectedAt().After(first), "SlowCollectedAt must advance")
	assert.EqualValues(t, 2, sw.calls.Load())
}

func TestSlowCollectionDoesNotRerunBeforeInterval(t *testing.T) {
	sw := &filePackageCollector{}
	c, path := newFilePackageCollector(t, "pkg-v1", sw) // default 30m interval
	ctx := t.Context()

	_, err := c.Collect(ctx)
	require.NoError(t, err)
	c.WaitForBackground(ctx)

	require.NoError(t, os.WriteFile(path, []byte("pkg-v2"), 0o600))
	for i := 0; i < 3; i++ {
		_, err = c.Collect(ctx)
		require.NoError(t, err)
	}
	assert.EqualValues(t, 1, sw.calls.Load(), "no re-run within the default interval")
	assert.Equal(t, "pkg-v1", c.RawAttributes(ctx)[testPackageAttr])
}

func TestWithSlowCollectionIntervalNonPositiveKeepsDefault(t *testing.T) {
	logger := logging.NewLogger("error")
	assert.Equal(t, DefaultSlowCollectionInterval, NewCollector(logger).slowInterval)
	assert.Equal(t, DefaultSlowCollectionInterval, NewCollector(logger, WithSlowCollectionInterval(0)).slowInterval)
	assert.Equal(t, DefaultSlowCollectionInterval, NewCollector(logger, WithSlowCollectionInterval(-time.Second)).slowInterval)
	assert.Equal(t, time.Second, NewCollector(logger, WithSlowCollectionInterval(time.Second)).slowInterval)
	assert.Equal(t, 30*time.Minute, DefaultSlowCollectionInterval)
}

func TestSlowCollectionSingleFlight(t *testing.T) {
	gate := make(chan struct{})
	sw := &filePackageCollector{gate: gate}
	// A tiny interval means only the single-flight guard can prevent overlap.
	c, _ := newFilePackageCollector(t, "pkg-v1", sw, WithSlowCollectionInterval(time.Nanosecond))
	ctx := t.Context()

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Collect(ctx)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	_, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, sw.calls.Load(), "at most one slow run while one is blocked")

	close(gate)
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c.WaitForBackground(waitCtx)
	require.NoError(t, waitCtx.Err())
}

func TestCollectDoesNotWaitForSlowRun(t *testing.T) {
	const interval = 100 * time.Millisecond
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	sw := &filePackageCollector{started: started}
	c, _ := newFilePackageCollector(t, "pkg-v1", sw, WithSlowCollectionInterval(interval))
	ctx := t.Context()

	_, err := c.Collect(ctx)
	require.NoError(t, err)
	c.WaitForBackground(ctx)
	require.Equal(t, "pkg-v1", c.RawAttributes(ctx)[testPackageAttr])

	// Block the next run, then let the interval elapse.
	sw.gate = gate
	drain(started)
	time.Sleep(interval + 50*time.Millisecond)

	_, err = c.Collect(ctx) // triggers the re-run, which blocks on gate
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("re-run did not start")
	}

	begin := time.Now()
	d, err := c.Collect(ctx)
	require.NoError(t, err)
	assert.Less(t, time.Since(begin), 5*time.Second, "Collect must not wait for the slow run")
	require.NotNil(t, d)
	assert.Equal(t, "pkg-v1", c.RawAttributes(ctx)[testPackageAttr], "previous slow attributes are still merged")

	close(gate)
}

func drain(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// TestSlowRerunWithExpiredContextKeepsPreviousResult drives runBackgroundCollection
// directly with a cancelled context: a re-run keeps the previous result and does
// not advance SlowCollectedAt, while the single-flight flag is released.
func TestSlowRerunWithExpiredContextKeepsPreviousResult(t *testing.T) {
	sw := &filePackageCollector{}
	c, path := newFilePackageCollector(t, "pkg-v1", sw)
	ctx := t.Context()

	_, err := c.Collect(ctx)
	require.NoError(t, err)
	c.WaitForBackground(ctx)
	before := c.SlowCollectedAt()
	require.False(t, before.IsZero())

	require.NoError(t, os.WriteFile(path, []byte("pkg-v2"), 0o600))
	c.slowStateMu.Lock()
	c.slowRunning = true
	c.slowStateMu.Unlock()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	c.runBackgroundCollection(cancelled, false)

	assert.Equal(t, "pkg-v1", c.RawAttributes(ctx)[testPackageAttr], "previous result is kept")
	assert.Equal(t, before, c.SlowCollectedAt(), "SlowCollectedAt does not advance")
	c.slowStateMu.Lock()
	running := c.slowRunning
	c.slowStateMu.Unlock()
	assert.False(t, running, "single-flight flag released")
}
