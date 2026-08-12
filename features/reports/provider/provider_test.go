// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// warnCapturingLogger records Warn-level log calls; all other levels are no-ops.
// It is a real log-buffer implementation — not a mock of any CFGMS component —
// following the same pattern as errorCapturingLogger in handlers_jobs_test.go.
type warnCapturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []struct {
		msg string
		kvs []interface{}
	}
}

func (l *warnCapturingLogger) Warn(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, struct {
		msg string
		kvs []interface{}
	}{msg: msg, kvs: kvs})
}

// kvValue returns the first value for key across all captured Warn entries, or nil.
func (l *warnCapturingLogger) kvValue(key string) interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == key {
				return e.kvs[i+1]
			}
		}
	}
	return nil
}

// kvValues returns every value logged for key, in the order the Warn calls were made.
func (l *warnCapturingLogger) kvValues(key string) []interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	var values []interface{}
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == key {
				values = append(values, e.kvs[i+1])
			}
		}
	}
	return values
}

// countMessages returns how many captured Warn entries used the given message.
func (l *warnCapturingLogger) countMessages(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	count := 0
	for _, e := range l.entries {
		if e.msg == msg {
			count++
		}
	}
	return count
}

// newTestStorageManager creates a real storage.Manager backed by a t.TempDir()-isolated
// SQLite database, following the same convention as storage_test.go's createTestConfig.
func newTestStorageManager(t *testing.T) *storage.Manager {
	t.Helper()
	config := storage.DefaultConfig()
	config.DataDir = t.TempDir()
	manager, err := storage.NewManager(config, logging.NewNoopLogger())
	require.NoError(t, err, "failed to create test storage manager")
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Logf("test storage manager Close() failed: %v", err)
		}
	})
	return manager
}

// newClosedTestStorageManager returns a real storage.Manager whose SQLite database
// has been closed. Every GetHistory call against it fails with a genuine storage
// error — no substitute implementation is needed to exercise the error paths, and
// because SQLiteBackend.GetHistoryByDeviceID formats the caller-supplied device ID
// into its error text, the resulting error carries real tainted input.
func newClosedTestStorageManager(t *testing.T) *storage.Manager {
	t.Helper()
	manager := newTestStorageManager(t)
	require.NoError(t, manager.Close(), "closing the test storage manager must succeed")
	return manager
}

// closedStoreErrorText returns the exact error text a closed storage.Manager produces
// for deviceID, so assertions compare against the real message rather than a
// hand-written approximation of one.
func closedStoreErrorText(t *testing.T, manager *storage.Manager, deviceID string) string {
	t.Helper()
	_, err := manager.GetHistory(context.Background(), deviceID, &storage.QueryOptions{IncludeData: true})
	require.Error(t, err, "a closed storage manager must fail GetHistory")
	return err.Error()
}

// newTestDriftDetector creates a real drift.Detector with the default configuration.
func newTestDriftDetector(t *testing.T) drift.Detector {
	t.Helper()
	detector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logging.NewNoopLogger())
	require.NoError(t, err, "failed to create test drift detector")
	t.Cleanup(func() {
		if err := detector.Close(); err != nil {
			t.Logf("test drift detector Close() failed: %v", err)
		}
	})
	return detector
}

// newTestDNA builds a minimal commonpb.DNA for the given device ID and attribute set.
func newTestDNA(deviceID string, attributes map[string]string) *commonpb.DNA {
	return &commonpb.DNA{
		Id:             deviceID,
		Attributes:     attributes,
		LastUpdated:    timestamppb.Now(),
		AttributeCount: int32(len(attributes)),
	}
}

func TestGetDriftEvents_NoDeviceIDs_NoDiscoveredDevices_ReturnsEmpty(t *testing.T) {
	// When DeviceIDs is empty and no DNA records exist to discover devices from,
	// GetDriftEvents returns an empty (non-nil) slice without error.
	p := &DataProvider{
		// Real, empty storage: no DNA records exist, so device discovery finds nothing.
		storageManager: newTestStorageManager(t),
		driftDetector:  newTestDriftDetector(t),
		logger:         logging.NewNoopLogger(),
	}

	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
	}

	events, err := p.GetDriftEvents(context.Background(), query)

	require.NoError(t, err, "GetDriftEvents must not return an error")
	assert.NotNil(t, events, "GetDriftEvents must return a non-nil slice")
	assert.Empty(t, events, "no discovered devices means no drift events")
}

func TestGetDriftEvents_WithDeviceIDs_NoStoredSnapshots_ReturnsEmpty(t *testing.T) {
	// A device with no stored DNA snapshots in the queried time range produces
	// zero events, not an error. A real storage.Manager with nothing stored returns
	// 0 records for both device IDs, which is below the 2-snapshot pairing threshold.
	p := &DataProvider{
		storageManager: newTestStorageManager(t),
		driftDetector:  newTestDriftDetector(t),
		logger:         logging.NewNoopLogger(),
	}

	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-7 * 24 * time.Hour),
			End:   time.Now(),
		},
		DeviceIDs: []string{"device-1", "device-2"},
	}

	events, err := p.GetDriftEvents(context.Background(), query)

	require.NoError(t, err)
	assert.NotNil(t, events)
	assert.Empty(t, events, "devices with no stored snapshots produce no drift events")
}

// TestGetDriftEvents_TwoSnapshots_ProducesRealEvents is the required AC test verifying
// that two fixture DNA snapshots with a real attribute difference produce a non-empty
// DriftEvent slice with Severity set from the actual change.
//
// Uses real storage.Manager (SQLite, t.TempDir()) and real drift.Detector — no mocks.
func TestGetDriftEvents_TwoSnapshots_ProducesRealEvents(t *testing.T) {
	manager := newTestStorageManager(t)
	detector := newTestDriftDetector(t)

	deviceID := "test-device-two-snapshots"
	ctx := context.Background()

	// Store first DNA snapshot.
	dna1 := newTestDNA(deviceID, map[string]string{
		"os":       "linux",
		"hostname": "host-before",
		"arch":     "amd64",
	})
	require.NoError(t, manager.Store(ctx, deviceID, dna1, nil))

	// Store second DNA snapshot with a different hostname (network attribute → SeverityWarning).
	dna2 := newTestDNA(deviceID, map[string]string{
		"os":       "linux",
		"hostname": "host-after",
		"arch":     "amd64",
	})
	require.NoError(t, manager.Store(ctx, deviceID, dna2, nil))

	p := &DataProvider{
		storageManager: manager,
		driftDetector:  detector,
		logger:         logging.NewNoopLogger(),
	}

	events, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
		DeviceIDs: []string{deviceID},
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now().Add(1 * time.Hour),
		},
	})

	require.NoError(t, err)
	assert.NotEmpty(t, events, "two DNA snapshots with a real attribute difference must produce drift events")
	for _, event := range events {
		assert.NotEmpty(t, event.Severity, "each DriftEvent must have Severity set from the actual change")
	}
}

// TestGetDriftEvents_SingleSnapshot_NoEvents is the required AC test verifying that
// a device with only one stored snapshot (fewer than 2) in the queried time range
// returns an empty slice without error.
//
// Uses real storage.Manager (SQLite, t.TempDir()) and real drift.Detector — no mocks.
func TestGetDriftEvents_SingleSnapshot_NoEvents(t *testing.T) {
	manager := newTestStorageManager(t)
	detector := newTestDriftDetector(t)

	deviceID := "test-device-single-snapshot"
	ctx := context.Background()

	// Store exactly one DNA snapshot — no consecutive pair to diff.
	require.NoError(t, manager.Store(ctx, deviceID, newTestDNA(deviceID, map[string]string{
		"os":       "linux",
		"hostname": "host-only",
	}), nil))

	p := &DataProvider{
		storageManager: manager,
		driftDetector:  detector,
		logger:         logging.NewNoopLogger(),
	}

	events, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
		DeviceIDs: []string{deviceID},
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now().Add(1 * time.Hour),
		},
	})

	require.NoError(t, err, "single snapshot must not return an error")
	assert.Empty(t, events, "single snapshot has no baseline pair to diff against — zero events")
}

// ── GetDriftEvents log sanitization ──────────────────────────────────────────

// TestGetDriftEvents_StorageError_LogValueSanitized covers the log-injection
// mitigation in GetDriftEvents' per-device history-load failure path
// (provider.go, "failed to get DNA history for drift detection"), the analogue of
// the GetDNAData and GetDeviceStats fixes.
//
// The failing store is a real storage.Manager whose database has been closed.
// SQLiteBackend formats the caller-supplied device ID into its error text, so a
// device ID carrying \n/\r produces a genuinely tainted error from real CFGMS
// code — both the device_id and error fields must be stripped in the log while
// their payload text survives.
func TestGetDriftEvents_StorageError_LogValueSanitized(t *testing.T) {
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	t.Run("newlines_stripped_in_device_id_and_error", func(t *testing.T) {
		manager := newClosedTestStorageManager(t)
		dirtyDeviceID := "device-1\nINJECTED drift event\r\nseverity=critical"

		require.Contains(t, closedStoreErrorText(t, manager, dirtyDeviceID), "\n",
			"precondition: the real storage error must carry the injected newlines")

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			driftDetector:  newTestDriftDetector(t),
			logger:         capLog,
		}

		events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{dirtyDeviceID},
		})

		require.NoError(t, err, "GetDriftEvents logs the per-device failure and continues")
		assert.Empty(t, events, "a device whose history cannot be read contributes no drift events")
		require.Equal(t, 1, capLog.countMessages("failed to get DNA history for drift detection"),
			"the failing device must be warned about exactly once")

		loggedID := capLog.kvValue("device_id")
		require.NotNil(t, loggedID, "expected 'device_id' key in logged Warn entries")
		loggedIDStr, ok := loggedID.(string)
		require.True(t, ok, "sanitized device_id must be logged as a string")
		assert.NotContains(t, loggedIDStr, "\n", "\\n must be stripped from logged device_id")
		assert.NotContains(t, loggedIDStr, "\r", "\\r must be stripped from logged device_id")
		assert.Contains(t, loggedIDStr, "device-1", "device id text must be preserved")

		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr, "expected 'error' key in logged Warn entries")
		loggedErrStr, ok := loggedErr.(string)
		require.True(t, ok, "sanitized error must be logged as a string")
		assert.NotContains(t, loggedErrStr, "\n", "\\n must be stripped from logged error")
		assert.NotContains(t, loggedErrStr, "\r", "\\r must be stripped from logged error")
		assert.Contains(t, loggedErrStr, "failed to query DNA records", "error message text must be preserved")
	})

	t.Run("clean_device_id_and_error_pass_through", func(t *testing.T) {
		manager := newClosedTestStorageManager(t)
		rawErr := closedStoreErrorText(t, manager, "device-clean")
		require.NotContains(t, rawErr, "\n", "precondition: this storage error is untainted")

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			driftDetector:  newTestDriftDetector(t),
			logger:         capLog,
		}

		events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{"device-clean"},
		})

		require.NoError(t, err)
		assert.Empty(t, events)

		assert.Equal(t, "device-clean", capLog.kvValue("device_id"),
			"clean device id must pass through unchanged")
		assert.Equal(t, rawErr, capLog.kvValue("error"),
			"clean error message must pass through unchanged")
	})
}

// TestGetDriftEvents_DetectDriftError_SkipsPairAndLogsSanitized covers the
// drift-detection failure branch in GetDriftEvents ("drift detection failed for
// consecutive snapshots"): the offending snapshot pair is skipped rather than
// failing the whole report, and both logged fields are sanitized.
//
// The failure comes from the real drift.Detector rejecting a malformed pair: the
// two snapshots stored under one fleet device ID carry mismatched DNA.Id values,
// which DetectDrift refuses to compare. Storage is a real SQLite-backed
// storage.Manager under t.TempDir() — no substitute detector or store.
func TestGetDriftEvents_DetectDriftError_SkipsPairAndLogsSanitized(t *testing.T) {
	ctx := context.Background()
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now().Add(1 * time.Hour),
	}

	// storeMismatchedPair writes two snapshots for deviceID whose embedded DNA.Id
	// values differ, so the consecutive pair is one the real detector rejects.
	storeMismatchedPair := func(t *testing.T, manager *storage.Manager, deviceID string) {
		t.Helper()
		require.NoError(t, manager.Store(ctx, deviceID, newTestDNA("dna-id-before", map[string]string{
			"os":       "linux",
			"hostname": "host-before",
		}), nil))
		require.NoError(t, manager.Store(ctx, deviceID, newTestDNA("dna-id-after", map[string]string{
			"os":       "linux",
			"hostname": "host-after",
		}), nil))
	}

	t.Run("baseline_matching_dna_ids_produce_events", func(t *testing.T) {
		// Proves the fixture shape reaches DetectDrift at all: with consistent DNA
		// IDs the very same two snapshots yield events, so the empty result below
		// is caused by the detection error and not by an unreached code path.
		manager := newTestStorageManager(t)
		deviceID := "device-matching-ids"
		require.NoError(t, manager.Store(ctx, deviceID, newTestDNA(deviceID, map[string]string{
			"os":       "linux",
			"hostname": "host-before",
		}), nil))
		require.NoError(t, manager.Store(ctx, deviceID, newTestDNA(deviceID, map[string]string{
			"os":       "linux",
			"hostname": "host-after",
		}), nil))

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			driftDetector:  newTestDriftDetector(t),
			logger:         capLog,
		}

		events, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{deviceID},
		})

		require.NoError(t, err)
		assert.NotEmpty(t, events, "a well-formed pair must produce drift events")
		assert.Zero(t, capLog.countMessages("drift detection failed for consecutive snapshots"),
			"a well-formed pair must not warn")
	})

	t.Run("newlines_stripped_in_device_id", func(t *testing.T) {
		manager := newTestStorageManager(t)
		dirtyDeviceID := "device-1\nINJECTED drift event\r\nseverity=critical"
		storeMismatchedPair(t, manager, dirtyDeviceID)

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			driftDetector:  newTestDriftDetector(t),
			logger:         capLog,
		}

		events, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{dirtyDeviceID},
		})

		require.NoError(t, err, "a rejected snapshot pair is skipped, not surfaced as a query error")
		assert.Empty(t, events, "the only snapshot pair was rejected, so no events remain")
		require.Equal(t, 1, capLog.countMessages("drift detection failed for consecutive snapshots"),
			"exactly one consecutive pair exists, so exactly one warning is expected")

		loggedID := capLog.kvValue("device_id")
		require.NotNil(t, loggedID, "expected 'device_id' key in logged Warn entries")
		loggedIDStr, ok := loggedID.(string)
		require.True(t, ok, "sanitized device_id must be logged as a string")
		assert.NotContains(t, loggedIDStr, "\n", "\\n must be stripped from logged device_id")
		assert.NotContains(t, loggedIDStr, "\r", "\\r must be stripped from logged device_id")
		assert.Contains(t, loggedIDStr, "device-1", "device id text must be preserved")

		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr, "expected 'error' key in logged Warn entries")
		loggedErrStr, ok := loggedErr.(string)
		require.True(t, ok, "sanitized error must be logged as a string")
		assert.NotContains(t, loggedErrStr, "\n", "\\n must be stripped from logged error")
		assert.NotContains(t, loggedErrStr, "\r", "\\r must be stripped from logged error")
		assert.Contains(t, loggedErrStr, "DNA IDs must match for comparison",
			"the real detector's rejection reason must be preserved")
	})

	t.Run("clean_device_id_and_error_pass_through", func(t *testing.T) {
		manager := newTestStorageManager(t)
		deviceID := "device-clean-mismatched-dna"
		storeMismatchedPair(t, manager, deviceID)

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			driftDetector:  newTestDriftDetector(t),
			logger:         capLog,
		}

		events, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{deviceID},
		})

		require.NoError(t, err)
		assert.Empty(t, events)

		assert.Equal(t, deviceID, capLog.kvValue("device_id"),
			"clean device id must pass through unchanged")
		assert.Equal(t, "DNA IDs must match for comparison", capLog.kvValue("error"),
			"clean error message must pass through unchanged")
	})
}

// ── GetTrendData ─────────────────────────────────────────────────────────────

func TestGetTrendData_UnsupportedMetric_ReturnsError(t *testing.T) {
	p := &DataProvider{
		logger: logging.NewNoopLogger(),
	}
	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
	}

	_, err := p.GetTrendData(context.Background(), "unknown_metric", query)

	require.Error(t, err, "unsupported metric must return an error")
	assert.Contains(t, err.Error(), "unknown_metric")
}

// newTrendFixture stores real DNA history in a real storage.Manager and returns a
// provider plus a query spanning exactly two daily buckets.
//
// The range is anchored on UTC midnight so createTimeBuckets is deterministic:
// bucket[0] is yesterday (no records were stored then) and bucket[1] is today
// (every record and every drift event lands there). Fixture contents:
//
//	device-a — two snapshots differing only in hostname, which the drift detector
//	           categorises as network/warning: exactly one DriftEvent.
//	device-b — one snapshot: counted as a device, contributes no drift event.
func newTrendFixture(t *testing.T) (*DataProvider, interfaces.DataQuery) {
	t.Helper()

	manager := newTestStorageManager(t)
	ctx := context.Background()

	require.NoError(t, manager.Store(ctx, "device-a", newTestDNA("device-a", map[string]string{
		"os":       "linux",
		"hostname": "host-before",
	}), nil))
	require.NoError(t, manager.Store(ctx, "device-a", newTestDNA("device-a", map[string]string{
		"os":       "linux",
		"hostname": "host-after",
	}), nil))
	require.NoError(t, manager.Store(ctx, "device-b", newTestDNA("device-b", map[string]string{
		"os":       "windows",
		"hostname": "host-b",
	}), nil))

	p := &DataProvider{
		storageManager: manager,
		driftDetector:  newTestDriftDetector(t),
		logger:         logging.NewNoopLogger(),
	}

	midnightUTC := time.Now().UTC().Truncate(24 * time.Hour)
	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: midnightUTC.Add(-24 * time.Hour),
			End:   midnightUTC.Add(24 * time.Hour),
		},
		DeviceIDs: []string{"device-a", "device-b"},
	}

	return p, query
}

// assertDailyBuckets checks that points are the two expected day buckets of the
// fixture query, in ascending order.
func assertDailyBuckets(t *testing.T, query interfaces.DataQuery, points []interfaces.TrendPoint) {
	t.Helper()
	require.Len(t, points, 2, "a 48h range anchored on UTC midnight yields exactly two daily buckets")
	assert.True(t, points[0].Timestamp.Equal(query.TimeRange.Start),
		"first bucket must start at the range start, got %v", points[0].Timestamp)
	assert.True(t, points[1].Timestamp.Equal(query.TimeRange.Start.Add(24*time.Hour)),
		"second bucket must start 24h later, got %v", points[1].Timestamp)
}

func TestGetTrendData_DriftEvents_CountsEventsPerDailyBucket(t *testing.T) {
	p, query := newTrendFixture(t)

	points, err := p.GetTrendData(context.Background(), "drift_events", query)

	require.NoError(t, err)
	assertDailyBuckets(t, query, points)

	assert.Equal(t, 0.0, points[0].Value, "no DNA was stored yesterday, so no drift events bucket there")
	assert.Equal(t, "0 events", points[0].Label)

	assert.Equal(t, 1.0, points[1].Value,
		"device-a's single hostname change is the only drift event, and it lands in today's bucket")
	assert.Equal(t, "1 events", points[1].Label)
}

func TestGetTrendData_ComplianceScore_ScoresEachDailyBucket(t *testing.T) {
	p, query := newTrendFixture(t)

	points, err := p.GetTrendData(context.Background(), "compliance_score", query)

	require.NoError(t, err)
	assertDailyBuckets(t, query, points)

	assert.Equal(t, 1.0, points[0].Value, "a day with no drift events scores perfect compliance")
	assert.Equal(t, "1.00", points[0].Label)

	// One warning-severity event over a one-day bucket: weight 0.5, so
	// score = 1 - (0.5 / 1 day) / 5 = 0.90.
	assert.InDelta(t, 0.90, points[1].Value, 1e-9,
		"one warning-severity drift event in a one-day bucket scores 0.90")
	assert.Equal(t, "0.90", points[1].Label)
}

func TestGetTrendData_DeviceCount_CountsUniqueDevicesPerDailyBucket(t *testing.T) {
	p, query := newTrendFixture(t)

	points, err := p.GetTrendData(context.Background(), "device_count", query)

	require.NoError(t, err)
	assertDailyBuckets(t, query, points)

	assert.Equal(t, 0.0, points[0].Value, "no DNA was stored yesterday")
	assert.Equal(t, "0 devices", points[0].Label)

	assert.Equal(t, 2.0, points[1].Value,
		"device-a (three records across two devices' worth of snapshots) and device-b are two unique devices")
	assert.Equal(t, "2 devices", points[1].Label)
}

// ── GetTrendData day-query failure paths ─────────────────────────────────────

// TestGetTrendData_ComplianceScore_DayQueryFails_SkipsBucketAndWarns covers the
// error branch in getComplianceTrends: when the per-day GetDriftEvents call fails,
// that bucket is dropped from the trend line and a Warn naming the bucket is emitted.
//
// The failure is produced by a real cancelled request rather than a substituted
// store: GetDriftEvents rejects an aborted context, which is exactly the systemic
// (as opposed to per-device) failure this branch exists to absorb.
func TestGetTrendData_ComplianceScore_DayQueryFails_SkipsBucketAndWarns(t *testing.T) {
	p, query := newTrendFixture(t)
	capLog := &warnCapturingLogger{}
	p.logger = capLog

	healthy, err := p.GetTrendData(context.Background(), "compliance_score", query)
	require.NoError(t, err)
	require.Len(t, healthy, 2, "baseline: both daily buckets are produced when the day query succeeds")
	require.Zero(t, capLog.countMessages("failed to get events for compliance trend"),
		"baseline run must not warn")

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	points, err := p.GetTrendData(cancelledCtx, "compliance_score", query)

	require.NoError(t, err, "a failed day is skipped, not surfaced as a trend-wide error")
	assert.Less(t, len(points), len(healthy), "each bucket whose day query fails is dropped")
	assert.Empty(t, points, "every day query fails once the request is cancelled")

	assert.Equal(t, len(healthy), capLog.countMessages("failed to get events for compliance trend"),
		"one warning per skipped bucket")

	skipped := capLog.kvValues("date")
	require.Len(t, skipped, len(healthy))
	for i, value := range skipped {
		bucket, ok := value.(time.Time)
		require.True(t, ok, "the skipped bucket must be logged as a time.Time")
		assert.True(t, bucket.Equal(healthy[i].Timestamp),
			"warning %d must name the bucket that was skipped", i)
	}

	loggedErr, ok := capLog.kvValue("error").(string)
	require.True(t, ok, "the sanitized error must be logged as a string")
	assert.Contains(t, loggedErr, "context canceled", "the underlying cause must be logged")
	assert.NotContains(t, loggedErr, "\n", "\\n must be stripped from the logged error")
	assert.NotContains(t, loggedErr, "\r", "\\r must be stripped from the logged error")
}

// TestGetTrendData_DeviceCount_DayQueryFails_SkipsBucketAndWarns covers the
// equivalent error branch in getDeviceCountTrends.
func TestGetTrendData_DeviceCount_DayQueryFails_SkipsBucketAndWarns(t *testing.T) {
	p, query := newTrendFixture(t)
	capLog := &warnCapturingLogger{}
	p.logger = capLog

	healthy, err := p.GetTrendData(context.Background(), "device_count", query)
	require.NoError(t, err)
	require.Len(t, healthy, 2, "baseline: both daily buckets are produced when the day query succeeds")
	require.Zero(t, capLog.countMessages("failed to get DNA records for device count trend"),
		"baseline run must not warn")

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	points, err := p.GetTrendData(cancelledCtx, "device_count", query)

	require.NoError(t, err, "a failed day is skipped, not surfaced as a trend-wide error")
	assert.Less(t, len(points), len(healthy), "each bucket whose day query fails is dropped")
	assert.Empty(t, points, "every day query fails once the request is cancelled")

	assert.Equal(t, len(healthy), capLog.countMessages("failed to get DNA records for device count trend"),
		"one warning per skipped bucket")

	skipped := capLog.kvValues("date")
	require.Len(t, skipped, len(healthy))
	for i, value := range skipped {
		bucket, ok := value.(time.Time)
		require.True(t, ok, "the skipped bucket must be logged as a time.Time")
		assert.True(t, bucket.Equal(healthy[i].Timestamp),
			"warning %d must name the bucket that was skipped", i)
	}

	loggedErr, ok := capLog.kvValue("error").(string)
	require.True(t, ok, "the sanitized error must be logged as a string")
	assert.Contains(t, loggedErr, "context canceled", "the underlying cause must be logged")
	assert.NotContains(t, loggedErr, "\n", "\\n must be stripped from the logged error")
	assert.NotContains(t, loggedErr, "\r", "\\r must be stripped from the logged error")
}

// ── calculateComplianceScore ──────────────────────────────────────────────────

func TestCalculateComplianceScore_NoEvents_ReturnsPerfect(t *testing.T) {
	p := &DataProvider{logger: logging.NewNoopLogger()}
	tr := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	score := p.calculateComplianceScore(nil, tr)

	assert.Equal(t, 1.0, score, "no drift events must yield perfect compliance")
}

func TestCalculateComplianceScore_ZeroDuration_DoesNotPanic(t *testing.T) {
	p := &DataProvider{logger: logging.NewNoopLogger()}
	now := time.Now()
	tr := interfaces.TimeRange{Start: now, End: now}

	// Should not panic; durationDays floors to 1 internally.
	score := p.calculateComplianceScore(nil, tr)
	assert.Equal(t, 1.0, score)
}

// ── calculateRiskLevel ────────────────────────────────────────────────────────

func TestCalculateRiskLevel_HighComplianceNoCritical_ReturnsLow(t *testing.T) {
	p := &DataProvider{logger: logging.NewNoopLogger()}

	level := p.calculateRiskLevel(0.9, nil)

	assert.Equal(t, interfaces.RiskLevelLow, level)
}

func TestCalculateRiskLevel_LowCompliance_ReturnsCritical(t *testing.T) {
	p := &DataProvider{logger: logging.NewNoopLogger()}

	level := p.calculateRiskLevel(0.1, nil)

	assert.Equal(t, interfaces.RiskLevelCritical, level)
}

// ── GetDNAData log sanitization ───────────────────────────────────────────────

// TestGetDNAData_StorageError_LogValueSanitized is the required AC test for the
// CodeQL go/log-injection fix at provider.go (GetDNAData error log path).
//
// It asserts that a storage error containing \n/\r is stripped in the logged
// "error" field (preventing log-line forgery), and that a normal error message
// passes through unchanged.
//
// The failing store is a real storage.Manager whose database has been closed. Its
// error text embeds the caller-supplied device ID (SQLiteBackend formats it into
// "failed to count history for device %s"), so a device ID carrying newlines
// produces a genuinely tainted error from real CFGMS code — the exact flow CodeQL
// flags — with no substitute store involved.
func TestGetDNAData_StorageError_LogValueSanitized(t *testing.T) {
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	t.Run("newlines_stripped", func(t *testing.T) {
		manager := newClosedTestStorageManager(t)
		dirtyDeviceID := "device-1\nforged log line\r\nalso forged"

		rawErr := closedStoreErrorText(t, manager, dirtyDeviceID)
		require.Contains(t, rawErr, "\n",
			"precondition: the real storage error must carry the injected newlines")

		capLog := &warnCapturingLogger{}
		p := &DataProvider{storageManager: manager, logger: capLog}

		_, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{dirtyDeviceID},
		})

		require.NoError(t, err, "GetDNAData logs the error and continues; it must not surface it")
		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr, "expected 'error' key in logged Warn entries")
		loggedStr, ok := loggedErr.(string)
		require.True(t, ok, "sanitized error must be logged as a string")
		assert.NotContains(t, loggedStr, "\n", "\\n must be stripped from logged error")
		assert.NotContains(t, loggedStr, "\r", "\\r must be stripped from logged error")
		assert.Contains(t, loggedStr, "failed to query DNA records", "error message text must be preserved")

		loggedID := capLog.kvValue("device_id")
		loggedIDStr, ok := loggedID.(string)
		require.True(t, ok, "sanitized device_id must be logged as a string")
		assert.NotContains(t, loggedIDStr, "\n", "\\n must be stripped from logged device_id")
		assert.NotContains(t, loggedIDStr, "\r", "\\r must be stripped from logged device_id")
		assert.Contains(t, loggedIDStr, "device-1", "device id text must be preserved")
	})

	t.Run("clean_error_passes_through", func(t *testing.T) {
		manager := newClosedTestStorageManager(t)
		rawErr := closedStoreErrorText(t, manager, "device-clean")
		require.NotContains(t, rawErr, "\n", "precondition: this storage error is untainted")

		capLog := &warnCapturingLogger{}
		p := &DataProvider{storageManager: manager, logger: capLog}

		_, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{"device-clean"},
		})

		require.NoError(t, err)
		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr)
		loggedStr, ok := loggedErr.(string)
		require.True(t, ok)
		assert.Equal(t, rawErr, loggedStr,
			"clean error message must pass through unchanged")
	})
}

// ── GetDeviceStats log sanitization ──────────────────────────────────────────

// TestGetDeviceStats_CalculateError_LogValueSanitized covers the log-injection
// mitigation in GetDeviceStats' per-device failure path (provider.go), the
// analogue of the GetDNAData fix. A single-device storage failure propagates out
// of calculateDeviceStats; GetDeviceStats then skips the device and logs a Warn.
//
// Both the caller-supplied device_id AND the wrapped error message can carry
// attacker-controlled \n/\r, so this asserts both fields are stripped in the log
// while their payload text survives.
func TestGetDeviceStats_CalculateError_LogValueSanitized(t *testing.T) {
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	t.Run("newlines_stripped_in_device_id_and_error", func(t *testing.T) {
		manager := newClosedTestStorageManager(t)
		dirtyDeviceID := "device-1\nINJECTED admin login\r\nfrom 10.0.0.1"

		require.Contains(t, closedStoreErrorText(t, manager, dirtyDeviceID), "\n",
			"precondition: the real storage error must carry the injected newlines")

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			logger:         capLog,
		}

		stats, err := p.GetDeviceStats(context.Background(), []string{dirtyDeviceID}, timeRange)

		require.NoError(t, err, "GetDeviceStats logs the per-device failure and continues")
		assert.Empty(t, stats, "device with a failing calculateDeviceStats must be skipped")

		loggedID := capLog.kvValue("device_id")
		require.NotNil(t, loggedID, "expected 'device_id' key in logged Warn entries")
		loggedIDStr, ok := loggedID.(string)
		require.True(t, ok, "sanitized device_id must be logged as a string")
		assert.NotContains(t, loggedIDStr, "\n", "\\n must be stripped from logged device_id")
		assert.NotContains(t, loggedIDStr, "\r", "\\r must be stripped from logged device_id")
		assert.Contains(t, loggedIDStr, "device-1", "device id text must be preserved")

		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr, "expected 'error' key in logged Warn entries")
		loggedErrStr, ok := loggedErr.(string)
		require.True(t, ok, "sanitized error must be logged as a string")
		assert.NotContains(t, loggedErrStr, "\n", "\\n must be stripped from logged error")
		assert.NotContains(t, loggedErrStr, "\r", "\\r must be stripped from logged error")
		assert.Contains(t, loggedErrStr, "failed to get DNA records", "error message text must be preserved")
	})

	t.Run("clean_device_id_and_error_pass_through", func(t *testing.T) {
		manager := newClosedTestStorageManager(t)
		rawErr := closedStoreErrorText(t, manager, "device-clean")
		require.NotContains(t, rawErr, "\n", "precondition: this storage error is untainted")

		capLog := &warnCapturingLogger{}
		p := &DataProvider{
			storageManager: manager,
			logger:         capLog,
		}

		stats, err := p.GetDeviceStats(context.Background(), []string{"device-clean"}, timeRange)

		require.NoError(t, err)
		assert.Empty(t, stats)

		loggedID := capLog.kvValue("device_id")
		require.NotNil(t, loggedID)
		assert.Equal(t, "device-clean", loggedID,
			"clean device id must pass through unchanged")

		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr)
		loggedErrStr, ok := loggedErr.(string)
		require.True(t, ok)
		assert.Contains(t, loggedErrStr, rawErr,
			"clean error message must pass through unchanged")
	})
}
