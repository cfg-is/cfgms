// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/dna/drift"
	eginterfaces "github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	egsqlite "github.com/cfgis/cfgms/pkg/entitygraph/providers/sqlite"
	egtypes "github.com/cfgis/cfgms/pkg/entitygraph/types"
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

// newTestEGProvider creates a real SQLiteEntityGraphProvider backed by a t.TempDir()
// isolated database — no mocks, real component following CLAUDE.md testing standards.
func newTestEGProvider(t *testing.T) *egsqlite.SQLiteEntityGraphProvider {
	t.Helper()
	path := filepath.Join(t.TempDir(), "eg.db")
	p, err := egsqlite.NewSQLiteEntityGraphProvider(path)
	require.NoError(t, err, "failed to create test entity graph provider")
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Logf("test entity graph provider Close() failed: %v", err)
		}
	})
	return p
}

// newClosedTestEGProvider returns a real SQLiteEntityGraphProvider whose database has
// been closed. Every method call against it fails with a genuine storage error — no
// substitute needed to exercise the error paths.
func newClosedTestEGProvider(t *testing.T) *egsqlite.SQLiteEntityGraphProvider {
	t.Helper()
	p := newTestEGProvider(t)
	require.NoError(t, p.Close(), "closing the test entity graph provider must succeed")
	return p
}

// storeHostEntity records a state observation for the bare host entity
// host:<deviceID> at the given time. This gives the host entity an observation
// history that GetHistory and GetDNAData can read.
func storeHostEntity(t *testing.T, egp eginterfaces.EntityGraphProvider, deviceID string, at time.Time) {
	t.Helper()
	eid, err := egtypes.NewEID("host", deviceID, "")
	require.NoError(t, err)
	err = egp.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: deviceID,
		Observations: []egtypes.Observation{
			{
				Source:     deviceID,
				ObservedAt: at,
				RecordedAt: at,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind": "host",
				},
			},
		},
	})
	require.NoError(t, err, "storing host entity observation must succeed")
}

// storeDriftState records a drift-diff observation for a fragment entity
// host:<deviceID>/<fragmentID> at the given time with the given field diffs.
// This creates a drift projection that ListDrifted and GetDriftEvents will return.
func storeDriftState(t *testing.T, egp eginterfaces.EntityGraphProvider, deviceID, fragmentID string, at time.Time, fields []interface{}) {
	t.Helper()
	eid, err := egtypes.NewEID("host", deviceID, fragmentID)
	require.NoError(t, err)
	err = egp.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: deviceID,
		Observations: []egtypes.Observation{
			{
				Source:     deviceID,
				ObservedAt: at,
				RecordedAt: at,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindDriftDiff,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"config_revision": "rev-1",
					"fields":          fields,
				},
			},
		},
	})
	require.NoError(t, err, "storing drift-diff observation must succeed")
}

// ── GetDriftEvents ────────────────────────────────────────────────────────────

func TestGetDriftEvents_EmptyEGProvider_ReturnsEmpty(t *testing.T) {
	// When the entity graph has no drift states, GetDriftEvents returns a
	// non-nil empty slice without error.
	p := &DataProvider{
		egProvider: newTestEGProvider(t),
		logger:     logging.NewNoopLogger(),
	}
	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
	}

	events, err := p.GetDriftEvents(context.Background(), query)

	require.NoError(t, err)
	assert.NotNil(t, events)
	assert.Empty(t, events, "no drift states in the entity graph means no drift events")
}

func TestGetDriftEvents_DeviceIDFilterExcludesOtherDevices(t *testing.T) {
	// A device ID filter must exclude drift states belonging to other devices.
	egp := newTestEGProvider(t)
	now := time.Now()

	storeDriftState(t, egp, "device-wanted", "host:hostname", now, []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "web01", "actual": "web02", "matching": false},
	})
	storeDriftState(t, egp, "device-excluded", "host:hostname", now, []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "db01", "actual": "db02", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		DeviceIDs: []string{"device-wanted"},
		TimeRange: interfaces.TimeRange{
			Start: now.Add(-1 * time.Hour),
			End:   now.Add(1 * time.Hour),
		},
	})

	require.NoError(t, err)
	require.Len(t, events, 1, "only device-wanted's drift event must be returned")
	assert.Equal(t, "device-wanted", events[0].DeviceID)
}

// TestGetDriftEvents_WithDriftState_ProducesEvent is the required AC test verifying
// that a persisted drift-diff observation in the entity graph produces a non-empty
// DriftEvent slice with Severity and DeviceID set correctly.
//
// Uses the real SQLiteEntityGraphProvider (t.TempDir()) — no mocks.
func TestGetDriftEvents_WithDriftState_ProducesEvent(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()
	deviceID := "test-device-drift"

	storeDriftState(t, egp, deviceID, "host:hostname", now, []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "web01", "actual": "web02", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		DeviceIDs: []string{deviceID},
		TimeRange: interfaces.TimeRange{
			Start: now.Add(-1 * time.Hour),
			End:   now.Add(1 * time.Hour),
		},
	})

	require.NoError(t, err)
	assert.NotEmpty(t, events, "a drift-diff observation must produce a drift event")
	assert.Equal(t, deviceID, events[0].DeviceID)
	assert.NotEmpty(t, events[0].Severity, "each DriftEvent must have Severity set")
}

func TestGetDriftEvents_OutsideTimeRange_Excluded(t *testing.T) {
	// A drift state whose DetectedAt is outside the query range is excluded.
	egp := newTestEGProvider(t)
	past := time.Now().Add(-48 * time.Hour)
	deviceID := "test-device-time-filter"

	storeDriftState(t, egp, deviceID, "host:hostname", past, []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "old", "actual": "new", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		DeviceIDs: []string{deviceID},
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now(),
		},
	})

	require.NoError(t, err)
	assert.Empty(t, events, "drift state outside the requested time range must be excluded")
}

func TestGetDriftEvents_CancelledContext_ReturnsError(t *testing.T) {
	// A cancelled context must be fatal, not swallowed.
	p := &DataProvider{
		egProvider: newTestEGProvider(t),
		logger:     logging.NewNoopLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.GetDriftEvents(ctx, interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{Start: time.Now().Add(-1 * time.Hour), End: time.Now()},
	})

	require.Error(t, err, "a cancelled context must cause an error")
	assert.Contains(t, err.Error(), "context canceled")
}

// ── GetDNAData ────────────────────────────────────────────────────────────────

// TestGetDNAData_WithHostEntity_ReturnsRecords is the required AC test verifying
// that a host entity with observation history in the entity graph produces
// DNARecord entries in GetDNAData.
//
// Uses the real SQLiteEntityGraphProvider (t.TempDir()) — no mocks.
func TestGetDNAData_WithHostEntity_ReturnsRecords(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()
	deviceID := "test-device-dna"

	// Store two state observations for the host entity — each becomes one DNARecord.
	storeHostEntity(t, egp, deviceID, now.Add(-30*time.Minute))
	storeHostEntity(t, egp, deviceID, now.Add(-10*time.Minute))

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		DeviceIDs: []string{deviceID},
		TimeRange: interfaces.TimeRange{
			Start: now.Add(-1 * time.Hour),
			End:   now.Add(1 * time.Hour),
		},
	})

	require.NoError(t, err)
	assert.Len(t, records, 2, "two stored observations must yield two DNARecords")
	for _, rec := range records {
		assert.Equal(t, deviceID, rec.DeviceID)
	}
}

func TestGetDNAData_EmptyProvider_ReturnsEmpty(t *testing.T) {
	p := &DataProvider{
		egProvider: newTestEGProvider(t),
		logger:     logging.NewNoopLogger(),
	}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		DeviceIDs: []string{"nonexistent-device"},
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-1 * time.Hour),
			End:   time.Now(),
		},
	})

	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestGetDNAData_CancelledContext_ReturnsError(t *testing.T) {
	p := &DataProvider{
		egProvider: newTestEGProvider(t),
		logger:     logging.NewNoopLogger(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.GetDNAData(ctx, interfaces.DataQuery{
		DeviceIDs: []string{"some-device"},
		TimeRange: interfaces.TimeRange{Start: time.Now().Add(-1 * time.Hour), End: time.Now()},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// TestGetDNAData_EntityGraphError_DeviceIDSanitized covers the log-injection
// mitigation in GetDNAData's per-device history-load failure path.
// A closed entity graph provider causes GetHistory to fail; the device_id
// must be sanitized in the logged Warn entry even when it contains \n/\r.
func TestGetDNAData_EntityGraphError_DeviceIDSanitized(t *testing.T) {
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	t.Run("newlines_stripped_from_device_id", func(t *testing.T) {
		egp := newClosedTestEGProvider(t)
		dirtyDeviceID := "device-1\nINJECTED log line\r\nalso injected"

		capLog := &warnCapturingLogger{}
		p := &DataProvider{egProvider: egp, logger: capLog}

		_, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{dirtyDeviceID},
		})

		require.NoError(t, err, "GetDNAData logs the per-device failure and continues")
		require.True(t, capLog.countMessages("failed to get entity history for device") > 0,
			"the failing device must trigger a warn log")

		loggedID := capLog.kvValue("device_id")
		require.NotNil(t, loggedID, "expected 'device_id' key in logged Warn entries")
		loggedIDStr, ok := loggedID.(string)
		require.True(t, ok, "sanitized device_id must be logged as a string")
		assert.NotContains(t, loggedIDStr, "\n", "\\n must be stripped from logged device_id")
		assert.NotContains(t, loggedIDStr, "\r", "\\r must be stripped from logged device_id")
		assert.Contains(t, loggedIDStr, "device-1", "device id text must be preserved")
	})

	t.Run("clean_device_id_passes_through", func(t *testing.T) {
		egp := newClosedTestEGProvider(t)

		capLog := &warnCapturingLogger{}
		p := &DataProvider{egProvider: egp, logger: capLog}

		_, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
			TimeRange: timeRange,
			DeviceIDs: []string{"device-clean"},
		})

		require.NoError(t, err)
		assert.Equal(t, "device-clean", capLog.kvValue("device_id"),
			"clean device id must pass through unchanged")
	})
}

// ── GetDeviceStats ────────────────────────────────────────────────────────────

// TestGetDeviceStats_WithEntityGraph_ComputesStats is the required AC test verifying
// that GetDeviceStats reads from the entity graph provider: history for record count
// and last-seen, drift projection for drift events.
//
// Uses the real SQLiteEntityGraphProvider (t.TempDir()) — no mocks.
func TestGetDeviceStats_WithEntityGraph_ComputesStats(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()
	deviceID := "test-device-stats"

	// Two observations → DNARecordCount = 2, LastSeen = now.
	storeHostEntity(t, egp, deviceID, now.Add(-30*time.Minute))
	storeHostEntity(t, egp, deviceID, now)

	// One drift event → DriftEventCount = 1.
	storeDriftState(t, egp, deviceID, "host:hostname", now.Add(-10*time.Minute), []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "web01", "actual": "web02", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	stats, err := p.GetDeviceStats(context.Background(), []string{deviceID}, interfaces.TimeRange{
		Start: now.Add(-1 * time.Hour),
		End:   now.Add(1 * time.Hour),
	})

	require.NoError(t, err)
	require.Contains(t, stats, deviceID)
	s := stats[deviceID]
	assert.Equal(t, deviceID, s.DeviceID)
	assert.Equal(t, 2, s.DNARecordCount, "two host entity observations must yield DNARecordCount = 2")
	assert.Equal(t, 1, s.DriftEventCount, "one drift-diff observation must yield DriftEventCount = 1")
	assert.NotZero(t, s.LastSeen, "LastSeen must be populated from entity observation timestamps")
}

func TestGetDeviceStats_CalculateError_DeviceIDSanitized(t *testing.T) {
	// A device with an invalid EID (containing '/') causes calculateDeviceStats
	// to fail (NewEID returns an error); GetDeviceStats logs the device_id sanitized.
	timeRange := interfaces.TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}

	t.Run("invalid_device_id_with_slash_and_newlines", func(t *testing.T) {
		egp := newTestEGProvider(t)
		// A device ID containing '/' will fail NewEID; we also add \n/\r to check sanitization.
		dirtyDeviceID := "device-1/injected\nINJECTED admin login\r\nfrom 10.0.0.1"

		capLog := &warnCapturingLogger{}
		p := &DataProvider{egProvider: egp, logger: capLog}

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
	})

	t.Run("clean_device_id_not_in_graph_returns_empty_stats", func(t *testing.T) {
		egp := newTestEGProvider(t)
		p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

		stats, err := p.GetDeviceStats(context.Background(), []string{"device-clean"}, timeRange)

		require.NoError(t, err)
		// A device with no observations in the graph has DNARecordCount=0 and
		// no drift events; calculateDeviceStats succeeds with zeroed stats.
		assert.Contains(t, stats, "device-clean")
		assert.Equal(t, 0, stats["device-clean"].DNARecordCount)
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

// newTrendFixture seeds the entity graph with two devices (device-a and device-b)
// and returns a provider plus a query spanning exactly two daily buckets.
//
// The range is anchored on UTC midnight so createTimeBuckets is deterministic:
// bucket[0] is yesterday (no records stored there) and bucket[1] is today
// (every observation and drift event lands there). Fixture contents:
//
//	device-a — two host-entity observations (for DNARecordCount) plus one drift-diff
//	           observation (one DriftEvent, SeverityWarning).
//	device-b — one host-entity observation: counted as a device, no drift event.
func newTrendFixture(t *testing.T) (*DataProvider, interfaces.DataQuery) {
	t.Helper()

	egp := newTestEGProvider(t)
	now := time.Now().UTC()

	// device-a: two observations + one drift event (hostname change)
	storeHostEntity(t, egp, "device-a", now.Add(-20*time.Minute))
	storeHostEntity(t, egp, "device-a", now.Add(-10*time.Minute))
	storeDriftState(t, egp, "device-a", "host:hostname", now.Add(-5*time.Minute), []interface{}{
		map[string]interface{}{"attribute": "hostname", "desired": "host-before", "actual": "host-after", "matching": false},
	})

	// device-b: one observation, no drift
	storeHostEntity(t, egp, "device-b", now.Add(-15*time.Minute))

	p := &DataProvider{
		egProvider: egp,
		logger:     logging.NewNoopLogger(),
	}

	midnightUTC := now.Truncate(24 * time.Hour)
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

	assert.Equal(t, 0.0, points[0].Value, "no drift stored yesterday, so no drift events in that bucket")
	assert.Equal(t, "0 events", points[0].Label)

	assert.Equal(t, 1.0, points[1].Value,
		"device-a's single hostname drift-diff is the only event, landing in today's bucket")
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

	assert.Equal(t, 0.0, points[0].Value, "no observations were stored yesterday")
	assert.Equal(t, "0 devices", points[0].Label)

	assert.Equal(t, 2.0, points[1].Value,
		"device-a and device-b both have observations today — two unique devices")
	assert.Equal(t, "2 devices", points[1].Label)
}

// ── GetTrendData day-query failure paths ─────────────────────────────────────

// TestGetTrendData_ComplianceScore_DayQueryFails_SkipsBucketAndWarns covers the
// error branch in getComplianceTrends: when the per-day GetDriftEvents call fails
// (cancelled context), that bucket is dropped and a Warn is emitted.
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

// ── convertDriftStateToEvent ──────────────────────────────────────────────────

func TestConvertDriftStateToEvent_NonMatchingFields_ProducesChanges(t *testing.T) {
	eid, err := egtypes.NewEID("host", "device-1", "host:hostname")
	require.NoError(t, err)

	state := &eginterfaces.DriftState{
		EID:         eid,
		DetectedAt:  time.Now(),
		Fields: []eginterfaces.DriftField{
			{Attribute: "hostname", Desired: "web01", Actual: "web02", Matching: false},
			{Attribute: "os", Desired: "linux", Actual: "linux", Matching: true},
		},
	}

	event := convertDriftStateToEvent("device-1", state)

	assert.Equal(t, "device-1", event.DeviceID)
	assert.Equal(t, drift.SeverityWarning, event.Severity)
	assert.Len(t, event.Changes, 1, "only non-matching fields produce attribute changes")
	assert.Equal(t, "hostname", event.Changes[0].Attribute)
	assert.Equal(t, "web01", event.Changes[0].PreviousValue)
	assert.Equal(t, "web02", event.Changes[0].CurrentValue)
	assert.Equal(t, 1, event.ChangeCount)
}

func TestConvertDriftStateToEvent_AllMatching_ProducesInfoEvent(t *testing.T) {
	eid, err := egtypes.NewEID("host", "device-2", "host:hostname")
	require.NoError(t, err)

	state := &eginterfaces.DriftState{
		EID:        eid,
		DetectedAt: time.Now(),
		Fields: []eginterfaces.DriftField{
			{Attribute: "hostname", Desired: "web01", Actual: "web01", Matching: true},
		},
	}

	event := convertDriftStateToEvent("device-2", state)

	assert.Equal(t, drift.SeverityInfo, event.Severity, "all-matching drift state yields info severity")
	assert.Empty(t, event.Changes)
	assert.Equal(t, 0, event.ChangeCount)
}
