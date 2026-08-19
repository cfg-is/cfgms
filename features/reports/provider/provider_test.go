// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"fmt"
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
//
// The payload embeds "at" so two calls for the same device at different times
// hash differently — ReportObservations content-hash dedupes bit-identical
// payloads from the same (subject, source), and a fixture calling this twice
// with the same deviceID intends two distinct history entries, not a dedup.
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
					"observed_at": at.Format(time.RFC3339Nano),
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

// storeTenantScopedEntity records a state observation that places subject in the
// entity index under owningTenant.
//
// owning_tenant is the entity graph's only access-control axis (ADR-023): both
// EntityFilter.TenantFilter and DriftFilter.TenantFilter resolve through the index
// row, so a fixture that must be visible to a tenant-scoped read has to carry one.
func storeTenantScopedEntity(
	t *testing.T,
	egp eginterfaces.EntityGraphProvider,
	eid egtypes.EID,
	kind, owningTenant string,
	at time.Time,
) {
	t.Helper()
	err := egp.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source: eid.AuthorityName(),
		Observations: []egtypes.Observation{
			{
				Source:     eid.AuthorityName(),
				ObservedAt: at,
				RecordedAt: at,
				Subject:    eid.String(),
				Kind:       egtypes.ObservationKindState,
				Confidence: egtypes.ConfidenceHigh,
				Payload: map[string]interface{}{
					"entity_kind":   kind,
					"owning_tenant": owningTenant,
					"observed_at":   at.Format(time.RFC3339Nano),
				},
			},
		},
	})
	require.NoError(t, err, "storing tenant-scoped entity observation must succeed")
}

// storeTenantHost records one observation of the host entity host:<deviceID> owned
// by owningTenant, so fleet-wide discovery over that tenant subtree finds it.
func storeTenantHost(
	t *testing.T,
	egp eginterfaces.EntityGraphProvider,
	deviceID, owningTenant string,
	at time.Time,
) {
	t.Helper()
	eid, err := egtypes.NewEID("host", deviceID, "")
	require.NoError(t, err)
	storeTenantScopedEntity(t, egp, eid, "host", owningTenant, at)
}

// storeTenantHosts records count host entities named <prefix>-<i>, all owned by
// owningTenant, in a single observation batch (one transaction) and returns their
// device IDs. Used to build a host set larger than one discovery page.
func storeTenantHosts(
	t *testing.T,
	egp eginterfaces.EntityGraphProvider,
	prefix, owningTenant string,
	count int,
	at time.Time,
) []string {
	t.Helper()
	deviceIDs := make([]string, 0, count)
	observations := make([]egtypes.Observation, 0, count)
	for i := 0; i < count; i++ {
		deviceID := fmt.Sprintf("%s-%03d", prefix, i)
		eid, err := egtypes.NewEID("host", deviceID, "")
		require.NoError(t, err)
		deviceIDs = append(deviceIDs, deviceID)
		observations = append(observations, egtypes.Observation{
			Source:     deviceID,
			ObservedAt: at,
			RecordedAt: at,
			Subject:    eid.String(),
			Kind:       egtypes.ObservationKindState,
			Confidence: egtypes.ConfidenceHigh,
			Payload: map[string]interface{}{
				"entity_kind":   "host",
				"owning_tenant": owningTenant,
				"observed_at":   at.Format(time.RFC3339Nano),
			},
		})
	}
	require.NoError(t, egp.ReportObservations(context.Background(), eginterfaces.ObservationBatch{
		Source:       prefix,
		Observations: observations,
	}), "storing the host batch must succeed")
	return deviceIDs
}

// storeTenantDriftState indexes the drifted fragment entity under owningTenant and
// then records its drift-diff, which is the shape a tenant-scoped ListDrifted can
// see: the drift projection is keyed by subject only, so its tenant is resolved
// through the fragment's entity index row.
func storeTenantDriftState(
	t *testing.T,
	egp eginterfaces.EntityGraphProvider,
	deviceID, fragmentID, owningTenant string,
	at time.Time,
	fields []interface{},
) {
	t.Helper()
	eid, err := egtypes.NewEID("host", deviceID, fragmentID)
	require.NoError(t, err)
	storeTenantScopedEntity(t, egp, eid, "host", owningTenant, at)
	storeDriftState(t, egp, deviceID, fragmentID, at, fields)
}

// ── GetDriftEvents ────────────────────────────────────────────────────────────

func TestGetDriftEvents_EmptyEGProvider_ReturnsEmpty(t *testing.T) {
	// When the entity graph has no drift states, GetDriftEvents returns a
	// non-nil empty slice without error. The query names a tenant because a
	// query naming neither tenant nor device is refused outright — see
	// TestGetDriftEvents_NoTenantScopeNoDevices_FailsClosed.
	p := &DataProvider{
		egProvider: newTestEGProvider(t),
		logger:     logging.NewNoopLogger(),
	}
	query := interfaces.DataQuery{
		TenantIDs: []string{"root/tenant-a"},
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

// ── GetDriftEvents tenant isolation ──────────────────────────────────────────

// TestGetDriftEvents_NoTenantScopeNoDevices_FailsClosed verifies that a query
// naming neither a device nor a tenant is refused. Such a query has no
// authorization cut: an empty DriftFilter makes the provider skip the entity-index
// join and return every drifted entity in the deployment, and with no device filter
// nothing downstream narrows it either.
func TestGetDriftEvents_NoTenantScopeNoDevices_FailsClosed(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()

	storeTenantDriftState(t, egp, "device-a", "auth:enabled", "root/tenant-a", now, []interface{}{
		map[string]interface{}{"attribute": "auth:enabled", "desired": "true", "actual": "false", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.ErrorIs(t, err, errTenantScopeRequired,
		"a drift query with neither tenant scope nor device list must fail closed")
	assert.Empty(t, events, "no drift data may be returned when the query is refused")
}

// TestGetDriftEvents_TenantScope_ExcludesOtherTenants verifies the provider-side
// tenant cut on the fleet-wide drift path: a caller scoped to one tenant sees only
// that tenant's drift, and never another tenant's desired/actual field values.
func TestGetDriftEvents_TenantScope_ExcludesOtherTenants(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()

	storeTenantDriftState(t, egp, "device-a", "auth:enabled", "root/tenant-a", now, []interface{}{
		map[string]interface{}{"attribute": "auth:enabled", "desired": "tenant-a-desired", "actual": "tenant-a-actual", "matching": false},
	})
	storeTenantDriftState(t, egp, "device-b", "auth:enabled", "root/tenant-b", now, []interface{}{
		map[string]interface{}{"attribute": "auth:enabled", "desired": "tenant-b-secret", "actual": "tenant-b-actual", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		TenantIDs: []string{"root/tenant-a"},
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.NoError(t, err)
	require.Len(t, events, 1, "only the caller tenant's drift may be returned")
	assert.Equal(t, "device-a", events[0].DeviceID)
	for _, change := range events[0].Changes {
		assert.NotContains(t, change.PreviousValue, "tenant-b-secret",
			"another tenant's desired value must never reach the caller")
	}
}

// TestGetDriftEvents_TenantSubtree_IncludesDescendants verifies that the tenant cut
// is a subtree cut: an MSP-scoped caller sees its client tenants' drift, and a
// sibling tenant sharing a name prefix is not swept in.
func TestGetDriftEvents_TenantSubtree_IncludesDescendants(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()

	storeTenantDriftState(t, egp, "msp-host", "auth:enabled", "root/msp-a", now, []interface{}{
		map[string]interface{}{"attribute": "auth:enabled", "desired": "true", "actual": "false", "matching": false},
	})
	storeTenantDriftState(t, egp, "client-host", "auth:enabled", "root/msp-a/client-1", now, []interface{}{
		map[string]interface{}{"attribute": "auth:enabled", "desired": "true", "actual": "false", "matching": false},
	})
	storeTenantDriftState(t, egp, "sibling-host", "auth:enabled", "root/msp-a-other", now, []interface{}{
		map[string]interface{}{"attribute": "auth:enabled", "desired": "true", "actual": "false", "matching": false},
	})

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		TenantIDs: []string{"root/msp-a"},
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.NoError(t, err)
	devices := make([]string, 0, len(events))
	for _, e := range events {
		devices = append(devices, e.DeviceID)
	}
	assert.ElementsMatch(t, []string{"msp-host", "client-host"}, devices,
		"the subtree cut includes descendants and excludes prefix-sharing siblings")
}

// TestGetDriftEvents_MultipleTenantScopes_QueriesEachSeparately verifies that a
// multi-tenant query is answered by one filtered read per tenant — the union of the
// named tenants, not the whole deployment.
func TestGetDriftEvents_MultipleTenantScopes_QueriesEachSeparately(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()

	for _, tc := range []struct{ device, tenant string }{
		{"device-a", "root/tenant-a"},
		{"device-b", "root/tenant-b"},
		{"device-c", "root/tenant-c"},
	} {
		storeTenantDriftState(t, egp, tc.device, "auth:enabled", tc.tenant, now, []interface{}{
			map[string]interface{}{"attribute": "auth:enabled", "desired": "true", "actual": "false", "matching": false},
		})
	}

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	events, err := p.GetDriftEvents(context.Background(), interfaces.DataQuery{
		// The blank and duplicate entries must not widen the read: a blank
		// TenantFilter means "every tenant" to the provider.
		TenantIDs: []string{"root/tenant-a", "", "root/tenant-b", "root/tenant-a"},
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.NoError(t, err)
	devices := make([]string, 0, len(events))
	for _, e := range events {
		devices = append(devices, e.DeviceID)
	}
	assert.ElementsMatch(t, []string{"device-a", "device-b"}, devices,
		"exactly the named tenants' drift, each device once, and never tenant-c")
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

// ── GetDNAData fleet-wide discovery ──────────────────────────────────────────

// TestGetDNAData_Discovery_NoTenantScope_FailsClosed verifies that a query naming
// neither a device nor a tenant is refused rather than discovering every host in
// every tenant: an empty EntityFilter.TenantFilter applies no owning_tenant
// predicate at all.
func TestGetDNAData_Discovery_NoTenantScope_FailsClosed(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()
	storeTenantHost(t, egp, "device-a", "root/tenant-a", now)

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.ErrorIs(t, err, errTenantScopeRequired,
		"an all-device query with no tenant scope must fail closed")
	assert.Empty(t, records, "no records may be returned when the query is refused")
}

// TestGetDNAData_Discovery_ReturnsOnlyScopedTenantHosts is the discovery-path
// counterpart of TestGetDNAData_WithHostEntity_ReturnsRecords: with no DeviceIDs,
// hosts are discovered through the entity graph, and only those inside the queried
// tenant subtree are returned.
func TestGetDNAData_Discovery_ReturnsOnlyScopedTenantHosts(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()

	// Two hosts in the queried tenant, one of them with two observations.
	storeTenantHost(t, egp, "device-a1", "root/tenant-a", now.Add(-30*time.Minute))
	storeTenantHost(t, egp, "device-a1", "root/tenant-a", now.Add(-10*time.Minute))
	storeTenantHost(t, egp, "device-a2", "root/tenant-a", now.Add(-20*time.Minute))
	// One host in another tenant, which must not be discovered.
	storeTenantHost(t, egp, "device-b1", "root/tenant-b", now.Add(-15*time.Minute))

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		TenantIDs: []string{"root/tenant-a"},
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.NoError(t, err)

	counts := make(map[string]int)
	for _, rec := range records {
		counts[rec.DeviceID]++
		assert.False(t, rec.StoredAt.IsZero(), "each discovered record carries its observation time")
	}
	assert.Equal(t, map[string]int{"device-a1": 2, "device-a2": 1}, counts,
		"discovery must cover every host of the scoped tenant and no other tenant's host")
}

// TestGetDNAData_Discovery_PagesBeyondFirstPage verifies that discovery follows the
// entity graph's page token: a host set larger than one page is fully walked, and
// the walk terminates.
func TestGetDNAData_Discovery_PagesBeyondFirstPage(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()

	// One more than two full pages, so at least two page tokens are followed.
	total := hostDiscoveryPageSize*2 + 1
	deviceIDs := storeTenantHosts(t, egp, "paged", "root/tenant-paged", total, now.Add(-10*time.Minute))
	// A host in another tenant must stay out of the paged walk.
	storeTenantHost(t, egp, "other-tenant-host", "root/tenant-other", now.Add(-10*time.Minute))

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		TenantIDs: []string{"root/tenant-paged"},
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.NoError(t, err)
	require.Len(t, records, total,
		"every host across all pages must be discovered exactly once")

	seen := make(map[string]bool, len(records))
	for _, rec := range records {
		assert.False(t, seen[rec.DeviceID], "a host must not be returned twice across pages")
		seen[rec.DeviceID] = true
	}
	for _, deviceID := range deviceIDs {
		assert.True(t, seen[deviceID], "host %s must appear in the discovered set", deviceID)
	}
	assert.False(t, seen["other-tenant-host"], "another tenant's host must never be discovered")
}

// TestGetDNAData_Discovery_QueryFailure_ReturnsError verifies that a failure of the
// discovery query itself is fatal. Truncating the fleet silently would understate
// every count computed from the result.
func TestGetDNAData_Discovery_QueryFailure_ReturnsError(t *testing.T) {
	p := &DataProvider{egProvider: newClosedTestEGProvider(t), logger: logging.NewNoopLogger()}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		TenantIDs: []string{"root/tenant-a"},
		TimeRange: interfaces.TimeRange{Start: time.Now().Add(-1 * time.Hour), End: time.Now()},
	})

	require.Error(t, err, "a failed discovery query must not be reported as an empty fleet")
	assert.Contains(t, err.Error(), "failed to query host entities")
	assert.Empty(t, records)
}

// TestGetDNAData_Discovery_HostOutsideTimeRange_YieldsNoRecords verifies that a
// discovered host contributes records only for observations inside the requested
// window — discovery widens which hosts are considered, never the time cut.
func TestGetDNAData_Discovery_HostOutsideTimeRange_YieldsNoRecords(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()
	storeTenantHost(t, egp, "device-recent", "root/tenant-a", now.Add(-10*time.Minute))
	storeTenantHost(t, egp, "device-stale", "root/tenant-a", now.Add(-72*time.Hour))

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	records, err := p.GetDNAData(context.Background(), interfaces.DataQuery{
		TenantIDs: []string{"root/tenant-a"},
		TimeRange: interfaces.TimeRange{Start: now.Add(-1 * time.Hour), End: now.Add(1 * time.Hour)},
	})

	require.NoError(t, err)
	require.Len(t, records, 1, "only the in-window observation may produce a record")
	assert.Equal(t, "device-recent", records[0].DeviceID)
}

// ── GetDeviceStats ────────────────────────────────────────────────────────────

// TestGetDeviceStats_NoDeviceIDs_ReturnsEmpty verifies GetDeviceStats' fail-closed
// contract: its signature carries no tenant, so an empty device list has no
// authorization cut and yields no statistics rather than discovering — and
// reporting on — every tenant's fleet.
func TestGetDeviceStats_NoDeviceIDs_ReturnsEmpty(t *testing.T) {
	egp := newTestEGProvider(t)
	now := time.Now()
	storeTenantHost(t, egp, "device-a", "root/tenant-a", now)
	storeTenantHost(t, egp, "device-b", "root/tenant-b", now)

	p := &DataProvider{egProvider: egp, logger: logging.NewNoopLogger()}

	stats, err := p.GetDeviceStats(context.Background(), nil, interfaces.TimeRange{
		Start: now.Add(-1 * time.Hour),
		End:   now.Add(1 * time.Hour),
	})

	require.NoError(t, err)
	assert.Empty(t, stats, "no device list means no statistics, never a cross-tenant scan")
}

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
		EID:        eid,
		DetectedAt: time.Now(),
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
