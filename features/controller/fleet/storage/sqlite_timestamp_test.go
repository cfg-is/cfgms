// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTimestampTestBackend returns a SQLiteBackend on a temp data dir.
func newTimestampTestBackend(t *testing.T) *SQLiteBackend {
	t.Helper()
	b, err := NewSQLiteBackend(&Config{DataDir: t.TempDir()}, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, b.Close()) })
	return b
}

func storeAt(t *testing.T, b *SQLiteBackend, deviceID string, storedAt time.Time, version int64) {
	t.Helper()
	require.NoError(t, b.StoreRecord(context.Background(), &DNARecord{
		DeviceID:    deviceID,
		DNA:         &commonpb.DNA{Id: deviceID},
		StoredAt:    storedAt,
		ContentHash: deviceID + "-" + storedAt.UTC().Format(time.RFC3339Nano),
		Version:     version,
	}, nil))
}

// TestGetHistoryByDeviceID_TimeRangeIsZoneIndependent pins the defect that made
// DNA history land in the wrong day.
//
// The timestamp column is DATETIME and the driver stores a bound time.Time as
// text. Rendering that text in the value's own location meant the WHERE clause
// compared a record written in one zone against bounds expressed in another,
// as a plain string comparison — so an instant inside the queried window was
// excluded from it and included in the preceding one.
//
// The record here is 01:30 UTC written in a -04:00 zone, where the same instant
// reads as 21:30 the previous day. It must be found by the UTC day window that
// actually contains it, and must not be found by the day before.
//
// A fixed zone (not time.Local) keeps this deterministic: the failure would
// otherwise only reproduce on hosts whose local date differs from the UTC date,
// which is why CI — always UTC — could never catch it.
func TestGetHistoryByDeviceID_TimeRangeIsZoneIndependent(t *testing.T) {
	b := newTimestampTestBackend(t)
	ctx := context.Background()

	minusFour := time.FixedZone("TEST-4", -4*60*60)
	instant := time.Date(2026, 8, 14, 1, 30, 0, 0, time.UTC)

	storeAt(t, b, "device-zone", instant.In(minusFour), 1)

	dayStart := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)

	t.Run("found in the UTC day that contains it", func(t *testing.T) {
		records, total, err := b.GetHistoryByDeviceID(ctx, "device-zone", &QueryOptions{
			TimeRange:   &TimeRange{Start: dayStart, End: dayStart.Add(24 * time.Hour)},
			IncludeData: true,
		})
		require.NoError(t, err)
		assert.Len(t, records, 1,
			"an instant at 01:30 UTC belongs to the 14 Aug UTC bucket no matter which zone it was written in")
		assert.Equal(t, int64(1), total)
	})

	t.Run("absent from the preceding UTC day", func(t *testing.T) {
		records, total, err := b.GetHistoryByDeviceID(ctx, "device-zone", &QueryOptions{
			TimeRange:   &TimeRange{Start: dayStart.Add(-24 * time.Hour), End: dayStart},
			IncludeData: true,
		})
		require.NoError(t, err)
		assert.Empty(t, records,
			"the record must not leak into the previous day's bucket, which is what the zone-dependent text comparison did")
		assert.Equal(t, int64(0), total)
	})
}

// TestGetHistoryByDeviceID_TimeRangeOrdersAcrossZones verifies that records
// written in different zones are filtered on their instants rather than on the
// wall-clock text each zone produced. All three instants are minutes apart and
// inside the same UTC hour, so any zone leaking into the comparison drops some
// of them from a window that contains all three.
func TestGetHistoryByDeviceID_TimeRangeOrdersAcrossZones(t *testing.T) {
	b := newTimestampTestBackend(t)
	ctx := context.Background()

	base := time.Date(2026, 8, 14, 1, 0, 0, 0, time.UTC)
	zones := []*time.Location{
		time.UTC,
		time.FixedZone("TEST-4", -4*60*60),
		time.FixedZone("TEST+9", 9*60*60),
	}

	for i, loc := range zones {
		storeAt(t, b, "device-multi", base.Add(time.Duration(i)*time.Minute).In(loc), int64(i+1))
	}

	records, total, err := b.GetHistoryByDeviceID(ctx, "device-multi", &QueryOptions{
		TimeRange:   &TimeRange{Start: base.Add(-time.Hour), End: base.Add(time.Hour)},
		IncludeData: true,
	})
	require.NoError(t, err)
	assert.Len(t, records, len(zones),
		"every record falls inside the window by instant; the zone it was authored in must not matter")
	assert.Equal(t, int64(len(zones)), total)
}

// TestStoreRecord_TimestampPersistsAsUTC asserts the stored representation
// directly. Filtering correctness above depends on every row being written in
// one canonical zone, so this pins the invariant at the point of writing rather
// than only through its downstream effect.
func TestStoreRecord_TimestampPersistsAsUTC(t *testing.T) {
	b := newTimestampTestBackend(t)
	ctx := context.Background()

	instant := time.Date(2026, 8, 14, 1, 30, 0, 0, time.UTC)
	storeAt(t, b, "device-utc", instant.In(time.FixedZone("TEST-4", -4*60*60)), 1)

	var raw string
	require.NoError(t, b.db.QueryRowContext(ctx,
		"SELECT CAST(timestamp AS TEXT) FROM dna_history WHERE device_id = ?", "device-utc").Scan(&raw))

	assert.Equal(t, instant.UTC().Format(sqliteTimestampLayout), raw,
		"timestamps must persist in the canonical UTC layout regardless of the zone they arrive in")
	assert.NotContains(t, raw, "m=",
		"a monotonic clock reading must never reach the column: it is not comparable and not parseable back")
}
