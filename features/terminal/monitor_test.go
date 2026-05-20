// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAuditStore is an in-memory SessionAuditStore for use in tests.
type testAuditStore struct {
	records map[string][]SessionAuditRecord
	err     error
}

func (s *testAuditStore) GetRecentSessions(_ context.Context, userID string, limit int) ([]SessionAuditRecord, error) {
	if s.err != nil {
		return nil, s.err
	}
	records := s.records[userID]
	if limit > 0 && len(records) > limit {
		records = records[:limit]
	}
	return records, nil
}

// writeMeta writes a recordingMeta as a JSON .rec.meta file in dir.
func writeMeta(t *testing.T, dir, sessionID string, meta recordingMeta) {
	t.Helper()
	data, err := json.Marshal(meta)
	require.NoError(t, err)
	path := filepath.Join(dir, sessionID+".rec.meta")
	require.NoError(t, os.WriteFile(path, data, 0600))
}

func TestGetBaselineMetrics_NoAuditStore(t *testing.T) {
	sm := &SessionMonitor{}
	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	// Must return conservative defaults, not the old hardcoded "healthy" values
	assert.Equal(t, 1.0, baseline.AvgCommandRate, "conservative rate should be 1.0, not the old hardcode of 10.0")
	assert.Equal(t, 15*time.Minute, baseline.AvgSessionDuration, "conservative duration should be short, not 30min hardcode")
	assert.Empty(t, baseline.CommonCommands, "no commands should be pre-assumed as common")
	assert.Equal(t, []int{9, 10, 11, 12, 13, 14, 15, 16, 17}, baseline.TypicalHours)
}

func TestGetBaselineMetrics_EmptyStore(t *testing.T) {
	store := &testAuditStore{records: map[string][]SessionAuditRecord{}}
	sm := &SessionMonitor{auditStore: store}
	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	assert.Equal(t, 1.0, baseline.AvgCommandRate, "empty store should produce conservative defaults")
	assert.Equal(t, 15*time.Minute, baseline.AvgSessionDuration)
	assert.Empty(t, baseline.CommonCommands)
}

func TestGetBaselineMetrics_StoreError(t *testing.T) {
	store := &testAuditStore{err: errors.New("store unavailable")}
	sm := &SessionMonitor{auditStore: store}
	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	assert.Equal(t, 1.0, baseline.AvgCommandRate, "store error should fall back to conservative defaults")
	assert.Equal(t, 15*time.Minute, baseline.AvgSessionDuration)
}

func TestGetBaselineMetrics_WithHistoricalData(t *testing.T) {
	// 4 completed sessions, each 1 hour long with 120 events → 2.0 events/min
	var sessions []SessionAuditRecord
	for i := 0; i < 4; i++ {
		start := time.Date(2026, 1, 15-i, 10, 0, 0, 0, time.UTC)
		end := start.Add(time.Hour)
		sessions = append(sessions, SessionAuditRecord{
			UserID:     "user123",
			StartedAt:  start,
			EndedAt:    &end,
			EventCount: 120,
		})
	}
	store := &testAuditStore{records: map[string][]SessionAuditRecord{"user123": sessions}}
	sm := &SessionMonitor{auditStore: store}

	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	assert.InDelta(t, 2.0, baseline.AvgCommandRate, 0.001, "rate should be 120 events / 60 min = 2.0")
	assert.Equal(t, time.Hour, baseline.AvgSessionDuration, "avg duration should reflect actual session length")
	assert.Empty(t, baseline.CommonCommands, "command distribution is not derivable from session metadata")
}

func TestGetBaselineMetrics_TypicalHoursFromData(t *testing.T) {
	// 8 sessions at hour 14, 2 sessions at hour 3
	// With 10 records, threshold = 10/5 = 2; hour 14 qualifies (8>=2), hour 3 does not (2<2)
	var sessions []SessionAuditRecord
	for i := 0; i < 8; i++ {
		start := time.Date(2026, 1, 1+i, 14, 0, 0, 0, time.UTC)
		end := start.Add(30 * time.Minute)
		sessions = append(sessions, SessionAuditRecord{
			UserID:     "user123",
			StartedAt:  start,
			EndedAt:    &end,
			EventCount: 30,
		})
	}
	for i := 0; i < 2; i++ {
		start := time.Date(2026, 1, 20+i, 3, 0, 0, 0, time.UTC)
		end := start.Add(30 * time.Minute)
		sessions = append(sessions, SessionAuditRecord{
			UserID:     "user123",
			StartedAt:  start,
			EndedAt:    &end,
			EventCount: 30,
		})
	}
	store := &testAuditStore{records: map[string][]SessionAuditRecord{"user123": sessions}}
	sm := &SessionMonitor{auditStore: store}

	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	assert.Contains(t, baseline.TypicalHours, 14, "hour 14 should be typical (seen in 80% of sessions)")
	assert.NotContains(t, baseline.TypicalHours, 3, "hour 3 should not be typical (seen in exactly 20% of sessions, threshold requires strictly more than 20%)")
}

func TestGetBaselineMetrics_SkipsOpenSessions(t *testing.T) {
	// Mix of one completed session (2 hours, 120 events) and one open session (no EndedAt)
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	sessions := []SessionAuditRecord{
		{UserID: "user123", StartedAt: start, EndedAt: &end, EventCount: 120},
		{UserID: "user123", StartedAt: start, EndedAt: nil, EventCount: 0},
	}
	store := &testAuditStore{records: map[string][]SessionAuditRecord{"user123": sessions}}
	sm := &SessionMonitor{auditStore: store}

	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	assert.Equal(t, 2*time.Hour, baseline.AvgSessionDuration, "open sessions must not skew duration calculation")
	assert.InDelta(t, 1.0, baseline.AvgCommandRate, 0.001, "120 events / 120 min = 1.0")
}

func TestGetBaselineMetrics_AllOpenSessionsFallsBack(t *testing.T) {
	// All sessions are still open — no EndedAt → fall back to conservative defaults
	start := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	sessions := []SessionAuditRecord{
		{UserID: "user123", StartedAt: start, EndedAt: nil, EventCount: 50},
		{UserID: "user123", StartedAt: start, EndedAt: nil, EventCount: 80},
	}
	store := &testAuditStore{records: map[string][]SessionAuditRecord{"user123": sessions}}
	sm := &SessionMonitor{auditStore: store}

	baseline := sm.getBaselineMetrics(context.Background(), "user123")

	assert.Equal(t, 1.0, baseline.AvgCommandRate, "all-open sessions should fall back to conservative defaults")
	assert.Equal(t, 15*time.Minute, baseline.AvgSessionDuration)
}

func TestRecordingMetaAuditStore_GetRecentSessions(t *testing.T) {
	dir := t.TempDir()
	store := NewRecordingMetaAuditStore(dir)

	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	end := base.Add(30 * time.Minute)

	// 2 sessions for user123, 1 for user456
	writeMeta(t, dir, "sess-1", recordingMeta{SessionID: "sess-1", UserID: "user123", StartedAt: base, EndedAt: &end, EventCount: 30})
	writeMeta(t, dir, "sess-2", recordingMeta{SessionID: "sess-2", UserID: "user123", StartedAt: base.Add(-24 * time.Hour), EndedAt: &end, EventCount: 20})
	writeMeta(t, dir, "sess-3", recordingMeta{SessionID: "sess-3", UserID: "user456", StartedAt: base, EndedAt: &end, EventCount: 15})

	records, err := store.GetRecentSessions(context.Background(), "user123", 10)
	require.NoError(t, err)
	require.Len(t, records, 2, "only user123 sessions should be returned")
	assert.Equal(t, "user123", records[0].UserID)
	assert.Equal(t, "user123", records[1].UserID)
	assert.True(t, records[0].StartedAt.After(records[1].StartedAt), "results must be ordered most-recent-first")
}

func TestRecordingMetaAuditStore_RespectsLimit(t *testing.T) {
	dir := t.TempDir()
	store := NewRecordingMetaAuditStore(dir)

	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	end := base.Add(time.Hour)
	for i := 0; i < 5; i++ {
		writeMeta(t, dir, fmt.Sprintf("sess-%d", i), recordingMeta{
			SessionID:  fmt.Sprintf("sess-%d", i),
			UserID:     "user123",
			StartedAt:  base.Add(time.Duration(-i) * 24 * time.Hour),
			EndedAt:    &end,
			EventCount: 10,
		})
	}

	records, err := store.GetRecentSessions(context.Background(), "user123", 3)
	require.NoError(t, err)
	assert.Len(t, records, 3, "limit parameter must be respected")
}

func TestRecordingMetaAuditStore_NonexistentDirectory(t *testing.T) {
	store := NewRecordingMetaAuditStore("/nonexistent/path/that/does/not/exist")
	records, err := store.GetRecentSessions(context.Background(), "user123", 10)
	assert.NoError(t, err, "nonexistent directory should return empty result, not error")
	assert.Empty(t, records)
}

func TestRecordingMetaAuditStore_IgnoresMalformedMeta(t *testing.T) {
	dir := t.TempDir()
	store := NewRecordingMetaAuditStore(dir)

	// Write one valid and one malformed meta file
	base := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	end := base.Add(time.Hour)
	writeMeta(t, dir, "good-sess", recordingMeta{SessionID: "good-sess", UserID: "user123", StartedAt: base, EndedAt: &end, EventCount: 60})
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad-sess.rec.meta"), []byte("not json"), 0600))

	records, err := store.GetRecentSessions(context.Background(), "user123", 10)
	require.NoError(t, err, "malformed meta files should be skipped silently")
	assert.Len(t, records, 1, "only the valid meta file should be returned")
}

func TestAddSession_UsesAuditStoreForBaseline(t *testing.T) {
	// Verify that AddSession completes without error when an audit store is wired in
	start := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Hour)
	records := []SessionAuditRecord{
		{UserID: "user123", StartedAt: start, EndedAt: &end, EventCount: 120},
	}
	store := &testAuditStore{records: map[string][]SessionAuditRecord{"user123": records}}

	validator := NewSecurityValidator(nil)
	config := DefaultMonitorConfig()
	config.AutoTerminateOnCritical = false
	sm := NewSessionMonitor(validator, config, WithAuditStore(store))

	session := &Session{
		ID:        "test-audit-baseline",
		UserID:    "user123",
		StewardID: "steward-x",
		CreatedAt: time.Now(),
	}
	secCtx := &SessionSecurityContext{
		SessionID: session.ID,
		UserID:    session.UserID,
		StewardID: session.StewardID,
		TenantID:  "tenant1",
	}

	require.NoError(t, sm.AddSession(session, secCtx))

	info, err := sm.GetSessionInfo(session.ID)
	require.NoError(t, err)
	assert.Equal(t, "test-audit-baseline", info.Session.ID)
}
