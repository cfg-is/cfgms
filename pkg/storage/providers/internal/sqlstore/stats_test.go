// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlstore

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func openSessionsDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE sessions (id TEXT, session_type TEXT, status TEXT)`)
	require.NoError(t, err)
	return db
}

var testStatsErrors = StatsErrors{Total: "total failed", ByType: "type failed", ByStatus: "status failed"}

func TestSessionStats_Counts(t *testing.T) {
	db := openSessionsDB(t)
	ctx := context.Background()

	empty, err := SessionStats(ctx, db, testStatsErrors)
	require.NoError(t, err)
	assert.Equal(t, int64(0), empty.TotalSessions)
	assert.NotNil(t, empty.SessionsByType)
	assert.NotNil(t, empty.SessionsByStatus)

	_, err = db.Exec(`INSERT INTO sessions VALUES ('1','api','active'),('2','api','expired'),('3','web','active')`)
	require.NoError(t, err)
	stats, err := SessionStats(ctx, db, testStatsErrors)
	require.NoError(t, err)
	assert.Equal(t, int64(3), stats.TotalSessions)
	assert.Equal(t, map[string]int64{"api": 2, "web": 1}, stats.SessionsByType)
	assert.Equal(t, map[string]int64{"active": 2, "expired": 1}, stats.SessionsByStatus)
	assert.Equal(t, int64(2), stats.ActiveSessions)
}

func TestSessionStats_ErrorText(t *testing.T) {
	db := openSessionsDB(t)
	_, err := db.Exec(`DROP TABLE sessions`)
	require.NoError(t, err)
	_, err = SessionStats(context.Background(), db, testStatsErrors)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "total failed: ")
}

func TestSessionStats_GroupQueryErrorText(t *testing.T) {
	db := openSessionsDB(t)
	dst := map[string]int64{}
	err := countGroups(context.Background(), db, `SELECT nope FROM sessions`, dst, "type failed")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type failed: ")
}
