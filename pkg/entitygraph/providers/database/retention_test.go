// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package database

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/entitygraph/interfaces"
	"github.com/stretchr/testify/require"
)

// TestRunRetentionGC_AdvisoryLockPinnedToConnection verifies Issue #4074 (1):
// the pg_try_advisory_lock guard must be acquired, held, and released on one
// pinned connection. pg_try_advisory_lock is session-scoped, so if the acquire
// statement returns its connection to the pool before the sweep finishes,
// SetMaxIdleConns(0) closes that connection synchronously, ending the Postgres
// session and releasing the lock early — a second raw connection would then be
// able to take the lock while RunRetentionGC is still running.
func TestRunRetentionGC_AdvisoryLockPinnedToConnection(t *testing.T) {
	dsn := skipIfNoPostgres(t)
	p := newTestDBProvider(t, dsn)
	p.db.SetMaxIdleConns(0)

	ctx := context.Background()

	probeDB, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probeDB.Close() })

	probeConn, err := probeDB.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probeConn.Close() })

	var gcErr error
	gcDone := make(chan struct{})
	go func() {
		defer close(gcDone)
		gcErr = p.RunRetentionGC(ctx, interfaces.RetentionPolicy{HistoryDays: 30})
	}()

	deadline := time.Now().Add(10 * time.Second)
	sawLockHeldDuringGC := false

loop:
	for {
		select {
		case <-gcDone:
			break loop
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for RunRetentionGC to finish")
		}

		var acquired bool
		require.NoError(t, probeConn.QueryRowContext(ctx,
			`SELECT pg_try_advisory_lock($1)`, gcAdvisoryLockKey).Scan(&acquired))
		if !acquired {
			sawLockHeldDuringGC = true
			continue
		}

		// We took the lock — only acceptable if RunRetentionGC had already
		// returned by the time the acquire committed.
		select {
		case <-gcDone:
			_, _ = probeConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
			break loop
		default:
			_, _ = probeConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
			t.Fatal("a second connection acquired the advisory lock while RunRetentionGC was still running — the lock is not connection-pinned")
		}
	}

	<-gcDone
	require.NoError(t, gcErr)
	require.True(t, sawLockHeldDuringGC,
		"test never observed the lock held by RunRetentionGC; strengthen the workload or timing before trusting this test")

	// The lock must be free now that RunRetentionGC has returned.
	var acquiredAfter bool
	require.NoError(t, probeConn.QueryRowContext(ctx,
		`SELECT pg_try_advisory_lock($1)`, gcAdvisoryLockKey).Scan(&acquiredAfter))
	require.True(t, acquiredAfter, "advisory lock must be free after RunRetentionGC returns")
	_, err = probeConn.ExecContext(ctx, `SELECT pg_advisory_unlock($1)`, gcAdvisoryLockKey)
	require.NoError(t, err)
}
