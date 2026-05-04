// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// failingCloseConnection is a DirectoryConnection whose Close always returns an error.
type failingCloseConnection struct{}

func (f *failingCloseConnection) Open(_ context.Context, _ ProviderConfig) error { return nil }
func (f *failingCloseConnection) Close(_ context.Context) error {
	return fmt.Errorf("close failed")
}
func (f *failingCloseConnection) IsHealthy(_ context.Context) bool  { return true }
func (f *failingCloseConnection) GetConnectionInfo() ConnectionInfo { return ConnectionInfo{} }
func (f *failingCloseConnection) GetStatistics() ConnectionStatistics {
	return ConnectionStatistics{}
}
func (f *failingCloseConnection) Reset(_ context.Context) error              { return nil }
func (f *failingCloseConnection) RefreshCredentials(_ context.Context) error { return nil }

func newTestPool(t *testing.T, logger logging.Logger) *DefaultDirectoryConnectionPool {
	t.Helper()
	conn := &failingCloseConnection{}
	config := PoolConfig{
		MaxConnections:      2,
		MinConnections:      1,
		InitialSize:         1,
		ConnectionTimeout:   time.Second,
		HealthCheckInterval: time.Hour,
		HealthCheckTimeout:  time.Second,
		MaxRetries:          1,
		RetryDelay:          time.Millisecond,
	}
	pool, err := NewDirectoryConnectionPool(config, func(_ context.Context) (DirectoryConnection, error) {
		return conn, nil
	}, logger)
	require.NoError(t, err)
	return pool
}

// TestDirectoryConnectionPool_Close_logsWarnings verifies that Close and Put on a closed pool
// log "failed to close connection" warnings when the connection's Close method returns an error.
func TestDirectoryConnectionPool_Close_logsWarnings(t *testing.T) {
	t.Run("Put on closed pool logs warning", func(t *testing.T) {
		mockLogger := pkgtesting.NewMockLogger(true)
		pool := newTestPool(t, mockLogger)

		// Drain pool state cleanly for the closed-pool Put path test.
		require.NoError(t, pool.Close())
		mockLogger.Reset()

		// Put with a closed pool triggers conn.Close which returns an error.
		conn := &failingCloseConnection{}
		err := pool.Put(conn)
		require.Error(t, err, "Put on a closed pool must return an error")

		logs := mockLogger.GetLogs("warn")
		require.GreaterOrEqual(t, len(logs), 1, "expected at least one warn log entry")
		assert.Equal(t, "failed to close connection", logs[0].Message)
	})

	t.Run("Close logs warnings for connections that fail to close", func(t *testing.T) {
		mockLogger := pkgtesting.NewMockLogger(true)
		pool := newTestPool(t, mockLogger)

		// Close triggers conn.Close on every idle connection; failingCloseConnection returns an error.
		require.NoError(t, pool.Close())

		logs := mockLogger.GetLogs("warn")
		require.GreaterOrEqual(t, len(logs), 1, "expected at least one warn log entry from Close")
		assert.Equal(t, "failed to close connection", logs[0].Message)
	})
}

// TestNewDirectoryConnectionPool_NilLoggerDefaultsToNoop verifies that passing nil for the
// logger parameter does not panic and the pool operates normally.
func TestNewDirectoryConnectionPool_NilLoggerDefaultsToNoop(t *testing.T) {
	config := PoolConfig{
		MaxConnections:      1,
		MinConnections:      1,
		InitialSize:         1,
		ConnectionTimeout:   time.Second,
		HealthCheckInterval: time.Hour,
		HealthCheckTimeout:  time.Second,
		MaxRetries:          1,
		RetryDelay:          time.Millisecond,
	}
	pool, err := NewDirectoryConnectionPool(config, func(_ context.Context) (DirectoryConnection, error) {
		return &failingCloseConnection{}, nil
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, pool)
	require.NoError(t, pool.Close()) // must not panic with nil-guarded noop logger
}
