// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/reports/interfaces"
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

// errDNAHistoryStore is a test component that returns a pre-configured error from
// GetHistory. It satisfies the dnaHistory interface without depending on storage.Manager.
type errDNAHistoryStore struct {
	err error
}

func (s *errDNAHistoryStore) GetHistory(_ context.Context, _ string, _ *storage.QueryOptions) (*storage.HistoryResult, error) {
	return nil, s.err
}

func TestGetDriftEvents_ReturnsEmptySlice(t *testing.T) {
	p := &DataProvider{
		logger: logging.NewNoopLogger(),
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
	assert.Empty(t, events, "GetDriftEvents returns empty: drift events have no persistent store yet")
}

func TestGetDriftEvents_WithDeviceIDs(t *testing.T) {
	p := &DataProvider{
		logger: logging.NewNoopLogger(),
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
	// No persistent drift store means empty regardless of DeviceIDs filter
	assert.Empty(t, events)
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

func TestGetTrendData_DriftEvents_ReturnsSlice(t *testing.T) {
	p := &DataProvider{
		logger: logging.NewNoopLogger(),
	}
	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-48 * time.Hour),
			End:   time.Now(),
		},
	}

	points, err := p.GetTrendData(context.Background(), "drift_events", query)

	require.NoError(t, err)
	assert.NotNil(t, points)
}

func TestGetTrendData_ComplianceScore_ReturnsSlice(t *testing.T) {
	p := &DataProvider{
		logger: logging.NewNoopLogger(),
	}
	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-48 * time.Hour),
			End:   time.Now(),
		},
	}

	points, err := p.GetTrendData(context.Background(), "compliance_score", query)

	require.NoError(t, err)
	assert.NotNil(t, points)
}

func TestGetTrendData_DeviceCount_ReturnsSlice(t *testing.T) {
	p := &DataProvider{
		logger: logging.NewNoopLogger(),
	}
	query := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-48 * time.Hour),
			End:   time.Now(),
		},
	}

	points, err := p.GetTrendData(context.Background(), "device_count", query)

	require.NoError(t, err)
	assert.NotNil(t, points)
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
func TestGetDNAData_StorageError_LogValueSanitized(t *testing.T) {
	baseQuery := interfaces.DataQuery{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
		DeviceIDs: []string{"device-1"},
	}

	t.Run("newlines_stripped", func(t *testing.T) {
		capLog := &warnCapturingLogger{}
		dirtyErr := errors.New("storage lookup failed\nforged log line\r\nalso forged")
		p := &DataProvider{
			storageManager: &errDNAHistoryStore{err: dirtyErr},
			logger:         capLog,
		}

		_, err := p.GetDNAData(context.Background(), baseQuery)

		require.NoError(t, err, "GetDNAData logs the error and continues; it must not surface it")
		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr, "expected 'error' key in logged Warn entries")
		loggedStr, ok := loggedErr.(string)
		require.True(t, ok, "sanitized error must be logged as a string")
		assert.NotContains(t, loggedStr, "\n", "\\n must be stripped from logged error")
		assert.NotContains(t, loggedStr, "\r", "\\r must be stripped from logged error")
		assert.Contains(t, loggedStr, "storage lookup failed", "error message text must be preserved")
	})

	t.Run("clean_error_passes_through", func(t *testing.T) {
		capLog := &warnCapturingLogger{}
		cleanErr := errors.New("normal storage failure")
		p := &DataProvider{
			storageManager: &errDNAHistoryStore{err: cleanErr},
			logger:         capLog,
		}

		_, err := p.GetDNAData(context.Background(), baseQuery)

		require.NoError(t, err)
		loggedErr := capLog.kvValue("error")
		require.NotNil(t, loggedErr)
		loggedStr, ok := loggedErr.(string)
		require.True(t, ok)
		assert.Equal(t, "normal storage failure", loggedStr,
			"clean error message must pass through unchanged")
	})
}
