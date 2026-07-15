// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

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
