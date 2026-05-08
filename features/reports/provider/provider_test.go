// SPDX-License-Identifier: Apache-2.0
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
