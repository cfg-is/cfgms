// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package interfaces

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManagerExecuteProviderOp_RecordsCountsAndLatency(t *testing.T) {
	m := NewDirectoryProviderManager(NewDirectoryProviderFactory())
	p := newRecordingProvider("alpha")
	require.NoError(t, m.RegisterProvider("alpha", p, nil))
	ctx := context.Background()

	require.NoError(t, m.ExecuteProviderOp(ctx, "alpha", func(DirectoryProvider) error {
		time.Sleep(10 * time.Millisecond)
		return nil
	}))
	opErr := errors.New("boom")
	err := m.ExecuteProviderOp(ctx, "", func(DirectoryProvider) error {
		time.Sleep(10 * time.Millisecond)
		return opErr
	})
	require.ErrorIs(t, err, opErr)

	stats, err := m.GetProviderStatistics(ctx, "alpha")
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.RequestCount)
	assert.Equal(t, int64(1), stats.ErrorCount)
	assert.GreaterOrEqual(t, stats.AverageLatency, 10*time.Millisecond)
}

func TestManagerExecuteProviderOp_ConnectFailureCountsAsError(t *testing.T) {
	m := NewDirectoryProviderManager(NewDirectoryProviderFactory())
	p := newRecordingProvider("alpha")
	resolverErr := errors.New("no config")
	failing := true
	require.NoError(t, m.RegisterProvider("alpha", p, func(context.Context) (ProviderConfig, error) {
		if failing {
			return ProviderConfig{}, resolverErr
		}
		return ProviderConfig{}, nil
	}))
	ctx := context.Background()

	called := false
	err := m.ExecuteProviderOp(ctx, "alpha", func(DirectoryProvider) error { called = true; return nil })
	require.ErrorIs(t, err, resolverErr)
	assert.False(t, called)

	failing = false // statistics read the live counts, so the provider must connect
	stats, err := m.GetProviderStatistics(ctx, "alpha")
	require.NoError(t, err)
	assert.Equal(t, int64(1), stats.RequestCount)
	assert.Equal(t, int64(1), stats.ErrorCount)
}

func TestManagerExecuteProviderOp_UnknownProvider(t *testing.T) {
	m := NewDirectoryProviderManager(NewDirectoryProviderFactory())
	err := m.ExecuteProviderOp(context.Background(), "nope", func(DirectoryProvider) error { return nil })
	require.Error(t, err)
	err = m.ExecuteProviderOp(context.Background(), "", func(DirectoryProvider) error { return nil })
	require.Error(t, err)
}

func TestManagerGetProviderStatistics_LiveCounts(t *testing.T) {
	m := NewDirectoryProviderManager(NewDirectoryProviderFactory())
	p := newRecordingProvider("alpha")
	p.userTotal, p.groupTotal = 7, 3
	require.NoError(t, m.RegisterProvider("alpha", p, nil))

	stats, err := m.GetProviderStatistics(context.Background(), "alpha")
	require.NoError(t, err)
	assert.Equal(t, 7, stats.UserCount)
	assert.Equal(t, 3, stats.GroupCount)
	assert.Equal(t, "alpha", stats.ProviderName)
}

func TestManagerGetProviderStatistics_UnknownCountWhenTotalCountZero(t *testing.T) {
	m := NewDirectoryProviderManager(NewDirectoryProviderFactory())
	p := newRecordingProvider("alpha")
	p.userTotal = 0
	p.usersReturned = 1 // non-empty page, TotalCount unset
	p.groupHasMore = true
	require.NoError(t, m.RegisterProvider("alpha", p, nil))

	stats, err := m.GetProviderStatistics(context.Background(), "alpha")
	require.NoError(t, err)
	assert.Equal(t, -1, stats.UserCount)
	assert.Equal(t, -1, stats.GroupCount)

	// A genuinely empty directory reports 0.
	q := newRecordingProvider("beta")
	require.NoError(t, m.RegisterProvider("beta", q, nil))
	stats, err = m.GetProviderStatistics(context.Background(), "beta")
	require.NoError(t, err)
	assert.Equal(t, 0, stats.UserCount)
	assert.Equal(t, 0, stats.GroupCount)
}

func TestManagerGetProviderStatistics_UnknownProvider(t *testing.T) {
	m := NewDirectoryProviderManager(NewDirectoryProviderFactory())
	_, err := m.GetProviderStatistics(context.Background(), "nope")
	require.Error(t, err)
}
