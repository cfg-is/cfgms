//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestDiscovery_Stop_logsStop(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)

	cfg := &DiscoveryConfig{
		Method:      "static",
		Config:      make(map[string]interface{}),
		NodeTimeout: 30 * time.Second,
	}

	d, err := newStaticDiscovery(cfg, mock, nil)
	require.NoError(t, err)

	// Mark as started so Stop() proceeds past the early-return guard.
	d.mu.Lock()
	d.started = true
	d.mu.Unlock()

	ctx := context.Background()
	err = d.Stop(ctx)
	require.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs, "expected info logs from Stop()")
	assert.Equal(t, "Static discovery stopped", infoLogs[0].Message)
}
