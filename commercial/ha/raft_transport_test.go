//go:build commercial

// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Jordan Ritz
// +build commercial

package ha

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestRaftTransport_Start_logsStartup(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)

	transport := newRaftTransport(1, "localhost:8080", nil, nil, mock)

	ctx := context.Background()
	err := transport.Start(ctx)
	require.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs, "expected at least one info log after Start()")
	assert.True(t, strings.Contains(infoLogs[0].Message, "RAFT_TRANSPORT"),
		"startup log should contain RAFT_TRANSPORT, got: %s", infoLogs[0].Message)
}
