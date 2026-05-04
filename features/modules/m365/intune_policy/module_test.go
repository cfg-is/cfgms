// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package intune_policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestIntunePolicyModule_DefaultLoggingSupport_embed(t *testing.T) {
	mod := &intunePolicyModule{}

	// intunePolicyModule must implement LoggingInjectable via DefaultLoggingSupport embed
	injectable, ok := modules.Module(mod).(modules.LoggingInjectable)
	require.True(t, ok, "intunePolicyModule must implement modules.LoggingInjectable")

	// Before injection, GetLogger returns nil, false
	logger, injected := injectable.GetLogger()
	assert.Nil(t, logger)
	assert.False(t, injected)

	// After SetLogger, GetLogger returns the injected logger
	mock := pkgtesting.NewMockLogger(true)
	require.NoError(t, injectable.SetLogger(mock))

	logger, injected = injectable.GetLogger()
	assert.Equal(t, mock, logger)
	assert.True(t, injected)
}

func TestIntunePolicyModule_assignConfiguration_logsAssignment(t *testing.T) {
	mod := &intunePolicyModule{}

	mock := pkgtesting.NewMockLogger(true)
	require.NoError(t, mod.SetLogger(mock))

	assignments := []PolicyAssignment{
		{
			Target: PolicyAssignmentTarget{
				TargetType: "allDevices",
			},
		},
	}

	err := mod.assignConfiguration(context.Background(), nil, "config-123", assignments)
	require.NoError(t, err)

	logs := mock.GetLogs("info")
	require.NotEmpty(t, logs, "expected info log from assignConfiguration")
	assert.Equal(t, "assigning configuration", logs[0].Message)
}
