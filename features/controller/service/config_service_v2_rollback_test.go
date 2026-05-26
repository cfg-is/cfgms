// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"fmt"
	"testing"

	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTranslateRollbackRequest verifies the mapping from config.RollbackRequest to rollback.RollbackRequest.
func TestTranslateRollbackRequest(t *testing.T) {
	svc := &ConfigurationServiceV2{}

	req := config.RollbackRequest{
		StewardID:      "s1",
		TargetVersion:  3,
		ValidateOnly:   true,
		SkipValidation: false,
		Reason:         "test reason",
	}

	got := svc.translateRollbackRequest(&req)

	assert.Equal(t, "s1", got.TargetID)
	assert.Equal(t, rollback.TargetTypeSteward, got.TargetType)
	assert.True(t, got.DryRun)
	assert.False(t, got.Options.SkipValidation)
	assert.Equal(t, fmt.Sprintf("v%d", req.TargetVersion), got.RollbackTo)
	assert.Equal(t, "test reason", got.Reason)
}

// TestTranslateRollbackRequestSkipValidation verifies SkipValidation is mapped correctly when true.
func TestTranslateRollbackRequestSkipValidation(t *testing.T) {
	svc := &ConfigurationServiceV2{}

	req := config.RollbackRequest{
		StewardID:      "s2",
		TargetVersion:  7,
		ValidateOnly:   false,
		SkipValidation: true,
		Reason:         "emergency",
	}

	got := svc.translateRollbackRequest(&req)

	assert.Equal(t, "s2", got.TargetID)
	assert.Equal(t, rollback.TargetTypeSteward, got.TargetType)
	assert.False(t, got.DryRun)
	assert.True(t, got.Options.SkipValidation)
	assert.Equal(t, "v7", got.RollbackTo)
	assert.Equal(t, "emergency", got.Reason)
}

// TestRollbackConfiguration_NilManager verifies the nil-manager guard returns a clear error.
func TestRollbackConfiguration_NilManager(t *testing.T) {
	svc := &ConfigurationServiceV2{}

	_, err := svc.RollbackConfiguration(context.Background(), &config.RollbackRequest{
		StewardID:     "s1",
		TargetVersion: 1,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rollback manager not initialized")
}
