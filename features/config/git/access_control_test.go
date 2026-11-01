// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2025 CFGMS Contributors
package git

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestNewDriftDetector_nilLogger_usesNoop(t *testing.T) {
	dd := NewDriftDetector(nil)
	require.NotNil(t, dd)
	// Verify it doesn't panic when used
	ctx := context.Background()
	repo := &Repository{Name: "test-repo"}
	drift := &DriftDetection{Path: "config.yaml"}
	err := dd.RevertDrift(ctx, repo, drift)
	assert.NoError(t, err)
}

func TestNewDriftDetector_injectsLogger(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	dd := NewDriftDetector(mock)
	require.NotNil(t, dd)

	ctx := context.Background()
	repo := &Repository{Name: "test-repo"}
	drift := &DriftDetection{Path: "config.yaml"}
	err := dd.RevertDrift(ctx, repo, drift)
	assert.NoError(t, err)

	logs := mock.GetLogs("info")
	require.Len(t, logs, 1)
	assert.Equal(t, "reverting drift", logs[0].Message)
}

func TestNewGitModeManager_nilLogger_usesNoop(t *testing.T) {
	gmm := NewGitModeManager(nil)
	require.NotNil(t, gmm)

	// Verify no panic on usage
	ctx := context.Background()
	repo := &Repository{
		Name: "test-repo",
		AccessControl: &RepositoryAccessControl{
			Mode: AccessModeReadOnly,
			ProtectedBranches: []BranchProtection{
				{Pattern: "main"},
			},
		},
	}
	err := gmm.ValidateReadOnlyMode(ctx, repo)
	assert.NoError(t, err)
}

func TestNewGitModeManager_logsUnknownWebhookAction(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	gmm := NewGitModeManager(mock)
	require.NotNil(t, gmm)

	repo := &Repository{
		Name: "test-repo",
		AccessControl: &RepositoryAccessControl{
			Mode: AccessModeReadOnly,
		},
	}

	webhookData := map[string]interface{}{
		"action": "unknown_action",
	}
	err := gmm.ProcessGitWebhook(context.Background(), repo, webhookData)
	assert.NoError(t, err)

	warns := mock.GetLogs("warn")
	require.NotEmpty(t, warns)
	assert.Equal(t, "unknown webhook action", warns[0].Message)
}

func TestNewAccessControlManager_propagatesLogger(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	acm := NewAccessControlManager(mock)
	require.NotNil(t, acm)
	require.NotNil(t, acm.driftDetector)
}
