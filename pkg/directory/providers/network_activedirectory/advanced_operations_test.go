// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package network_activedirectory

import (
	"context"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBulkCreateUsers_ReturnsDesignDecisionError(t *testing.T) {
	provider := &ActiveDirectoryProvider{
		logger: logging.NewNoopLogger(),
	}
	ctx := context.Background()

	_, err := provider.BulkCreateUsers(ctx, []*interfaces.DirectoryUser{}, &interfaces.BulkOptions{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "design decision"),
		"expected design decision error, got: %s", err.Error())
}

func TestBulkDeleteUsers_ReturnsDesignDecisionError(t *testing.T) {
	provider := &ActiveDirectoryProvider{
		logger: logging.NewNoopLogger(),
	}
	ctx := context.Background()

	_, err := provider.BulkDeleteUsers(ctx, []string{}, &interfaces.BulkOptions{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "design decision"),
		"expected design decision error, got: %s", err.Error())
}

func TestBulkUpdateUsers_ReturnsDesignDecisionError(t *testing.T) {
	provider := &ActiveDirectoryProvider{
		logger: logging.NewNoopLogger(),
	}
	ctx := context.Background()

	_, err := provider.BulkUpdateUsers(ctx, []*interfaces.UserUpdate{}, &interfaces.BulkOptions{})
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "design decision"),
		"expected design decision error, got: %s", err.Error())
}
