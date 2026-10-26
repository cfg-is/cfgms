// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package m365

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func TestRequireExecutionTenant(t *testing.T) {
	t.Run("returns the tenant from the context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "root/msp-a")
		got, err := requireExecutionTenant(ctx)
		require.NoError(t, err)
		assert.Equal(t, "root/msp-a", got)
	})

	t.Run("fails closed when absent", func(t *testing.T) {
		_, err := requireExecutionTenant(context.Background())
		assert.Error(t, err)
	})

	t.Run("fails closed when empty", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "")
		_, err := requireExecutionTenant(ctx)
		assert.Error(t, err)
	})

	t.Run("fails closed when not a string", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, 42)
		_, err := requireExecutionTenant(ctx)
		assert.Error(t, err)
	})
}
