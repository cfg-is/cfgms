// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func TestExtractTenantID(t *testing.T) {
	t.Run("returns tenant ID from context", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "acme-corp")
		id, ok := extractTenantID(ctx)
		assert.True(t, ok)
		assert.Equal(t, "acme-corp", id)
	})

	t.Run("reports absent and substitutes nothing when context has no tenant ID", func(t *testing.T) {
		id, ok := extractTenantID(context.Background())
		assert.False(t, ok)
		assert.Empty(t, id)
	})

	t.Run("reports absent when tenant ID is empty string", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "")
		id, ok := extractTenantID(ctx)
		assert.False(t, ok)
		assert.Empty(t, id)
	})
}
