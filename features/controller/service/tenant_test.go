// SPDX-License-Identifier: Apache-2.0
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
		assert.Equal(t, "acme-corp", extractTenantID(ctx))
	})

	t.Run("returns default when context has no tenant ID", func(t *testing.T) {
		assert.Equal(t, "default", extractTenantID(context.Background()))
	})

	t.Run("returns default when tenant ID is empty string", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "")
		assert.Equal(t, "default", extractTenantID(ctx))
	})
}
