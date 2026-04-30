// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package ctxkeys_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

func TestTenantIDRoundtrip(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, "my-tenant")
	got, ok := ctx.Value(ctxkeys.TenantID).(string)
	assert.True(t, ok)
	assert.Equal(t, "my-tenant", got)
}

func TestTenantIDMissing(t *testing.T) {
	ctx := context.Background()
	got, ok := ctx.Value(ctxkeys.TenantID).(string)
	assert.False(t, ok)
	assert.Empty(t, got)
}

func TestContextKeyCollision(t *testing.T) {
	// A plain string key must not collide with the typed ContextKey.
	//nolint:staticcheck // SA1029: intentionally using a plain string to verify typed key does not collide
	ctx := context.WithValue(context.Background(), "tenant_id", "plain-string-value")
	got, ok := ctx.Value(ctxkeys.TenantID).(string)
	assert.False(t, ok, "typed key must not match plain string key")
	assert.Empty(t, got)
}
