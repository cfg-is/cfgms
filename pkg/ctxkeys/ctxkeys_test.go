// SPDX-License-Identifier: AGPL-3.0-only
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
	// A plain string key must not collide with the struct-typed TenantID key.
	//nolint:staticcheck // SA1029: intentionally using a plain string to verify typed key does not collide
	ctx := context.WithValue(context.Background(), "tenant_id", "plain-string-value")
	got, ok := ctx.Value(ctxkeys.TenantID).(string)
	assert.False(t, ok, "struct-typed key must not match plain string key")
	assert.Empty(t, got)
}

func TestCorrelationIDKeyRoundtrip(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxkeys.CorrelationIDKey, "test-correlation-123")
	got, ok := ctx.Value(ctxkeys.CorrelationIDKey).(string)
	assert.True(t, ok)
	assert.Equal(t, "test-correlation-123", got)
}

func TestCorrelationIDKeyMissing(t *testing.T) {
	ctx := context.Background()
	got, ok := ctx.Value(ctxkeys.CorrelationIDKey).(string)
	assert.False(t, ok)
	assert.Empty(t, got)
}

func TestCorrelationIDKeyCollision(t *testing.T) {
	// A plain string key must not collide with the struct-typed CorrelationIDKey.
	//nolint:staticcheck // SA1029: intentionally using a plain string to verify typed key does not collide
	ctx := context.WithValue(context.Background(), "correlation_id", "plain-string-value")
	got, ok := ctx.Value(ctxkeys.CorrelationIDKey).(string)
	assert.False(t, ok, "struct-typed key must not match plain string key")
	assert.Empty(t, got)
}

func TestUserIDKeyRoundtrip(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, "user-abc-123")
	got, ok := ctx.Value(ctxkeys.UserIDKey).(string)
	assert.True(t, ok)
	assert.Equal(t, "user-abc-123", got)
}

func TestUserIDKeyMissing(t *testing.T) {
	ctx := context.Background()
	got, ok := ctx.Value(ctxkeys.UserIDKey).(string)
	assert.False(t, ok)
	assert.Empty(t, got)
}

func TestUserIDKeyCollision(t *testing.T) {
	// A plain string key must not collide with the struct-typed UserIDKey.
	//nolint:staticcheck // SA1029: intentionally using a plain string to verify typed key does not collide
	ctx := context.WithValue(context.Background(), "user_id", "plain-string-value")
	got, ok := ctx.Value(ctxkeys.UserIDKey).(string)
	assert.False(t, ok, "struct-typed key must not match plain string key")
	assert.Empty(t, got)
}

func TestAuthClaimsKeyRoundtrip(t *testing.T) {
	claims := map[string]interface{}{"sub": "user-123", "role": "admin"}
	ctx := context.WithValue(context.Background(), ctxkeys.AuthClaimsKey, claims)
	got, ok := ctx.Value(ctxkeys.AuthClaimsKey).(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, claims, got)
}

func TestAuthClaimsKeyMissing(t *testing.T) {
	ctx := context.Background()
	got, ok := ctx.Value(ctxkeys.AuthClaimsKey).(map[string]interface{})
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestAuthClaimsKeyCollision(t *testing.T) {
	// A plain string key must not collide with the struct-typed AuthClaimsKey.
	//nolint:staticcheck // SA1029: intentionally using a plain string to verify typed key does not collide
	ctx := context.WithValue(context.Background(), "auth_claims", map[string]interface{}{"sub": "bad"})
	got, ok := ctx.Value(ctxkeys.AuthClaimsKey).(map[string]interface{})
	assert.False(t, ok, "struct-typed key must not match plain string key")
	assert.Nil(t, got)
}
