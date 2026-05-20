// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// minimalValidConfig returns a StewardConfig that passes basic validation.
func minimalValidConfig() *stewardconfig.StewardConfig {
	return &stewardconfig.StewardConfig{
		Steward: stewardconfig.StewardSettings{
			ID:   "steward-1",
			Mode: stewardconfig.ModeStandalone,
			Logging: stewardconfig.LoggingConfig{
				Level: "info",
			},
		},
	}
}

func TestValidateTenantContext_TenantExists(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	ctx := context.Background()

	require.NoError(t, sm.GetTenantStore().CreateTenant(ctx, &business.TenantData{
		ID:     "acme-corp",
		Name:   "Acme Corp",
		Status: business.TenantStatusActive,
	}))

	vm := NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())
	result := vm.ValidateConfiguration(ctx, "acme-corp", "steward-1", minimalValidConfig())

	require.NotNil(t, result.TenantChecks)
	assert.True(t, result.TenantChecks.TenantExists)
	assert.Equal(t, "acme-corp", result.TenantChecks.TenantID)
}

func TestValidateTenantContext_TenantNotFound(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	vm := NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())
	ctx := context.Background()

	result := vm.ValidateConfiguration(ctx, "nonexistent-tenant", "steward-1", minimalValidConfig())

	require.NotNil(t, result.TenantChecks)
	assert.False(t, result.TenantChecks.TenantExists)
	for _, e := range result.Errors {
		assert.NotEqual(t, "TENANT_LOOKUP_ERROR", e.Code, "not-found must not produce a TENANT_LOOKUP_ERROR")
	}
}

func TestValidateTenantContext_EmptyTenantID(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	vm := NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())
	ctx := context.Background()

	result := vm.ValidateConfiguration(ctx, "", "steward-1", minimalValidConfig())

	require.NotNil(t, result.TenantChecks)
	assert.False(t, result.TenantChecks.TenantExists)
	for _, e := range result.Errors {
		assert.NotEqual(t, "TENANT_LOOKUP_ERROR", e.Code, "empty tenantID must not trigger a store lookup error")
	}
}

func TestValidateTenantContext_StoreError(t *testing.T) {
	sm := pkgtesting.SetupTestStorage(t)
	vm := NewValidationManager(sm.GetConfigStore(), sm.GetTenantStore())

	// Force a real store error by closing the underlying database.
	_ = sm.Close()

	result := vm.ValidateConfiguration(context.Background(), "some-tenant", "steward-1", minimalValidConfig())

	assert.False(t, result.Valid)
	codes := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		codes = append(codes, e.Code)
	}
	assert.Contains(t, codes, "TENANT_LOOKUP_ERROR")
}
