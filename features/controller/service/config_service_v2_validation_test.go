// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for ValidationFailedError formatting and the SetConfiguration
// TENANT_LOOKUP_ERROR filtering logic (Issue #2482).
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/logging"
	storageifaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// tenantLookupFailureMessage is a distinctive raw backend error surfaced by
// tenantLookupFailingStore. It must not contain "not found" so that
// validateTenantContext classifies it as a real store error (TENANT_LOOKUP_ERROR)
// rather than a benign absent-tenant condition. Tests assert this string never
// reaches the caller-visible error.
const tenantLookupFailureMessage = "tenant backend connection refused"

// tenantLookupFailingStore is a real TenantStore whose GetTenant always returns a
// non-not-found error, driving the validation layer to emit a TENANT_LOOKUP_ERROR.
// Every other operation delegates to the embedded real store.
type tenantLookupFailingStore struct {
	business.TenantStore
}

func (s *tenantLookupFailingStore) GetTenant(context.Context, string) (*business.TenantData, error) {
	return nil, errors.New(tenantLookupFailureMessage)
}

// newServiceWithFailingTenantLookup builds a ConfigurationServiceV2 whose tenant
// store fails GetTenant with a raw backend error, without mocking: all stores are
// real, only the tenant lookup is wrapped to force the infrastructure-error path.
func newServiceWithFailingTenantLookup(t *testing.T) *ConfigurationServiceV2 {
	t.Helper()
	sm := pkgtesting.SetupTestStorage(t)
	composite := storageifaces.NewStorageManagerFromStores(
		sm.GetConfigStore(),
		sm.GetAuditStore(),
		sm.GetRBACStore(),
		&tenantLookupFailingStore{TenantStore: sm.GetTenantStore()},
		sm.GetClientTenantStore(),
		sm.GetRegistrationTokenStore(),
		sm.GetSessionStore(),
		sm.GetStewardStore(),
		sm.GetCommandStore(),
		sm.GetTriggerStore(),
		sm.GetPushStore(),
	)
	svc := NewConfigurationServiceV2(logging.NewNoopLogger(), composite, nil)
	t.Cleanup(svc.Close)
	return svc
}

// TestValidationFailedError_Error_WithErrors verifies the multi-error formatting
// branch of ValidationFailedError.Error(): every field/message pair is joined into
// the human-readable summary (Issue #2482).
func TestValidationFailedError_Error_WithErrors(t *testing.T) {
	vfe := &ValidationFailedError{
		Errors: []config.ValidationError{
			{Field: "resources[0].name", Message: "Invalid resource name format: docker.io", Code: "INVALID_RESOURCE_NAME"},
			{Field: "resources[1].module", Message: "Module name is required", Code: "MISSING_MODULE_NAME"},
		},
	}

	msg := vfe.Error()

	assert.Equal(t,
		"configuration validation failed: resources[0].name: Invalid resource name format: docker.io; resources[1].module: Module name is required",
		msg)
}

// TestValidationFailedError_Error_Empty verifies the zero-errors branch of
// ValidationFailedError.Error() returns the generic summary (Issue #2482).
func TestValidationFailedError_Error_Empty(t *testing.T) {
	vfe := &ValidationFailedError{}
	assert.Equal(t, "configuration validation failed", vfe.Error())

	vfeNilSlice := &ValidationFailedError{Errors: nil}
	assert.Equal(t, "configuration validation failed", vfeNilSlice.Error())
}

// TestSetConfiguration_InfraOnlyError_ReturnsSentinel exercises SetConfiguration
// branch (a): when the only validation error is a TENANT_LOOKUP_ERROR, the config
// itself is valid, so vfe.Errors ends up empty and the function must return the
// generic infrastructure-error sentinel — NOT a *ValidationFailedError — and must
// not leak the raw tenant backend message to the caller (Issue #2482).
func TestSetConfiguration_InfraOnlyError_ReturnsSentinel(t *testing.T) {
	svc := newServiceWithFailingTenantLookup(t)
	cfg := createTestStewardConfig("infra-only-steward")

	err := svc.SetConfiguration(context.Background(), "some-tenant", "infra-only-steward", cfg)

	require.Error(t, err)

	var vfe *ValidationFailedError
	assert.False(t, errors.As(err, &vfe),
		"a purely-infrastructure failure must not surface as a *ValidationFailedError")

	assert.Contains(t, err.Error(), "infrastructure error")
	assert.NotContains(t, err.Error(), tenantLookupFailureMessage,
		"raw tenant backend message must never reach the caller")
}

// TestSetConfiguration_MixedErrors_StripsInfra exercises SetConfiguration branch
// (b): when validation yields both a TENANT_LOOKUP_ERROR and a genuine
// config-derived error, the returned error must be a *ValidationFailedError that
// contains only the config-derived error(s) with the infrastructure entry stripped
// and its raw backend message absent from the caller-visible output (Issue #2482).
func TestSetConfiguration_MixedErrors_StripsInfra(t *testing.T) {
	svc := newServiceWithFailingTenantLookup(t)

	// Duplicate resource names pass individual name-format validation but trigger a
	// DUPLICATE_RESOURCE_NAME config-derived error at the service layer.
	cfg := createTestStewardConfig("mixed-error-steward")
	cfg.Resources[1].Name = cfg.Resources[0].Name

	err := svc.SetConfiguration(context.Background(), "some-tenant", "mixed-error-steward", cfg)

	require.Error(t, err)

	var vfe *ValidationFailedError
	require.True(t, errors.As(err, &vfe),
		"a config-derived validation error must surface as a *ValidationFailedError")

	require.NotEmpty(t, vfe.Errors)
	for _, ve := range vfe.Errors {
		assert.NotEqual(t, "TENANT_LOOKUP_ERROR", ve.Code,
			"infrastructure error code must be stripped from the caller-visible error")
	}

	foundDuplicate := false
	for _, ve := range vfe.Errors {
		if ve.Code == "DUPLICATE_RESOURCE_NAME" {
			foundDuplicate = true
		}
	}
	assert.True(t, foundDuplicate, "config-derived DUPLICATE_RESOURCE_NAME must be preserved")

	assert.NotContains(t, err.Error(), tenantLookupFailureMessage,
		"raw tenant backend message must never reach the caller")
}
