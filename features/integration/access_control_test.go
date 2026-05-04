// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package integration_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/integration"
	"github.com/cfgis/cfgms/features/tenant/security"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestEnhancedAccessControlManager_ZeroTrustModeConfiguration(t *testing.T) {
	manager := integration.NewEnhancedAccessControlManager(nil, nil, nil)

	// Test initial state
	assert.Equal(t, integration.ZeroTrustPolicyModeDisabled, manager.GetZeroTrustPolicyMode())

	// Test setting zero-trust policy mode to augmented
	manager.SetZeroTrustPolicyMode(integration.ZeroTrustPolicyModeAugmented)
	assert.Equal(t, integration.ZeroTrustPolicyModeAugmented, manager.GetZeroTrustPolicyMode())

	// Test setting mode to auditing
	manager.SetZeroTrustPolicyMode(integration.ZeroTrustPolicyModeAuditing)
	assert.Equal(t, integration.ZeroTrustPolicyModeAuditing, manager.GetZeroTrustPolicyMode())

	// Test disabling by setting to disabled mode
	manager.SetZeroTrustPolicyMode(integration.ZeroTrustPolicyModeDisabled)
	assert.Equal(t, integration.ZeroTrustPolicyModeDisabled, manager.GetZeroTrustPolicyMode())
}

func TestEnhancedAccessControlManager_CheckAccess_SequentialMode(t *testing.T) {
	ctx := context.Background()

	rbacMgr := pkgtesting.SetupTestRBACManager(t)
	tenantSecurity := security.NewTenantSecurityMiddleware(rbacMgr, nil, nil, nil)
	manager := integration.NewEnhancedAccessControlManager(rbacMgr, nil, tenantSecurity)

	request := &common.AccessRequest{
		SubjectId:    "unknown-subject",
		TenantId:     "unknown-tenant",
		PermissionId: "unknown.permission",
	}

	response, err := manager.CheckAccess(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, response)
	assert.False(t, response.StandardResponse.Granted)
}
