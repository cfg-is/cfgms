// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/config/rollback"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// ctxWithCaller injects the UserIDKey and TenantID context values that validatePermissions reads.
func ctxWithCaller(userID, tenantID string) context.Context {
	ctx := context.WithValue(context.Background(), ctxkeys.UserIDKey, userID)
	return context.WithValue(ctx, ctxkeys.TenantID, tenantID)
}

// adminCtx returns a background context with a sensitive-operation justification, required by
// RBAC manager methods that modify roles or assignments (M-AUTH-2).
func adminCtx() context.Context {
	return rbac.WithSensitiveOperationJustification(context.Background(), "test: validator_test setup")
}

// TestValidatePermissions_EmergencyRollback_Denied verifies that a caller without the
// rollback.emergency permission is denied when requesting an emergency rollback.
func TestValidatePermissions_EmergencyRollback_Denied(t *testing.T) {
	rbacManager := pkgtesting.SetupTestRBACManager(t)
	ctx := context.Background()

	// Create a subject with no rollback-related permissions (no role assigned).
	subject := &common.Subject{
		Id:          "user-no-emergency-perm",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Unprivileged User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, rbacManager.CreateSubject(ctx, subject))

	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, nil, rbacManager)

	callerCtx := ctxWithCaller("user-no-emergency-perm", "test-tenant")
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "device-1",
		RollbackType: rollback.RollbackTypeEmergency,
		Emergency:    true,
		Reason:       "Critical production failure",
		RollbackTo:   "v1.0",
	}

	result, err := validator.ValidateRollback(callerCtx, request, nil)
	require.NoError(t, err)
	assert.False(t, result.Passed)

	found := false
	for _, e := range result.Errors {
		if e.Type == "permission_validation" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected permission_validation error for caller without rollback.emergency")
}

// TestValidatePermissions_EmergencyRollback_Granted verifies that a caller holding a role
// with rollback.emergency passes the permission check and the rollback proceeds.
func TestValidatePermissions_EmergencyRollback_Granted(t *testing.T) {
	rbacManager := pkgtesting.SetupTestRBACManager(t)
	setupCtx := adminCtx()

	// Create the permission (already loaded by Initialize; just verify it exists).
	_, err := rbacManager.GetPermission(setupCtx, "rollback.emergency")
	require.NoError(t, err, "rollback.emergency permission must exist after Initialize")

	// Create a role that grants emergency rollback access.
	role := &common.Role{
		Id:            "emergency-operator",
		Name:          "Emergency Operator",
		TenantId:      "test-tenant",
		PermissionIds: []string{"rollback.emergency"},
	}
	require.NoError(t, rbacManager.CreateRole(setupCtx, role))

	// Create the subject and assign the role.
	subject := &common.Subject{
		Id:          "user-with-emergency-perm",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Emergency Operator User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, rbacManager.CreateSubject(setupCtx, subject))
	require.NoError(t, rbacManager.AssignRole(setupCtx, &common.RoleAssignment{
		SubjectId: "user-with-emergency-perm",
		RoleId:    "emergency-operator",
		TenantId:  "test-tenant",
	}))

	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, nil, rbacManager)

	callerCtx := ctxWithCaller("user-with-emergency-perm", "test-tenant")
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "device-1",
		RollbackType: rollback.RollbackTypeEmergency,
		Emergency:    true,
		Reason:       "Critical production failure",
		RollbackTo:   "v1.0",
	}

	result, err := validator.ValidateRollback(callerCtx, request, nil)
	require.NoError(t, err)

	for _, e := range result.Errors {
		assert.NotEqual(t, "permission_validation", e.Type,
			"caller with rollback.emergency must not receive a permission error")
	}
	assert.True(t, result.Passed)
}

// TestValidatePermissions_MSPRollback_Denied verifies that a caller without rollback.msp
// is denied when the rollback targets MSP scope.
func TestValidatePermissions_MSPRollback_Denied(t *testing.T) {
	rbacManager := pkgtesting.SetupTestRBACManager(t)
	ctx := context.Background()

	subject := &common.Subject{
		Id:          "user-no-msp-perm",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Non-MSP User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, rbacManager.CreateSubject(ctx, subject))

	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, nil, rbacManager)

	callerCtx := ctxWithCaller("user-no-msp-perm", "test-tenant")
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeMSP,
		TargetID:     "msp-org-1",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "v1.0",
	}

	result, err := validator.ValidateRollback(callerCtx, request, nil)
	require.NoError(t, err)
	assert.False(t, result.Passed)

	found := false
	for _, e := range result.Errors {
		if e.Type == "permission_validation" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected permission_validation error for caller without rollback.msp")
}

// TestValidatePermissions_MSPRollback_Granted verifies that a caller holding rollback.msp
// passes the permission check for MSP-scope rollbacks.
func TestValidatePermissions_MSPRollback_Granted(t *testing.T) {
	rbacManager := pkgtesting.SetupTestRBACManager(t)
	setupCtx := adminCtx()

	_, err := rbacManager.GetPermission(setupCtx, "rollback.msp")
	require.NoError(t, err, "rollback.msp permission must exist after Initialize")

	role := &common.Role{
		Id:            "msp-operator",
		Name:          "MSP Operator",
		TenantId:      "test-tenant",
		PermissionIds: []string{"rollback.msp"},
	}
	require.NoError(t, rbacManager.CreateRole(setupCtx, role))

	subject := &common.Subject{
		Id:          "user-with-msp-perm",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "MSP Operator User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, rbacManager.CreateSubject(setupCtx, subject))
	require.NoError(t, rbacManager.AssignRole(setupCtx, &common.RoleAssignment{
		SubjectId: "user-with-msp-perm",
		RoleId:    "msp-operator",
		TenantId:  "test-tenant",
	}))

	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, nil, rbacManager)

	callerCtx := ctxWithCaller("user-with-msp-perm", "test-tenant")
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeMSP,
		TargetID:     "msp-org-1",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "v1.0",
	}

	result, err := validator.ValidateRollback(callerCtx, request, nil)
	require.NoError(t, err)

	for _, e := range result.Errors {
		assert.NotEqual(t, "permission_validation", e.Type,
			"caller with rollback.msp must not receive a permission error")
	}
	assert.True(t, result.Passed)
}

// TestCheckSystemHealth_ReturnsRealMetrics verifies that ValidateRollback populates
// cpu_usage_percent and disk_usage_percent in Metadata from real OS probes (not hardcoded).
func TestCheckSystemHealth_ReturnsRealMetrics(t *testing.T) {
	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, nil, nil)

	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "device-1",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "v1.0",
	}

	result, err := validator.ValidateRollback(context.Background(), request, nil)
	require.NoError(t, err)

	cpuVal, ok := result.Metadata["cpu_usage_percent"]
	require.True(t, ok, "cpu_usage_percent must be present in Metadata")
	cpuPct, ok := cpuVal.(float64)
	require.True(t, ok, "cpu_usage_percent must be float64")
	assert.GreaterOrEqual(t, cpuPct, 0.0, "CPU percent must be >= 0")
	assert.LessOrEqual(t, cpuPct, 100.0, "CPU percent must be <= 100")

	diskVal, ok := result.Metadata["disk_usage_percent"]
	require.True(t, ok, "disk_usage_percent must be present in Metadata")
	diskPct, ok := diskVal.(float64)
	require.True(t, ok, "disk_usage_percent must be float64")
	assert.Greater(t, diskPct, 0.0, "disk percent must be > 0 (container has data on disk)")
	assert.LessOrEqual(t, diskPct, 100.0, "disk percent must be <= 100")
}

// TestEvaluateSystemHealthMetrics_HighCPU verifies that CPU usage above 90% produces a warning.
func TestEvaluateSystemHealthMetrics_HighCPU(t *testing.T) {
	issues := rollback.EvaluateSystemHealthMetrics(91.5, 50.0)
	require.Len(t, issues, 1)
	assert.Equal(t, "system_health", issues[0].Type)
	assert.Equal(t, "warning", issues[0].Severity)
	assert.Contains(t, issues[0].Message, "CPU")
}

// TestEvaluateSystemHealthMetrics_HighDisk verifies that disk usage above 95% produces a warning.
func TestEvaluateSystemHealthMetrics_HighDisk(t *testing.T) {
	issues := rollback.EvaluateSystemHealthMetrics(50.0, 96.0)
	require.Len(t, issues, 1)
	assert.Equal(t, "system_health", issues[0].Type)
	assert.Equal(t, "warning", issues[0].Severity)
	assert.Contains(t, issues[0].Message, "disk")
}

// TestEvaluateSystemHealthMetrics_Healthy verifies that normal CPU and disk usage produces no issues.
func TestEvaluateSystemHealthMetrics_Healthy(t *testing.T) {
	issues := rollback.EvaluateSystemHealthMetrics(50.0, 60.0)
	assert.Empty(t, issues)
}

// TestEvaluateSystemHealthMetrics_BothUnhealthy verifies that CPU and disk thresholds can both trigger.
func TestEvaluateSystemHealthMetrics_BothUnhealthy(t *testing.T) {
	issues := rollback.EvaluateSystemHealthMetrics(95.0, 97.0)
	require.Len(t, issues, 2)
	assert.Equal(t, "system_health", issues[0].Type)
	assert.Equal(t, "system_health", issues[1].Type)
}

// TestEvaluateSystemHealthMetrics_AtThreshold verifies behavior exactly at the threshold boundaries.
func TestEvaluateSystemHealthMetrics_AtThreshold(t *testing.T) {
	// Exactly at threshold — not unhealthy (>90, not >=90)
	assert.Empty(t, rollback.EvaluateSystemHealthMetrics(90.0, 95.0))
	// One tick above CPU threshold
	assert.Len(t, rollback.EvaluateSystemHealthMetrics(90.1, 50.0), 1)
	// One tick above disk threshold
	assert.Len(t, rollback.EvaluateSystemHealthMetrics(50.0, 95.1), 1)
}

// TestValidatePermissions_StandardRollback_NoCheck verifies that a standard (non-emergency,
// non-MSP) rollback does not require any rollback-specific permission.
func TestValidatePermissions_StandardRollback_NoCheck(t *testing.T) {
	rbacManager := pkgtesting.SetupTestRBACManager(t)
	ctx := context.Background()

	// Subject with no rollback permissions at all.
	subject := &common.Subject{
		Id:          "user-standard-only",
		Type:        common.SubjectType_SUBJECT_TYPE_USER,
		DisplayName: "Standard User",
		TenantId:    "test-tenant",
		IsActive:    true,
	}
	require.NoError(t, rbacManager.CreateSubject(ctx, subject))

	validator := rollback.NewRollbackValidator(&noopModuleRegistry{}, nil, rbacManager)

	callerCtx := ctxWithCaller("user-standard-only", "test-tenant")
	request := rollback.RollbackRequest{
		TargetType:   rollback.TargetTypeDevice,
		TargetID:     "device-1",
		RollbackType: rollback.RollbackTypeFull,
		RollbackTo:   "v1.0",
	}

	result, err := validator.ValidateRollback(callerCtx, request, nil)
	require.NoError(t, err)

	for _, e := range result.Errors {
		assert.NotEqual(t, "permission_validation", e.Type,
			"standard rollback must not trigger permission check")
	}
	assert.True(t, result.Passed)
}
