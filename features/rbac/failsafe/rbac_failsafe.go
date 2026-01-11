// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package failsafe

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// FailsafeRBACManager provides fail-secure behavior for RBAC operations
// When the underlying RBAC manager is unavailable, it defaults to denying access
type FailsafeRBACManager struct {
	underlying  rbac.RBACManager
	healthCheck *HealthChecker
	failureMode FailureMode
	mutex       sync.RWMutex
	metrics     *FailsafeMetrics
}

// FailureMode defines how the failsafe manager behaves during failures
type FailureMode string

const (
	// FailureModeFailSecure denies all access during failures (default)
	FailureModeFailSecure FailureMode = "fail_secure"
	// FailureModeReadOnlyCached allows read-only operations from cache during failures
	FailureModeReadOnlyCached FailureMode = "read_only_cached"
	// FailureModeGracefulDegradation allows limited operations with enhanced logging
	FailureModeGracefulDegradation FailureMode = "graceful_degradation"
)

// HealthChecker monitors the health of the underlying RBAC manager
type HealthChecker struct {
	rbacManager            rbac.RBACManager
	lastHealthCheck        time.Time
	healthCheckInterval    time.Duration
	consecutiveFailures    int
	maxConsecutiveFailures int
	isHealthy              bool
	mutex                  sync.RWMutex
}

// FailsafeMetrics tracks failsafe operation metrics
type FailsafeMetrics struct {
	TotalRequests       int64
	FailedRequests      int64
	DeniedByFailsafe    int64
	HealthCheckFailures int64
	RecoveryEvents      int64
	mutex               sync.RWMutex
}

// NewFailsafeRBACManager creates a new failsafe RBAC manager
func NewFailsafeRBACManager(underlying rbac.RBACManager) *FailsafeRBACManager {
	healthChecker := &HealthChecker{
		rbacManager:            underlying,
		healthCheckInterval:    30 * time.Second,
		maxConsecutiveFailures: 3,
		isHealthy:              true,
		mutex:                  sync.RWMutex{},
	}

	fsm := &FailsafeRBACManager{
		underlying:  underlying,
		healthCheck: healthChecker,
		failureMode: FailureModeFailSecure,
		mutex:       sync.RWMutex{},
		metrics: &FailsafeMetrics{
			mutex: sync.RWMutex{},
		},
	}

	// Start health checking in background
	go fsm.startHealthChecking()

	return fsm
}

// SetFailureMode sets the failure behavior mode
func (fsm *FailsafeRBACManager) SetFailureMode(mode FailureMode) {
	fsm.mutex.Lock()
	defer fsm.mutex.Unlock()
	fsm.failureMode = mode
}

// IsHealthy returns the current health status of the underlying RBAC manager
func (fsm *FailsafeRBACManager) IsHealthy() bool {
	fsm.healthCheck.mutex.RLock()
	defer fsm.healthCheck.mutex.RUnlock()
	return fsm.healthCheck.isHealthy
}

// GetMetrics returns the current failsafe metrics
func (fsm *FailsafeRBACManager) GetMetrics() *FailsafeMetrics {
	fsm.metrics.mutex.RLock()
	defer fsm.metrics.mutex.RUnlock()
	return &FailsafeMetrics{
		TotalRequests:       fsm.metrics.TotalRequests,
		FailedRequests:      fsm.metrics.FailedRequests,
		DeniedByFailsafe:    fsm.metrics.DeniedByFailsafe,
		HealthCheckFailures: fsm.metrics.HealthCheckFailures,
		RecoveryEvents:      fsm.metrics.RecoveryEvents,
	}
}

// CheckPermission implements fail-secure permission checking
func (fsm *FailsafeRBACManager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	fsm.metrics.mutex.Lock()
	fsm.metrics.TotalRequests++
	fsm.metrics.mutex.Unlock()

	if !fsm.IsHealthy() {
		fsm.metrics.mutex.Lock()
		fsm.metrics.DeniedByFailsafe++
		fsm.metrics.mutex.Unlock()

		// Fail secure: deny access when underlying system is unhealthy
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: RBAC system unavailable (fail-secure mode)",
		}, fmt.Errorf("RBAC system is unhealthy, failing securely by denying access")
	}

	response, err := fsm.underlying.CheckPermission(ctx, request)
	if err != nil {
		fsm.metrics.mutex.Lock()
		fsm.metrics.FailedRequests++
		fsm.metrics.mutex.Unlock()

		// Mark as unhealthy and fail secure
		fsm.markUnhealthy()
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: RBAC system error (fail-secure mode)",
		}, fmt.Errorf("RBAC permission check failed, failing securely: %w", err)
	}

	return response, nil
}

// ValidateAccess implements fail-secure access validation
func (fsm *FailsafeRBACManager) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	fsm.metrics.mutex.Lock()
	fsm.metrics.TotalRequests++
	fsm.metrics.mutex.Unlock()

	if !fsm.IsHealthy() {
		fsm.metrics.mutex.Lock()
		fsm.metrics.DeniedByFailsafe++
		fsm.metrics.mutex.Unlock()

		// Fail secure: deny access when underlying system is unhealthy
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: RBAC system unavailable (fail-secure mode)",
		}, fmt.Errorf("RBAC system is unhealthy, failing securely by denying access")
	}

	response, err := fsm.underlying.ValidateAccess(ctx, authContext, requiredPermission)
	if err != nil {
		fsm.metrics.mutex.Lock()
		fsm.metrics.FailedRequests++
		fsm.metrics.mutex.Unlock()

		// Mark as unhealthy and fail secure
		fsm.markUnhealthy()
		return &common.AccessResponse{
			Granted: false,
			Reason:  "Access denied: RBAC system error (fail-secure mode)",
		}, fmt.Errorf("RBAC access validation failed, failing securely: %w", err)
	}

	return response, nil
}

// GetSubjectPermissions returns empty permissions when system is unhealthy (fail-secure)
func (fsm *FailsafeRBACManager) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	fsm.metrics.mutex.Lock()
	fsm.metrics.TotalRequests++
	fsm.metrics.mutex.Unlock()

	if !fsm.IsHealthy() {
		fsm.metrics.mutex.Lock()
		fsm.metrics.DeniedByFailsafe++
		fsm.metrics.mutex.Unlock()

		// Fail secure: return empty permissions when system is unhealthy
		return []*common.Permission{}, fmt.Errorf("RBAC system is unhealthy, failing securely by returning no permissions")
	}

	permissions, err := fsm.underlying.GetSubjectPermissions(ctx, subjectID, tenantID)
	if err != nil {
		fsm.metrics.mutex.Lock()
		fsm.metrics.FailedRequests++
		fsm.metrics.mutex.Unlock()

		fsm.markUnhealthy()
		// Fail secure: return empty permissions on error
		return []*common.Permission{}, fmt.Errorf("RBAC get subject permissions failed, failing securely: %w", err)
	}

	return permissions, nil
}

// startHealthChecking runs continuous health checks in background
func (fsm *FailsafeRBACManager) startHealthChecking() {
	ticker := time.NewTicker(fsm.healthCheck.healthCheckInterval)
	defer ticker.Stop()

	for range ticker.C {
		fsm.performHealthCheck()
	}
}

// performHealthCheck checks the health of the underlying RBAC manager
func (fsm *FailsafeRBACManager) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try a simple permission check to verify system health
	testRequest := &common.AccessRequest{
		SubjectId:    "__health_check__",
		PermissionId: "__health_check__",
		TenantId:     "__health_check__",
		ResourceId:   "__health_check__",
	}

	_, err := fsm.underlying.CheckPermission(ctx, testRequest)

	fsm.healthCheck.mutex.Lock()
	defer fsm.healthCheck.mutex.Unlock()

	fsm.healthCheck.lastHealthCheck = time.Now()

	if err != nil {
		fsm.healthCheck.consecutiveFailures++
		fsm.metrics.mutex.Lock()
		fsm.metrics.HealthCheckFailures++
		fsm.metrics.mutex.Unlock()

		if fsm.healthCheck.consecutiveFailures >= fsm.healthCheck.maxConsecutiveFailures {
			fsm.healthCheck.isHealthy = false
			// System transitioned to unhealthy state (would log in production)
		}
	} else {
		// Health check succeeded
		wasHealthy := fsm.healthCheck.isHealthy
		fsm.healthCheck.consecutiveFailures = 0
		fsm.healthCheck.isHealthy = true

		if !wasHealthy {
			// System recovered
			fsm.metrics.mutex.Lock()
			fsm.metrics.RecoveryEvents++
			fsm.metrics.mutex.Unlock()
		}
	}
}

// markUnhealthy marks the system as unhealthy due to operational failure
func (fsm *FailsafeRBACManager) markUnhealthy() {
	fsm.healthCheck.mutex.Lock()
	defer fsm.healthCheck.mutex.Unlock()

	fsm.healthCheck.consecutiveFailures++
	if fsm.healthCheck.consecutiveFailures >= fsm.healthCheck.maxConsecutiveFailures {
		fsm.healthCheck.isHealthy = false
	}
}

// Delegate all other RBACManager interface methods to underlying manager with fail-secure behavior

func (fsm *FailsafeRBACManager) Initialize(ctx context.Context) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot initialize")
	}
	return fsm.underlying.Initialize(ctx)
}

func (fsm *FailsafeRBACManager) CreateTenantDefaultRoles(ctx context.Context, tenantID string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot create tenant default roles")
	}
	return fsm.underlying.CreateTenantDefaultRoles(ctx, tenantID)
}

// Permission Store Methods - fail secure by rejecting operations when unhealthy
func (fsm *FailsafeRBACManager) CreatePermission(ctx context.Context, permission *common.Permission) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot create permission")
	}
	return fsm.underlying.CreatePermission(ctx, permission)
}

func (fsm *FailsafeRBACManager) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get permission")
	}
	return fsm.underlying.GetPermission(ctx, id)
}

func (fsm *FailsafeRBACManager) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	if !fsm.IsHealthy() {
		return []*common.Permission{}, fmt.Errorf("RBAC system is unhealthy, cannot list permissions")
	}
	return fsm.underlying.ListPermissions(ctx, resourceType)
}

func (fsm *FailsafeRBACManager) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot update permission")
	}
	return fsm.underlying.UpdatePermission(ctx, permission)
}

func (fsm *FailsafeRBACManager) DeletePermission(ctx context.Context, id string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot delete permission")
	}
	return fsm.underlying.DeletePermission(ctx, id)
}

// Role Store Methods - fail secure
func (fsm *FailsafeRBACManager) CreateRole(ctx context.Context, role *common.Role) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot create role")
	}
	return fsm.underlying.CreateRole(ctx, role)
}

func (fsm *FailsafeRBACManager) GetRole(ctx context.Context, id string) (*common.Role, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get role")
	}
	return fsm.underlying.GetRole(ctx, id)
}

func (fsm *FailsafeRBACManager) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	if !fsm.IsHealthy() {
		return []*common.Role{}, fmt.Errorf("RBAC system is unhealthy, cannot list roles")
	}
	return fsm.underlying.ListRoles(ctx, tenantID)
}

func (fsm *FailsafeRBACManager) UpdateRole(ctx context.Context, role *common.Role) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot update role")
	}
	return fsm.underlying.UpdateRole(ctx, role)
}

func (fsm *FailsafeRBACManager) DeleteRole(ctx context.Context, id string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot delete role")
	}
	return fsm.underlying.DeleteRole(ctx, id)
}

func (fsm *FailsafeRBACManager) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	if !fsm.IsHealthy() {
		return []*common.Permission{}, fmt.Errorf("RBAC system is unhealthy, cannot get role permissions")
	}
	return fsm.underlying.GetRolePermissions(ctx, roleID)
}

// Subject Store Methods - fail secure
func (fsm *FailsafeRBACManager) CreateSubject(ctx context.Context, subject *common.Subject) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot create subject")
	}
	return fsm.underlying.CreateSubject(ctx, subject)
}

func (fsm *FailsafeRBACManager) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get subject")
	}
	return fsm.underlying.GetSubject(ctx, id)
}

func (fsm *FailsafeRBACManager) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	if !fsm.IsHealthy() {
		return []*common.Subject{}, fmt.Errorf("RBAC system is unhealthy, cannot list subjects")
	}
	return fsm.underlying.ListSubjects(ctx, tenantID, subjectType)
}

func (fsm *FailsafeRBACManager) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot update subject")
	}
	return fsm.underlying.UpdateSubject(ctx, subject)
}

func (fsm *FailsafeRBACManager) DeleteSubject(ctx context.Context, id string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot delete subject")
	}
	return fsm.underlying.DeleteSubject(ctx, id)
}

func (fsm *FailsafeRBACManager) GetSubjectRoles(ctx context.Context, subjectID string, tenantID string) ([]*common.Role, error) {
	if !fsm.IsHealthy() {
		return []*common.Role{}, fmt.Errorf("RBAC system is unhealthy, cannot get subject roles")
	}
	return fsm.underlying.GetSubjectRoles(ctx, subjectID, tenantID)
}

// Role Assignment Store Methods - fail secure
func (fsm *FailsafeRBACManager) AssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot assign role")
	}
	return fsm.underlying.AssignRole(ctx, assignment)
}

func (fsm *FailsafeRBACManager) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot revoke role")
	}
	return fsm.underlying.RevokeRole(ctx, subjectID, roleID, tenantID)
}

func (fsm *FailsafeRBACManager) GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get assignment")
	}
	return fsm.underlying.GetAssignment(ctx, id)
}

func (fsm *FailsafeRBACManager) ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	if !fsm.IsHealthy() {
		return []*common.RoleAssignment{}, fmt.Errorf("RBAC system is unhealthy, cannot list assignments")
	}
	return fsm.underlying.ListAssignments(ctx, subjectID, roleID, tenantID)
}

func (fsm *FailsafeRBACManager) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	if !fsm.IsHealthy() {
		return []*common.RoleAssignment{}, fmt.Errorf("RBAC system is unhealthy, cannot get subject assignments")
	}
	return fsm.underlying.GetSubjectAssignments(ctx, subjectID, tenantID)
}

func (fsm *FailsafeRBACManager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	if !fsm.IsHealthy() {
		return []*common.Permission{}, fmt.Errorf("RBAC system is unhealthy, cannot get effective permissions")
	}
	return fsm.underlying.GetEffectivePermissions(ctx, subjectID, tenantID)
}

// Hierarchy operations - fail secure
func (fsm *FailsafeRBACManager) GetRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get role hierarchy")
	}
	return fsm.underlying.GetRoleHierarchy(ctx, roleID)
}

func (fsm *FailsafeRBACManager) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	if !fsm.IsHealthy() {
		return []*common.Role{}, fmt.Errorf("RBAC system is unhealthy, cannot get child roles")
	}
	return fsm.underlying.GetChildRoles(ctx, roleID)
}

func (fsm *FailsafeRBACManager) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get parent role")
	}
	return fsm.underlying.GetParentRole(ctx, roleID)
}

func (fsm *FailsafeRBACManager) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot set role parent")
	}
	return fsm.underlying.SetRoleParent(ctx, roleID, parentRoleID, inheritanceType)
}

func (fsm *FailsafeRBACManager) RemoveRoleParent(ctx context.Context, roleID string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot remove role parent")
	}
	return fsm.underlying.RemoveRoleParent(ctx, roleID)
}

func (fsm *FailsafeRBACManager) ValidateRoleHierarchy(ctx context.Context, roleID string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot validate role hierarchy")
	}
	return fsm.underlying.ValidateRoleHierarchy(ctx, roleID)
}

func (fsm *FailsafeRBACManager) ComputeRolePermissions(ctx context.Context, roleID string) (*memory.EffectivePermissions, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot compute role permissions")
	}
	return fsm.underlying.ComputeRolePermissions(ctx, roleID)
}

func (fsm *FailsafeRBACManager) CreateRoleWithParent(ctx context.Context, role *common.Role, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot create role with parent")
	}
	return fsm.underlying.CreateRoleWithParent(ctx, role, parentRoleID, inheritanceType)
}

func (fsm *FailsafeRBACManager) GetRoleHierarchyTree(ctx context.Context, rootRoleID string, maxDepth int) (*memory.RoleHierarchy, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot get role hierarchy tree")
	}
	return fsm.underlying.GetRoleHierarchyTree(ctx, rootRoleID, maxDepth)
}

func (fsm *FailsafeRBACManager) ValidateHierarchyOperation(ctx context.Context, childRoleID, parentRoleID string) error {
	if !fsm.IsHealthy() {
		return fmt.Errorf("RBAC system is unhealthy, cannot validate hierarchy operation")
	}
	return fsm.underlying.ValidateHierarchyOperation(ctx, childRoleID, parentRoleID)
}

func (fsm *FailsafeRBACManager) ResolvePermissionConflicts(ctx context.Context, roleID string, conflictingPermissions map[string][]*common.Permission) (map[string]*common.Permission, error) {
	if !fsm.IsHealthy() {
		return nil, fmt.Errorf("RBAC system is unhealthy, cannot resolve permission conflicts")
	}
	return fsm.underlying.ResolvePermissionConflicts(ctx, roleID, conflictingPermissions)
}

// Verify that FailsafeRBACManager implements the RBACManager interface
var _ rbac.RBACManager = (*FailsafeRBACManager)(nil)
