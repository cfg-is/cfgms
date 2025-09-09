package rbac

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// EscalationPreventionManager provides comprehensive privilege escalation attack prevention
type EscalationPreventionManager struct {
	rbacManager RBACManager
	
	// Concurrent modification protection
	operationMutex sync.RWMutex
	operationLog   []OperationRecord
	
	// Timing-based attack protection
	recentOperations map[string][]time.Time
	timingMutex      sync.RWMutex
	
	// Escalation detection
	escalationAlerts []EscalationAlert
	alertMutex       sync.RWMutex
	
	// Configuration
	maxOperationsPerSecond int
	operationTimeWindow    time.Duration
	maxConcurrentOps       int
}

// OperationRecord tracks RBAC operations for audit and analysis
type OperationRecord struct {
	ID              string                    `json:"id"`
	Type            OperationType            `json:"type"`
	SubjectID       string                   `json:"subject_id,omitempty"`
	RoleID          string                   `json:"role_id,omitempty"`
	ParentRoleID    string                   `json:"parent_role_id,omitempty"`
	TenantID        string                   `json:"tenant_id"`
	Timestamp       time.Time                `json:"timestamp"`
	Success         bool                     `json:"success"`
	Error           string                   `json:"error,omitempty"`
	Context         map[string]interface{}   `json:"context,omitempty"`
}

// OperationType defines types of RBAC operations that can be tracked
type OperationType string

const (
	OpTypeRoleAssignment    OperationType = "role_assignment"
	OpTypeRoleRevocation   OperationType = "role_revocation"
	OpTypeRoleParentSet    OperationType = "role_parent_set"
	OpTypeRoleParentRemove OperationType = "role_parent_remove"
	OpTypePermissionCheck  OperationType = "permission_check"
)

// EscalationAlert represents a detected privilege escalation attempt
type EscalationAlert struct {
	ID              string                   `json:"id"`
	Type            EscalationAlertType      `json:"type"`
	Severity        AlertSeverity            `json:"severity"`
	SubjectID       string                   `json:"subject_id,omitempty"`
	RoleID          string                   `json:"role_id,omitempty"`
	TenantID        string                   `json:"tenant_id"`
	Description     string                   `json:"description"`
	DetectedAt      time.Time                `json:"detected_at"`
	Evidence        map[string]interface{}   `json:"evidence"`
	Blocked         bool                     `json:"blocked"`
}

// EscalationAlertType defines types of escalation alerts
type EscalationAlertType string

const (
	AlertTypeCircularInheritance      EscalationAlertType = "circular_inheritance"
	AlertTypeConcurrentModification   EscalationAlertType = "concurrent_modification"
	AlertTypeRapidEscalation         EscalationAlertType = "rapid_escalation"
	AlertTypeTimingAttack            EscalationAlertType = "timing_attack"
	AlertTypeSuspiciousPattern       EscalationAlertType = "suspicious_pattern"
	AlertTypeCrossTimZoneEscalation  EscalationAlertType = "cross_tenant_escalation"
)

// AlertSeverity defines severity levels for escalation alerts
type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

// NewEscalationPreventionManager creates a new privilege escalation prevention manager
func NewEscalationPreventionManager(rbacManager RBACManager) *EscalationPreventionManager {
	return &EscalationPreventionManager{
		rbacManager:            rbacManager,
		operationLog:           make([]OperationRecord, 0),
		recentOperations:       make(map[string][]time.Time),
		escalationAlerts:       make([]EscalationAlert, 0),
		maxOperationsPerSecond: 5,  // Maximum 5 operations per second per subject
		operationTimeWindow:    time.Second * 10,
		maxConcurrentOps:       3,  // Maximum 3 concurrent operations per subject
	}
}

// ValidateAndSetRoleParent validates and sets role parent with escalation prevention
func (epm *EscalationPreventionManager) ValidateAndSetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType, subjectID string) error {
	operationID := fmt.Sprintf("set-parent-%d", time.Now().UnixNano())
	startTime := time.Now()
	
	// Record operation start
	operation := OperationRecord{
		ID:           operationID,
		Type:         OpTypeRoleParentSet,
		RoleID:       roleID,
		ParentRoleID: parentRoleID,
		SubjectID:    subjectID,
		Timestamp:    startTime,
		Context:      map[string]interface{}{"inheritance_type": inheritanceType.String()},
	}
	
	// Check for concurrent modification attacks
	if err := epm.checkConcurrentModificationProtection(ctx, subjectID, roleID); err != nil {
		operation.Success = false
		operation.Error = err.Error()
		epm.recordOperation(operation)
		
		// Generate escalation alert
		epm.generateAlert(AlertTypeConcurrentModification, SeverityHigh, subjectID, roleID, "", 
			fmt.Sprintf("Concurrent modification detected for role %s", roleID), 
			map[string]interface{}{"attempted_parent": parentRoleID}, true)
		
		return fmt.Errorf("concurrent modification protection: %w", err)
	}
	
	// Check for timing-based attacks
	if err := epm.checkTimingBasedProtection(ctx, subjectID, roleID); err != nil {
		operation.Success = false
		operation.Error = err.Error()
		epm.recordOperation(operation)
		
		// Generate escalation alert
		epm.generateAlert(AlertTypeTimingAttack, SeverityCritical, subjectID, roleID, "", 
			fmt.Sprintf("Timing-based attack detected for role %s", roleID), 
			map[string]interface{}{"attempted_parent": parentRoleID}, true)
		
		return fmt.Errorf("timing-based protection: %w", err)
	}
	
	// Enhanced circular dependency prevention
	if err := epm.enhancedCircularDependencyCheck(ctx, roleID, parentRoleID); err != nil {
		operation.Success = false
		operation.Error = err.Error()
		epm.recordOperation(operation)
		
		// Generate escalation alert
		epm.generateAlert(AlertTypeCircularInheritance, SeverityCritical, subjectID, roleID, "", 
			fmt.Sprintf("Circular inheritance attack blocked: %s -> %s", roleID, parentRoleID), 
			map[string]interface{}{"role_chain": epm.getRoleChain(ctx, roleID)}, true)
		
		return fmt.Errorf("circular inheritance prevention: %w", err)
	}
	
	// Acquire operation lock for thread safety
	epm.operationMutex.Lock()
	defer epm.operationMutex.Unlock()
	
	// First perform validation using the RBAC manager
	if err := epm.rbacManager.ValidateHierarchyOperation(ctx, roleID, parentRoleID); err != nil {
		operation.Success = false
		operation.Error = err.Error()
		epm.recordOperation(operation)
		return fmt.Errorf("hierarchy validation failed: %w", err)
	}
	
	// Perform the actual role parent assignment directly through the underlying store
	// to avoid circular calls back to the Manager's SetRoleParent method
	manager, ok := epm.rbacManager.(*Manager)
	if !ok {
		return fmt.Errorf("escalation prevention manager requires Manager implementation")
	}
	err := manager.GetStore().SetRoleParent(ctx, roleID, parentRoleID, inheritanceType)
	
	// Record operation result
	operation.Success = (err == nil)
	if err != nil {
		operation.Error = err.Error()
	}
	epm.recordOperation(operation)
	
	// Check for escalation patterns after successful operation
	if err == nil {
		epm.detectEscalationPatterns(ctx, subjectID, roleID, parentRoleID)
	}
	
	return err
}

// ValidateAndAssignRole validates and assigns role with escalation prevention
func (epm *EscalationPreventionManager) ValidateAndAssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	operationID := fmt.Sprintf("assign-role-%d", time.Now().UnixNano())
	startTime := time.Now()
	
	// Record operation start
	operation := OperationRecord{
		ID:        operationID,
		Type:      OpTypeRoleAssignment,
		SubjectID: assignment.SubjectId,
		RoleID:    assignment.RoleId,
		TenantID:  assignment.TenantId,
		Timestamp: startTime,
	}
	
	// Check for rapid escalation attacks
	if err := epm.checkRapidEscalationProtection(ctx, assignment.SubjectId, assignment.RoleId); err != nil {
		operation.Success = false
		operation.Error = err.Error()
		epm.recordOperation(operation)
		
		// Generate escalation alert
		epm.generateAlert(AlertTypeRapidEscalation, SeverityHigh, assignment.SubjectId, assignment.RoleId, assignment.TenantId,
			fmt.Sprintf("Rapid escalation attack detected for subject %s", assignment.SubjectId), 
			map[string]interface{}{"attempted_role": assignment.RoleId}, true)
		
		return fmt.Errorf("rapid escalation protection: %w", err)
	}
	
	// Check for cross-tenant escalation attempts
	if err := epm.checkCrossTenantEscalationProtection(ctx, assignment.SubjectId, assignment.TenantId); err != nil {
		operation.Success = false
		operation.Error = err.Error()
		epm.recordOperation(operation)
		
		// Generate escalation alert
		epm.generateAlert(AlertTypeCrossTimZoneEscalation, SeverityCritical, assignment.SubjectId, assignment.RoleId, assignment.TenantId,
			fmt.Sprintf("Cross-tenant escalation attack detected: subject %s in tenant %s", assignment.SubjectId, assignment.TenantId), 
			map[string]interface{}{"attempted_role": assignment.RoleId}, true)
		
		return fmt.Errorf("cross-tenant escalation protection: %w", err)
	}
	
	// Acquire operation lock for thread safety
	epm.operationMutex.Lock()
	defer epm.operationMutex.Unlock()
	
	// Perform the actual role assignment with write-through persistence
	// Store in ephemeral store first, then persist to RBAC store
	manager, ok := epm.rbacManager.(*Manager)
	if !ok {
		return fmt.Errorf("escalation prevention manager requires Manager implementation")
	}
	
	// First, store in ephemeral memory store for immediate access
	err := manager.GetStore().AssignRole(ctx, assignment)
	if err != nil {
		return fmt.Errorf("failed to store role assignment in memory: %w", err)
	}
	
	// Then, persist to RBAC store for durability (write-through pattern)
	if manager.GetRBACStore() != nil {
		if persistErr := manager.GetRBACStore().StoreRoleAssignment(ctx, assignment); persistErr != nil {
			// If persistence fails, we should remove from memory store to maintain consistency
			_ = manager.GetStore().RevokeRole(ctx, assignment.SubjectId, assignment.RoleId, assignment.TenantId)
			return fmt.Errorf("failed to persist role assignment: %w", persistErr)
		}
	}
	
	// Record operation result
	operation.Success = (err == nil)
	if err != nil {
		operation.Error = err.Error()
	}
	epm.recordOperation(operation)
	
	// Check for privilege escalation detection after successful assignment
	if err == nil {
		epm.detectPrivilegeEscalation(ctx, assignment.SubjectId, assignment.RoleId, assignment.TenantId)
	}
	
	return err
}

// checkConcurrentModificationProtection prevents concurrent modification attacks
func (epm *EscalationPreventionManager) checkConcurrentModificationProtection(ctx context.Context, subjectID, roleID string) error {
	epm.timingMutex.RLock()
	defer epm.timingMutex.RUnlock()
	
	// Check for concurrent operations on the same subject/role
	key := fmt.Sprintf("%s:%s", subjectID, roleID)
	if operations, exists := epm.recentOperations[key]; exists {
		// Check if there are too many concurrent operations
		recentCount := 0
		cutoff := time.Now().Add(-time.Second * 2) // 2 second window
		
		for _, opTime := range operations {
			if opTime.After(cutoff) {
				recentCount++
			}
		}
		
		if recentCount > epm.maxConcurrentOps {
			return fmt.Errorf("too many concurrent operations detected for %s (count: %d)", key, recentCount)
		}
	}
	
	return nil
}

// checkTimingBasedProtection prevents timing-based privilege escalation attacks
func (epm *EscalationPreventionManager) checkTimingBasedProtection(ctx context.Context, subjectID, roleID string) error {
	epm.timingMutex.Lock()
	defer epm.timingMutex.Unlock()
	
	now := time.Now()
	key := subjectID
	
	// Initialize if first operation
	if epm.recentOperations[key] == nil {
		epm.recentOperations[key] = make([]time.Time, 0)
	}
	
	// Clean old operations outside the time window
	cutoff := now.Add(-epm.operationTimeWindow)
	validOperations := make([]time.Time, 0)
	
	for _, opTime := range epm.recentOperations[key] {
		if opTime.After(cutoff) {
			validOperations = append(validOperations, opTime)
		}
	}
	
	// Check rate limiting
	if len(validOperations) >= epm.maxOperationsPerSecond {
		return fmt.Errorf("operation rate limit exceeded for subject %s (operations: %d in %v)", 
			subjectID, len(validOperations), epm.operationTimeWindow)
	}
	
	// Record current operation
	validOperations = append(validOperations, now)
	epm.recentOperations[key] = validOperations
	
	return nil
}

// enhancedCircularDependencyCheck performs comprehensive circular dependency validation
func (epm *EscalationPreventionManager) enhancedCircularDependencyCheck(ctx context.Context, roleID, parentRoleID string) error {
	// Use the existing RBAC manager's validation, but add additional checks
	err := epm.rbacManager.ValidateHierarchyOperation(ctx, roleID, parentRoleID)
	if err != nil {
		return err
	}
	
	// Additional check: prevent long chains that could hide circular dependencies
	chainLength := epm.calculateRoleChainLength(ctx, parentRoleID)
	if chainLength > 10 {
		return fmt.Errorf("role hierarchy chain too long (%d levels) - potential circular dependency or complexity attack", chainLength)
	}
	
	// Additional check: prevent rapid chain creation
	recentChainModifications := epm.countRecentChainModifications(parentRoleID)
	if recentChainModifications > 5 {
		return fmt.Errorf("too many recent modifications to role chain involving %s (%d modifications)", parentRoleID, recentChainModifications)
	}
	
	return nil
}

// checkRapidEscalationProtection detects rapid privilege escalation attempts
func (epm *EscalationPreventionManager) checkRapidEscalationProtection(ctx context.Context, subjectID, roleID string) error {
	// Check for rapid assignment of high-privilege roles
	recentAssignments := epm.countRecentRoleAssignments(subjectID)
	if recentAssignments > 3 {
		return fmt.Errorf("rapid role assignment detected for subject %s (%d assignments)", subjectID, recentAssignments)
	}
	
	// Check if this is a high-privilege role
	if epm.isHighPrivilegeRole(ctx, roleID) {
		recentHighPrivAssignments := epm.countRecentHighPrivilegeAssignments(subjectID)
		if recentHighPrivAssignments > 1 {
			return fmt.Errorf("rapid high-privilege role assignment detected for subject %s", subjectID)
		}
	}
	
	return nil
}

// checkCrossTenantEscalationProtection prevents cross-tenant privilege escalation
func (epm *EscalationPreventionManager) checkCrossTenantEscalationProtection(ctx context.Context, subjectID, tenantID string) error {
	// Check if subject exists in multiple tenants recently
	recentTenants := epm.getRecentSubjectTenants(subjectID)
	if len(recentTenants) > 1 {
		return fmt.Errorf("cross-tenant activity detected for subject %s across tenants: %v", subjectID, recentTenants)
	}
	
	// Additional validation: ensure subject belongs to the tenant
	subject, err := epm.rbacManager.GetSubject(ctx, subjectID)
	if err != nil {
		return fmt.Errorf("failed to validate subject tenant: %w", err)
	}
	
	if subject.TenantId != tenantID {
		return fmt.Errorf("cross-tenant escalation attempt: subject %s (tenant %s) accessing tenant %s", 
			subjectID, subject.TenantId, tenantID)
	}
	
	return nil
}

// Helper functions for analysis

func (epm *EscalationPreventionManager) calculateRoleChainLength(ctx context.Context, roleID string) int {
	visited := make(map[string]bool)
	return epm.calculateRoleChainLengthRecursive(ctx, roleID, visited)
}

func (epm *EscalationPreventionManager) calculateRoleChainLengthRecursive(ctx context.Context, roleID string, visited map[string]bool) int {
	if visited[roleID] {
		return 0 // Circular dependency - return 0 to avoid infinite loop
	}
	
	visited[roleID] = true
	
	role, err := epm.rbacManager.GetRole(ctx, roleID)
	if err != nil || role.ParentRoleId == "" {
		return 1
	}
	
	return 1 + epm.calculateRoleChainLengthRecursive(ctx, role.ParentRoleId, visited)
}

func (epm *EscalationPreventionManager) countRecentChainModifications(roleID string) int {
	cutoff := time.Now().Add(-time.Minute * 5) // 5 minute window
	count := 0
	
	for _, operation := range epm.operationLog {
		if operation.Type == OpTypeRoleParentSet && 
		   (operation.RoleID == roleID || operation.ParentRoleID == roleID) &&
		   operation.Timestamp.After(cutoff) {
			count++
		}
	}
	
	return count
}

func (epm *EscalationPreventionManager) countRecentRoleAssignments(subjectID string) int {
	cutoff := time.Now().Add(-time.Minute * 2) // 2 minute window
	count := 0
	
	for _, operation := range epm.operationLog {
		if operation.Type == OpTypeRoleAssignment && 
		   operation.SubjectID == subjectID &&
		   operation.Timestamp.After(cutoff) &&
		   operation.Success {
			count++
		}
	}
	
	return count
}

func (epm *EscalationPreventionManager) isHighPrivilegeRole(ctx context.Context, roleID string) bool {
	// Simple heuristic: roles containing "admin", "super", "root", etc. are high-privilege
	role, err := epm.rbacManager.GetRole(ctx, roleID)
	if err != nil {
		return false
	}
	
	highPrivKeywords := []string{"admin", "super", "root", "system", "manager", "owner"}
	roleName := role.Name
	roleID = role.Id
	
	for _, keyword := range highPrivKeywords {
		// Check if role name or ID contains the keyword (case-insensitive)
		if contains(strings.ToLower(roleName), strings.ToLower(keyword)) || 
		   contains(strings.ToLower(roleID), strings.ToLower(keyword)) {
			return true
		}
	}
	
	return false
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func (epm *EscalationPreventionManager) countRecentHighPrivilegeAssignments(subjectID string) int {
	cutoff := time.Now().Add(-time.Minute * 5) // 5 minute window
	count := 0
	
	for _, operation := range epm.operationLog {
		if operation.Type == OpTypeRoleAssignment && 
		   operation.SubjectID == subjectID &&
		   operation.Timestamp.After(cutoff) &&
		   operation.Success {
			// Check if the assigned role is high-privilege
			if epm.isHighPrivilegeRole(context.Background(), operation.RoleID) {
				count++
			}
		}
	}
	
	return count
}

func (epm *EscalationPreventionManager) getRecentSubjectTenants(subjectID string) []string {
	cutoff := time.Now().Add(-time.Minute * 10) // 10 minute window
	tenantSet := make(map[string]bool)
	
	for _, operation := range epm.operationLog {
		if operation.SubjectID == subjectID && 
		   operation.Timestamp.After(cutoff) &&
		   operation.TenantID != "" {
			tenantSet[operation.TenantID] = true
		}
	}
	
	tenants := make([]string, 0, len(tenantSet))
	for tenant := range tenantSet {
		tenants = append(tenants, tenant)
	}
	
	return tenants
}

func (epm *EscalationPreventionManager) getRoleChain(ctx context.Context, roleID string) []string {
	chain := make([]string, 0)
	visited := make(map[string]bool)
	current := roleID
	
	for current != "" && !visited[current] {
		chain = append(chain, current)
		visited[current] = true
		
		role, err := epm.rbacManager.GetRole(ctx, current)
		if err != nil {
			break
		}
		current = role.ParentRoleId
	}
	
	return chain
}

// Detection and alerting functions

func (epm *EscalationPreventionManager) detectEscalationPatterns(ctx context.Context, subjectID, roleID, parentRoleID string) {
	// Detect suspicious patterns in role hierarchy modifications
	if epm.detectSuspiciousHierarchyPattern(roleID, parentRoleID) {
		epm.generateAlert(AlertTypeSuspiciousPattern, SeverityMedium, subjectID, roleID, "",
			fmt.Sprintf("Suspicious hierarchy pattern detected: %s -> %s", roleID, parentRoleID),
			map[string]interface{}{
				"role_chain": epm.getRoleChain(ctx, roleID),
				"pattern_type": "complex_hierarchy",
			}, false)
	}
}

func (epm *EscalationPreventionManager) detectPrivilegeEscalation(ctx context.Context, subjectID, roleID, tenantID string) {
	// Simple escalation detection: check if user's privilege level increased significantly
	previousRoles := epm.getPreviousSubjectRoles(subjectID, tenantID)
	currentRoles, err := epm.rbacManager.GetSubjectRoles(ctx, subjectID, tenantID)
	
	if err != nil {
		return // Cannot perform detection
	}
	
	if len(currentRoles) > len(previousRoles)+1 {
		epm.generateAlert(AlertTypeRapidEscalation, SeverityMedium, subjectID, roleID, tenantID,
			fmt.Sprintf("Privilege escalation detected: subject %s role count increased from %d to %d", 
				subjectID, len(previousRoles), len(currentRoles)),
			map[string]interface{}{
				"previous_role_count": len(previousRoles),
				"current_role_count": len(currentRoles),
				"new_role": roleID,
			}, false)
	}
}

func (epm *EscalationPreventionManager) detectSuspiciousHierarchyPattern(roleID, parentRoleID string) bool {
	// Detect patterns like rapid chain creation or complex hierarchies
	recentModifications := epm.countRecentChainModifications(roleID) + epm.countRecentChainModifications(parentRoleID)
	return recentModifications > 3
}

func (epm *EscalationPreventionManager) getPreviousSubjectRoles(subjectID, tenantID string) []*common.Role {
	// Simple implementation: look for the most recent successful role query in operations
	// In production, this would use a proper state tracking system
	roles := make([]*common.Role, 0)
	
	for i := len(epm.operationLog) - 1; i >= 0; i-- {
		operation := epm.operationLog[i]
		if operation.SubjectID == subjectID && 
		   operation.TenantID == tenantID &&
		   operation.Type == OpTypeRoleAssignment &&
		   operation.Success {
			// This is a simplified implementation
			// In production, would track actual role states
			break
		}
	}
	
	return roles
}

// Utility functions

func (epm *EscalationPreventionManager) recordOperation(operation OperationRecord) {
	epm.operationLog = append(epm.operationLog, operation)
	
	// Limit log size to prevent memory growth
	if len(epm.operationLog) > 10000 {
		epm.operationLog = epm.operationLog[1000:] // Keep most recent 9000 operations
	}
}

func (epm *EscalationPreventionManager) generateAlert(alertType EscalationAlertType, severity AlertSeverity, subjectID, roleID, tenantID, description string, evidence map[string]interface{}, blocked bool) {
	epm.alertMutex.Lock()
	defer epm.alertMutex.Unlock()
	
	alert := EscalationAlert{
		ID:          fmt.Sprintf("alert-%d", time.Now().UnixNano()),
		Type:        alertType,
		Severity:    severity,
		SubjectID:   subjectID,
		RoleID:      roleID,
		TenantID:    tenantID,
		Description: description,
		DetectedAt:  time.Now(),
		Evidence:    evidence,
		Blocked:     blocked,
	}
	
	epm.escalationAlerts = append(epm.escalationAlerts, alert)
	
	// Limit alert storage
	if len(epm.escalationAlerts) > 1000 {
		epm.escalationAlerts = epm.escalationAlerts[100:] // Keep most recent 900 alerts
	}
}

// Public API functions

// GetEscalationAlerts returns recent escalation alerts
func (epm *EscalationPreventionManager) GetEscalationAlerts() []EscalationAlert {
	epm.alertMutex.RLock()
	defer epm.alertMutex.RUnlock()
	
	// Return copy to prevent modification
	alerts := make([]EscalationAlert, len(epm.escalationAlerts))
	copy(alerts, epm.escalationAlerts)
	
	return alerts
}

// GetOperationLog returns recent operations
func (epm *EscalationPreventionManager) GetOperationLog() []OperationRecord {
	epm.operationMutex.RLock()
	defer epm.operationMutex.RUnlock()
	
	// Return copy to prevent modification
	operations := make([]OperationRecord, len(epm.operationLog))
	copy(operations, epm.operationLog)
	
	return operations
}

// GetMetrics returns comprehensive metrics about escalation prevention
func (epm *EscalationPreventionManager) GetMetrics() map[string]interface{} {
	epm.alertMutex.RLock()
	epm.operationMutex.RLock()
	defer epm.alertMutex.RUnlock()
	defer epm.operationMutex.RUnlock()
	
	// Calculate metrics
	totalOperations := len(epm.operationLog)
	successfulOperations := 0
	blockedOperations := 0
	alertsBySeverity := map[AlertSeverity]int{
		SeverityLow:      0,
		SeverityMedium:   0,
		SeverityHigh:     0,
		SeverityCritical: 0,
	}
	
	for _, operation := range epm.operationLog {
		if operation.Success {
			successfulOperations++
		} else {
			blockedOperations++
		}
	}
	
	for _, alert := range epm.escalationAlerts {
		alertsBySeverity[alert.Severity]++
	}
	
	return map[string]interface{}{
		"total_operations":      totalOperations,
		"successful_operations": successfulOperations,
		"blocked_operations":    blockedOperations,
		"total_alerts":          len(epm.escalationAlerts),
		"alerts_by_severity":    alertsBySeverity,
		"block_rate":           float64(blockedOperations) / float64(totalOperations) * 100,
	}
}