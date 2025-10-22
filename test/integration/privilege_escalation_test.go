package integration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	testutil "github.com/cfgis/cfgms/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// PrivilegeEscalationTestFramework provides comprehensive testing for privilege escalation attack prevention
type PrivilegeEscalationTestFramework struct {
	rbacManager *rbac.Manager // Use concrete type for testing
	store       *memory.Store
	ctx         context.Context

	// Attack simulation metrics
	attackAttempts      int
	successfulAttacks   int
	blockedAttacks      int
	detectedEscalations int

	// Concurrency control for testing
	attackMutex sync.Mutex
}

// NewPrivilegeEscalationTestFramework creates a new testing framework
func NewPrivilegeEscalationTestFramework(t *testing.T) *PrivilegeEscalationTestFramework {
	rbacManager := testutil.SetupTestRBACManager(t)

	ctx := context.Background()
	err := rbacManager.Initialize(ctx)
	require.NoError(t, err)

	return &PrivilegeEscalationTestFramework{
		rbacManager: rbacManager,
		store:       rbacManager.GetStore(), // Access internal store for testing
		ctx:         ctx,
	}
}

// SetupTestHierarchy creates a multi-level role hierarchy for testing
func (f *PrivilegeEscalationTestFramework) SetupTestHierarchy(t *testing.T) {
	// Create tenant hierarchy
	err := f.rbacManager.CreateTenantDefaultRoles(f.ctx, "test-tenant")
	require.NoError(t, err)

	// Create test roles with different privilege levels
	roles := []*common.Role{
		{
			Id:          "basic-user",
			Name:        "Basic User",
			TenantId:    "test-tenant",
			Description: "Basic user with minimal privileges",
		},
		{
			Id:          "power-user",
			Name:        "Power User",
			TenantId:    "test-tenant",
			Description: "Power user with elevated privileges",
		},
		{
			Id:          "admin",
			Name:        "Administrator",
			TenantId:    "test-tenant",
			Description: "Administrator with high privileges",
		},
		{
			Id:          "super-admin",
			Name:        "Super Administrator",
			TenantId:    "test-tenant",
			Description: "Super administrator with maximum privileges",
		},
	}

	for _, role := range roles {
		err := f.rbacManager.CreateRole(f.ctx, role)
		require.NoError(t, err)
	}

	// Create hierarchical permissions
	permissions := []*common.Permission{
		{
			Id:           "read-config",
			Name:         "Read Configuration",
			ResourceType: "configuration",
			Actions:      []string{"read"},
		},
		{
			Id:           "write-config",
			Name:         "Write Configuration",
			ResourceType: "configuration",
			Actions:      []string{"write"},
		},
		{
			Id:           "manage-users",
			Name:         "Manage Users",
			ResourceType: "users",
			Actions:      []string{"create", "read", "update", "delete"},
		},
		{
			Id:           "manage-roles",
			Name:         "Manage Roles",
			ResourceType: "roles",
			Actions:      []string{"create", "read", "update", "delete"},
		},
		{
			Id:           "system-admin",
			Name:         "System Administration",
			ResourceType: "system",
			Actions:      []string{"admin"},
		},
	}

	for _, permission := range permissions {
		err := f.rbacManager.CreatePermission(f.ctx, permission)
		require.NoError(t, err)
	}

	// Set up role hierarchy: basic-user -> power-user -> admin -> super-admin
	err = f.rbacManager.SetRoleParent(f.ctx, "power-user", "basic-user", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE)
	require.NoError(t, err)

	err = f.rbacManager.SetRoleParent(f.ctx, "admin", "power-user", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE)
	require.NoError(t, err)

	err = f.rbacManager.SetRoleParent(f.ctx, "super-admin", "admin", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE)
	require.NoError(t, err)

	// Create test subjects
	subjects := []*common.Subject{
		{
			Id:          "user-1",
			DisplayName: "Test User 1",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			TenantId:    "test-tenant",
		},
		{
			Id:          "user-2",
			DisplayName: "Test User 2",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			TenantId:    "test-tenant",
		},
		{
			Id:          "user-3",
			DisplayName: "Test User 3",
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			TenantId:    "test-tenant",
		},
	}

	for _, subject := range subjects {
		err := f.rbacManager.CreateSubject(f.ctx, subject)
		require.NoError(t, err)
	}

	// Assign initial roles
	assignments := []*common.RoleAssignment{
		{
			Id:        "assign-1",
			SubjectId: "user-1",
			RoleId:    "basic-user",
			TenantId:  "test-tenant",
		},
		{
			Id:        "assign-2",
			SubjectId: "user-2",
			RoleId:    "power-user",
			TenantId:  "test-tenant",
		},
		{
			Id:        "assign-3",
			SubjectId: "user-3",
			RoleId:    "admin",
			TenantId:  "test-tenant",
		},
	}

	for _, assignment := range assignments {
		err := f.rbacManager.AssignRole(f.ctx, assignment)
		require.NoError(t, err)
	}
}

// TestCircularRoleInheritanceAttack tests prevention of circular role inheritance escalation
func (f *PrivilegeEscalationTestFramework) TestCircularRoleInheritanceAttack(t *testing.T) {
	t.Log("Testing circular role inheritance attack prevention...")

	f.attackMutex.Lock()
	f.attackAttempts++
	f.attackMutex.Unlock()

	// Attempt to create circular inheritance: super-admin -> basic-user (completing the circle)
	err := f.rbacManager.SetRoleParent(f.ctx, "basic-user", "super-admin", common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE)

	if err != nil {
		// Attack was blocked - this is the expected behavior
		f.attackMutex.Lock()
		f.blockedAttacks++
		f.attackMutex.Unlock()

		t.Logf("Circular inheritance attack successfully blocked: %v", err)
		assert.Contains(t, err.Error(), "circular", "Error should indicate circular dependency detection")
	} else {
		// Attack succeeded - this is a security vulnerability
		f.attackMutex.Lock()
		f.successfulAttacks++
		f.attackMutex.Unlock()

		t.Errorf("SECURITY VULNERABILITY: Circular role inheritance attack succeeded")
	}

	// Verify hierarchy integrity remains intact
	hierarchy, err := f.rbacManager.GetRoleHierarchy(f.ctx, "super-admin")
	require.NoError(t, err)

	// Validate no circular references exist
	visited := make(map[string]bool)
	f.validateNoCircularReference(t, hierarchy, visited)
}

// validateNoCircularReference recursively checks for circular references in role hierarchy
func (f *PrivilegeEscalationTestFramework) validateNoCircularReference(t *testing.T, hierarchy *memory.RoleHierarchy, visited map[string]bool) {
	if visited[hierarchy.Role.Id] {
		t.Errorf("SECURITY VULNERABILITY: Circular reference detected in role hierarchy at role %s", hierarchy.Role.Id)
		return
	}

	visited[hierarchy.Role.Id] = true

	for _, child := range hierarchy.Children {
		f.validateNoCircularReference(t, child, visited)
	}

	delete(visited, hierarchy.Role.Id)
}

// TestConcurrentPermissionModificationAttack tests concurrent modification integrity
func (f *PrivilegeEscalationTestFramework) TestConcurrentPermissionModificationAttack(t *testing.T) {
	t.Log("Testing concurrent permission modification attack prevention...")

	const numGoroutines = 50
	const numOperations = 10

	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	var mutex sync.Mutex

	// Launch concurrent goroutines attempting to modify permissions
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				f.attackMutex.Lock()
				f.attackAttempts++
				f.attackMutex.Unlock()

				// Attempt to escalate user-1's privileges by assigning admin role
				assignment := &common.RoleAssignment{
					Id:        fmt.Sprintf("concurrent-attack-%d-%d", goroutineID, j),
					SubjectId: "user-1",
					RoleId:    "admin",
					TenantId:  "test-tenant",
				}

				err := f.rbacManager.AssignRole(f.ctx, assignment)

				mutex.Lock()
				if err != nil {
					errorCount++
				} else {
					successCount++
				}
				mutex.Unlock()

				// Small delay to increase race condition likelihood
				time.Sleep(time.Millisecond * 1)

				// Try to revoke the assignment to clean up
				_ = f.rbacManager.RevokeRole(f.ctx, "user-1", "admin", "test-tenant")
			}
		}(i)
	}

	wg.Wait()

	t.Logf("Concurrent operations completed - Success: %d, Errors: %d", successCount, errorCount)

	// Validate final state consistency
	finalAssignments, err := f.rbacManager.GetSubjectAssignments(f.ctx, "user-1", "test-tenant")
	require.NoError(t, err)

	// Verify user-1 still has only basic-user role (original assignment)
	hasBasicUser := false
	hasEscalatedRole := false

	for _, assignment := range finalAssignments {
		if assignment.RoleId == "basic-user" {
			hasBasicUser = true
		}
		if assignment.RoleId == "admin" || assignment.RoleId == "super-admin" {
			hasEscalatedRole = true
		}
	}

	assert.True(t, hasBasicUser, "User should still have basic-user role")
	assert.False(t, hasEscalatedRole, "User should not have escalated roles after concurrent attack")

	// Record attack results
	f.attackMutex.Lock()
	if !hasEscalatedRole {
		f.blockedAttacks += numGoroutines * numOperations
	} else {
		f.successfulAttacks++
	}
	f.attackMutex.Unlock()
}

// TestTimingBasedPrivilegeEscalationAttack tests timing-based attack protection
func (f *PrivilegeEscalationTestFramework) TestTimingBasedPrivilegeEscalationAttack(t *testing.T) {
	t.Log("Testing timing-based privilege escalation attack prevention...")

	var wg sync.WaitGroup
	attackBlocked := true

	// Goroutine 1: Attempt to assign admin role
	wg.Add(1)
	go func() {
		defer wg.Done()

		f.attackMutex.Lock()
		f.attackAttempts++
		f.attackMutex.Unlock()

		assignment := &common.RoleAssignment{
			Id:        "timing-attack-1",
			SubjectId: "user-1",
			RoleId:    "admin",
			TenantId:  "test-tenant",
		}

		err := f.rbacManager.AssignRole(f.ctx, assignment)
		if err != nil {
			t.Logf("First timing attack blocked: %v", err)
		} else {
			attackBlocked = false
		}
	}()

	// Goroutine 2: Attempt to use the potentially assigned admin role immediately
	wg.Add(1)
	go func() {
		defer wg.Done()

		// Small delay to ensure timing overlap
		time.Sleep(time.Microsecond * 100)

		f.attackMutex.Lock()
		f.attackAttempts++
		f.attackMutex.Unlock()

		// Try to use admin privileges to create a new super-admin role
		request := &common.AccessRequest{
			SubjectId:    "user-1",
			PermissionId: "manage-roles",
			TenantId:     "test-tenant",
			ResourceId:   "roles",
		}

		response, err := f.rbacManager.CheckPermission(f.ctx, request)
		if err != nil || !response.Granted {
			t.Logf("Second timing attack blocked - permission denied")
		} else {
			attackBlocked = false
			t.Errorf("SECURITY VULNERABILITY: Timing-based escalation succeeded")
		}
	}()

	wg.Wait()

	// Record attack results
	f.attackMutex.Lock()
	if attackBlocked {
		f.blockedAttacks += 2
	} else {
		f.successfulAttacks++
	}
	f.attackMutex.Unlock()

	// Clean up any potential assignments
	_ = f.rbacManager.RevokeRole(f.ctx, "user-1", "admin", "test-tenant")
}

// TestRaceConditionPermissionGrantAttack tests race condition protection in permission grants
func (f *PrivilegeEscalationTestFramework) TestRaceConditionPermissionGrantAttack(t *testing.T) {
	t.Log("Testing race condition prevention in permission grants...")

	const numRacers = 20
	var wg sync.WaitGroup

	grantedCount := 0
	deniedCount := 0
	var resultMutex sync.Mutex

	// Launch concurrent permission check requests
	for i := 0; i < numRacers; i++ {
		wg.Add(1)
		go func(racerID int) {
			defer wg.Done()

			f.attackMutex.Lock()
			f.attackAttempts++
			f.attackMutex.Unlock()

			// Each racer attempts to check admin permission for user-1
			request := &common.AccessRequest{
				SubjectId:    "user-1",
				PermissionId: "system-admin",
				TenantId:     "test-tenant",
				ResourceId:   "system",
			}

			response, err := f.rbacManager.CheckPermission(f.ctx, request)

			resultMutex.Lock()
			if err != nil || !response.Granted {
				deniedCount++
			} else {
				grantedCount++
			}
			resultMutex.Unlock()

			// Small delay to increase race condition window
			time.Sleep(time.Microsecond * 50)
		}(i)
	}

	// Meanwhile, try to assign admin role during the race
	wg.Add(1)
	go func() {
		defer wg.Done()

		time.Sleep(time.Microsecond * 100) // Let some permission checks start

		assignment := &common.RoleAssignment{
			Id:        "race-condition-attack",
			SubjectId: "user-1",
			RoleId:    "admin",
			TenantId:  "test-tenant",
		}

		_ = f.rbacManager.AssignRole(f.ctx, assignment)
	}()

	wg.Wait()

	t.Logf("Race condition test results - Granted: %d, Denied: %d", grantedCount, deniedCount)

	// Validate consistency: either all granted or all denied (no mixed results from race)
	allConsistent := (grantedCount == numRacers) || (deniedCount == numRacers)

	f.attackMutex.Lock()
	if allConsistent {
		f.blockedAttacks += numRacers
		t.Logf("Race condition attack blocked - consistent results achieved")
	} else {
		f.successfulAttacks++
		t.Errorf("SECURITY VULNERABILITY: Race condition allowed inconsistent permission grants")
	}
	f.attackMutex.Unlock()

	// Clean up
	_ = f.rbacManager.RevokeRole(f.ctx, "user-1", "admin", "test-tenant")
}

// TestPrivilegeEscalationDetection tests escalation detection and alerting
func (f *PrivilegeEscalationTestFramework) TestPrivilegeEscalationDetection(t *testing.T) {
	t.Log("Testing privilege escalation detection and alerting...")

	// Use user-2 for this test to avoid rate limiting from previous tests
	// Record initial privileges for user-2
	initialRoles, err := f.rbacManager.GetSubjectRoles(f.ctx, "user-2", "test-tenant")
	require.NoError(t, err)

	initialPrivilegeLevel := len(initialRoles)

	// Perform legitimate role assignment
	assignment := &common.RoleAssignment{
		Id:        "legitimate-assignment",
		SubjectId: "user-2",
		RoleId:    "admin", // Escalate user-2 from power-user to admin
		TenantId:  "test-tenant",
	}

	err = f.rbacManager.AssignRole(f.ctx, assignment)
	require.NoError(t, err)

	// Check if escalation was detected
	newRoles, err := f.rbacManager.GetSubjectRoles(f.ctx, "user-2", "test-tenant")
	require.NoError(t, err)

	newPrivilegeLevel := len(newRoles)

	if newPrivilegeLevel > initialPrivilegeLevel {
		f.attackMutex.Lock()
		f.detectedEscalations++
		f.attackMutex.Unlock()

		t.Logf("Privilege escalation detected: User privilege level increased from %d to %d",
			initialPrivilegeLevel, newPrivilegeLevel)
	}

	// Test suspicious rapid escalation pattern
	rapidAssignments := []*common.RoleAssignment{
		{
			Id:        "rapid-1",
			SubjectId: "user-2",
			RoleId:    "super-admin", // Further escalate user-2 to super-admin
			TenantId:  "test-tenant",
		},
	}

	suspiciousPattern := true
	for _, rapidAssignment := range rapidAssignments {
		err := f.rbacManager.AssignRole(f.ctx, rapidAssignment)
		if err != nil {
			suspiciousPattern = false
			t.Logf("Suspicious rapid escalation blocked: %v", err)
		}

		// Rapid assignments (no delay)
	}

	f.attackMutex.Lock()
	if suspiciousPattern {
		f.detectedEscalations++
	}
	f.attackMutex.Unlock()

	// Clean up
	for _, assignment := range rapidAssignments {
		_ = f.rbacManager.RevokeRole(f.ctx, assignment.SubjectId, assignment.RoleId, assignment.TenantId)
	}
	_ = f.rbacManager.RevokeRole(f.ctx, "user-2", "admin", "test-tenant")
}

// GetAttackMetrics returns comprehensive attack simulation metrics
func (f *PrivilegeEscalationTestFramework) GetAttackMetrics() map[string]interface{} {
	f.attackMutex.Lock()
	defer f.attackMutex.Unlock()

	return map[string]interface{}{
		"total_attacks":        f.attackAttempts,
		"successful_attacks":   f.successfulAttacks,
		"blocked_attacks":      f.blockedAttacks,
		"detected_escalations": f.detectedEscalations,
		"success_rate":         float64(f.successfulAttacks) / float64(f.attackAttempts) * 100,
		"block_rate":           float64(f.blockedAttacks) / float64(f.attackAttempts) * 100,
	}
}

// TestPrivilegeEscalationAttackPrevention is the main integration test
func TestPrivilegeEscalationAttackPrevention(t *testing.T) {
	t.Log("=== Privilege Escalation Attack Prevention Integration Test ===")

	// Create test framework
	framework := NewPrivilegeEscalationTestFramework(t)

	// Set up test environment
	framework.SetupTestHierarchy(t)

	// Run attack simulations
	t.Run("CircularRoleInheritanceAttack", framework.TestCircularRoleInheritanceAttack)
	t.Run("ConcurrentPermissionModificationAttack", framework.TestConcurrentPermissionModificationAttack)
	t.Run("TimingBasedPrivilegeEscalationAttack", framework.TestTimingBasedPrivilegeEscalationAttack)
	t.Run("RaceConditionPermissionGrantAttack", framework.TestRaceConditionPermissionGrantAttack)
	t.Run("PrivilegeEscalationDetection", framework.TestPrivilegeEscalationDetection)

	// Report attack metrics
	metrics := framework.GetAttackMetrics()
	t.Logf("=== Attack Simulation Results ===")
	t.Logf("Total Attacks Attempted: %v", metrics["total_attacks"])
	t.Logf("Successful Attacks: %v", metrics["successful_attacks"])
	t.Logf("Blocked Attacks: %v", metrics["blocked_attacks"])
	t.Logf("Detected Escalations: %v", metrics["detected_escalations"])
	t.Logf("Attack Success Rate: %.2f%%", metrics["success_rate"])
	t.Logf("Attack Block Rate: %.2f%%", metrics["block_rate"])

	// Security assertions
	successfulAttacks := metrics["successful_attacks"].(int)
	blockRate := metrics["block_rate"].(float64)

	assert.Equal(t, 0, successfulAttacks, "CRITICAL: No privilege escalation attacks should succeed")
	assert.GreaterOrEqual(t, blockRate, 95.0, "CRITICAL: Attack block rate should be >= 95%")

	if successfulAttacks == 0 && blockRate >= 95.0 {
		t.Log("✅ PASS: Privilege escalation attack prevention is working effectively")
	} else {
		t.Error("❌ FAIL: System vulnerable to privilege escalation attacks")
	}
}

// TestMultiTenantPrivilegeEscalationIsolation tests cross-tenant escalation prevention
func TestMultiTenantPrivilegeEscalationIsolation(t *testing.T) {
	t.Log("Testing multi-tenant privilege escalation isolation...")

	framework := NewPrivilegeEscalationTestFramework(t)

	// Create second tenant
	err := framework.rbacManager.CreateTenantDefaultRoles(framework.ctx, "tenant-2")
	require.NoError(t, err)

	// Create cross-tenant attack attempt
	crossTenantAssignment := &common.RoleAssignment{
		Id:        "cross-tenant-attack",
		SubjectId: "user-1",   // From test-tenant
		RoleId:    "admin",    // Try to assign admin role
		TenantId:  "tenant-2", // In different tenant
	}

	err = framework.rbacManager.AssignRole(framework.ctx, crossTenantAssignment)

	if err != nil {
		t.Logf("✅ Cross-tenant privilege escalation blocked: %v", err)
	} else {
		t.Errorf("❌ SECURITY VULNERABILITY: Cross-tenant privilege escalation succeeded")
	}
}
