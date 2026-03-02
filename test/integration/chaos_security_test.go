// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package integration

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/failsafe"
	"github.com/cfgis/cfgms/features/rbac/jit"
	"github.com/cfgis/cfgms/features/rbac/risk"
	pkgtestutil "github.com/cfgis/cfgms/pkg/testing"
	"github.com/cfgis/cfgms/test/integration/testutil"
)

// ChaosSecurityTestFramework provides chaos engineering tests for security components
type ChaosSecurityTestFramework struct {
	t           *testing.T
	env         *testutil.TestEnv
	rbacManager rbac.RBACManager
	riskEngine  *risk.RiskAssessmentEngine
	jitManager  *jit.JITAccessManager

	// Failsafe wrappers
	failsafeRBAC    *failsafe.FailsafeRBACManager
	failsafeRisk    *failsafe.FailsafeRiskEngine
	failsafeJIT     *failsafe.FailsafeJITAccessManager
	failsafeNetwork *failsafe.NetworkPartitionTolerantManager

	// Chaos control
	chaosRunning bool
	chaosStop    chan bool
	chaosMutex   sync.RWMutex
}

// ChaosScenario defines a chaos engineering scenario
type ChaosScenario struct {
	Name             string
	Description      string
	Duration         time.Duration
	FailureRate      float64  // 0.0 to 1.0
	ComponentTargets []string // "rbac", "risk", "jit", "network"
	FailureTypes     []string // "timeout", "error", "slow", "partition"
	RecoveryTime     time.Duration
	ValidationFunc   func(framework *ChaosSecurityTestFramework) error
}

// ChaosMetrics tracks chaos experiment results
type ChaosMetrics struct {
	TotalOperations      int64
	SuccessfulOperations int64
	FailedOperations     int64
	FailsafeActivations  int64
	SecurityViolations   int64
	AverageResponseTime  time.Duration
	MaxResponseTime      time.Duration
	mutex                sync.RWMutex
}

// NewChaosSecurityTestFramework creates a new chaos engineering test framework
func NewChaosSecurityTestFramework(t *testing.T) *ChaosSecurityTestFramework {
	// Chaos tests need longer timeout - allow 2 minutes for all scenarios
	env := testutil.NewTestEnvWithTimeout(t, 2*time.Minute)

	// Create standard components
	rbacManager := pkgtestutil.SetupTestRBACManager(t)
	riskEngine := risk.NewRiskAssessmentEngine()
	jitManager := jit.NewJITAccessManager(rbacManager, nil)

	// Create failsafe wrappers
	failsafeRBAC := failsafe.NewFailsafeRBACManager(rbacManager)
	failsafeRisk := failsafe.NewFailsafeRiskEngine(riskEngine)
	failsafeJIT := failsafe.NewFailsafeJITAccessManager(jitManager)
	failsafeNetwork := failsafe.NewNetworkPartitionTolerantManager(rbacManager)

	return &ChaosSecurityTestFramework{
		t:               t,
		env:             env,
		rbacManager:     rbacManager,
		riskEngine:      riskEngine,
		jitManager:      jitManager,
		failsafeRBAC:    failsafeRBAC,
		failsafeRisk:    failsafeRisk,
		failsafeJIT:     failsafeJIT,
		failsafeNetwork: failsafeNetwork,
		chaosRunning:    false,
		chaosStop:       make(chan bool, 1),
		chaosMutex:      sync.RWMutex{},
	}
}

// Setup initializes the chaos test framework
func (framework *ChaosSecurityTestFramework) Setup() error {
	ctx := framework.env.GetContext()

	// Initialize RBAC system
	err := framework.rbacManager.Initialize(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize RBAC manager: %w", err)
	}

	// Create system roles first
	systemRoles := []*common.Role{
		{
			Id:          "system.admin",
			Name:        "System Administrator",
			TenantId:    "chaos-tenant",
			Description: "Full administrative access to system",
		},
	}

	for _, role := range systemRoles {
		err = framework.rbacManager.CreateRole(ctx, role)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			return fmt.Errorf("failed to create system role %s: %w", role.Id, err)
		}
	}

	// Create test data
	err = framework.rbacManager.CreateTenantDefaultRoles(ctx, "chaos-tenant")
	if err != nil {
		return fmt.Errorf("failed to create tenant roles: %w", err)
	}

	// Create multiple test subjects for chaos testing
	subjects := []string{"chaos-user-1", "chaos-user-2", "chaos-admin", "chaos-service"}
	for _, subjectID := range subjects {
		subject := &common.Subject{
			Id:          subjectID,
			Type:        common.SubjectType_SUBJECT_TYPE_USER,
			DisplayName: fmt.Sprintf("Chaos Test User %s", subjectID),
			TenantId:    "chaos-tenant",
			IsActive:    true,
		}
		err = framework.rbacManager.CreateSubject(ctx, subject)
		if err != nil {
			return fmt.Errorf("failed to create subject %s: %w", subjectID, err)
		}

		// Assign roles
		roleID := "chaos-tenant.tenant.viewer"
		if subjectID == "chaos-admin" {
			roleID = "system.admin"
		}

		assignment := &common.RoleAssignment{
			SubjectId: subjectID,
			RoleId:    roleID,
			TenantId:  "chaos-tenant",
		}
		err = framework.rbacManager.AssignRole(ctx, assignment)
		if err != nil {
			return fmt.Errorf("failed to assign role to %s: %w", subjectID, err)
		}
	}

	return nil
}

// Cleanup cleans up the chaos test framework
func (framework *ChaosSecurityTestFramework) Cleanup() {
	framework.StopChaos()
	framework.env.Cleanup()
}

// StartChaos begins chaos engineering against the security components
func (framework *ChaosSecurityTestFramework) StartChaos(scenario ChaosScenario) {
	framework.chaosMutex.Lock()
	defer framework.chaosMutex.Unlock()

	if framework.chaosRunning {
		// Stop chaos without acquiring mutex again (already held)
		framework.chaosStop <- true
		framework.chaosRunning = false
	}

	framework.chaosRunning = true
	framework.chaosStop = make(chan bool, 1)

	// Start chaos goroutine
	go framework.runChaosScenario(scenario)
}

// StopChaos stops the chaos engineering
func (framework *ChaosSecurityTestFramework) StopChaos() {
	framework.chaosMutex.Lock()
	defer framework.chaosMutex.Unlock()

	if framework.chaosRunning {
		framework.chaosStop <- true
		framework.chaosRunning = false
	}
}

// runChaosScenario executes a chaos engineering scenario
func (framework *ChaosSecurityTestFramework) runChaosScenario(scenario ChaosScenario) {
	ticker := time.NewTicker(100 * time.Millisecond) // Inject failures every 100ms
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-framework.chaosStop:
			return
		case <-ticker.C:
			if time.Since(startTime) > scenario.Duration {
				return
			}

			// Randomly inject failures based on failure rate
			if rand.Float64() < scenario.FailureRate {
				framework.injectFailure(scenario)
			}
		}
	}
}

// injectFailure injects a specific type of failure into target components
func (framework *ChaosSecurityTestFramework) injectFailure(scenario ChaosScenario) {
	// Randomly select a component and failure type
	if len(scenario.ComponentTargets) == 0 || len(scenario.FailureTypes) == 0 {
		return
	}

	component := scenario.ComponentTargets[rand.Intn(len(scenario.ComponentTargets))]
	failureType := scenario.FailureTypes[rand.Intn(len(scenario.FailureTypes))]

	switch component {
	case "rbac":
		framework.injectRBACFailure(failureType)
	case "risk":
		framework.injectRiskFailure(failureType)
	case "jit":
		framework.injectJITFailure(failureType)
	case "network":
		framework.injectNetworkFailure(failureType)
	}
}

// injectRBACFailure injects failures into the RBAC component
func (framework *ChaosSecurityTestFramework) injectRBACFailure(failureType string) {
	switch failureType {
	case "timeout":
		// Cause timeout by using cancelled context
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			request := &common.AccessRequest{
				SubjectId:    "chaos-user-1",
				PermissionId: "chaos.test",
				TenantId:     "chaos-tenant",
			}

			_, _ = framework.failsafeRBAC.CheckPermission(ctx, request)
		}()
	case "error":
		// Cause error by invalid operations
		go func() {
			_, _ = framework.failsafeRBAC.GetRole(context.Background(), "non-existent-role")
		}()
	case "slow":
		// Simulate slow response by blocking briefly
		go func() {
			time.Sleep(50 * time.Millisecond)
			_, _ = framework.failsafeRBAC.ListRoles(context.Background(), "chaos-tenant")
		}()
	}
}

// injectRiskFailure injects failures into the risk assessment component
func (framework *ChaosSecurityTestFramework) injectRiskFailure(failureType string) {
	switch failureType {
	case "timeout":
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			request := &risk.RiskAssessmentRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId: "chaos-user-1",
					TenantId:  "chaos-tenant",
				},
				UserContext:        &risk.UserContext{UserID: "chaos-user-1"},
				ResourceContext:    &risk.ResourceContext{ResourceID: "chaos-resource"},
				RequiredConfidence: 0.7,
			}

			_, _ = framework.failsafeRisk.EvaluateRisk(ctx, request)
		}()
	case "error":
		go func() {
			// Invalid request to cause error
			request := &risk.RiskAssessmentRequest{
				AccessRequest: nil, // This should cause error
			}
			_, _ = framework.failsafeRisk.EvaluateRisk(context.Background(), request)
		}()
	}
}

// injectJITFailure injects failures into the JIT access component
func (framework *ChaosSecurityTestFramework) injectJITFailure(failureType string) {
	switch failureType {
	case "timeout":
		go func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			spec := &jit.JITAccessRequestSpec{
				RequesterID:   "chaos-user-1",
				TargetID:      "chaos-user-1",
				TenantID:      "chaos-tenant",
				Permissions:   []string{"chaos.test"},
				Duration:      15 * time.Minute,
				Justification: "Chaos test",
			}

			_, _ = framework.failsafeJIT.RequestAccess(ctx, spec)
		}()
	}
}

// injectNetworkFailure injects network-related failures
func (framework *ChaosSecurityTestFramework) injectNetworkFailure(failureType string) {
	switch failureType {
	case "partition":
		// Actually partition the network for 5 seconds with auto-heal
		if framework.failsafeNetwork != nil {
			framework.failsafeNetwork.ForcePartition(5 * time.Second)
		}
	}
}

// runWorkload executes a continuous security workload during chaos
func (framework *ChaosSecurityTestFramework) runWorkload(ctx context.Context, duration time.Duration, metrics *ChaosMetrics) {
	ticker := time.NewTicker(50 * time.Millisecond) // High frequency operations
	defer ticker.Stop()

	startTime := time.Now()
	subjects := []string{"chaos-user-1", "chaos-user-2", "chaos-admin"}
	permissions := []string{"config.read", "config.write", "admin.read"}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if time.Since(startTime) > duration {
				return
			}

			// Run parallel security operations
			var wg sync.WaitGroup

			// RBAC operations
			wg.Add(1)
			go func() {
				defer wg.Done()
				framework.runRBACWorkload(ctx, subjects, permissions, metrics)
			}()

			// Risk assessment operations
			wg.Add(1)
			go func() {
				defer wg.Done()
				framework.runRiskWorkload(ctx, subjects, metrics)
			}()

			// JIT access operations
			wg.Add(1)
			go func() {
				defer wg.Done()
				framework.runJITWorkload(ctx, subjects, metrics)
			}()

			wg.Wait()
		}
	}
}

// runRBACWorkload executes RBAC operations during chaos
func (framework *ChaosSecurityTestFramework) runRBACWorkload(ctx context.Context, subjects, permissions []string, metrics *ChaosMetrics) {
	subject := subjects[rand.Intn(len(subjects))]
	permission := permissions[rand.Intn(len(permissions))]

	request := &common.AccessRequest{
		SubjectId:    subject,
		PermissionId: permission,
		TenantId:     "chaos-tenant",
		ResourceId:   "chaos-resource",
	}

	start := time.Now()
	response, err := framework.failsafeRBAC.CheckPermission(ctx, request)
	duration := time.Since(start)

	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	metrics.TotalOperations++
	if duration > metrics.MaxResponseTime {
		metrics.MaxResponseTime = duration
	}

	if err != nil {
		metrics.FailedOperations++
		// Check if this is a failsafe activation (security preserved)
		if response != nil && !response.Granted {
			metrics.FailsafeActivations++
		} else {
			// This would be a security violation - access granted when it should be denied
			metrics.SecurityViolations++
		}
	} else {
		metrics.SuccessfulOperations++
	}
}

// runRiskWorkload executes risk assessment operations during chaos
func (framework *ChaosSecurityTestFramework) runRiskWorkload(ctx context.Context, subjects []string, metrics *ChaosMetrics) {
	subject := subjects[rand.Intn(len(subjects))]

	request := &risk.RiskAssessmentRequest{
		AccessRequest: &common.AccessRequest{
			SubjectId: subject,
			TenantId:  "chaos-tenant",
		},
		UserContext: &risk.UserContext{
			UserID: subject,
		},
		ResourceContext: &risk.ResourceContext{
			ResourceID: "chaos-resource",
		},
		RequiredConfidence: 0.5,
	}

	start := time.Now()
	result, err := framework.failsafeRisk.EvaluateRisk(ctx, request)
	duration := time.Since(start)

	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	metrics.TotalOperations++
	if duration > metrics.MaxResponseTime {
		metrics.MaxResponseTime = duration
	}

	if err != nil {
		metrics.FailedOperations++
		// Risk engine failures should result in conservative (high-risk) assessments
		if result != nil && (result.RiskLevel == risk.RiskLevelHigh || result.RiskLevel == risk.RiskLevelCritical) {
			metrics.FailsafeActivations++
		} else {
			metrics.SecurityViolations++
		}
	} else {
		metrics.SuccessfulOperations++
	}
}

// runJITWorkload executes JIT access operations during chaos
func (framework *ChaosSecurityTestFramework) runJITWorkload(ctx context.Context, subjects []string, metrics *ChaosMetrics) {
	subject := subjects[rand.Intn(len(subjects))]

	spec := &jit.JITAccessRequestSpec{
		RequesterID:   subject,
		TargetID:      subject,
		TenantID:      "chaos-tenant",
		Permissions:   []string{"config.write"},
		Duration:      10 * time.Minute,
		Justification: "Chaos workload test",
		AutoApprove:   true,
	}

	start := time.Now()
	request, err := framework.failsafeJIT.RequestAccess(ctx, spec)
	duration := time.Since(start)

	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	metrics.TotalOperations++
	if duration > metrics.MaxResponseTime {
		metrics.MaxResponseTime = duration
	}

	if err != nil {
		metrics.FailedOperations++
		// JIT failures should deny access (fail-secure)
		metrics.FailsafeActivations++
	} else {
		metrics.SuccessfulOperations++

		// If access was granted during chaos, track controlled access metrics
		if request.Status == jit.JITAccessRequestStatusApproved && request.GrantedAccess != nil {
			// This is acceptable - system granted controlled access
			// Track this as a successful controlled access grant
			metrics.SuccessfulOperations++ // Additional metric for controlled grants
		}
	}
}

// TestChaosEngineeringBasicFailures tests basic chaos scenarios
func TestChaosEngineeringBasicFailures(t *testing.T) {
	t.Skip("Skipping until Issue #291: Chaos framework needs proper network failure injection implementation")

	framework := NewChaosSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())

	scenarios := []ChaosScenario{
		{
			Name:             "Low Intensity RBAC Failures",
			Description:      "Inject low-frequency failures into RBAC component",
			Duration:         10 * time.Second,
			FailureRate:      0.1, // 10% failure rate
			ComponentTargets: []string{"rbac"},
			FailureTypes:     []string{"timeout", "error"},
			RecoveryTime:     2 * time.Second,
		},
		{
			Name:             "Medium Intensity Risk Engine Failures",
			Description:      "Inject medium-frequency failures into risk assessment",
			Duration:         15 * time.Second,
			FailureRate:      0.3, // 30% failure rate
			ComponentTargets: []string{"risk"},
			FailureTypes:     []string{"timeout", "error", "slow"},
			RecoveryTime:     3 * time.Second,
		},
		{
			Name:             "High Intensity Multi-Component Failures",
			Description:      "Inject high-frequency failures across all components",
			Duration:         20 * time.Second,
			FailureRate:      0.5, // 50% failure rate
			ComponentTargets: []string{"rbac", "risk", "jit", "network"},
			FailureTypes:     []string{"timeout", "error", "slow", "partition"},
			RecoveryTime:     5 * time.Second,
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.Name, func(t *testing.T) {
			metrics := &ChaosMetrics{
				mutex: sync.RWMutex{},
			}

			// Start chaos engineering
			framework.StartChaos(scenario)

			// Run workload during chaos
			ctx, cancel := context.WithTimeout(context.Background(), scenario.Duration)
			framework.runWorkload(ctx, scenario.Duration, metrics)
			cancel()

			// Stop chaos
			framework.StopChaos()

			// Allow recovery time
			time.Sleep(scenario.RecoveryTime)

			// Validate results
			metrics.mutex.RLock()
			totalOps := metrics.TotalOperations
			failsafeActivations := metrics.FailsafeActivations
			securityViolations := metrics.SecurityViolations
			successfulOps := metrics.SuccessfulOperations
			failedOps := metrics.FailedOperations
			maxResponseTime := metrics.MaxResponseTime
			metrics.mutex.RUnlock()

			t.Logf("Scenario: %s", scenario.Name)
			t.Logf("Total Operations: %d", totalOps)
			t.Logf("Successful: %d, Failed: %d", successfulOps, failedOps)
			t.Logf("Failsafe Activations: %d", failsafeActivations)
			t.Logf("Security Violations: %d", securityViolations)
			t.Logf("Max Response Time: %v", maxResponseTime)

			// Assert security properties
			assert.Greater(t, totalOps, int64(0), "Should have executed operations")
			assert.Equal(t, int64(0), securityViolations, "Should have no security violations - failsafe should prevent them")
			assert.Greater(t, failsafeActivations, int64(0), "Should have failsafe activations during chaos")

			// Response times should be reasonable even during chaos
			assert.Less(t, maxResponseTime, 10*time.Second, "Max response time should be reasonable")

			// System should maintain some level of availability
			if totalOps > 0 {
				availabilityRatio := float64(successfulOps) / float64(totalOps)
				t.Logf("Availability Ratio: %.2f", availabilityRatio)
				// Even under chaos, some operations should succeed
				// The exact threshold depends on chaos intensity
				switch scenario.FailureRate {
				case 0.1:
					assert.Greater(t, availabilityRatio, 0.6, "Should maintain >60% availability under low chaos")
				case 0.3:
					assert.Greater(t, availabilityRatio, 0.4, "Should maintain >40% availability under medium chaos")
				case 0.5:
					assert.Greater(t, availabilityRatio, 0.2, "Should maintain >20% availability under high chaos")
				}
			}
		})
	}
}

// TestChaosRecoveryBehavior tests system recovery behavior after chaos
func TestChaosRecoveryBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	framework := NewChaosSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())

	t.Run("Recovery After Intense Chaos", func(t *testing.T) {
		// Measure baseline performance
		baselineMetrics := &ChaosMetrics{mutex: sync.RWMutex{}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		framework.runWorkload(ctx, 5*time.Second, baselineMetrics)
		cancel()

		baselineMetrics.mutex.RLock()
		baselineSuccess := baselineMetrics.SuccessfulOperations
		baselineTotal := baselineMetrics.TotalOperations
		baselineAvailability := float64(baselineSuccess) / float64(baselineTotal)
		baselineMetrics.mutex.RUnlock()

		t.Logf("Baseline - Total: %d, Success: %d, Availability: %.2f",
			baselineTotal, baselineSuccess, baselineAvailability)

		// Run intense chaos
		chaosScenario := ChaosScenario{
			Name:             "Intense Recovery Test",
			Duration:         30 * time.Second,
			FailureRate:      0.8, // Very high failure rate
			ComponentTargets: []string{"rbac", "risk", "jit", "network"},
			FailureTypes:     []string{"timeout", "error", "slow", "partition"},
		}

		framework.StartChaos(chaosScenario)

		chaosMetrics := &ChaosMetrics{mutex: sync.RWMutex{}}
		ctx, cancel = context.WithTimeout(context.Background(), chaosScenario.Duration)
		framework.runWorkload(ctx, chaosScenario.Duration, chaosMetrics)
		cancel()

		framework.StopChaos()

		// Measure chaos impact
		chaosMetrics.mutex.RLock()
		chaosSuccess := chaosMetrics.SuccessfulOperations
		chaosTotal := chaosMetrics.TotalOperations
		chaosViolations := chaosMetrics.SecurityViolations
		chaosAvailability := float64(chaosSuccess) / float64(chaosTotal)
		chaosMetrics.mutex.RUnlock()

		t.Logf("Chaos - Total: %d, Success: %d, Availability: %.2f, Violations: %d",
			chaosTotal, chaosSuccess, chaosAvailability, chaosViolations)

		// Critical: No security violations during chaos
		assert.Equal(t, int64(0), chaosViolations, "Must have no security violations during chaos")

		// Allow recovery time
		recoveryTime := 10 * time.Second
		t.Logf("Allowing %v for system recovery...", recoveryTime)
		time.Sleep(recoveryTime)

		// Measure post-recovery performance
		recoveryMetrics := &ChaosMetrics{mutex: sync.RWMutex{}}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		framework.runWorkload(ctx, 5*time.Second, recoveryMetrics)
		cancel()

		recoveryMetrics.mutex.RLock()
		recoverySuccess := recoveryMetrics.SuccessfulOperations
		recoveryTotal := recoveryMetrics.TotalOperations
		recoveryViolations := recoveryMetrics.SecurityViolations
		recoveryAvailability := float64(recoverySuccess) / float64(recoveryTotal)
		recoveryMetrics.mutex.RUnlock()

		t.Logf("Recovery - Total: %d, Success: %d, Availability: %.2f, Violations: %d",
			recoveryTotal, recoverySuccess, recoveryAvailability, recoveryViolations)

		// Assert recovery properties
		assert.Equal(t, int64(0), recoveryViolations, "Must have no security violations after recovery")

		// System should recover to near-baseline performance
		recoveryRatio := recoveryAvailability / baselineAvailability
		t.Logf("Recovery Ratio: %.2f (recovery availability / baseline availability)", recoveryRatio)

		// Should recover to at least 80% of baseline performance
		assert.Greater(t, recoveryRatio, 0.8, "Should recover to at least 80% of baseline availability")

		// Verify health status of components
		t.Logf("Component Health - RBAC: %v, Risk: %v, JIT: %v",
			framework.failsafeRBAC.IsHealthy(),
			framework.failsafeRisk.IsHealthy(),
			framework.failsafeJIT.IsHealthy())

		// At least some components should have recovered
		healthyComponents := 0
		if framework.failsafeRBAC.IsHealthy() {
			healthyComponents++
		}
		if framework.failsafeRisk.IsHealthy() {
			healthyComponents++
		}
		if framework.failsafeJIT.IsHealthy() {
			healthyComponents++
		}

		assert.Greater(t, healthyComponents, 0, "At least some components should be healthy after recovery")
	})
}

// TestChaosNetworkPartitionTolerance tests network partition tolerance under chaos
func TestChaosNetworkPartitionTolerance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	framework := NewChaosSecurityTestFramework(t)
	defer framework.Cleanup()

	require.NoError(t, framework.Setup())

	t.Run("Partition Tolerance Under Chaos", func(t *testing.T) {
		t.Skip("Skipping until Issue #291: Chaos framework needs proper network failure injection implementation")

		// Set to graceful degradation mode
		framework.failsafeNetwork.SetPartitionMode(failsafe.PartitionModeGracefulDegradation)

		// CRITICAL: Cache policies BEFORE partitioning (fail-secure requires cached policies)
		ctx := context.Background()

		// Cache multiple permissions for the test user
		testPermissions := []struct {
			permission string
			resource   string
		}{
			{"config.read", "chaos-resource"},
			{"config.write", "chaos-resource"},
			{"chaos.network", "chaos-resource"},
		}

		for _, perm := range testPermissions {
			request := &common.AccessRequest{
				SubjectId:    "chaos-user-1",
				PermissionId: perm.permission,
				TenantId:     "chaos-tenant",
				ResourceId:   perm.resource,
			}
			// Make successful request to cache the policy
			_, err := framework.failsafeNetwork.CheckPermission(ctx, request)
			require.NoError(t, err)
		}

		// Re-create request for main test workload
		request := &common.AccessRequest{
			SubjectId:    "chaos-user-1",
			PermissionId: "config.read",
			TenantId:     "chaos-tenant",
			ResourceId:   "chaos-resource",
		}

		// Start network partition chaos
		partitionScenario := ChaosScenario{
			Name:             "Network Partition Chaos",
			Duration:         20 * time.Second,
			FailureRate:      0.7, // High partition rate
			ComponentTargets: []string{"network"},
			FailureTypes:     []string{"partition"},
		}

		framework.StartChaos(partitionScenario)

		partitionMetrics := &ChaosMetrics{mutex: sync.RWMutex{}}

		// Run workload during partition
		workloadCtx, cancel := context.WithTimeout(context.Background(), partitionScenario.Duration)
		defer cancel()

		// Create wait group for workload synchronization (Issue #291)
		var workloadWg sync.WaitGroup
		workloadWg.Add(1)

		// Custom workload focusing on network partition tolerance
		go func() {
			defer workloadWg.Done()
			ticker := time.NewTicker(100 * time.Millisecond)
			defer ticker.Stop()

			startTime := time.Now()
			for {
				select {
				case <-workloadCtx.Done():
					return
				case <-ticker.C:
					if time.Since(startTime) > partitionScenario.Duration {
						return
					}

					// Test partition tolerance
					start := time.Now()
					response, err := framework.failsafeNetwork.CheckPermission(ctx, request)
					duration := time.Since(start)

					partitionMetrics.mutex.Lock()
					partitionMetrics.TotalOperations++
					if duration > partitionMetrics.MaxResponseTime {
						partitionMetrics.MaxResponseTime = duration
					}

					if err != nil {
						partitionMetrics.FailedOperations++
						if response != nil && !response.Granted {
							// Fail-secure behavior - acceptable
							partitionMetrics.FailsafeActivations++
						} else {
							// Should not grant access when it should deny
							partitionMetrics.SecurityViolations++
						}
					} else {
						partitionMetrics.SuccessfulOperations++

						// If access granted during partition, it should be from cache (graceful degradation)
						// This is acceptable and expected behavior - already counted in SuccessfulOperations above
					}
					partitionMetrics.mutex.Unlock()
				}
			}
		}()

		// Wait for workload to complete OR context timeout (Issue #291)
		workloadWg.Wait()

		framework.StopChaos()

		// Check partition metrics
		partitionMetrics.mutex.RLock()
		totalOps := partitionMetrics.TotalOperations
		securityViolations := partitionMetrics.SecurityViolations
		failsafeActivations := partitionMetrics.FailsafeActivations
		successfulOps := partitionMetrics.SuccessfulOperations
		partitionMetrics.mutex.RUnlock()

		t.Logf("Partition Test - Total: %d, Success: %d, Failsafe: %d, Violations: %d",
			totalOps, successfulOps, failsafeActivations, securityViolations)

		// Critical: No security violations during network partitions
		assert.Equal(t, int64(0), securityViolations, "Must have no security violations during network partitions")
		assert.Greater(t, totalOps, int64(0), "Should have processed operations")

		// In graceful degradation mode with cached policies, operations should SUCCEED from cache
		// Failsafe activations only occur in fail-secure mode or when cache misses
		// Instead, verify that:
		// 1. Operations succeeded during partition (using cache)
		// 2. Partition was actually detected by the manager
		assert.Greater(t, successfulOps, int64(0), "Should have successful operations using cache during partition")

		// Check final partition metrics - this is the KEY validation
		finalMetrics := framework.failsafeNetwork.GetPartitionMetrics()
		assert.Greater(t, finalMetrics.TotalRequests, int64(0), "Should have partition requests")
		assert.Greater(t, finalMetrics.PartitionedRequests, int64(0), "Should have detected partitions")
		assert.Greater(t, finalMetrics.CacheHits, int64(0), "Should have cache hits during partition")
	})
}
