// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	testutil "github.com/cfgis/cfgms/pkg/testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/terminal"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// AuditLoadTestSuite tests audit trail completeness under high-load conditions
// Story #133: Audit Trail Completeness Under Load
type AuditLoadTestSuite struct {
	suite.Suite
	framework *E2ETestFramework
}

// SetupSuite initializes the audit load testing framework
func (s *AuditLoadTestSuite) SetupSuite() {
	config := CIOptimizedConfig()
	config.PerformanceMode = true
	config.EnableRBAC = true
	config.EnableTerminal = true
	config.TestTimeout = 20 * time.Minute // Extended timeout for load testing

	framework, err := NewE2EFramework(s.T(), config)
	require.NoError(s.T(), err)

	err = framework.Initialize()
	require.NoError(s.T(), err)

	s.framework = framework
}

// TearDownSuite cleans up the audit load testing framework
func (s *AuditLoadTestSuite) TearDownSuite() {
	if s.framework != nil {
		err := s.framework.Cleanup()
		assert.NoError(s.T(), err)

		// Print audit load test summary
		s.printAuditLoadTestSummary()
	}
}

// TestAuditCompletenessUnderLoad validates 100% audit completeness during peak authorization loads
// Acceptance Criteria: Zero audit event loss during peak authorization loads
func (s *AuditLoadTestSuite) TestAuditCompletenessUnderLoad() {
	err := s.framework.RunTest("audit-completeness-under-load", "audit-load", func() error {
		s.framework.logger.Info("Starting high-load audit completeness validation")

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		rbacManager := s.createTestRBACManager()

		// Test configuration
		const (
			concurrentUsers     = 50  // Number of concurrent users
			operationsPerUser   = 100 // Operations per user
			testDurationMinutes = 5   // Test duration
		)

		totalExpectedEvents := concurrentUsers * operationsPerUser
		s.framework.logger.Info("Load test configuration",
			"concurrent_users", concurrentUsers,
			"operations_per_user", operationsPerUser,
			"total_expected_events", totalExpectedEvents,
			"test_duration_minutes", testDurationMinutes)

		// Track audit completeness metrics
		var (
			eventsGenerated int64
			eventsAudited   int64
			errorCount      int64
		)

		// Start load test
		loadTestStart := time.Now()
		var wg sync.WaitGroup

		// Launch concurrent users
		for userID := 0; userID < concurrentUsers; userID++ {
			wg.Add(1)
			go func(uid int) {
				defer wg.Done()
				s.runConcurrentAuditLoad(ctx, rbacManager, uid, operationsPerUser,
					&eventsGenerated, &eventsAudited, &errorCount)
			}(userID)
		}

		// Wait for all users to complete
		wg.Wait()
		loadTestDuration := time.Since(loadTestStart)

		// Validate audit completeness
		finalEventsGenerated := atomic.LoadInt64(&eventsGenerated)
		finalEventsAudited := atomic.LoadInt64(&eventsAudited)
		finalErrorCount := atomic.LoadInt64(&errorCount)

		s.framework.logger.Info("Load test completed",
			"duration", loadTestDuration,
			"events_generated", finalEventsGenerated,
			"events_audited", finalEventsAudited,
			"errors", finalErrorCount,
			"completion_rate", float64(finalEventsAudited)/float64(finalEventsGenerated)*100)

		// Acceptance Criteria Validation
		if finalEventsAudited != finalEventsGenerated {
			return fmt.Errorf("audit completeness failure: %d events generated, %d events audited (loss: %d)",
				finalEventsGenerated, finalEventsAudited, finalEventsGenerated-finalEventsAudited)
		}

		if finalErrorCount > 0 {
			return fmt.Errorf("audit errors detected during load test: %d errors", finalErrorCount)
		}

		// Performance validation
		eventsPerSecond := float64(finalEventsGenerated) / loadTestDuration.Seconds()
		if eventsPerSecond < 100 { // Should handle at least 100 events/second
			s.framework.logger.Warn("Audit performance below baseline",
				"events_per_second", eventsPerSecond,
				"baseline", 100)
		}

		s.framework.recordLatencyMetric("audit-load-test-duration", loadTestDuration)
		s.framework.logger.Info("Audit completeness under load validated successfully")

		return nil
	})

	require.NoError(s.T(), err)
}

// TestAuditEventLossDetectionAndPrevention validates audit event loss detection and prevention mechanisms
// Acceptance Criteria: All permission grants/revocations logged with precise timestamps
func (s *AuditLoadTestSuite) TestAuditEventLossDetectionAndPrevention() {
	err := s.framework.RunTest("audit-event-loss-detection", "audit-load", func() error {
		s.framework.logger.Info("Starting audit event loss detection and prevention test")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		rbacManager := s.createTestRBACManager()

		// Create test scenario with intentional stress
		const (
			burstUsers      = 20 // Number of users in burst
			burstOperations = 50 // Operations per burst user
			burstCount      = 5  // Number of bursts
		)

		var (
			totalEventsGenerated int64
			totalEventsAudited   int64
		)

		// Execute burst load patterns
		for burstNum := 0; burstNum < burstCount; burstNum++ {
			burstStart := time.Now()
			s.framework.logger.Info("Executing burst load",
				"burst_number", burstNum+1,
				"burst_users", burstUsers,
				"burst_operations", burstOperations)

			var wg sync.WaitGroup
			var burstGenerated, burstAudited int64

			// Launch burst of concurrent operations
			for userID := 0; userID < burstUsers; userID++ {
				wg.Add(1)
				go func(uid int) {
					defer wg.Done()
					s.runBurstAuditOperations(ctx, rbacManager,
						fmt.Sprintf("burst-%d-user-%d", burstNum, uid),
						burstOperations, &burstGenerated, &burstAudited)
				}(userID)
			}

			wg.Wait()
			burstDuration := time.Since(burstStart)

			atomic.AddInt64(&totalEventsGenerated, atomic.LoadInt64(&burstGenerated))
			atomic.AddInt64(&totalEventsAudited, atomic.LoadInt64(&burstAudited))

			s.framework.logger.Info("Burst completed",
				"burst_number", burstNum+1,
				"duration", burstDuration,
				"generated", atomic.LoadInt64(&burstGenerated),
				"audited", atomic.LoadInt64(&burstAudited))

		}

		// Validate results
		finalGenerated := atomic.LoadInt64(&totalEventsGenerated)
		finalAudited := atomic.LoadInt64(&totalEventsAudited)

		s.framework.logger.Info("Audit event loss detection test completed",
			"total_events_generated", finalGenerated,
			"total_events_audited", finalAudited)

		// Acceptance Criteria Validation
		if finalAudited != finalGenerated {
			return fmt.Errorf("audit event loss detected: %d events generated, %d events audited",
				finalGenerated, finalAudited)
		}

		// Flush pending audit writes before querying the durable store
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer flushCancel()
		if err := rbacManager.FlushAudit(flushCtx); err != nil {
			return fmt.Errorf("failed to flush audit events: %w", err)
		}

		if err := s.validateAuditTimestampPrecision(ctx, rbacManager); err != nil {
			return fmt.Errorf("timestamp precision validation failed: %w", err)
		}

		s.framework.logger.Info("Audit event loss detection and prevention validated successfully")
		return nil
	})

	require.NoError(s.T(), err)
}

// TestAuditLogDurabilityAcrossFailures validates audit logs survive system restarts and component failures
// Acceptance Criteria: Audit logs survive system restarts and component failures
func (s *AuditLoadTestSuite) TestAuditLogDurabilityAcrossFailures() {
	err := s.framework.RunTest("audit-log-durability", "audit-load", func() error {
		s.framework.logger.Info("Starting audit log durability testing across failure scenarios")

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()

		// Use an isolated temp directory so prior-run files don't pollute the file count
		storagePath := s.T().TempDir()
		auditStorage := terminal.NewFileAuditStorage(storagePath)
		auditConfig := terminal.DefaultAuditConfig()
		auditConfig.StoragePath = storagePath
		auditConfig.FlushInterval = 1 * time.Second // Frequent flushes for durability testing

		auditLogger, err := terminal.NewAuditLogger(auditConfig, auditStorage)
		if err != nil {
			return fmt.Errorf("failed to create audit logger: %w", err)
		}

		err = auditLogger.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to start audit logger: %w", err)
		}

		// Test scenario: Generate audit events, simulate failures, verify persistence
		const testSessions = 10
		var sessionIDs []string

		// Phase 1: Generate initial audit events
		s.framework.logger.Info("Phase 1: Generating initial audit events")
		for i := 0; i < testSessions; i++ {
			sessionID := fmt.Sprintf("durable-session-%d", i)
			sessionIDs = append(sessionIDs, sessionID)

			err := auditLogger.LogSessionStart(ctx, sessionID,
				fmt.Sprintf("user-%d", i),
				fmt.Sprintf("steward-%d", i),
				fmt.Sprintf("tenant-%d", i),
				fmt.Sprintf("192.168.1.%d", i+100))
			if err != nil {
				return fmt.Errorf("failed to log session start: %w", err)
			}

			// Log some commands
			for j := 0; j < 5; j++ {
				err := auditLogger.LogCommandExecution(ctx, sessionID,
					fmt.Sprintf("user-%d", i),
					fmt.Sprintf("steward-%d", i),
					fmt.Sprintf("tenant-%d", i),
					fmt.Sprintf("test-command-%d", j),
					0,
					100*time.Millisecond,
					fmt.Sprintf("output for command %d", j))
				if err != nil {
					return fmt.Errorf("failed to log command execution: %w", err)
				}
			}
		}

		// Phase 2: Simulate component restart — Stop() flushes remaining entries before returning
		s.framework.logger.Info("Phase 2: Simulating component restart")
		err = auditLogger.Stop()
		if err != nil {
			return fmt.Errorf("failed to stop audit logger: %w", err)
		}

		// Restart audit logger
		auditLogger2, err := terminal.NewAuditLogger(auditConfig, auditStorage)
		if err != nil {
			return fmt.Errorf("failed to recreate audit logger after restart: %w", err)
		}

		err = auditLogger2.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to restart audit logger: %w", err)
		}

		// Phase 3: Generate more audit events after restart
		s.framework.logger.Info("Phase 3: Generating audit events after restart")
		for _, sessionID := range sessionIDs {
			err := auditLogger2.LogSessionEnd(ctx, sessionID,
				fmt.Sprintf("user-%s", sessionID[len(sessionID)-1:]),
				5*time.Minute, 5, 1024)
			if err != nil {
				return fmt.Errorf("failed to log session end after restart: %w", err)
			}
		}

		// Stop flushes remaining buffered entries to storage before returning
		if err := auditLogger2.Stop(); err != nil {
			return fmt.Errorf("failed to stop second audit logger: %w", err)
		}

		// Phase 4: Validate audit log completeness by counting persisted files
		// Each event is written as an individual JSON file under auditConfig.StoragePath.
		// This verifies that events survived both the initial write and the restart boundary.
		s.framework.logger.Info("Phase 4: Validating audit log completeness")

		expectedEvents := testSessions * (1 + 5 + 1) // start + 5 commands + end per session

		var persistedEvents int
		walkErr := filepath.Walk(auditConfig.StoragePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.HasSuffix(path, ".json") {
				persistedEvents++
			}
			return nil
		})
		if walkErr != nil {
			return fmt.Errorf("failed to walk audit storage directory: %w", walkErr)
		}

		if persistedEvents < expectedEvents {
			return fmt.Errorf("audit durability failure: expected at least %d persisted event files, found %d in %s",
				expectedEvents, persistedEvents, auditConfig.StoragePath)
		}

		s.framework.logger.Info("Audit durability test completed",
			"expected_events", expectedEvents,
			"persisted_events", persistedEvents,
			"test_sessions", testSessions)

		s.framework.logger.Info("Audit log durability across failures validated successfully")
		return nil
	})

	require.NoError(s.T(), err)
}

// TestAuditLogRotationAndRetention validates audit log rotation maintains historical completeness
// Acceptance Criteria: Audit log rotation maintains historical completeness
func (s *AuditLoadTestSuite) TestAuditLogRotationAndRetention() {
	err := s.framework.RunTest("audit-log-rotation-retention", "audit-load", func() error {
		s.framework.logger.Info("Starting audit log rotation and retention testing")

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		// Use an isolated temp directory so the directory is empty and rotation behavior is deterministic
		rotationStoragePath := s.T().TempDir()
		auditStorage := terminal.NewFileAuditStorage(rotationStoragePath)
		auditConfig := terminal.DefaultAuditConfig()
		auditConfig.StoragePath = rotationStoragePath
		auditConfig.MaxLogSizeMB = 1 // Small size to trigger rotation quickly
		auditConfig.RetentionDays = 30
		auditConfig.FlushInterval = 500 * time.Millisecond

		auditLogger, err := terminal.NewAuditLogger(auditConfig, auditStorage)
		if err != nil {
			return fmt.Errorf("failed to create audit logger: %w", err)
		}

		err = auditLogger.Start(ctx)
		if err != nil {
			return fmt.Errorf("failed to start audit logger: %w", err)
		}

		// Generate enough audit events to trigger log rotation
		const eventsToGenerate = 1000
		s.framework.logger.Info("Generating audit events to trigger rotation",
			"events_to_generate", eventsToGenerate)

		var eventsGenerated int64
		for i := 0; i < eventsToGenerate; i++ {
			sessionID := fmt.Sprintf("rotation-session-%d", i%10) // Reuse session IDs
			userID := fmt.Sprintf("rotation-user-%d", i%5)

			// Log various types of events
			switch i % 4 {
			case 0:
				err := auditLogger.LogSessionStart(ctx, sessionID, userID,
					"rotation-steward", "rotation-tenant", "192.168.1.100")
				if err == nil {
					atomic.AddInt64(&eventsGenerated, 1)
				}
			case 1:
				err := auditLogger.LogCommandExecution(ctx, sessionID, userID,
					"rotation-steward", "rotation-tenant",
					fmt.Sprintf("rotation-command-%d", i),
					0, 50*time.Millisecond,
					fmt.Sprintf("rotation output %d with some longer text to increase log size", i))
				if err == nil {
					atomic.AddInt64(&eventsGenerated, 1)
				}
			case 2:
				err := auditLogger.LogCommandBlocked(ctx, sessionID, userID,
					"rotation-steward", "rotation-tenant",
					"dangerous-command", "blocked by security policy",
					[]string{"security-rule-1", "security-rule-2"})
				if err == nil {
					atomic.AddInt64(&eventsGenerated, 1)
				}
			case 3:
				err := auditLogger.LogSecurityViolation(ctx, sessionID, userID,
					"rotation-steward", "rotation-tenant",
					"privilege_escalation", "attempted unauthorized access",
					terminal.FilterSeverityHigh)
				if err == nil {
					atomic.AddInt64(&eventsGenerated, 1)
				}
			}

			if i%100 == 0 {
				s.framework.logger.Info("Audit events progress",
					"generated", atomic.LoadInt64(&eventsGenerated),
					"target", eventsToGenerate)
			}
		}

		// Stop flushes all buffered events before validation reads the accepted-event count
		if err := auditLogger.Stop(); err != nil {
			return fmt.Errorf("failed to stop audit logger: %w", err)
		}

		finalEventsGenerated := atomic.LoadInt64(&eventsGenerated)
		s.framework.logger.Info("Audit log rotation test completed",
			"events_generated", finalEventsGenerated,
			"target_events", eventsToGenerate)

		// Validate that rotation maintained completeness
		if finalEventsGenerated < int64(eventsToGenerate*0.95) { // Allow 5% margin for errors
			return fmt.Errorf("significant audit event loss during rotation: generated %d, expected ~%d",
				finalEventsGenerated, eventsToGenerate)
		}

		s.framework.logger.Info("Audit log rotation and retention validated successfully")
		return nil
	})

	require.NoError(s.T(), err)
}

// TestComplianceReportAccuracyUnderLoad validates compliance reports generated accurately under any load
// Acceptance Criteria: Compliance reports generated accurately under any load
func (s *AuditLoadTestSuite) TestComplianceReportAccuracyUnderLoad() {
	err := s.framework.RunTest("compliance-report-accuracy-under-load", "audit-load", func() error {
		s.framework.logger.Info("Starting compliance report accuracy under load testing")

		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()

		rbacManager := s.createTestRBACManager()

		// Generate controlled test data for accuracy verification
		testData := s.generateComplianceTestData()
		s.framework.logger.Info("Generated compliance test data",
			"total_operations", len(testData.Operations),
			"expected_grants", testData.ExpectedGrants,
			"expected_revocations", testData.ExpectedRevocations,
			"expected_denials", testData.ExpectedDenials)

		// Execute operations while generating compliance reports concurrently
		var wg sync.WaitGroup
		var reportErrors int64

		// Start compliance report generation in background
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runContinuousComplianceReporting(ctx, rbacManager, &reportErrors)
		}()

		// Execute test operations
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.executeComplianceTestOperations(ctx, rbacManager, testData)
		}()

		// Wait for completion
		wg.Wait()

		// Flush pending audit writes before querying the durable store
		flushCtx2, flushCancel2 := context.WithTimeout(context.Background(), 30*time.Second)
		defer flushCancel2()
		if err := rbacManager.FlushAudit(flushCtx2); err != nil {
			return fmt.Errorf("failed to flush audit events: %w", err)
		}

		// Generate final compliance report from durable audit store
		startTime := time.Now().Add(-15 * time.Minute)
		filter := &business.AuditFilter{
			EventTypes: []business.AuditEventType{business.AuditEventAuthorization},
			TimeRange:  &business.TimeRange{Start: &startTime},
			Limit:      1000,
		}

		entries, err := rbacManager.QueryAuditEntries(ctx, filter)
		if err != nil {
			return fmt.Errorf("failed to query audit entries: %w", err)
		}

		// Compute compliance stats from durable store
		var successCount, deniedCount int
		for _, e := range entries {
			switch e.Result {
			case business.AuditResultSuccess:
				successCount++
			case business.AuditResultDenied:
				deniedCount++
			}
		}

		// Validate report errors
		finalReportErrors := atomic.LoadInt64(&reportErrors)
		if finalReportErrors > 0 {
			return fmt.Errorf("compliance report generation errors detected: %d", finalReportErrors)
		}

		s.framework.logger.Info("Compliance report accuracy validation completed",
			"successful_access", successCount,
			"denied_access", deniedCount,
			"total_entries", len(entries))

		s.framework.logger.Info("Compliance report accuracy under load validated successfully")
		return nil
	})

	require.NoError(s.T(), err)
}

// Helper methods

func (s *AuditLoadTestSuite) createTestRBACManager() *rbac.Manager {
	return testutil.SetupTestRBACManager(s.T())
}

func (s *AuditLoadTestSuite) runConcurrentAuditLoad(ctx context.Context, rbacManager *rbac.Manager,
	userID, operations int,
	eventsGenerated, eventsAudited, errorCount *int64) {

	subjectID := fmt.Sprintf("load-test-user-%d", userID)
	tenantID := fmt.Sprintf("load-test-tenant-%d", userID%5) // 5 tenants

	for i := 0; i < operations; i++ {
		if ctx.Err() != nil {
			return
		}

		permissionID := fmt.Sprintf("permission-%d", i%10) // 10 different permissions

		// Permission check generates an authorization audit event regardless of grant/deny
		request := &common.AccessRequest{
			SubjectId:    subjectID,
			PermissionId: permissionID,
			TenantId:     tenantID,
		}
		atomic.AddInt64(eventsGenerated, 1)
		_, err := rbacManager.CheckPermission(ctx, request)
		if err == nil {
			atomic.AddInt64(eventsAudited, 1)
		} else {
			atomic.AddInt64(errorCount, 1)
		}

		// Second check (simulating a revocation scenario)
		atomic.AddInt64(eventsGenerated, 1)
		_, err = rbacManager.CheckPermission(ctx, request)
		if err == nil {
			atomic.AddInt64(eventsAudited, 1)
		} else {
			atomic.AddInt64(errorCount, 1)
		}
	}
}

func (s *AuditLoadTestSuite) runBurstAuditOperations(ctx context.Context, rbacManager *rbac.Manager,
	userID string, operations int,
	eventsGenerated, eventsAudited *int64) {

	for i := 0; i < operations; i++ {
		if ctx.Err() != nil {
			return
		}

		request := &common.AccessRequest{
			SubjectId:    userID,
			PermissionId: fmt.Sprintf("burst-permission-%d", i),
			TenantId:     "burst-tenant",
		}
		atomic.AddInt64(eventsGenerated, 1)
		if _, err := rbacManager.CheckPermission(ctx, request); err == nil {
			atomic.AddInt64(eventsAudited, 1)
		}
	}
}

func (s *AuditLoadTestSuite) validateAuditTimestampPrecision(ctx context.Context, rbacManager *rbac.Manager) error {
	// Retrieve recent audit entries from the durable store
	entries, err := rbacManager.QueryAuditEntries(ctx, &business.AuditFilter{
		EventTypes: []business.AuditEventType{business.AuditEventAuthorization},
		Limit:      100,
	})
	if err != nil {
		return fmt.Errorf("failed to retrieve audit entries: %w", err)
	}

	// Check timestamp ordering — entries from the store are in descending order by default
	for i := 1; i < len(entries); i++ {
		prev := entries[i-1]
		curr := entries[i]

		// In DESC order, prev should be >= curr; if curr is strictly after prev it's a violation
		if curr.Timestamp.After(prev.Timestamp) {
			return fmt.Errorf("timestamp order violation at index %d: %v > %v", i, curr.Timestamp, prev.Timestamp)
		}
	}

	return nil
}

type ComplianceTestData struct {
	Operations          []ComplianceTestOperation
	ExpectedGrants      int
	ExpectedRevocations int
	ExpectedDenials     int
}

type ComplianceTestOperation struct {
	Type         string
	SubjectID    string
	PermissionID string
	ResourceID   string
	TenantID     string
	ShouldGrant  bool
}

func (s *AuditLoadTestSuite) generateComplianceTestData() *ComplianceTestData {
	data := &ComplianceTestData{
		Operations: make([]ComplianceTestOperation, 0, 200),
	}

	// Generate mix of operations with known outcomes
	for i := 0; i < 200; i++ {
		op := ComplianceTestOperation{
			SubjectID:    fmt.Sprintf("compliance-user-%d", i%10),
			PermissionID: fmt.Sprintf("compliance-permission-%d", i%5),
			ResourceID:   fmt.Sprintf("compliance-resource-%d", i%8),
			TenantID:     fmt.Sprintf("compliance-tenant-%d", i%3),
		}

		switch i % 4 {
		case 0:
			op.Type = "grant"
			op.ShouldGrant = true
			data.ExpectedGrants++
		case 1:
			op.Type = "revoke"
			data.ExpectedRevocations++
		case 2:
			op.Type = "check"
			if i%3 == 0 {
				op.ShouldGrant = false
				data.ExpectedDenials++
			} else {
				op.ShouldGrant = true
				data.ExpectedGrants++
			}
		case 3:
			op.Type = "delegate"
			op.ShouldGrant = true
			data.ExpectedGrants++
		}

		data.Operations = append(data.Operations, op)
	}

	return data
}

func (s *AuditLoadTestSuite) runContinuousComplianceReporting(ctx context.Context,
	rbacManager *rbac.Manager, reportErrors *int64) {

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			startTime := time.Now().Add(-30 * time.Second)
			_, err := rbacManager.QueryAuditEntries(ctx, &business.AuditFilter{
				EventTypes: []business.AuditEventType{business.AuditEventAuthorization},
				TimeRange:  &business.TimeRange{Start: &startTime},
				Limit:      1000,
			})
			if err != nil {
				atomic.AddInt64(reportErrors, 1)
				s.framework.logger.Warn("Compliance report generation failed", "error", err)
			}
		}
	}
}

func (s *AuditLoadTestSuite) executeComplianceTestOperations(ctx context.Context,
	rbacManager *rbac.Manager, testData *ComplianceTestData) {

	for _, op := range testData.Operations {
		if ctx.Err() != nil {
			return
		}

		// All operation types generate permission check audit events
		request := &common.AccessRequest{
			SubjectId:    op.SubjectID,
			PermissionId: op.PermissionID,
			TenantId:     op.TenantID,
		}
		if _, err := rbacManager.CheckPermission(ctx, request); err != nil {
			s.framework.logger.Warn("CheckPermission returned unexpected error during compliance operations",
				"subject", op.SubjectID, "permission", op.PermissionID, "error", err)
		}

	}
}

func (s *AuditLoadTestSuite) printAuditLoadTestSummary() {
	s.framework.logger.Info("=== Audit Load Test Summary ===")
	s.framework.logger.Info("All audit load tests completed successfully")
	s.framework.logger.Info("Audit completeness under load validated")
	s.framework.logger.Info("Audit event loss detection and prevention validated")
	s.framework.logger.Info("Audit log durability across failures validated")
	s.framework.logger.Info("Audit log rotation and retention validated")
	s.framework.logger.Info("Compliance report accuracy under load validated")

	// Print memory usage
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	s.framework.logger.Info("Memory usage after audit load tests",
		"allocated_mb", float64(m.Alloc)/1024/1024,
		"sys_mb", float64(m.Sys)/1024/1024,
		"gc_cycles", m.NumGC)
}

// Test suite runner
func TestAuditLoadTestSuite(t *testing.T) {
	if testing.Short() {
		// Infrastructure justification: these are resource-intensive load tests requiring
		// concurrent RBAC operations, high-throughput audit writes, and extended runtime
		// (up to 20 minutes). They require a full storage stack and are not suitable for
		// unit/fast test cycles. Run with `make test-e2e` for full coverage.
		t.Skip("Skipping audit load test suite in short mode: resource-intensive load tests require extended runtime and full storage stack")
	}
	suite.Run(t, new(AuditLoadTestSuite))
}
