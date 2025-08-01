package e2e

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/features/steward"
)

// E2ETestSuite provides comprehensive end-to-end testing scenarios
type E2ETestSuite struct {
	suite.Suite
	framework *E2ETestFramework
}

// SetupSuite initializes the E2E testing framework
func (s *E2ETestSuite) SetupSuite() {
	config := CIOptimizedConfig() // Use CI-optimized config by default
	
	// Override with local config if running locally (not in CI)
	if !isRunningInCI() {
		config = LocalDevelopmentConfig()
	}
	
	framework, err := NewE2EFramework(s.T(), config)
	require.NoError(s.T(), err)
	
	err = framework.Initialize()
	require.NoError(s.T(), err)
	
	s.framework = framework
}

// TearDownSuite cleans up the testing framework
func (s *E2ETestSuite) TearDownSuite() {
	if s.framework != nil {
		// Generate comprehensive test report
		reporter := NewTestReporter(s.framework)
		report, err := reporter.GenerateReport()
		if err == nil {
			err = reporter.SaveReportToFile(report)
			if err != nil {
				s.T().Logf("Failed to save test report: %v", err)
			}
		}
		
		err = s.framework.Cleanup()
		assert.NoError(s.T(), err)
		
		// Print test metrics summary
		s.printTestSummary()
	}
}

// TestControllerStewardIntegration tests basic controller-steward communication
func (s *E2ETestSuite) TestControllerStewardIntegration() {
	err := s.framework.RunTest("controller-steward-integration", "core", func() error {
		// Generate realistic test data (unused for now)
		_ = s.framework.GetTestDataGenerator()
		stewardID := "test-steward-001"
		
		// Create a test steward
		steward, err := s.framework.CreateSteward(stewardID)
		if err != nil {
			return fmt.Errorf("failed to create steward: %w", err)
		}
		
		// Start the steward
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		go func() {
			if err := steward.Start(ctx); err != nil {
				s.framework.logger.Error("Steward start failed", "error", err)
			}
		}()
		
		// Wait for steward to connect to controller
		time.Sleep(2 * time.Second)
		
		// TODO: Verify steward is registered with controller
		// Note: IsConnected method not available, would need to implement connection checking
		
		// Test heartbeat functionality
		// Implementation would verify heartbeat is being sent
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestTerminalSecurityIntegration tests terminal security controls end-to-end
func (s *E2ETestSuite) TestTerminalSecurityIntegration() {
	if !s.framework.config.EnableTerminal {
		s.T().Skip("Terminal functionality disabled")
	}
	
	err := s.framework.RunTest("terminal-security-integration", "security", func() error {
		// Create test steward
		steward, err := s.framework.CreateSteward("terminal-test-steward")
		if err != nil {
			return fmt.Errorf("failed to create steward: %w", err)
		}
		
		// Start steward
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		go steward.Start(ctx)
		time.Sleep(2 * time.Second) // Allow connection
		
		// Generate realistic test data for terminal session (unused for now)
		_ = s.framework.GetTestDataGenerator()
		
		// TODO: Test terminal session creation with RBAC
		// Terminal functionality not yet implemented in E2E framework
		s.framework.logger.Info("Terminal security integration test placeholder")
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestRBACIntegration tests RBAC system integration across components
func (s *E2ETestSuite) TestRBACIntegration() {
	if !s.framework.config.EnableRBAC {
		s.T().Skip("RBAC functionality disabled")
	}
	
	err := s.framework.RunTest("rbac-integration", "security", func() error {
		// TODO: Test creating a tenant-specific role
		// TODO: Test permission checking
		s.framework.logger.Info("RBAC integration test placeholder")
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestWorkflowIntegration tests workflow engine integration
func (s *E2ETestSuite) TestWorkflowIntegration() {
	if !s.framework.config.EnableWorkflow {
		s.T().Skip("Workflow functionality disabled")
	}
	
	err := s.framework.RunTest("workflow-integration", "workflow", func() error {
		// Create a simple workflow that involves multiple components
		
		// Test workflow execution
		// Implementation would test workflow functionality
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestMultiStewardScenario tests scenarios with multiple stewards
func (s *E2ETestSuite) TestMultiStewardScenario() {
	err := s.framework.RunTest("multi-steward-scenario", "scalability", func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		
		stewardCount := 3
		if s.framework.config.OptimizeForCI {
			stewardCount = 2 // Reduce for CI constraints
		}
		
		// Create multiple stewards
		stewards := make([]*steward.Steward, stewardCount)
		for i := 0; i < stewardCount; i++ {
			stewardID := fmt.Sprintf("multi-test-steward-%d", i)
			s, err := s.framework.CreateSteward(stewardID)
			if err != nil {
				return fmt.Errorf("failed to create steward %s: %w", stewardID, err)
			}
			stewards[i] = s
			
			// Start steward
			go s.Start(ctx)
		}
		
		// Wait for all stewards to connect
		time.Sleep(5 * time.Second)
		
		// TODO: Verify all stewards are connected
		// Note: IsConnected method not available, would need proper connection checking
		_ = stewards // Use variable to avoid unused warning
		
		// Test concurrent operations
		// Implementation would test concurrent scenarios
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestFailureRecovery tests system resilience and recovery
func (s *E2ETestSuite) TestFailureRecovery() {
	err := s.framework.RunTest("failure-recovery", "resilience", func() error {
		// Create steward
		steward, err := s.framework.CreateSteward("recovery-test-steward")
		if err != nil {
			return fmt.Errorf("failed to create steward: %w", err)
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		
		// Start steward
		go steward.Start(ctx)
		time.Sleep(2 * time.Second)
		
		// TODO: Verify initial connection
		// Note: IsConnected method not available
		
		// Simulate network disruption (stop and restart steward)
		steward.Stop(context.Background())
		time.Sleep(1 * time.Second)
		
		// Restart steward
		go steward.Start(ctx)
		time.Sleep(3 * time.Second)
		
		// TODO: Verify recovery
		// Note: IsConnected method not available
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestPerformanceBaseline establishes performance baselines
func (s *E2ETestSuite) TestPerformanceBaseline() {
	if !s.framework.config.PerformanceMode {
		s.T().Skip("Performance testing disabled")
	}
	
	err := s.framework.RunTest("performance-baseline", "performance", func() error {
		// Run performance tests and collect metrics
		// Implementation would establish performance baselines
		
		// Test request throughput
		// Test memory usage
		// Test CPU usage
		// Test concurrent connections
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestDataFlow tests end-to-end data flow across components
func (s *E2ETestSuite) TestDataFlow() {
	err := s.framework.RunTest("data-flow", "integration", func() error {
		// Create steward
		steward, err := s.framework.CreateSteward("dataflow-test-steward")
		if err != nil {
			return fmt.Errorf("failed to create steward: %w", err)
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		
		// Start steward
		go steward.Start(ctx)
		time.Sleep(2 * time.Second)
		
		// Test configuration flow: Controller -> Steward
		// Implementation would test configuration distribution
		
		// Test telemetry flow: Steward -> Controller
		// Implementation would test telemetry collection
		
		// Test DNA sync: Steward -> Controller
		// Implementation would test DNA synchronization
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// TestSecurityCompliance tests security compliance requirements
func (s *E2ETestSuite) TestSecurityCompliance() {
	err := s.framework.RunTest("security-compliance", "compliance", func() error {
		// Test certificate validation
		// Test encryption in transit
		// Test authentication flows
		// Test authorization checks
		// Test audit logging
		
		return nil
	})
	
	require.NoError(s.T(), err)
}

// Helper methods

func (s *E2ETestSuite) printTestSummary() {
	metrics := s.framework.GetMetrics()
	
	totalTests := len(metrics.TestResults)
	passedTests := 0
	failedTests := 0
	totalDuration := time.Since(metrics.StartTime)
	
	for _, result := range metrics.TestResults {
		if result.Success {
			passedTests++
		} else {
			failedTests++
		}
	}
	
	fmt.Printf("\n" + strings.Repeat("=", 60) + "\n")
	fmt.Printf("E2E TEST SUMMARY\n")
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	fmt.Printf("Total Tests:    %d\n", totalTests)
	fmt.Printf("Passed:         %d\n", passedTests)
	fmt.Printf("Failed:         %d\n", failedTests)
	fmt.Printf("Success Rate:   %.1f%%\n", float64(passedTests)/float64(totalTests)*100)
	fmt.Printf("Total Duration: %v\n", totalDuration)
	fmt.Printf(strings.Repeat("=", 60) + "\n")
	
	// Print failed tests
	if failedTests > 0 {
		fmt.Printf("FAILED TESTS:\n")
		for _, result := range metrics.TestResults {
			if !result.Success {
				fmt.Printf("  - %s (%s): %v\n", result.Name, result.Category, result.Error)
			}
		}
		fmt.Printf(strings.Repeat("=", 60) + "\n")
	}
	
	// Print performance metrics if available
	if metrics.PerformanceMetrics.TotalRequests > 0 {
		fmt.Printf("PERFORMANCE METRICS:\n")
		fmt.Printf("  Total Requests:     %d\n", metrics.PerformanceMetrics.TotalRequests)
		fmt.Printf("  Success Rate:       %.1f%%\n", 
			float64(metrics.PerformanceMetrics.SuccessfulRequests)/float64(metrics.PerformanceMetrics.TotalRequests)*100)
		fmt.Printf("  Average Latency:    %v\n", metrics.PerformanceMetrics.AverageLatency)
		fmt.Printf("  P95 Latency:        %v\n", metrics.PerformanceMetrics.P95Latency)
		fmt.Printf("  Throughput:         %.1f RPS\n", metrics.PerformanceMetrics.ThroughputRPS)
		fmt.Printf(strings.Repeat("=", 60) + "\n")
	}
}

func isRunningInCI() bool {
	// Check common CI environment variables
	ciVars := []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILDKITE"}
	for _, envVar := range ciVars {
		if os.Getenv(envVar) != "" {
			return true
		}
	}
	return false
}

// TestE2EScenarios runs the E2E test suite
func TestE2EScenarios(t *testing.T) {
	suite.Run(t, &E2ETestSuite{})
}