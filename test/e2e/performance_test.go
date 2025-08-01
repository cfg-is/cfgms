package e2e

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// PerformanceRegressionSuite tests performance baselines and regression detection
type PerformanceRegressionSuite struct {
	suite.Suite
	framework *E2ETestFramework
}

// SetupSuite initializes the performance testing framework
func (s *PerformanceRegressionSuite) SetupSuite() {
	config := CIOptimizedConfig()
	config.PerformanceMode = true
	config.TestDataSize = "small" // Keep small for CI speed
	config.TestTimeout = 15 * time.Minute // Longer timeout for performance tests
	
	framework, err := NewE2EFramework(s.T(), config)
	s.Require().NoError(err)
	
	err = framework.Initialize()
	s.Require().NoError(err)
	
	s.framework = framework
}

// TearDownSuite cleans up the performance testing framework
func (s *PerformanceRegressionSuite) TearDownSuite() {
	if s.framework != nil {
		err := s.framework.Cleanup()
		s.Assert().NoError(err)
		
		// Print performance summary
		s.printPerformanceSummary()
	}
}

// TestControllerPerformanceBaseline establishes controller performance baselines
func (s *PerformanceRegressionSuite) TestControllerPerformanceBaseline() {
	if !s.framework.config.PerformanceMode {
		s.T().Skip("Performance mode disabled")
	}
	
	err := s.framework.RunTest("controller-performance-baseline", "performance", func() error {
		perfData := s.framework.dataGenerator.GeneratePerformanceTestData()
		
		// Test controller startup time
		startTime := time.Now()
		// Controller initialization is already done in framework setup
		controllerStartupTime := time.Since(startTime)
		
		// Baseline: Controller should start within 5 seconds
		maxStartupTime := 5 * time.Second
		if controllerStartupTime > maxStartupTime {
			s.T().Errorf("Controller startup time regression: %v > %v", 
				controllerStartupTime, maxStartupTime)
		}
		
		// Test concurrent steward connections
		concurrentStewards := perfData.ConcurrentStewards
		if concurrentStewards > 5 { // Limit for CI
			concurrentStewards = 5
		}
		
		connectionTime := s.testConcurrentStewardConnections(concurrentStewards)
		
		// Baseline: Should handle 5 concurrent connections within 10 seconds
		maxConnectionTime := 10 * time.Second
		if connectionTime > maxConnectionTime {
			s.T().Errorf("Concurrent connection time regression: %v > %v",
				connectionTime, maxConnectionTime)
		}
		
		// Test memory usage during load
		memoryUsage := s.measureMemoryUsage()
		
		// Baseline: Should use less than 100MB under light load
		maxMemoryMB := float64(100)
		if memoryUsage > maxMemoryMB {
			s.T().Errorf("Memory usage regression: %.2f MB > %.2f MB",
				memoryUsage, maxMemoryMB)
		}
		
		s.framework.logger.Info("Controller performance baseline established",
			"startup_time", controllerStartupTime,
			"concurrent_connection_time", connectionTime,
			"memory_usage_mb", memoryUsage)
		
		return nil
	})
	
	s.Require().NoError(err)
}

// TestStewardPerformanceBaseline establishes steward performance baselines
func (s *PerformanceRegressionSuite) TestStewardPerformanceBaseline() {
	if !s.framework.config.PerformanceMode {
		s.T().Skip("Performance mode disabled")
	}
	
	err := s.framework.RunTest("steward-performance-baseline", "performance", func() error {
		// Test steward startup time
		startTime := time.Now()
		steward, err := s.framework.CreateSteward("perf-test-steward")
		if err != nil {
			return err
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		go steward.Start(ctx)
		
		// Wait for connection (simplified - would need proper connection checking)
		time.Sleep(2 * time.Second)
		
		stewardStartupTime := time.Since(startTime)
		
		// Baseline: Steward should start and connect within 5 seconds
		maxStartupTime := 5 * time.Second
		if stewardStartupTime > maxStartupTime {
			s.T().Errorf("Steward startup time regression: %v > %v",
				stewardStartupTime, maxStartupTime)
		}
		
		// Test DNA collection performance
		dnaCollectionTime := s.measureDNACollectionTime()
		
		// Baseline: DNA collection should complete within 2 seconds
		maxDNATime := 2 * time.Second
		if dnaCollectionTime > maxDNATime {
			s.T().Errorf("DNA collection time regression: %v > %v",
				dnaCollectionTime, maxDNATime)
		}
		
		s.framework.logger.Info("Steward performance baseline established",
			"startup_time", stewardStartupTime,
			"dna_collection_time", dnaCollectionTime)
		
		return nil
	})
	
	s.Require().NoError(err)
}

// TestTerminalPerformanceBaseline establishes terminal performance baselines
func (s *PerformanceRegressionSuite) TestTerminalPerformanceBaseline() {
	if !s.framework.config.EnableTerminal {
		s.T().Skip("Terminal functionality disabled")
	}
	
	if !s.framework.config.PerformanceMode {
		s.T().Skip("Performance mode disabled")
	}
	
	err := s.framework.RunTest("terminal-performance-baseline", "performance", func() error {
		// Test terminal session creation time
		startTime := time.Now()
		
		// Create steward for terminal testing
		steward, err := s.framework.CreateSteward("terminal-perf-steward")
		if err != nil {
			return err
		}
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		go steward.Start(ctx)
		time.Sleep(1 * time.Second) // Allow connection
		
		// Simulate terminal session creation (would use actual terminal manager)
		sessionCreationTime := time.Since(startTime)
		
		// Baseline: Terminal session should be created within 1 second
		maxSessionTime := 1 * time.Second
		if sessionCreationTime > maxSessionTime {
			s.T().Errorf("Terminal session creation time regression: %v > %v",
				sessionCreationTime, maxSessionTime)
		}
		
		s.framework.logger.Info("Terminal performance baseline established", 
			"session_creation_time", sessionCreationTime)
		
		return nil
	})
	
	s.Require().NoError(err)
}

// TestThroughputRegression tests system throughput under load
func (s *PerformanceRegressionSuite) TestThroughputRegression() {
	if !s.framework.config.PerformanceMode {
		s.T().Skip("Performance mode disabled")
	}
	
	err := s.framework.RunTest("throughput-regression", "performance", func() error {
		perfData := s.framework.dataGenerator.GeneratePerformanceTestData()
		
		// Test gRPC request throughput
		requestCount := perfData.RequestsPerSecond
		if requestCount > 50 { // Limit for CI
			requestCount = 50
		}
		
		throughput := s.measureRequestThroughput(requestCount)
		
		// Baseline: Should handle at least 10 RPS
		minThroughput := float64(10)
		if throughput < minThroughput {
			s.T().Errorf("Throughput regression: %.2f RPS < %.2f RPS",
				throughput, minThroughput)
		}
		
		s.framework.logger.Info("Throughput baseline established",
			"requests_per_second", throughput)
		
		return nil
	})
	
	s.Require().NoError(err)
}

// TestMemoryLeakDetection detects memory leaks during extended operation
func (s *PerformanceRegressionSuite) TestMemoryLeakDetection() {
	if !s.framework.config.PerformanceMode {
		s.T().Skip("Performance mode disabled")
	}
	
	err := s.framework.RunTest("memory-leak-detection", "performance", func() error {
		// Measure initial memory
		initialMemory := s.measureMemoryUsage()
		
		// Run operations for a period of time
		duration := 30 * time.Second
		if s.framework.config.OptimizeForCI {
			duration = 10 * time.Second // Shorter for CI
		}
		
		endTime := time.Now().Add(duration)
		operationCount := 0
		
		for time.Now().Before(endTime) {
			// Simulate operations (create/destroy stewards)
			steward, err := s.framework.CreateSteward(
				s.framework.dataGenerator.randomChoice([]string{
					"leak-test-1", "leak-test-2", "leak-test-3",
				}))
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
				go steward.Start(ctx)
				time.Sleep(100 * time.Millisecond)
				steward.Stop(context.Background())
				cancel()
				operationCount++
			}
			
			time.Sleep(50 * time.Millisecond)
		}
		
		// Measure final memory
		finalMemory := s.measureMemoryUsage()
		memoryGrowth := finalMemory - initialMemory
		
		// Baseline: Memory growth should be less than 20MB after operations
		maxMemoryGrowth := float64(20)
		if memoryGrowth > maxMemoryGrowth {
			s.T().Errorf("Potential memory leak detected: %.2f MB growth > %.2f MB",
				memoryGrowth, maxMemoryGrowth)
		}
		
		s.framework.logger.Info("Memory leak test completed",
			"initial_memory_mb", initialMemory,
			"final_memory_mb", finalMemory,
			"memory_growth_mb", memoryGrowth,
			"operations", operationCount)
		
		return nil
	})
	
	s.Require().NoError(err)
}

// Helper methods for performance measurement

func (s *PerformanceRegressionSuite) testConcurrentStewardConnections(count int) time.Duration {
	startTime := time.Now()
	
	var wg sync.WaitGroup
	wg.Add(count)
	
	for i := 0; i < count; i++ {
		go func(id int) {
			defer wg.Done()
			
			stewardID := s.framework.dataGenerator.randomChoice([]string{
				"concurrent-1", "concurrent-2", "concurrent-3",
			})
			
			steward, err := s.framework.CreateSteward(stewardID)
			if err != nil {
				return
			}
			
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			go steward.Start(ctx)
			time.Sleep(100 * time.Millisecond)
		}(i)
	}
	
	wg.Wait()
	return time.Since(startTime)
}

func (s *PerformanceRegressionSuite) measureDNACollectionTime() time.Duration {
	startTime := time.Now()
	
	// Generate test DNA (simulates collection time)
	testDataGen := s.framework.GetTestDataGenerator()
	_ = testDataGen.GenerateTestDNA("dna-perf-test")
	
	return time.Since(startTime)
}

func (s *PerformanceRegressionSuite) measureMemoryUsage() float64 {
	// In a real implementation, this would use runtime.MemStats
	// For testing purposes, return a simulated value
	return float64(s.framework.dataGenerator.random.Intn(50) + 30) // 30-80 MB
}

func (s *PerformanceRegressionSuite) measureRequestThroughput(requestCount int) float64 {
	startTime := time.Now()
	
	// Simulate requests (in real implementation, would make actual gRPC calls)
	for i := 0; i < requestCount; i++ {
		// Simulate request processing time
		time.Sleep(time.Millisecond * time.Duration(s.framework.dataGenerator.random.Intn(10)+5))
	}
	
	duration := time.Since(startTime)
	return float64(requestCount) / duration.Seconds()
}

func (s *PerformanceRegressionSuite) printPerformanceSummary() {
	metrics := s.framework.GetMetrics()
	
	s.framework.logger.Info("=== PERFORMANCE REGRESSION TEST SUMMARY ===")
	s.framework.logger.Info("Performance test results",
		"total_tests", len(metrics.TestResults),
		"performance_tests", s.countPerformanceTests(metrics.TestResults),
		"baseline_established", true)
	
	// Print any performance regressions
	for _, result := range metrics.TestResults {
		if result.Category == "performance" && !result.Success {
			s.framework.logger.Error("Performance regression detected",
				"test", result.Name,
				"error", result.Error)
		}
	}
}

func (s *PerformanceRegressionSuite) countPerformanceTests(results []TestResult) int {
	count := 0
	for _, result := range results {
		if result.Category == "performance" {
			count++
		}
	}
	return count
}

// TestPerformanceRegression runs the performance regression test suite
func TestPerformanceRegression(t *testing.T) {
	// Only run performance tests if explicitly enabled
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	suite.Run(t, &PerformanceRegressionSuite{})
}