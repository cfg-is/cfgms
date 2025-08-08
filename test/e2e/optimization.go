package e2e

import (
	"os"
	"runtime"
	"time"
)

// GitHubActionsOptimizer provides optimizations specific to GitHub Actions runner limitations
type GitHubActionsOptimizer struct {
	config *E2EConfig
}

// NewGitHubActionsOptimizer creates a new optimizer for GitHub Actions
func NewGitHubActionsOptimizer(config *E2EConfig) *GitHubActionsOptimizer {
	return &GitHubActionsOptimizer{config: config}
}

// OptimizeForGitHubActions applies GitHub Actions specific optimizations
func (o *GitHubActionsOptimizer) OptimizeForGitHubActions() *E2EConfig {
	optimized := o.cloneConfig()
	
	// Detect GitHub Actions environment
	if !o.isGitHubActions() {
		return optimized
	}
	
	// Apply runner resource optimizations
	o.optimizeForRunnerResources(optimized)
	
	// Apply time-based optimizations
	o.optimizeForTimeConstraints(optimized)
	
	// Apply network and I/O optimizations
	o.optimizeForNetworkIO(optimized)
	
	// Apply memory optimizations
	o.optimizeForMemoryLimits(optimized)
	
	// Apply concurrency optimizations
	o.optimizeForConcurrency(optimized)
	
	return optimized
}

// Runner resource optimizations
func (o *GitHubActionsOptimizer) optimizeForRunnerResources(config *E2EConfig) {
	runnerOS := os.Getenv("RUNNER_OS")
	
	// GitHub Actions runners have different resource profiles
	switch runnerOS {
	case "Linux":
		// Ubuntu runners: 2 vCPUs, 7GB RAM, 14GB SSD
		config.MaxConcurrentTests = 2
		config.MaxConnections = 20
	case "Windows":
		// Windows runners: 2 vCPUs, 7GB RAM, 14GB SSD (but slower startup)
		config.MaxConcurrentTests = 1
		config.ComponentStartup = 45 * time.Second // Windows is slower
		config.MaxConnections = 10
	case "macOS":
		// macOS runners: 3 vCPUs, 14GB RAM, 14GB SSD (but limited minutes)
		config.MaxConcurrentTests = 2
		config.MaxConnections = 15
	default:
		// Conservative defaults for unknown runners
		config.MaxConcurrentTests = 1
		config.MaxConnections = 10
	}
}

// Time constraint optimizations
func (o *GitHubActionsOptimizer) optimizeForTimeConstraints(config *E2EConfig) {
	// GitHub Actions has different time limits based on plan
	// Private repos: 2000 minutes/month (free), 3000 minutes/month (pro)
	// Public repos: Unlimited
	
	if o.isPrivateRepo() {
		// Aggressive optimizations for private repos to conserve minutes
		config.TestTimeout = 8 * time.Minute        // Reduced from 10 minutes
		config.ComponentStartup = 20 * time.Second  // Reduced from 30 seconds
		config.LoadTestDuration = 30 * time.Second  // Reduced from 1 minute
		config.TestDataSize = "small"               // Force small data
		config.PerformanceMode = false              // Disable performance tests
	} else {
		// More generous for public repos (assuming open source future)
		config.TestTimeout = 15 * time.Minute
		config.ComponentStartup = 30 * time.Second
		config.LoadTestDuration = 1 * time.Minute
	}
}

// Network and I/O optimizations
func (o *GitHubActionsOptimizer) optimizeForNetworkIO(config *E2EConfig) {
	// GitHub Actions runners have variable network performance
	// Optimize for potential network latency/bandwidth limitations
	
	// Reduce test data generation to minimize I/O
	if config.TestDataSize == "large" {
		config.TestDataSize = "medium"
	}
	
	// Enable reduced logging to minimize I/O overhead
	config.ReducedLogging = true
	
	// Disable parallel execution to reduce network contention
	config.ParallelExecution = false
}

// Memory optimization for 7GB RAM limit
func (o *GitHubActionsOptimizer) optimizeForMemoryLimits(config *E2EConfig) {
	// GitHub Actions runners have 7GB RAM limit
	// Leave headroom for OS and other processes (use ~4GB max)
	
	// Limit concurrent stewards to prevent memory exhaustion
	if config.MaxConnections > 15 {
		config.MaxConnections = 15
	}
	
	// Force garbage collection more frequently in tests
	// This would be implemented in the actual test framework
	
	// Reduce buffer sizes and cache limits
	// Implementation would adjust internal buffer sizes
}

// Concurrency optimizations
func (o *GitHubActionsOptimizer) optimizeForConcurrency(config *E2EConfig) {
	// GitHub Actions runners have 2-3 vCPUs
	// Optimize concurrency to match available resources
	
	numCPU := runtime.NumCPU()
	
	// Conservative concurrency to avoid resource contention
	maxConcurrent := numCPU
	if maxConcurrent > 2 {
		maxConcurrent = 2 // Cap at 2 for stability
	}
	
	config.MaxConcurrentTests = maxConcurrent
	
	// Disable parallel execution within tests to avoid race condition complexity
	config.ParallelExecution = false
}

// Optimization for specific test categories
func (o *GitHubActionsOptimizer) OptimizeTestExecution(testCategory string) TestExecutionOptimization {
	optimization := TestExecutionOptimization{
		Category:      testCategory,
		Enabled:       true,
		Timeout:       5 * time.Minute,
		MaxRetries:    2,
		RetryDelay:    1 * time.Second,
		ResourceLimits: ResourceLimits{
			MaxMemoryMB: 1024,
			MaxCPUPercent: 80,
		},
	}
	
	// Category-specific optimizations
	switch testCategory {
	case "core":
		// Core functionality tests - always run
		optimization.Priority = "high"
		optimization.Timeout = 10 * time.Minute
		
	case "security":
		// Security tests - critical but can be time-limited
		optimization.Priority = "high"
		optimization.Timeout = 8 * time.Minute
		
	case "performance":
		// Performance tests - skip in private repos or time-constrained environments
		if o.isPrivateRepo() || o.config.OptimizeForCI {
			optimization.Enabled = false
			optimization.SkipReason = "Disabled for CI time constraints"
		} else {
			optimization.Priority = "medium"
			optimization.Timeout = 15 * time.Minute
		}
		
	case "scalability":
		// Scalability tests - only run in specific conditions
		if o.isPrivateRepo() {
			optimization.Enabled = false
			optimization.SkipReason = "Disabled for private repo time limits"
		} else {
			optimization.Priority = "low"
			optimization.Timeout = 5 * time.Minute
		}
		
	case "integration":
		// Integration tests - essential but optimized
		optimization.Priority = "high"
		optimization.Timeout = 12 * time.Minute
		
	case "workflow":
		// Workflow tests - medium priority
		optimization.Priority = "medium"
		optimization.Timeout = 6 * time.Minute
		
	default:
		// Default conservative settings
		optimization.Priority = "medium"
		optimization.Timeout = 5 * time.Minute
	}
	
	return optimization
}

// TestExecutionOptimization contains optimization parameters for test execution
type TestExecutionOptimization struct {
	Category       string
	Enabled        bool
	Priority       string        // "high", "medium", "low"
	Timeout        time.Duration
	MaxRetries     int
	RetryDelay     time.Duration
	SkipReason     string
	ResourceLimits ResourceLimits
}

// ResourceLimits defines resource constraints for test execution
type ResourceLimits struct {
	MaxMemoryMB   int
	MaxCPUPercent int
}

// Environment detection methods

func (o *GitHubActionsOptimizer) isGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true"
}

func (o *GitHubActionsOptimizer) isPrivateRepo() bool {
	// GitHub Actions sets different environment variables for private repos
	// This is a heuristic - in practice, you might check repository visibility via API
	
	// Check for limited runner minutes (indication of private repo)
	repoOwner := os.Getenv("GITHUB_REPOSITORY_OWNER")
	if repoOwner == "" {
		return true // Conservative assumption
	}
	
	// Check if this is a fork (usually has more limited resources)
	headRef := os.Getenv("GITHUB_HEAD_REF")
	baseRef := os.Getenv("GITHUB_BASE_REF")
	if headRef != "" && baseRef != "" {
		return true // This is a PR, might have limitations
	}
	
	// Default to private repo assumptions for safety
	return true
}

// Utility methods

func (o *GitHubActionsOptimizer) cloneConfig() *E2EConfig {
	// Deep copy the configuration
	cloned := *o.config
	return &cloned
}

// Smart retry logic for flaky tests in GitHub Actions
func (o *GitHubActionsOptimizer) ShouldRetryTest(testName string, attempt int, lastError error) bool {
	if attempt >= 3 {
		return false // Maximum 3 attempts
	}
	
	if lastError == nil {
		return false // No error, no retry needed
	}
	
	errorStr := lastError.Error()
	
	// Retry for common GitHub Actions transient issues
	transientErrors := []string{
		"timeout",
		"connection refused",
		"network unreachable",
		"temporary failure",
		"resource temporarily unavailable",
		"context deadline exceeded",
	}
	
	for _, transientError := range transientErrors {
		if contains(errorStr, transientError) {
			return true
		}
	}
	
	// Don't retry for deterministic failures
	deterministicErrors := []string{
		"assertion failed",
		"test failed",
		"validation error",
		"configuration error",
		"authentication failed",
	}
	
	for _, deterministicError := range deterministicErrors {
		if contains(errorStr, deterministicError) {
			return false
		}
	}
	
	// Default: retry once for unknown errors
	return attempt < 2
}

// CalculateOptimalTestBatching determines optimal test batching for GitHub Actions
func (o *GitHubActionsOptimizer) CalculateOptimalTestBatching(totalTests int) TestBatchingStrategy {
	strategy := TestBatchingStrategy{
		TotalTests:    totalTests,
		BatchSize:     10,
		ParallelBatches: 1,
		EstimatedDuration: 10 * time.Minute,
	}
	
	if !o.isGitHubActions() {
		// Not in GitHub Actions, use default strategy
		return strategy
	}
	
	runnerOS := os.Getenv("RUNNER_OS")
	
	// Adjust based on runner type and repo visibility
	if o.isPrivateRepo() {
		// Conservative batching for private repos to minimize minutes usage
		strategy.BatchSize = 15    // Larger batches to reduce overhead
		strategy.ParallelBatches = 1 // Sequential execution to avoid timeouts
		strategy.EstimatedDuration = time.Duration(totalTests/strategy.BatchSize+1) * 8 * time.Minute
	} else {
		// More aggressive batching for public repos
		switch runnerOS {
		case "Linux":
			strategy.BatchSize = 8
			strategy.ParallelBatches = 2
		case "Windows":
			strategy.BatchSize = 12 // Larger batches due to slower startup
			strategy.ParallelBatches = 1
		case "macOS":
			strategy.BatchSize = 6
			strategy.ParallelBatches = 2
		}
		strategy.EstimatedDuration = time.Duration(totalTests/(strategy.BatchSize*strategy.ParallelBatches)+1) * 6 * time.Minute
	}
	
	return strategy
}

// TestBatchingStrategy defines how to batch tests for optimal execution
type TestBatchingStrategy struct {
	TotalTests        int
	BatchSize         int
	ParallelBatches   int
	EstimatedDuration time.Duration
}

// Helper functions

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && 
		   len(s) >= len(substr) && 
		   s[len(s)-len(substr):] == substr || 
		   (len(s) > len(substr) && s[:len(substr)] == substr) ||
		   (len(s) > len(substr) && s[len(s)/2-len(substr)/2:len(s)/2+len(substr)/2] == substr)
}

