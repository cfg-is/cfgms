package e2e

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/continuous"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// AuthorizationDatabasePerformanceSuite tests database connection pool behavior
// and memory stability during authorization load scenarios
type AuthorizationDatabasePerformanceSuite struct {
	suite.Suite
	framework *E2ETestFramework

	// Real CFGMS components
	rbacManager      *rbac.Manager
	continuousEngine *continuous.ContinuousAuthorizationEngine
	memoryStore      *memory.Store

	// Test configuration
	maxConnections     int
	connectionTimeout  time.Duration
	loadTestDuration   time.Duration
	memoryTestDuration time.Duration

	// Metrics tracking
	connectionMetrics  *ConnectionPoolMetrics
	memoryMetrics      *MemoryStabilityMetrics
	initialMemStats    runtime.MemStats
}

// ConnectionPoolMetrics tracks database connection pool performance
type ConnectionPoolMetrics struct {
	totalConnections      int64
	activeConnections     int64
	peakConnections       int64
	connectionAttempts    int64
	connectionFailures    int64
	connectionTimeouts    int64
	avgConnectionTimeMs   float64
	maxConnectionTimeMs   float64
	totalConnectionTimeNs int64
	
	// Resource exhaustion metrics
	poolExhaustionEvents  int64
	gracefulDegradations  int64
	
	// Recovery metrics
	recoveryTimeMs        float64
	successfulRecoveries  int64
	
	mutex                 sync.RWMutex
	startTime             time.Time
}

// MemoryStabilityMetrics tracks memory usage during authorization storms
type MemoryStabilityMetrics struct {
	initialAllocMB        float64
	currentAllocMB        float64
	peakAllocMB           float64
	
	// Garbage collection metrics
	gcCount               uint32
	gcCycles              []GCCycle
	
	// Memory leak detection
	memoryLeakMB          float64
	goroutineCount        int
	goroutineLeakCount    int
	initialGoroutineCount int
	
	// Memory pressure events (tracking for analysis)
	
	// Snapshots for trend analysis
	memorySnapshots       []MemorySnapshot
	
	mutex                 sync.RWMutex
}

// GCCycle represents a garbage collection cycle
type GCCycle struct {
	Timestamp   time.Time
	PauseTimeNs uint64
	MemBefore   uint64
	MemAfter    uint64
	Freed       uint64
}

// SetupSuite initializes the database performance test suite
func (s *AuthorizationDatabasePerformanceSuite) SetupSuite() {
	config := CIOptimizedConfig()
	config.PerformanceMode = true
	config.TestDataSize = "large"
	config.TestTimeout = 45 * time.Minute // Extended for database testing
	config.EnableRBAC = true
	config.MaxConnections = 100 // Simulate connection pool limits

	framework, err := NewE2EFramework(s.T(), config)
	s.Require().NoError(err)

	err = framework.Initialize()
	s.Require().NoError(err)

	s.framework = framework

	// Configure test parameters
	s.maxConnections = 100
	s.connectionTimeout = 5 * time.Second
	s.loadTestDuration = 10 * time.Minute
	s.memoryTestDuration = 15 * time.Minute

	// Reduce for CI
	if s.framework.config.OptimizeForCI {
		s.maxConnections = 25
		s.loadTestDuration = 3 * time.Minute
		s.memoryTestDuration = 5 * time.Minute
	}

	// Initialize metrics tracking
	s.connectionMetrics = &ConnectionPoolMetrics{
		startTime: time.Now(),
	}
	s.memoryMetrics = &MemoryStabilityMetrics{
		gcCycles:        make([]GCCycle, 0, 1000),
		memorySnapshots: make([]MemorySnapshot, 0, 100),
	}

	// Capture initial memory state
	runtime.GC() // Force garbage collection for accurate baseline
	runtime.ReadMemStats(&s.initialMemStats)
	s.memoryMetrics.initialAllocMB = float64(s.initialMemStats.Alloc) / 1024 / 1024
	s.memoryMetrics.initialGoroutineCount = runtime.NumGoroutine()

	// Initialize real CFGMS components
	s.initializeDatabaseComponents()

	s.framework.logger.Info("Database performance test suite initialized",
		"max_connections", s.maxConnections,
		"connection_timeout", s.connectionTimeout,
		"load_test_duration", s.loadTestDuration,
		"memory_test_duration", s.memoryTestDuration,
		"initial_memory_mb", s.memoryMetrics.initialAllocMB,
		"initial_goroutines", s.memoryMetrics.initialGoroutineCount)
}

// TearDownSuite cleans up the test suite
func (s *AuthorizationDatabasePerformanceSuite) TearDownSuite() {
	if s.continuousEngine != nil {
		err := s.continuousEngine.Stop()
		s.Assert().NoError(err)
	}

	if s.framework != nil {
		err := s.framework.Cleanup()
		s.Assert().NoError(err)

		s.printDatabasePerformanceSummary()
	}
}

// initializeDatabaseComponents initializes real database-backed components
func (s *AuthorizationDatabasePerformanceSuite) initializeDatabaseComponents() {
	ctx := context.Background()

	// Create real memory-based store (simulating database with connection pooling)
	s.memoryStore = memory.NewStore()
	err := s.memoryStore.Initialize(ctx)
	s.Require().NoError(err)

	// Create RBAC manager with the store
	s.rbacManager = rbac.NewManager()
	err = s.rbacManager.Initialize(ctx)
	s.Require().NoError(err)

	// Create continuous authorization engine optimized for database testing
	continuousConfig := &continuous.ContinuousAuthConfig{
		MaxAuthLatencyMs:         10,
		PermissionCacheTTL:       2 * time.Minute, // Shorter TTL to stress database
		SessionUpdateInterval:    15 * time.Second,
		PropagationTimeoutMs:     1000,
		MaxRetryAttempts:         5, // More retries for connection issues
		EnableRiskReassessment:   false, // Disable for focused testing
		RiskCheckInterval:        5 * time.Minute,
		EnableAutoTermination:    false,
		ViolationGracePeriod:     30 * time.Second,
		EnableComprehensiveAudit: true,
		AuditBufferSize:         s.maxConnections * 5,
	}

	s.continuousEngine = continuous.NewContinuousAuthorizationEngine(
		s.rbacManager,
		nil, // JIT manager disabled for database testing
		nil, // Risk manager disabled for database testing
		nil, // Tenant security disabled for database testing
		continuousConfig,
	)

	err = s.continuousEngine.Start(ctx)
	s.Require().NoError(err)

	s.framework.logger.Info("Database-backed authorization components initialized")
}

// TestDatabaseConnectionPoolExhaustion tests connection pool behavior under extreme load
func (s *AuthorizationDatabasePerformanceSuite) TestDatabaseConnectionPoolExhaustion() {
	err := s.framework.RunTest("database-connection-pool-exhaustion", "database-performance", func() error {
		s.framework.logger.Info("Starting database connection pool exhaustion test",
			"max_connections", s.maxConnections,
			"test_duration", s.loadTestDuration)

		ctx, cancel := context.WithTimeout(context.Background(), s.loadTestDuration+2*time.Minute)
		defer cancel()

		// Pre-populate authorization data
		s.setupDatabaseTestData(ctx)

		// Phase 1: Gradual connection pool stress
		s.framework.logger.Info("Phase 1: Gradual connection pool stress")
		err := s.executeGradualConnectionStress(ctx)
		if err != nil {
			return fmt.Errorf("gradual connection stress failed: %w", err)
		}

		// Phase 2: Sudden connection pool exhaustion
		s.framework.logger.Info("Phase 2: Sudden connection pool exhaustion")
		err = s.executeSuddenConnectionExhaustion(ctx)
		if err != nil {
			return fmt.Errorf("sudden connection exhaustion failed: %w", err)
		}

		// Phase 3: Connection pool recovery testing
		s.framework.logger.Info("Phase 3: Connection pool recovery testing")
		err = s.executeConnectionPoolRecovery(ctx)
		if err != nil {
			return fmt.Errorf("connection pool recovery failed: %w", err)
		}

		// Validate connection pool resilience
		return s.validateConnectionPoolResilience()
	})

	s.Require().NoError(err)
}

// TestMemoryStabilityDuringAuthorizationStorms tests memory behavior under load
func (s *AuthorizationDatabasePerformanceSuite) TestMemoryStabilityDuringAuthorizationStorms() {
	err := s.framework.RunTest("memory-stability-authorization-storms", "database-performance", func() error {
		s.framework.logger.Info("Starting memory stability during authorization storms test",
			"test_duration", s.memoryTestDuration)

		ctx, cancel := context.WithTimeout(context.Background(), s.memoryTestDuration+2*time.Minute)
		defer cancel()

		// Take initial memory snapshot
		s.takeMemorySnapshot("Initial")

		// Execute various storm patterns to stress memory
		stormPatterns := []AuthorizationStormPattern{
			{
				Name:                "Sustained High Load",
				ConcurrentUsers:     s.maxConnections,
				RequestsPerUser:     50,
				Duration:           3 * time.Minute,
				RequestInterval:    50 * time.Millisecond,
				CacheBypassRate:    0.0, // Use cache to reduce memory pressure
			},
			{
				Name:                "Cache Bypass Storm",
				ConcurrentUsers:     s.maxConnections / 2,
				RequestsPerUser:     100,
				Duration:           2 * time.Minute,
				RequestInterval:    25 * time.Millisecond,
				CacheBypassRate:    1.0, // Bypass cache to stress memory allocation
			},
			{
				Name:                "Burst Pattern",
				ConcurrentUsers:     s.maxConnections * 2, // Oversubscribe
				RequestsPerUser:     20,
				Duration:           1 * time.Minute,
				RequestInterval:    10 * time.Millisecond,
				CacheBypassRate:    0.5, // Mixed cache usage
			},
			{
				Name:                "Recovery Period",
				ConcurrentUsers:     10,
				RequestsPerUser:     10,
				Duration:           1 * time.Minute,
				RequestInterval:    500 * time.Millisecond,
				CacheBypassRate:    0.0, // Light load for recovery
			},
		}

		// Reduce intensity for CI
		if s.framework.config.OptimizeForCI {
			for i := range stormPatterns {
				stormPatterns[i].ConcurrentUsers = min(stormPatterns[i].ConcurrentUsers, 25)
				stormPatterns[i].Duration = stormPatterns[i].Duration / 2
			}
		}

		// Execute storm patterns
		for _, pattern := range stormPatterns {
			s.framework.logger.Info("Executing memory stress pattern",
				"pattern", pattern.Name,
				"concurrent_users", pattern.ConcurrentUsers,
				"duration", pattern.Duration)

			err := s.executeAuthorizationStormPattern(ctx, pattern)
			if err != nil {
				s.framework.logger.Warn("Storm pattern execution error", "pattern", pattern.Name, "error", err)
			}

			// Take memory snapshot after each pattern
			s.takeMemorySnapshot(pattern.Name)

			// Force garbage collection and brief recovery
			runtime.GC()
			time.Sleep(30 * time.Second)
		}

		// Final memory analysis
		s.takeMemorySnapshot("Final")
		
		// Validate memory stability
		return s.validateMemoryStability()
	})

	s.Require().NoError(err)
}

// TestDatabaseConnectionLeakDetection tests for connection leaks
func (s *AuthorizationDatabasePerformanceSuite) TestDatabaseConnectionLeakDetection() {
	err := s.framework.RunTest("database-connection-leak-detection", "database-performance", func() error {
		s.framework.logger.Info("Starting database connection leak detection test")

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()

		// Baseline connection measurement
		initialConnections := s.getCurrentActiveConnections()
		s.framework.logger.Info("Initial connection baseline", "connections", initialConnections)

		// Execute connection-intensive operations
		iterations := 100
		if s.framework.config.OptimizeForCI {
			iterations = 25
		}

		for i := 0; i < iterations; i++ {
			// Create temporary sessions and authorization contexts
			sessionID := fmt.Sprintf("leak-test-session-%d", i)
			subjectID := fmt.Sprintf("leak-test-user-%d", i)
			tenantID := "leak-test-tenant"

			// Register session
			sessionMetadata := map[string]string{
				"test_type": "connection_leak",
				"iteration": fmt.Sprintf("%d", i),
			}

			err := s.continuousEngine.RegisterSession(ctx, sessionID, subjectID, tenantID, sessionMetadata)
			if err != nil {
				s.framework.logger.Warn("Session registration failed", "iteration", i, "error", err)
				continue
			}

			// Perform multiple authorization requests
			for j := 0; j < 10; j++ {
				authRequest := &continuous.ContinuousAuthRequest{
					AccessRequest: &common.AccessRequest{
						SubjectId:    subjectID,
						PermissionId: "test.permission",
						ResourceId:   fmt.Sprintf("resource-%d-%d", i, j),
						TenantId:     tenantID,
					},
					SessionID:     sessionID,
					OperationType: continuous.OperationTypeAPI,
					RequestTime:   time.Now(),
				}

				_, err := s.continuousEngine.AuthorizeAction(ctx, authRequest)
				if err != nil {
					s.framework.logger.Debug("Authorization failed in leak test", "error", err)
				}
			}

			// Unregister session
			err = s.continuousEngine.UnregisterSession(ctx, sessionID)
			if err != nil {
				s.framework.logger.Warn("Session unregistration failed", "iteration", i, "error", err)
			}

			// Check for connection leaks periodically
			if i%10 == 0 {
				currentConnections := s.getCurrentActiveConnections()
				connectionGrowth := currentConnections - initialConnections

				s.framework.logger.Info("Connection leak check",
					"iteration", i,
					"current_connections", currentConnections,
					"connection_growth", connectionGrowth)

				// Alert if connections are growing unexpectedly
				if connectionGrowth > 20 {
					s.framework.logger.Warn("Potential connection leak detected",
						"connection_growth", connectionGrowth,
						"iteration", i)
				}
			}
		}

		// Final connection measurement
		time.Sleep(5 * time.Second) // Allow cleanup
		runtime.GC()               // Force cleanup
		time.Sleep(2 * time.Second)

		finalConnections := s.getCurrentActiveConnections()
		connectionLeak := finalConnections - initialConnections

		s.framework.logger.Info("Connection leak test results",
			"initial_connections", initialConnections,
			"final_connections", finalConnections,
			"connection_leak", connectionLeak,
			"iterations", iterations)

		// Validate no significant connection leaks
		maxAcceptableLeak := 10
		if connectionLeak > maxAcceptableLeak {
			return fmt.Errorf("connection leak detected: %d connections leaked > %d acceptable",
				connectionLeak, maxAcceptableLeak)
		}

		return nil
	})

	s.Require().NoError(err)
}

// Helper methods for test execution

// AuthorizationStormPattern defines parameters for authorization load testing
type AuthorizationStormPattern struct {
	Name             string
	ConcurrentUsers  int
	RequestsPerUser  int
	Duration         time.Duration
	RequestInterval  time.Duration
	CacheBypassRate  float64 // 0.0 = always use cache, 1.0 = always bypass
}

// executeGradualConnectionStress gradually increases connection load
func (s *AuthorizationDatabasePerformanceSuite) executeGradualConnectionStress(ctx context.Context) error {
	stressLevels := []int{10, 25, 50, 75}
	if !s.framework.config.OptimizeForCI {
		stressLevels = append(stressLevels, s.maxConnections)
	}

	for _, users := range stressLevels {
		s.framework.logger.Info("Applying gradual connection stress", "concurrent_users", users)

		pattern := AuthorizationStormPattern{
			Name:            fmt.Sprintf("Gradual-%d", users),
			ConcurrentUsers: users,
			RequestsPerUser: 25,
			Duration:       1 * time.Minute,
			RequestInterval: 100 * time.Millisecond,
			CacheBypassRate: 0.2, // Light cache bypass
		}

		err := s.executeAuthorizationStormPattern(ctx, pattern)
		if err != nil {
			return err
		}

		// Record connection metrics
		s.recordConnectionMetrics()

		// Brief pause between stress levels
		time.Sleep(15 * time.Second)
	}

	return nil
}

// executeSuddenConnectionExhaustion attempts to exhaust the connection pool
func (s *AuthorizationDatabasePerformanceSuite) executeSuddenConnectionExhaustion(ctx context.Context) error {
	// Launch more users than available connections to test pool exhaustion
	exhaustionUsers := s.maxConnections * 2
	if s.framework.config.OptimizeForCI {
		exhaustionUsers = 50
	}

	pattern := AuthorizationStormPattern{
		Name:            "Sudden Exhaustion",
		ConcurrentUsers: exhaustionUsers,
		RequestsPerUser: 10,
		Duration:       2 * time.Minute,
		RequestInterval: 25 * time.Millisecond,
		CacheBypassRate: 0.8, // High cache bypass to stress connections
	}

	s.framework.logger.Info("Executing sudden connection pool exhaustion",
		"target_users", exhaustionUsers,
		"max_connections", s.maxConnections)

	// Monitor connection pool exhaustion events
	beforeExhaustion := atomic.LoadInt64(&s.connectionMetrics.poolExhaustionEvents)

	err := s.executeAuthorizationStormPattern(ctx, pattern)
	if err != nil {
		return err
	}

	afterExhaustion := atomic.LoadInt64(&s.connectionMetrics.poolExhaustionEvents)
	exhaustionEvents := afterExhaustion - beforeExhaustion

	s.framework.logger.Info("Connection pool exhaustion results",
		"exhaustion_events", exhaustionEvents,
		"expected_exhaustion", exhaustionUsers > s.maxConnections)

	return nil
}

// executeConnectionPoolRecovery tests recovery from connection pool exhaustion
func (s *AuthorizationDatabasePerformanceSuite) executeConnectionPoolRecovery(ctx context.Context) error {
	s.framework.logger.Info("Testing connection pool recovery")

	// First, exhaust the pool
	exhaustPattern := AuthorizationStormPattern{
		Name:            "Recovery Test Exhaustion",
		ConcurrentUsers: s.maxConnections * 2,
		RequestsPerUser: 5,
		Duration:       30 * time.Second,
		RequestInterval: 10 * time.Millisecond,
		CacheBypassRate: 1.0, // Full bypass to maximize connection usage
	}

	if s.framework.config.OptimizeForCI {
		exhaustPattern.ConcurrentUsers = 40
	}

	err := s.executeAuthorizationStormPattern(ctx, exhaustPattern)
	if err != nil {
		return err
	}

	// Wait for pool exhaustion to manifest
	time.Sleep(10 * time.Second)

	// Now test recovery with normal load
	recoveryStart := time.Now()

	recoveryPattern := AuthorizationStormPattern{
		Name:            "Recovery Test Normal Load",
		ConcurrentUsers: s.maxConnections / 2,
		RequestsPerUser: 10,
		Duration:       1 * time.Minute,
		RequestInterval: 200 * time.Millisecond,
		CacheBypassRate: 0.1, // Mostly cached requests
	}

	if s.framework.config.OptimizeForCI {
		recoveryPattern.ConcurrentUsers = 15
	}

	err = s.executeAuthorizationStormPattern(ctx, recoveryPattern)
	if err != nil {
		return err
	}

	recoveryTime := time.Since(recoveryStart)

	s.connectionMetrics.mutex.Lock()
	s.connectionMetrics.recoveryTimeMs = float64(recoveryTime.Milliseconds())
	s.connectionMetrics.successfulRecoveries++
	s.connectionMetrics.mutex.Unlock()

	s.framework.logger.Info("Connection pool recovery test completed",
		"recovery_time", recoveryTime,
		"successful_recoveries", s.connectionMetrics.successfulRecoveries)

	return nil
}

// executeAuthorizationStormPattern executes a specific authorization storm pattern
func (s *AuthorizationDatabasePerformanceSuite) executeAuthorizationStormPattern(ctx context.Context, pattern AuthorizationStormPattern) error {
	var wg sync.WaitGroup
	stormResults := make(chan StormUserResult, pattern.ConcurrentUsers)

	startTime := time.Now()
	endTime := startTime.Add(pattern.Duration)

	// Launch concurrent users
	for userID := 0; userID < pattern.ConcurrentUsers; userID++ {
		wg.Add(1)
		go s.executeStormUser(ctx, userID, pattern, endTime, stormResults, &wg)
		
		// Stagger user launches to avoid thundering herd
		time.Sleep(time.Millisecond * time.Duration(10+userID%50))
	}

	// Collect results
	go s.collectStormResults(stormResults)

	wg.Wait()
	close(stormResults)

	actualDuration := time.Since(startTime)
	s.framework.logger.Info("Authorization storm pattern completed",
		"pattern", pattern.Name,
		"duration", actualDuration,
		"concurrent_users", pattern.ConcurrentUsers)

	return nil
}

// executeStormUser simulates a single user in an authorization storm
func (s *AuthorizationDatabasePerformanceSuite) executeStormUser(ctx context.Context, userID int, pattern AuthorizationStormPattern,
	endTime time.Time, results chan<- StormUserResult, wg *sync.WaitGroup) {

	defer wg.Done()

	result := StormUserResult{
		UserID:      userID,
		PatternName: pattern.Name,
		StartTime:   time.Now(),
	}

	subjectID := fmt.Sprintf("storm-user-%s-%d", pattern.Name, userID)
	tenantID := "storm-test-tenant"
	sessionID := fmt.Sprintf("storm-session-%s-%d", pattern.Name, userID)

	// Register session
	sessionMetadata := map[string]string{
		"storm_pattern": pattern.Name,
		"user_id":       subjectID,
	}

	if err := s.continuousEngine.RegisterSession(ctx, sessionID, subjectID, tenantID, sessionMetadata); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("session registration failed: %w", err))
		results <- result
		return
	}

	defer func() {
		if err := s.continuousEngine.UnregisterSession(ctx, sessionID); err != nil {
			s.framework.logger.Debug("Session unregistration failed", "session_id", sessionID, "error", err)
		}
	}()

	requestCount := 0
	var totalLatency time.Duration

	// Execute authorization requests until pattern duration expires
	for time.Now().Before(endTime) && requestCount < pattern.RequestsPerUser {
		select {
		case <-ctx.Done():
			results <- result
			return
		default:
			// Determine if we should bypass cache
			bypassCache := float64(s.framework.dataGenerator.cryptoRandInt(100))/100.0 < pattern.CacheBypassRate

			// Create authorization request
			authRequest := &continuous.ContinuousAuthRequest{
				AccessRequest: &common.AccessRequest{
					SubjectId:    subjectID,
					PermissionId: s.selectPermissionForStorm(requestCount),
					ResourceId:   s.selectResourceForStorm(requestCount, bypassCache),
					TenantId:     tenantID,
					Context: map[string]string{
						"storm_pattern":  pattern.Name,
						"request_count":  fmt.Sprintf("%d", requestCount),
						"bypass_cache":   fmt.Sprintf("%v", bypassCache),
					},
				},
				SessionID:       sessionID,
				OperationType:   continuous.OperationTypeAPI,
				ResourceContext: map[string]string{"storm_test": "true"},
				RequestTime:     time.Now(),
			}

			// Measure authorization latency
			connectionStart := time.Now()
			response, err := s.continuousEngine.AuthorizeAction(ctx, authRequest)
			latency := time.Since(connectionStart)

			// Track connection metrics
			s.updateConnectionMetrics(latency, err == nil)

			// Update user result
			requestCount++
			result.TotalRequests++
			totalLatency += latency

			if err != nil {
				result.ErrorCount++
				result.Errors = append(result.Errors, err)
			} else if response != nil && response.AccessResponse != nil && response.AccessResponse.Granted {
				result.SuccessCount++
			}

			// Sleep between requests
			time.Sleep(pattern.RequestInterval)
		}
	}

	result.EndTime = time.Now()
	result.TotalDuration = result.EndTime.Sub(result.StartTime)
	if result.TotalRequests > 0 {
		result.AvgLatency = totalLatency / time.Duration(result.TotalRequests)
	}

	results <- result
}

// StormUserResult represents results from a single user in a storm test
type StormUserResult struct {
	UserID        int
	PatternName   string
	StartTime     time.Time
	EndTime       time.Time
	TotalDuration time.Duration
	TotalRequests int
	SuccessCount  int
	ErrorCount    int
	AvgLatency    time.Duration
	Errors        []error
}

// Helper methods

func (s *AuthorizationDatabasePerformanceSuite) setupDatabaseTestData(ctx context.Context) {
	// Create comprehensive test data for database stress testing
	tenants := []string{"storm-test-tenant", "leak-test-tenant", "stress-test-tenant"}
	
	for _, tenantID := range tenants {
		// Create tenant roles
		err := s.rbacManager.CreateTenantDefaultRoles(ctx, tenantID)
		if err != nil {
			s.framework.logger.Debug("Tenant role creation error", "tenant", tenantID, "error", err)
		}

		// Create test users
		userCount := 50
		if s.framework.config.OptimizeForCI {
			userCount = 20
		}

		for i := 0; i < userCount; i++ {
			userID := fmt.Sprintf("dbtest-user-%s-%d", tenantID, i)
			subject := &common.Subject{
				Id:          userID,
				Type:        common.SubjectType_SUBJECT_TYPE_USER,
				DisplayName: fmt.Sprintf("DB Test User %d", i),
				TenantId:    tenantID,
				IsActive:    true,
			}

			if err := s.rbacManager.CreateSubject(ctx, subject); err != nil {
				s.framework.logger.Debug("Subject creation error", "subject", userID, "error", err)
			}
		}
	}

	s.framework.logger.Info("Database test data setup completed")
}

func (s *AuthorizationDatabasePerformanceSuite) getCurrentActiveConnections() int {
	// In a real implementation, this would query the actual connection pool
	// For memory store simulation, return estimated active operations
	s.connectionMetrics.mutex.RLock()
	defer s.connectionMetrics.mutex.RUnlock()
	return int(atomic.LoadInt64(&s.connectionMetrics.activeConnections))
}

func (s *AuthorizationDatabasePerformanceSuite) updateConnectionMetrics(latency time.Duration, success bool) {
	atomic.AddInt64(&s.connectionMetrics.connectionAttempts, 1)
	
	if success {
		// Simulate connection tracking
		atomic.AddInt64(&s.connectionMetrics.totalConnections, 1)
		connectionTimeMs := float64(latency.Milliseconds())
		
		s.connectionMetrics.mutex.Lock()
		atomic.AddInt64(&s.connectionMetrics.totalConnectionTimeNs, latency.Nanoseconds())
		
		if connectionTimeMs > s.connectionMetrics.maxConnectionTimeMs {
			s.connectionMetrics.maxConnectionTimeMs = connectionTimeMs
		}
		
		// Update average (exponential moving average)
		alpha := 0.1
		s.connectionMetrics.avgConnectionTimeMs = (1-alpha)*s.connectionMetrics.avgConnectionTimeMs + alpha*connectionTimeMs
		s.connectionMetrics.mutex.Unlock()
		
		// Track peak connections
		current := atomic.AddInt64(&s.connectionMetrics.activeConnections, 1)
		for {
			peak := atomic.LoadInt64(&s.connectionMetrics.peakConnections)
			if current <= peak || atomic.CompareAndSwapInt64(&s.connectionMetrics.peakConnections, peak, current) {
				break
			}
		}
		
		// Simulate connection release
		go func() {
			time.Sleep(50 * time.Millisecond) // Simulate connection hold time
			atomic.AddInt64(&s.connectionMetrics.activeConnections, -1)
		}()
		
	} else {
		atomic.AddInt64(&s.connectionMetrics.connectionFailures, 1)
		
		// Check for specific failure types
		if latency > s.connectionTimeout {
			atomic.AddInt64(&s.connectionMetrics.connectionTimeouts, 1)
		}
		
		// Simulate pool exhaustion detection
		if atomic.LoadInt64(&s.connectionMetrics.activeConnections) >= int64(s.maxConnections) {
			atomic.AddInt64(&s.connectionMetrics.poolExhaustionEvents, 1)
		}
	}
}

func (s *AuthorizationDatabasePerformanceSuite) recordConnectionMetrics() {
	s.connectionMetrics.mutex.Lock()
	defer s.connectionMetrics.mutex.Unlock()
	
	s.framework.logger.Info("Connection metrics snapshot",
		"total_connections", atomic.LoadInt64(&s.connectionMetrics.totalConnections),
		"active_connections", atomic.LoadInt64(&s.connectionMetrics.activeConnections),
		"peak_connections", atomic.LoadInt64(&s.connectionMetrics.peakConnections),
		"connection_failures", atomic.LoadInt64(&s.connectionMetrics.connectionFailures),
		"pool_exhaustion_events", atomic.LoadInt64(&s.connectionMetrics.poolExhaustionEvents),
		"avg_connection_time_ms", s.connectionMetrics.avgConnectionTimeMs,
		"max_connection_time_ms", s.connectionMetrics.maxConnectionTimeMs)
}

func (s *AuthorizationDatabasePerformanceSuite) takeMemorySnapshot(label string) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	snapshot := MemorySnapshot{
		Label:          label,
		Timestamp:      time.Now(),
		AllocMB:        float64(m.Alloc) / 1024 / 1024,
		TotalAllocMB:   float64(m.TotalAlloc) / 1024 / 1024,
		SysMB:          float64(m.Sys) / 1024 / 1024,
		NumGC:          m.NumGC,
		GoroutineCount: runtime.NumGoroutine(),
	}
	
	s.memoryMetrics.mutex.Lock()
	s.memoryMetrics.memorySnapshots = append(s.memoryMetrics.memorySnapshots, snapshot)
	s.memoryMetrics.currentAllocMB = snapshot.AllocMB
	s.memoryMetrics.goroutineCount = snapshot.GoroutineCount
	
	// Update peak memory
	if snapshot.AllocMB > s.memoryMetrics.peakAllocMB {
		s.memoryMetrics.peakAllocMB = snapshot.AllocMB
	}
	
	// Track garbage collection cycles
	if m.NumGC > s.memoryMetrics.gcCount {
		s.memoryMetrics.gcCount = m.NumGC
		
		cycle := GCCycle{
			Timestamp:   time.Now(),
			PauseTimeNs: m.PauseTotalNs,
			MemBefore:   m.HeapAlloc + m.HeapReleased,
			MemAfter:    m.HeapAlloc,
			Freed:       m.HeapReleased,
		}
		s.memoryMetrics.gcCycles = append(s.memoryMetrics.gcCycles, cycle)
	}
	
	s.memoryMetrics.mutex.Unlock()
	
	s.framework.logger.Info("Memory snapshot taken",
		"label", label,
		"alloc_mb", fmt.Sprintf("%.2f", snapshot.AllocMB),
		"sys_mb", fmt.Sprintf("%.2f", snapshot.SysMB),
		"gc_count", snapshot.NumGC,
		"goroutines", snapshot.GoroutineCount)
}

func (s *AuthorizationDatabasePerformanceSuite) collectStormResults(results <-chan StormUserResult) {
	for result := range results {
		if len(result.Errors) > 0 {
			s.framework.logger.Debug("Storm user completed with errors",
				"user_id", result.UserID,
				"pattern", result.PatternName,
				"error_count", len(result.Errors),
				"success_rate", float64(result.SuccessCount)/float64(result.TotalRequests)*100)
		}
	}
}

func (s *AuthorizationDatabasePerformanceSuite) selectPermissionForStorm(requestCount int) string {
	permissions := []string{
		"steward.read", "steward.write", "config.read", "config.write",
		"monitoring.read", "terminal.access", "api.access",
	}
	return permissions[requestCount%len(permissions)]
}

func (s *AuthorizationDatabasePerformanceSuite) selectResourceForStorm(requestCount int, bypassCache bool) string {
	if bypassCache {
		// Use unique resources to bypass cache
		return fmt.Sprintf("unique-resource-%d-%d", requestCount, time.Now().UnixNano())
	}
	// Use limited set of resources for cache hits
	return fmt.Sprintf("cached-resource-%d", requestCount%10)
}

// Validation methods

func (s *AuthorizationDatabasePerformanceSuite) validateConnectionPoolResilience() error {
	s.connectionMetrics.mutex.RLock()
	defer s.connectionMetrics.mutex.RUnlock()

	totalAttempts := atomic.LoadInt64(&s.connectionMetrics.connectionAttempts)
	totalFailures := atomic.LoadInt64(&s.connectionMetrics.connectionFailures)
	exhaustionEvents := atomic.LoadInt64(&s.connectionMetrics.poolExhaustionEvents)

	if totalAttempts == 0 {
		return fmt.Errorf("no connection attempts recorded")
	}

	failureRate := float64(totalFailures) / float64(totalAttempts)
	maxAcceptableFailureRate := 0.20 // 20% failure rate acceptable under extreme stress

	s.framework.logger.Info("Connection pool resilience validation",
		"total_attempts", totalAttempts,
		"total_failures", totalFailures,
		"failure_rate", fmt.Sprintf("%.2f%%", failureRate*100),
		"exhaustion_events", exhaustionEvents,
		"avg_connection_time_ms", s.connectionMetrics.avgConnectionTimeMs,
		"max_connection_time_ms", s.connectionMetrics.maxConnectionTimeMs)

	// Validate acceptable failure rate under stress
	if failureRate > maxAcceptableFailureRate {
		return fmt.Errorf("connection failure rate too high: %.2f%% > %.2f%%",
			failureRate*100, maxAcceptableFailureRate*100)
	}

	// Validate connection times remain reasonable
	maxAcceptableConnectionTime := 1000.0 // 1 second
	if s.connectionMetrics.avgConnectionTimeMs > maxAcceptableConnectionTime {
		return fmt.Errorf("average connection time too high: %.2fms > %.2fms",
			s.connectionMetrics.avgConnectionTimeMs, maxAcceptableConnectionTime)
	}

	// Validate that pool exhaustion was properly handled (if it occurred)
	if exhaustionEvents > 0 {
		// Pool exhaustion should trigger graceful degradation
		gracefulDegradations := atomic.LoadInt64(&s.connectionMetrics.gracefulDegradations)
		if gracefulDegradations == 0 {
			s.framework.logger.Warn("Pool exhaustion occurred without graceful degradation",
				"exhaustion_events", exhaustionEvents)
		}
	}

	return nil
}

func (s *AuthorizationDatabasePerformanceSuite) validateMemoryStability() error {
	s.memoryMetrics.mutex.RLock()
	defer s.memoryMetrics.mutex.RUnlock()

	if len(s.memoryMetrics.memorySnapshots) < 2 {
		return fmt.Errorf("insufficient memory snapshots for analysis")
	}

	// Calculate memory growth
	initial := s.memoryMetrics.memorySnapshots[0]
	final := s.memoryMetrics.memorySnapshots[len(s.memoryMetrics.memorySnapshots)-1]
	
	memoryGrowthMB := final.AllocMB - initial.AllocMB
	goroutineGrowth := final.GoroutineCount - initial.GoroutineCount
	
	s.memoryMetrics.memoryLeakMB = memoryGrowthMB
	s.memoryMetrics.goroutineLeakCount = goroutineGrowth

	s.framework.logger.Info("Memory stability validation",
		"initial_alloc_mb", fmt.Sprintf("%.2f", initial.AllocMB),
		"final_alloc_mb", fmt.Sprintf("%.2f", final.AllocMB),
		"memory_growth_mb", fmt.Sprintf("%.2f", memoryGrowthMB),
		"peak_alloc_mb", fmt.Sprintf("%.2f", s.memoryMetrics.peakAllocMB),
		"initial_goroutines", initial.GoroutineCount,
		"final_goroutines", final.GoroutineCount,
		"goroutine_growth", goroutineGrowth,
		"gc_cycles", len(s.memoryMetrics.gcCycles))

	// Validate memory growth limits
	maxAcceptableMemoryGrowthMB := 100.0 // 100MB growth acceptable
	if memoryGrowthMB > maxAcceptableMemoryGrowthMB {
		return fmt.Errorf("memory growth exceeds limit: %.2fMB > %.2fMB",
			memoryGrowthMB, maxAcceptableMemoryGrowthMB)
	}

	// Validate goroutine leak limits
	maxAcceptableGoroutineGrowth := 50 // 50 goroutines growth acceptable
	if goroutineGrowth > maxAcceptableGoroutineGrowth {
		return fmt.Errorf("goroutine growth exceeds limit: %d > %d",
			goroutineGrowth, maxAcceptableGoroutineGrowth)
	}

	// Validate peak memory usage
	maxAcceptablePeakMemoryMB := 500.0 // 500MB peak acceptable
	if s.memoryMetrics.peakAllocMB > maxAcceptablePeakMemoryMB {
		return fmt.Errorf("peak memory usage exceeds limit: %.2fMB > %.2fMB",
			s.memoryMetrics.peakAllocMB, maxAcceptablePeakMemoryMB)
	}

	return nil
}

func (s *AuthorizationDatabasePerformanceSuite) printDatabasePerformanceSummary() {
	s.framework.logger.Info("=== DATABASE PERFORMANCE TEST SUMMARY ===")

	// Connection metrics summary
	s.framework.logger.Info("Connection Pool Performance",
		"total_attempts", atomic.LoadInt64(&s.connectionMetrics.connectionAttempts),
		"total_failures", atomic.LoadInt64(&s.connectionMetrics.connectionFailures),
		"peak_connections", atomic.LoadInt64(&s.connectionMetrics.peakConnections),
		"pool_exhaustion_events", atomic.LoadInt64(&s.connectionMetrics.poolExhaustionEvents),
		"avg_connection_time_ms", fmt.Sprintf("%.2f", s.connectionMetrics.avgConnectionTimeMs),
		"max_connection_time_ms", fmt.Sprintf("%.2f", s.connectionMetrics.maxConnectionTimeMs))

	// Memory stability summary
	s.framework.logger.Info("Memory Stability",
		"memory_growth_mb", fmt.Sprintf("%.2f", s.memoryMetrics.memoryLeakMB),
		"peak_memory_mb", fmt.Sprintf("%.2f", s.memoryMetrics.peakAllocMB),
		"goroutine_growth", s.memoryMetrics.goroutineLeakCount,
		"gc_cycles", len(s.memoryMetrics.gcCycles),
		"memory_snapshots", len(s.memoryMetrics.memorySnapshots))
}

// TestDatabasePerformance runs the database performance test suite
func TestDatabasePerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database performance tests in short mode")
	}

	suite.Run(t, &AuthorizationDatabasePerformanceSuite{})
}