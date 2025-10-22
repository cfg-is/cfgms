package dna

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestDirectoryDNAIntegration tests the complete DirectoryDNA system integration
func TestDirectoryDNAIntegration(t *testing.T) {
	// Set up real components (following CFGMS testing patterns)
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()

	// Create collector
	collector := NewDirectoryDNACollector(provider, logger)

	// Create drift detector
	driftDetector := NewDirectoryDriftDetector(logger)

	// Create storage using real backend implementations
	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	storage := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)

	// Create monitoring system
	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	t.Run("complete collection and storage workflow", func(t *testing.T) {
		// Step 1: Set up directory objects
		user := createTestUser("user1", "TestUser")
		group := createTestGroup("group1", "TestGroup")
		ou := createTestOU("ou1", "TestOU", "")

		provider.AddUser(user)
		provider.AddGroup(group)
		provider.AddOU(ou)

		// Step 2: Collect DNA for all objects
		userDNA, err := collector.CollectUserDNA(ctx, "user1")
		require.NoError(t, err)
		assert.NotNil(t, userDNA)

		groupDNA, err := collector.CollectGroupDNA(ctx, "group1")
		require.NoError(t, err)
		assert.NotNil(t, groupDNA)

		ouDNA, err := collector.CollectOUDNA(ctx, "ou1")
		require.NoError(t, err)
		assert.NotNil(t, ouDNA)

		// Step 3: Store DNA records
		err = storage.StoreDirectoryDNA(ctx, userDNA)
		require.NoError(t, err)

		err = storage.StoreDirectoryDNA(ctx, groupDNA)
		require.NoError(t, err)

		err = storage.StoreDirectoryDNA(ctx, ouDNA)
		require.NoError(t, err)

		// Step 4: Retrieve stored DNA
		retrievedUserDNA, err := storage.GetDirectoryDNA(ctx, "user1", interfaces.DirectoryObjectTypeUser)
		require.NoError(t, err)
		assert.Equal(t, "user1", retrievedUserDNA.ObjectID)

		retrievedGroupDNA, err := storage.GetDirectoryDNA(ctx, "group1", interfaces.DirectoryObjectTypeGroup)
		require.NoError(t, err)
		assert.Equal(t, "group1", retrievedGroupDNA.ObjectID)

		retrievedOUDNA, err := storage.GetDirectoryDNA(ctx, "ou1", interfaces.DirectoryObjectTypeOU)
		require.NoError(t, err)
		assert.Equal(t, "ou1", retrievedOUDNA.ObjectID)

		// Step 5: Verify statistics
		stats, err := storage.GetDirectoryStats(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, stats.TotalObjects, int64(3))
	})

	t.Run("drift detection workflow", func(t *testing.T) {
		// Step 1: Create baseline DNA
		baseline := &DirectoryDNA{
			ObjectID:   "user2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user2_baseline",
			Attributes: map[string]string{
				"username":   "user2",
				"email":      "user2@test.com",
				"department": "IT",
				"is_active":  "true",
			},
			Provider:       "TestProvider",
			LastUpdated:    timePtr(time.Now().Add(-1 * time.Hour)),
			AttributeCount: 4,
		}

		// Step 2: Store baseline
		err := storage.StoreDirectoryDNA(ctx, baseline)
		require.NoError(t, err)

		// Step 3: Create current state with changes
		current := &DirectoryDNA{
			ObjectID:   "user2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user2_current",
			Attributes: map[string]string{
				"username":   "user2",
				"email":      "newemail@test.com", // Changed
				"department": "Engineering",       // Changed
				"is_active":  "true",
			},
			Provider:       "TestProvider",
			LastUpdated:    timePtr(time.Now()),
			AttributeCount: 4,
		}

		// Step 4: Detect drift
		drift, err := driftDetector.DetectDrift(ctx, current, baseline)
		require.NoError(t, err)
		assert.NotNil(t, drift)

		// Step 5: Verify drift details
		assert.Equal(t, "user2", drift.ObjectID)
		assert.Len(t, drift.Changes, 2) // email and department changed
		assert.Greater(t, drift.RiskScore, float64(0))

		// Step 6: Store current state
		err = storage.StoreDirectoryDNA(ctx, current)
		require.NoError(t, err)

		// Step 7: Verify history
		history, err := storage.GetDirectoryHistory(ctx, "user2", nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(history), 2) // Should have baseline and current
	})

	t.Run("relationship collection and storage", func(t *testing.T) {
		// Step 1: Set up complex relationships
		manager := createTestUser("manager1", "Manager")
		employee := createTestUser("employee1", "Employee")
		employee.Manager = "manager1"
		employee.OU = "ou1"

		group := createTestGroup("team1", "TeamGroup")
		group.OU = "ou1"

		ou := createTestOU("ou1", "TeamOU", "")

		provider.AddUser(manager)
		provider.AddUser(employee)
		provider.AddGroup(group)
		provider.AddOU(ou)

		// Step 2: Collect relationships
		relationships, err := collector.CollectRelationships(ctx, "employee1")
		require.NoError(t, err)
		assert.NotNil(t, relationships)

		// Step 3: Store relationships
		err = storage.StoreRelationships(ctx, relationships)
		require.NoError(t, err)

		// Step 4: Retrieve relationships
		retrieved, err := storage.GetRelationships(ctx, "employee1")
		require.NoError(t, err)
		assert.Equal(t, "manager1", retrieved.Manager)
		assert.Equal(t, "ou1", retrieved.ParentOU)

		// Step 5: Collect hierarchy
		hierarchy, err := collector.CollectOUHierarchy(ctx)
		require.NoError(t, err)
		assert.NotNil(t, hierarchy)
		assert.Greater(t, hierarchy.TotalOUs, 0)
	})

	t.Run("monitoring system integration", func(t *testing.T) {
		// Use shorter intervals for testing
		config := &MonitoringConfig{
			CollectionInterval:  100 * time.Millisecond,
			DriftCheckInterval:  100 * time.Millisecond,
			HealthCheckInterval: 50 * time.Millisecond,
			MonitoredObjectTypes: []interfaces.DirectoryObjectType{
				interfaces.DirectoryObjectTypeUser,
				interfaces.DirectoryObjectTypeGroup,
			},
			AlertOnDriftSeverity:     DriftSeverityMedium,
			AlertOnHealthIssues:      true,
			MaxConcurrentCollections: 5,
			MaxConcurrentDriftChecks: 10,
			CollectionTimeout:        30 * time.Second,
			MetricsRetention:         time.Hour,
			HealthDataRetention:      time.Hour,
		}

		err := monitoring.UpdateConfig(config)
		require.NoError(t, err)

		// Start monitoring system
		err = monitoring.Start(ctx)
		require.NoError(t, err)

		// Allow monitoring to perform several cycles
		time.Sleep(300 * time.Millisecond)

		// Verify monitoring is working
		assert.True(t, monitoring.IsRunning())

		metrics := monitoring.GetMetrics()
		assert.NotNil(t, metrics)
		assert.Greater(t, metrics.TotalCollections, int64(0))

		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)
		assert.NotEmpty(t, status.ComponentStatuses)

		// Stop monitoring
		err = monitoring.Stop()
		require.NoError(t, err)
		assert.False(t, monitoring.IsRunning())
	})
}

func TestEndToEndDriftScenario(t *testing.T) {
	// Set up complete system
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)

	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	storage := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)

	_ = NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	// Scenario: User account compromise detection
	t.Run("user account compromise detection", func(t *testing.T) {
		// Step 1: Establish baseline
		user := createTestUser("critical_user", "CriticalUser")
		user.ProviderAttributes["security_clearance"] = "high"
		user.ProviderAttributes["privileged_access"] = "true"
		provider.AddUser(user)

		baselineDNA, err := collector.CollectUserDNA(ctx, "critical_user")
		require.NoError(t, err)

		err = storage.StoreDirectoryDNA(ctx, baselineDNA)
		require.NoError(t, err)

		// Step 2: Simulate compromise (account disabled, email changed)
		compromisedUser := *user
		compromisedUser.AccountEnabled = false
		compromisedUser.EmailAddress = "hacker@malicious.com"

		// Deep copy the ProviderAttributes map to avoid race conditions
		compromisedUser.ProviderAttributes = make(map[string]interface{})
		for k, v := range user.ProviderAttributes {
			compromisedUser.ProviderAttributes[k] = v
		}
		compromisedUser.ProviderAttributes["last_login"] = "suspicious_location"

		// Update the user data in a thread-safe way
		provider.mutex.Lock()
		provider.users["critical_user"] = &compromisedUser
		provider.mutex.Unlock()

		currentDNA, err := collector.CollectUserDNA(ctx, "critical_user")
		require.NoError(t, err)

		// Step 3: Detect drift
		drift, err := driftDetector.DetectDrift(ctx, currentDNA, baselineDNA)
		require.NoError(t, err)
		assert.NotNil(t, drift)

		// Step 4: Verify security assessment
		assert.Greater(t, drift.RiskScore, float64(70)) // High risk for account compromise
		assert.Contains(t, []DriftSeverity{DriftSeverityHigh, DriftSeverityCritical}, drift.Severity)

		// Verify critical changes are detected
		changeFields := make(map[string]bool)
		for _, change := range drift.Changes {
			changeFields[change.Field] = true
		}
		assert.True(t, changeFields["account_enabled"])
		assert.True(t, changeFields["email_address"])

		// Step 5: Verify suggested actions for security incident
		assert.NotEmpty(t, drift.SuggestedActions)
		assert.False(t, drift.AutoRemediable) // High-risk security changes should not be auto-remediable

		// Step 6: Store compromised state for audit trail
		err = storage.StoreDirectoryDNA(ctx, currentDNA)
		require.NoError(t, err)

		// Step 7: Verify audit trail
		history, err := storage.GetDirectoryHistory(ctx, "critical_user", nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(history), 2)
	})
}

func TestScalabilityScenario(t *testing.T) {
	// Test system behavior with larger datasets
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)

	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	storage := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)

	ctx := context.Background()

	t.Run("large organization simulation", func(t *testing.T) {
		// Create a simulated large organization
		const numUsers = 1000
		const numGroups = 100
		const numOUs = 50

		// Add users
		for i := 0; i < numUsers; i++ {
			userID := fmt.Sprintf("user%04d", i)
			user := createTestUser(userID, "User"+userID)
			user.OU = fmt.Sprintf("ou%02d", i%numOUs)
			provider.AddUser(user)
		}

		// Add groups
		for i := 0; i < numGroups; i++ {
			groupID := fmt.Sprintf("group%03d", i)
			group := createTestGroup(groupID, "Group"+groupID)
			group.OU = fmt.Sprintf("ou%02d", i%numOUs)
			provider.AddGroup(group)
		}

		// Add OUs
		for i := 0; i < numOUs; i++ {
			ouID := fmt.Sprintf("ou%02d", i)
			ou := createTestOU(ouID, "OU"+ouID, "")
			provider.AddOU(ou)
		}

		// Test bulk collection performance
		start := time.Now()
		allDNA, err := collector.CollectAll(ctx)
		collectionDuration := time.Since(start)

		require.NoError(t, err)
		assert.Len(t, allDNA, numUsers+numGroups+numOUs)

		// Should complete within reasonable time
		assert.Less(t, collectionDuration, 30*time.Second, "Collection took too long for large dataset")

		// Test storage performance
		start = time.Now()
		storedCount := 0
		for _, dna := range allDNA {
			err := storage.StoreDirectoryDNA(ctx, dna)
			if err == nil {
				storedCount++
			}
		}
		storageDuration := time.Since(start)

		assert.Greater(t, storedCount, numUsers+numGroups+numOUs-10) // Allow for some errors
		assert.Less(t, storageDuration, 60*time.Second, "Storage took too long for large dataset")

		// Test query performance
		start = time.Now()
		query := &DirectoryDNAQuery{
			ObjectTypes: []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
			Limit:       100,
		}
		results, err := storage.QueryDirectoryDNA(ctx, query)
		queryDuration := time.Since(start)

		require.NoError(t, err)
		assert.LessOrEqual(t, len(results), 100)
		assert.Less(t, queryDuration, 5*time.Second, "Query took too long")
	})
}

func TestMultiTenantScenario(t *testing.T) {
	// Test multi-tenant directory DNA collection
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()

	ctx := context.Background()

	t.Run("multi-tenant collection", func(t *testing.T) {
		// Create collectors for different tenants
		tenant1Config := &CollectorConfig{
			TenantID:          "tenant1",
			BatchSize:         100,
			CollectionTimeout: 30 * time.Second,
			MaxConcurrency:    5,
		}

		tenant2Config := &CollectorConfig{
			TenantID:          "tenant2",
			BatchSize:         100,
			CollectionTimeout: 30 * time.Second,
			MaxConcurrency:    5,
		}

		collector1 := NewDirectoryDNACollectorWithConfig(provider, logger, tenant1Config)
		collector2 := NewDirectoryDNACollectorWithConfig(provider, logger, tenant2Config)

		// Add tenant-specific users
		user1 := createTestUser("tenant1_user", "Tenant1User")
		user2 := createTestUser("tenant2_user", "Tenant2User")
		provider.AddUser(user1)
		provider.AddUser(user2)

		// Collect DNA for each tenant
		dna1, err := collector1.CollectUserDNA(ctx, "tenant1_user")
		require.NoError(t, err)
		assert.Equal(t, "tenant1", dna1.TenantID)

		dna2, err := collector2.CollectUserDNA(ctx, "tenant2_user")
		require.NoError(t, err)
		assert.Equal(t, "tenant2", dna2.TenantID)

		// Verify tenant isolation
		assert.NotEqual(t, dna1.TenantID, dna2.TenantID)
	})
}

func TestErrorRecoveryScenario(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("recovery from storage errors", func(t *testing.T) {
		// Add test data
		provider.AddUser(createTestUser("user1", "User1"))

		// Configure for fast testing
		config := &MonitoringConfig{
			CollectionInterval:       50 * time.Millisecond,
			DriftCheckInterval:       50 * time.Millisecond,
			HealthCheckInterval:      25 * time.Millisecond,
			MonitoredObjectTypes:     []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
			AlertOnDriftSeverity:     DriftSeverityMedium,
			AlertOnHealthIssues:      true,
			MaxConcurrentCollections: 5,
			MaxConcurrentDriftChecks: 10,
			CollectionTimeout:        30 * time.Second,
			MetricsRetention:         time.Hour,
			HealthDataRetention:      time.Hour,
		}

		err := monitoring.UpdateConfig(config)
		require.NoError(t, err)

		// Start monitoring
		err = monitoring.Start(ctx)
		require.NoError(t, err)

		// Allow initial successful operations
		time.Sleep(100 * time.Millisecond)

		// Introduce storage errors
		storage.SetShouldError(true)

		// Allow system to experience errors
		time.Sleep(150 * time.Millisecond)

		// Verify system continues running despite errors
		assert.True(t, monitoring.IsRunning())

		// Check health status reflects errors
		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)

		// Recovery: fix storage errors
		storage.SetShouldError(false)

		// Allow system to recover
		time.Sleep(150 * time.Millisecond)

		// Verify recovery
		finalStatus := monitoring.GetHealthStatus()
		assert.NotNil(t, finalStatus)

		err = monitoring.Stop()
		require.NoError(t, err)
	})
}

func TestRealWorldDriftPatterns(t *testing.T) {
	// Test realistic drift detection scenarios
	logger := logging.NewNoopLogger()
	driftDetector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	testCases := []struct {
		name               string
		baselineAttributes map[string]string
		currentAttributes  map[string]string
		expectedSeverity   DriftSeverity
		expectedMinRisk    float64
		expectedDriftType  DirectoryDriftType
	}{
		{
			name: "user promotion",
			baselineAttributes: map[string]string{
				"title":      "Developer",
				"department": "Engineering",
				"level":      "L3",
			},
			currentAttributes: map[string]string{
				"title":      "Senior Developer",
				"department": "Engineering",
				"level":      "L4",
			},
			expectedSeverity:  DriftSeverityLow,
			expectedMinRisk:   0.0,
			expectedDriftType: DirectoryDriftTypeAttributeChange,
		},
		{
			name: "security group addition",
			baselineAttributes: map[string]string{
				"groups": "users,developers",
				"access": "standard",
			},
			currentAttributes: map[string]string{
				"groups": "users,developers,admins",
				"access": "elevated",
			},
			expectedSeverity:  DriftSeverityHigh,
			expectedMinRisk:   60.0,
			expectedDriftType: DirectoryDriftTypePermissionEscalation,
		},
		{
			name: "account compromise indicators",
			baselineAttributes: map[string]string{
				"is_active":     "true",
				"email":         "user@company.com",
				"last_login":    "internal_network",
				"failed_logins": "0",
			},
			currentAttributes: map[string]string{
				"is_active":     "true",
				"email":         "user@suspicious.com",
				"last_login":    "unknown_location",
				"failed_logins": "15",
			},
			expectedSeverity:  DriftSeverityCritical,
			expectedMinRisk:   80.0,
			expectedDriftType: DirectoryDriftTypeUnauthorizedChange,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := &DirectoryDNA{
				ObjectID:       "test_user",
				ObjectType:     interfaces.DirectoryObjectTypeUser,
				ID:             "baseline",
				Attributes:     tc.baselineAttributes,
				Provider:       "TestProvider",
				LastUpdated:    timePtr(time.Now().Add(-1 * time.Hour)),
				AttributeCount: int32(len(tc.baselineAttributes)),
			}

			current := &DirectoryDNA{
				ObjectID:       "test_user",
				ObjectType:     interfaces.DirectoryObjectTypeUser,
				ID:             "current",
				Attributes:     tc.currentAttributes,
				Provider:       "TestProvider",
				LastUpdated:    timePtr(time.Now()),
				AttributeCount: int32(len(tc.currentAttributes)),
			}

			drift, err := driftDetector.DetectDrift(ctx, current, baseline)

			require.NoError(t, err)
			assert.NotNil(t, drift)
			assert.Equal(t, tc.expectedSeverity, drift.Severity)
			assert.GreaterOrEqual(t, drift.RiskScore, tc.expectedMinRisk)
			assert.Equal(t, tc.expectedDriftType, drift.DriftType)

			// Verify drift has actionable information
			assert.NotEmpty(t, drift.Description)
			assert.NotEmpty(t, drift.SuggestedActions)
			assert.Greater(t, len(drift.Changes), 0)
		})
	}
}

func TestSystemResourceUsage(t *testing.T) {
	// Test that the system doesn't consume excessive resources
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	// Add moderate dataset
	for i := 0; i < 100; i++ {
		userID := "user" + string(rune('0'+(i%10))) + string(rune('0'+(i/10)))
		provider.AddUser(createTestUser(userID, "User"+userID))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use reasonable intervals
	config := &MonitoringConfig{
		CollectionInterval:       1 * time.Second,
		DriftCheckInterval:       1 * time.Second,
		HealthCheckInterval:      500 * time.Millisecond,
		MonitoredObjectTypes:     []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
		AlertOnDriftSeverity:     DriftSeverityMedium,
		AlertOnHealthIssues:      true,
		MaxConcurrentCollections: 10,
		MaxConcurrentDriftChecks: 20,
		CollectionTimeout:        30 * time.Second,
		MetricsRetention:         time.Hour,
		HealthDataRetention:      time.Hour,
	}

	err := monitoring.UpdateConfig(config)
	require.NoError(t, err)

	// Start monitoring and let it run
	err = monitoring.Start(ctx)
	require.NoError(t, err)

	// Monitor for a reasonable time
	time.Sleep(3 * time.Second)

	// Check that system is performing well
	metrics := monitoring.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Greater(t, metrics.TotalCollections, int64(0))

	status := monitoring.GetHealthStatus()
	assert.NotNil(t, status)

	// Verify system health under load
	if status.CollectorHealth != nil {
		assert.LessOrEqual(t, status.CollectorHealth.ErrorRate, 0.1) // Less than 10% error rate
	}

	err = monitoring.Stop()
	require.NoError(t, err)
}

func TestComprehensiveWorkflow(t *testing.T) {
	// Test a complete workflow from setup to drift detection
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)

	backend := NewMockBackend()
	compressor := NewMockCompressor()
	indexer := NewMockIndexer()
	storage := NewDirectoryDNAStorageAdapter(backend, compressor, indexer, logger)

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	// Phase 1: Initial setup and baseline collection
	user := createTestUser("workflow_user", "WorkflowUser")
	group := createTestGroup("workflow_group", "WorkflowGroup")
	ou := createTestOU("workflow_ou", "WorkflowOU", "")

	provider.AddUser(user)
	provider.AddGroup(group)
	provider.AddOU(ou)

	// Collect initial DNA
	userDNA, err := collector.CollectUserDNA(ctx, "workflow_user")
	require.NoError(t, err)

	relationships, err := collector.CollectRelationships(ctx, "workflow_user")
	require.NoError(t, err)

	// Store baseline
	err = storage.StoreDirectoryDNA(ctx, userDNA)
	require.NoError(t, err)

	err = storage.StoreRelationships(ctx, relationships)
	require.NoError(t, err)

	// Phase 2: Start monitoring
	config := &MonitoringConfig{
		CollectionInterval:       200 * time.Millisecond,
		DriftCheckInterval:       200 * time.Millisecond,
		HealthCheckInterval:      100 * time.Millisecond,
		MonitoredObjectTypes:     []interfaces.DirectoryObjectType{interfaces.DirectoryObjectTypeUser},
		AlertOnDriftSeverity:     DriftSeverityMedium,
		AlertOnHealthIssues:      true,
		MaxConcurrentCollections: 5,
		MaxConcurrentDriftChecks: 10,
		CollectionTimeout:        30 * time.Second,
		MetricsRetention:         time.Hour,
		HealthDataRetention:      time.Hour,
	}

	err = monitoring.UpdateConfig(config)
	require.NoError(t, err)

	err = monitoring.Start(ctx)
	require.NoError(t, err)

	// Phase 3: Allow initial monitoring
	time.Sleep(300 * time.Millisecond)

	// Phase 4: Introduce changes
	modifiedUser := *user
	modifiedUser.EmailAddress = "modified@test.com"

	// Deep copy the ProviderAttributes map to avoid race conditions
	modifiedUser.ProviderAttributes = make(map[string]interface{})
	for k, v := range user.ProviderAttributes {
		modifiedUser.ProviderAttributes[k] = v
	}
	modifiedUser.ProviderAttributes["title"] = "Senior Developer"

	// Update the user data in a thread-safe way
	provider.mutex.Lock()
	provider.users["workflow_user"] = &modifiedUser
	provider.mutex.Unlock()

	// Allow drift detection
	time.Sleep(300 * time.Millisecond)

	// Phase 5: Verify system detected changes
	currentDNA, err := collector.CollectUserDNA(ctx, "workflow_user")
	require.NoError(t, err)

	drift, err := driftDetector.DetectDrift(ctx, currentDNA, userDNA)
	require.NoError(t, err)
	assert.Greater(t, len(drift.Changes), 0)

	// Phase 6: Verify monitoring metrics
	metrics := monitoring.GetMetrics()
	assert.Greater(t, metrics.TotalCollections, int64(0))
	assert.Greater(t, metrics.TotalDriftChecks, int64(0))

	status := monitoring.GetHealthStatus()
	assert.NotNil(t, status)

	// Phase 7: Clean shutdown
	err = monitoring.Stop()
	require.NoError(t, err)
	assert.False(t, monitoring.IsRunning())

	// Verify final statistics
	finalStats := collector.GetCollectionStats()
	assert.Greater(t, finalStats.TotalCollections, int64(0))

	driftStats := driftDetector.GetDriftDetectionStats()
	assert.Greater(t, driftStats.TotalComparisons, int64(0))
}
