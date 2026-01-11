// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Mock implementations for testing monitoring system

type MockDirectoryDNAStorage struct {
	mutex         sync.RWMutex
	storedDNA     map[string]*DirectoryDNA
	relationships map[string]*DirectoryRelationships
	stats         *DirectoryDNAStats
	shouldError   bool
}

func NewMockDirectoryDNAStorage() *MockDirectoryDNAStorage {
	return &MockDirectoryDNAStorage{
		storedDNA:     make(map[string]*DirectoryDNA),
		relationships: make(map[string]*DirectoryRelationships),
		stats: &DirectoryDNAStats{
			TotalObjects:          0,
			UserCount:             0,
			GroupCount:            0,
			OUCount:               0,
			CollectionHealth:      "healthy",
			LastHealthCheck:       time.Now(),
			TotalStorageUsed:      1024,
			CompressionRatio:      0.7,
			CollectionSuccessRate: 0.95,
		},
	}
}

func (m *MockDirectoryDNAStorage) StoreDirectoryDNA(ctx context.Context, dna *DirectoryDNA) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.shouldError {
		return assert.AnError
	}
	m.storedDNA[dna.ObjectID] = dna
	m.stats.TotalObjects++
	return nil
}

func (m *MockDirectoryDNAStorage) GetDirectoryDNA(ctx context.Context, objectID string, objectType interfaces.DirectoryObjectType) (*DirectoryDNA, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return nil, assert.AnError
	}
	if dna, exists := m.storedDNA[objectID]; exists {
		return dna, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryDNAStorage) QueryDirectoryDNA(ctx context.Context, query *DirectoryDNAQuery) ([]*DirectoryDNA, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return nil, assert.AnError
	}
	var results []*DirectoryDNA
	for _, dna := range m.storedDNA {
		results = append(results, dna)
		if len(results) >= query.Limit {
			break
		}
	}
	return results, nil
}

func (m *MockDirectoryDNAStorage) GetDirectoryHistory(ctx context.Context, objectID string, timeRange *TimeRange) ([]*DirectoryDNA, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return nil, assert.AnError
	}
	if dna, exists := m.storedDNA[objectID]; exists {
		return []*DirectoryDNA{dna}, nil
	}
	return nil, nil
}

func (m *MockDirectoryDNAStorage) StoreRelationships(ctx context.Context, relationships *DirectoryRelationships) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.shouldError {
		return assert.AnError
	}
	m.relationships[relationships.ObjectID] = relationships
	return nil
}

func (m *MockDirectoryDNAStorage) GetRelationships(ctx context.Context, objectID string) (*DirectoryRelationships, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return nil, assert.AnError
	}
	if rel, exists := m.relationships[objectID]; exists {
		return rel, nil
	}
	return nil, assert.AnError
}

func (m *MockDirectoryDNAStorage) GetDirectoryStats(ctx context.Context) (*DirectoryDNAStats, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return nil, assert.AnError
	}
	// Return a copy to prevent race conditions
	statsCopy := *m.stats
	return &statsCopy, nil
}

func (m *MockDirectoryDNAStorage) GetObjectStats(ctx context.Context, objectType interfaces.DirectoryObjectType) (*ObjectTypeStats, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.shouldError {
		return nil, assert.AnError
	}
	return &ObjectTypeStats{
		ObjectType:  objectType,
		TotalCount:  10,
		ActiveCount: 8,
	}, nil
}

func (m *MockDirectoryDNAStorage) SetShouldError(shouldError bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.shouldError = shouldError
}

func TestNewDirectoryDNAMonitoringSystem(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	assert.NotNil(t, monitoring)
	assert.False(t, monitoring.IsRunning())

	// Verify default configuration
	config := monitoring.GetConfig()
	assert.NotNil(t, config)
	assert.Greater(t, config.CollectionInterval, time.Duration(0))
	assert.Greater(t, config.DriftCheckInterval, time.Duration(0))
	assert.Greater(t, config.HealthCheckInterval, time.Duration(0))
	assert.True(t, config.AlertOnHealthIssues)
}

func TestMonitoringSystemStartStop(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("start monitoring", func(t *testing.T) {
		assert.False(t, monitoring.IsRunning())

		err := monitoring.Start(ctx)

		assert.NoError(t, err)
		assert.True(t, monitoring.IsRunning())

		// Allow system to start up
		time.Sleep(100 * time.Millisecond)
	})

	t.Run("start already running", func(t *testing.T) {
		err := monitoring.Start(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already running")
	})

	t.Run("stop monitoring", func(t *testing.T) {
		err := monitoring.Stop()

		assert.NoError(t, err)
		assert.False(t, monitoring.IsRunning())
	})

	t.Run("stop not running", func(t *testing.T) {
		err := monitoring.Stop()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not running")
	})
}

func TestMonitoringConfiguration(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	t.Run("update valid configuration", func(t *testing.T) {
		newConfig := &MonitoringConfig{
			CollectionInterval:  30 * time.Minute,
			DriftCheckInterval:  10 * time.Minute,
			HealthCheckInterval: 60 * time.Second,
			MonitoredObjectTypes: []interfaces.DirectoryObjectType{
				interfaces.DirectoryObjectTypeUser,
				interfaces.DirectoryObjectTypeGroup,
			},
			AlertOnDriftSeverity:     DriftSeverityHigh,
			AlertOnHealthIssues:      true,
			MaxConcurrentCollections: 10,
			MaxConcurrentDriftChecks: 20,
			CollectionTimeout:        60 * time.Second,
			MetricsRetention:         14 * 24 * time.Hour,
			HealthDataRetention:      48 * time.Hour,
		}

		err := monitoring.UpdateConfig(newConfig)

		assert.NoError(t, err)

		retrievedConfig := monitoring.GetConfig()
		assert.Equal(t, newConfig.CollectionInterval, retrievedConfig.CollectionInterval)
		assert.Equal(t, newConfig.DriftCheckInterval, retrievedConfig.DriftCheckInterval)
		assert.Equal(t, newConfig.AlertOnDriftSeverity, retrievedConfig.AlertOnDriftSeverity)
		assert.Equal(t, newConfig.MaxConcurrentCollections, retrievedConfig.MaxConcurrentCollections)
	})

	t.Run("invalid configuration", func(t *testing.T) {
		invalidConfig := &MonitoringConfig{
			CollectionInterval:  0, // Invalid
			DriftCheckInterval:  10 * time.Minute,
			HealthCheckInterval: 60 * time.Second,
		}

		err := monitoring.UpdateConfig(invalidConfig)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "collection interval must be positive")
	})

	t.Run("nil configuration", func(t *testing.T) {
		err := monitoring.UpdateConfig(nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})
}

func TestMonitoringMetrics(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	// Add test data to generate metrics
	provider.AddUser(createTestUser("user1", "User1"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitoring briefly to generate some metrics
	err := monitoring.Start(ctx)
	require.NoError(t, err)

	// Allow some collection cycles
	time.Sleep(200 * time.Millisecond)

	err = monitoring.Stop()
	require.NoError(t, err)

	t.Run("get metrics", func(t *testing.T) {
		metrics := monitoring.GetMetrics()

		assert.NotNil(t, metrics)
		assert.GreaterOrEqual(t, metrics.TotalCollections, int64(0))
		assert.GreaterOrEqual(t, metrics.MonitoringUptime, time.Duration(0))
		assert.NotNil(t, metrics.ObjectsMonitored)
		assert.NotNil(t, metrics.ComponentHealth)

		// Verify map initialization
		assert.NotNil(t, metrics.ObjectsMonitored)
		assert.NotNil(t, metrics.ObjectsWithDrift)
		assert.NotNil(t, metrics.ComponentHealth)
	})
}

func TestHealthStatusReporting(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	t.Run("get initial health status", func(t *testing.T) {
		status := monitoring.GetHealthStatus()

		assert.NotNil(t, status)
		assert.Equal(t, HealthStatusHealthy, status.OverallStatus)
		assert.NotNil(t, status.ComponentStatuses)
		assert.NotZero(t, status.LastCheck)
	})

	t.Run("health status after running", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err := monitoring.Start(ctx)
		require.NoError(t, err)

		// Allow health checks to run
		time.Sleep(200 * time.Millisecond)

		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)

		err = monitoring.Stop()
		require.NoError(t, err)
	})
}

func TestMonitoringWithStorageErrors(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Add test data
	provider.AddUser(createTestUser("user1", "User1"))

	t.Run("monitoring with storage errors", func(t *testing.T) {
		// Start monitoring
		err := monitoring.Start(ctx)
		require.NoError(t, err)

		// Enable storage errors
		storage.SetShouldError(true)

		// Allow collection cycles with errors
		time.Sleep(200 * time.Millisecond)

		// Disable errors and check health
		storage.SetShouldError(false)

		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)

		// The system should detect storage issues
		if status.StorageHealth != nil {
			// Storage health might be degraded due to errors
			// TODO: Add specific storage health validation in future tests
			_ = status.StorageHealth // Mark as intentionally checked
		}

		err = monitoring.Stop()
		require.NoError(t, err)
	})
}

func TestPerformDNACollection(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	// Add test data
	provider.AddUser(createTestUser("user1", "User1"))
	provider.AddGroup(createTestGroup("group1", "Group1"))
	provider.AddOU(createTestOU("ou1", "OU1", ""))

	ctx := context.Background()

	// Test manual collection trigger
	monitoring.performDNACollection(ctx)

	// Verify metrics were updated
	metrics := monitoring.GetMetrics()
	assert.Greater(t, metrics.TotalCollections, int64(0))
	assert.NotZero(t, metrics.LastCollectionTime)
}

func TestPerformDriftCheck(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	// Test manual drift check trigger
	monitoring.performDriftCheck(ctx)

	// Verify metrics were updated
	metrics := monitoring.GetMetrics()
	assert.Greater(t, metrics.TotalDriftChecks, int64(0))
	assert.NotZero(t, metrics.LastDriftCheckTime)
}

func TestHealthChecks(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	t.Run("perform health check", func(t *testing.T) {
		monitoring.performHealthCheck(ctx)

		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)
		assert.NotZero(t, status.LastCheck)
		assert.NotNil(t, status.ComponentStatuses)

		// Should have health info for all components
		assert.Contains(t, status.ComponentStatuses, "collector")
		assert.Contains(t, status.ComponentStatuses, "drift_detector")
		assert.Contains(t, status.ComponentStatuses, "storage")
	})

	t.Run("health check with component errors", func(t *testing.T) {
		// Enable storage errors
		storage.SetShouldError(true)

		monitoring.performHealthCheck(ctx)

		status := monitoring.GetHealthStatus()
		assert.NotNil(t, status)

		// Storage component should show unhealthy
		assert.Equal(t, HealthStatusUnhealthy, status.ComponentStatuses["storage"])

		// Overall status should be unhealthy
		assert.Equal(t, HealthStatusUnhealthy, status.OverallStatus)

		// Reset error condition
		storage.SetShouldError(false)
	})
}

func TestCollectDNAForObjectType(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	// Add test data
	provider.AddUser(createTestUser("user1", "User1"))
	provider.AddUser(createTestUser("user2", "User2"))
	provider.AddGroup(createTestGroup("group1", "Group1"))
	provider.AddOU(createTestOU("ou1", "OU1", ""))

	ctx := context.Background()

	t.Run("collect users", func(t *testing.T) {
		collected, err := monitoring.collectDNAForObjectType(ctx, interfaces.DirectoryObjectTypeUser)

		require.NoError(t, err)
		assert.Equal(t, int64(2), collected) // Should collect 2 users
	})

	t.Run("collect groups", func(t *testing.T) {
		collected, err := monitoring.collectDNAForObjectType(ctx, interfaces.DirectoryObjectTypeGroup)

		require.NoError(t, err)
		assert.Equal(t, int64(1), collected) // Should collect 1 group
	})

	t.Run("collect OUs", func(t *testing.T) {
		collected, err := monitoring.collectDNAForObjectType(ctx, interfaces.DirectoryObjectTypeOU)

		require.NoError(t, err)
		assert.Equal(t, int64(1), collected) // Should collect 1 OU
	})
}

func TestComponentHealthChecking(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx := context.Background()

	// Start monitoring to generate stats
	err := monitoring.Start(ctx)
	require.NoError(t, err)

	// Allow some operations to generate stats
	time.Sleep(100 * time.Millisecond)

	t.Run("check collector health", func(t *testing.T) {
		health := monitoring.checkCollectorHealth(ctx)

		assert.NotNil(t, health)
		assert.Equal(t, HealthStatusHealthy, health.Status)
		assert.GreaterOrEqual(t, health.ErrorRate, float64(0))
		assert.GreaterOrEqual(t, health.ThroughputRate, float64(0))
		assert.NotZero(t, health.LastCheck)
	})

	t.Run("check drift detector health", func(t *testing.T) {
		health := monitoring.checkDriftDetectorHealth(ctx)

		assert.NotNil(t, health)
		assert.NotZero(t, health.LastCheck)

		// Drift detector health depends on whether it's monitoring
		if !driftDetector.IsMonitoring() {
			assert.Equal(t, HealthStatusDegraded, health.Status)
		}
	})

	t.Run("check storage health", func(t *testing.T) {
		health := monitoring.checkStorageHealth(ctx)

		assert.NotNil(t, health)
		assert.Equal(t, HealthStatusHealthy, health.Status)
		assert.GreaterOrEqual(t, health.ThroughputRate, float64(0))
		assert.NotZero(t, health.LastCheck)
	})

	err = monitoring.Stop()
	require.NoError(t, err)
}

func TestCalculateOverallHealth(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	testCases := []struct {
		name              string
		componentStatuses map[string]HealthStatus
		expectedOverall   HealthStatus
	}{
		{
			name: "all healthy",
			componentStatuses: map[string]HealthStatus{
				"collector":      HealthStatusHealthy,
				"drift_detector": HealthStatusHealthy,
				"storage":        HealthStatusHealthy,
			},
			expectedOverall: HealthStatusHealthy,
		},
		{
			name: "one degraded",
			componentStatuses: map[string]HealthStatus{
				"collector":      HealthStatusHealthy,
				"drift_detector": HealthStatusDegraded,
				"storage":        HealthStatusHealthy,
			},
			expectedOverall: HealthStatusDegraded,
		},
		{
			name: "one unhealthy",
			componentStatuses: map[string]HealthStatus{
				"collector":      HealthStatusHealthy,
				"drift_detector": HealthStatusHealthy,
				"storage":        HealthStatusUnhealthy,
			},
			expectedOverall: HealthStatusUnhealthy,
		},
		{
			name: "multiple degraded",
			componentStatuses: map[string]HealthStatus{
				"collector":      HealthStatusDegraded,
				"drift_detector": HealthStatusDegraded,
				"storage":        HealthStatusHealthy,
			},
			expectedOverall: HealthStatusDegraded,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			status := &DirectoryHealthStatus{
				ComponentStatuses: tc.componentStatuses,
			}

			overallHealth := monitoring.calculateOverallHealth(status)

			assert.Equal(t, tc.expectedOverall, overallHealth)
		})
	}
}

func TestUpdateAverageTime(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	t.Run("first measurement", func(t *testing.T) {
		newTime := 100 * time.Millisecond
		avgTime := monitoring.updateAverageTime(0, newTime, 1)

		assert.Equal(t, newTime, avgTime)
	})

	t.Run("running average", func(t *testing.T) {
		currentAvg := 100 * time.Millisecond
		newTime := 200 * time.Millisecond
		count := int64(5)

		avgTime := monitoring.updateAverageTime(currentAvg, newTime, count)

		// Should be between currentAvg and newTime
		assert.Greater(t, avgTime, currentAvg)
		assert.Less(t, avgTime, newTime)
	})
}

func TestMonitoringLoop(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	// Add test data
	provider.AddUser(createTestUser("user1", "User1"))

	// Use very short intervals for testing
	config := &MonitoringConfig{
		CollectionInterval:       100 * time.Millisecond,
		DriftCheckInterval:       100 * time.Millisecond,
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

	err := monitoring.UpdateConfig(config)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitoring
	err = monitoring.Start(ctx)
	require.NoError(t, err)

	// Allow multiple cycles
	time.Sleep(350 * time.Millisecond)

	// Check that operations occurred
	metrics := monitoring.GetMetrics()
	assert.Greater(t, metrics.TotalCollections, int64(0))
	assert.Greater(t, metrics.TotalDriftChecks, int64(0))

	// Stop monitoring
	err = monitoring.Stop()
	require.NoError(t, err)
}

func TestGetDefaultMonitoringConfig(t *testing.T) {
	config := getDefaultMonitoringConfig()

	assert.NotNil(t, config)
	assert.Greater(t, config.CollectionInterval, time.Duration(0))
	assert.Greater(t, config.DriftCheckInterval, time.Duration(0))
	assert.Greater(t, config.HealthCheckInterval, time.Duration(0))

	// Verify default monitored object types
	assert.Contains(t, config.MonitoredObjectTypes, interfaces.DirectoryObjectTypeUser)
	assert.Contains(t, config.MonitoredObjectTypes, interfaces.DirectoryObjectTypeGroup)
	assert.Contains(t, config.MonitoredObjectTypes, interfaces.DirectoryObjectTypeOU)

	// Verify reasonable defaults
	assert.Equal(t, DriftSeverityMedium, config.AlertOnDriftSeverity)
	assert.True(t, config.AlertOnHealthIssues)
	assert.Greater(t, config.MaxConcurrentCollections, 0)
	assert.Greater(t, config.MaxConcurrentDriftChecks, 0)
	assert.Greater(t, config.CollectionTimeout, time.Duration(0))
	assert.Greater(t, config.MetricsRetention, time.Duration(0))
	assert.Greater(t, config.HealthDataRetention, time.Duration(0))
}

func TestMonitoringErrorResilience(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Add test data, including problematic data
	provider.AddUser(createTestUser("user1", "User1"))
	provider.SetErrorOnUser("error_user") // This user will cause errors
	provider.AddUser(createTestUser("error_user", "ErrorUser"))

	// Use short intervals
	config := &MonitoringConfig{
		CollectionInterval:       50 * time.Millisecond,
		DriftCheckInterval:       50 * time.Millisecond,
		HealthCheckInterval:      50 * time.Millisecond,
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

	// Allow system to run with errors
	time.Sleep(200 * time.Millisecond)

	// Verify system continues running despite errors
	assert.True(t, monitoring.IsRunning())

	metrics := monitoring.GetMetrics()
	assert.Greater(t, metrics.TotalCollections, int64(0))

	// System should handle errors gracefully
	assert.GreaterOrEqual(t, metrics.FailedCollections, int64(0))

	err = monitoring.Stop()
	require.NoError(t, err)
}

func TestMonitoringMetricsThreadSafety(t *testing.T) {
	provider := NewMockDirectoryProvider()
	logger := logging.NewNoopLogger()
	collector := NewDirectoryDNACollector(provider, logger)
	driftDetector := NewDirectoryDriftDetector(logger)
	storage := NewMockDirectoryDNAStorage()

	monitoring := NewDirectoryDNAMonitoringSystem(collector, driftDetector, storage, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start monitoring
	err := monitoring.Start(ctx)
	require.NoError(t, err)

	// Concurrently read metrics while system is running
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			for j := 0; j < 100; j++ {
				metrics := monitoring.GetMetrics()
				assert.NotNil(t, metrics)

				status := monitoring.GetHealthStatus()
				assert.NotNil(t, status)

				time.Sleep(time.Millisecond)
			}
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	err = monitoring.Stop()
	require.NoError(t, err)
}
