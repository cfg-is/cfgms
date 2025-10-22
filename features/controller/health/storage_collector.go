package health

import (
	"context"
	"sync"
	"time"
)

// StorageProviderStats defines the interface for accessing storage provider statistics
// This interface allows the collector to gather metrics from different storage implementations
type StorageProviderStats interface {
	// GetProviderName returns the storage provider name (git, database, etc.)
	GetProviderName() string

	// GetPoolUtilization returns the connection pool utilization (0.0 - 1.0)
	GetPoolUtilization() float64

	// GetQueryMetrics returns query latency and count metrics
	GetQueryMetrics() (avgLatencyMs, p95LatencyMs float64, totalQueries, slowQueries, queryErrors int64)
}

// DefaultStorageCollector implements StorageCollector
type DefaultStorageCollector struct {
	mu            sync.RWMutex
	metrics       *StorageMetrics
	providerStats StorageProviderStats
}

// NewDefaultStorageCollector creates a new storage metrics collector
func NewDefaultStorageCollector(providerStats StorageProviderStats) *DefaultStorageCollector {
	return &DefaultStorageCollector{
		metrics:       &StorageMetrics{},
		providerStats: providerStats,
	}
}

// CollectMetrics gathers storage provider metrics
func (c *DefaultStorageCollector) CollectMetrics(ctx context.Context) error {
	timestamp := time.Now()

	// Get metrics from storage provider
	provider := c.providerStats.GetProviderName()
	poolUtil := c.providerStats.GetPoolUtilization()
	avgLatency, p95Latency, totalQueries, slowQueries, queryErrors := c.providerStats.GetQueryMetrics()

	// Build metrics
	metrics := &StorageMetrics{
		Provider:          provider,
		PoolUtilization:   poolUtil,
		AvgQueryLatencyMs: avgLatency,
		P95QueryLatencyMs: p95Latency,
		SlowQueryCount:    slowQueries,
		TotalQueries:      totalQueries,
		QueryErrors:       queryErrors,
		CollectedAt:       timestamp,
	}

	c.mu.Lock()
	c.metrics = metrics
	c.mu.Unlock()

	return nil
}

// GetMetrics returns the current storage metrics
func (c *DefaultStorageCollector) GetMetrics() *StorageMetrics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metrics
}

// MockStorageProviderStats implements StorageProviderStats for testing
type MockStorageProviderStats struct {
	ProviderName    string
	PoolUtilization float64
	AvgLatencyMs    float64
	P95LatencyMs    float64
	TotalQueries    int64
	SlowQueries     int64
	QueryErrors     int64
}

// GetProviderName returns the storage provider name
func (m *MockStorageProviderStats) GetProviderName() string {
	return m.ProviderName
}

// GetPoolUtilization returns the pool utilization
func (m *MockStorageProviderStats) GetPoolUtilization() float64 {
	return m.PoolUtilization
}

// GetQueryMetrics returns query metrics
func (m *MockStorageProviderStats) GetQueryMetrics() (avgLatencyMs, p95LatencyMs float64, totalQueries, slowQueries, queryErrors int64) {
	return m.AvgLatencyMs, m.P95LatencyMs, m.TotalQueries, m.SlowQueries, m.QueryErrors
}
