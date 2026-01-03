// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package performance

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStorageBackend implements StorageBackend using in-memory storage
// This is a fallback implementation when time-series database is not configured
type MemoryStorageBackend struct {
	mu      sync.RWMutex
	metrics map[string][]*PerformanceMetrics // key: stewardID
}

// NewMemoryStorageBackend creates a new in-memory storage backend
func NewMemoryStorageBackend() StorageBackend {
	return &MemoryStorageBackend{
		metrics: make(map[string][]*PerformanceMetrics),
	}
}

// Connect establishes connection to the storage backend
func (s *MemoryStorageBackend) Connect(ctx context.Context) error {
	// No connection needed for memory storage
	return nil
}

// Close closes the connection to the storage backend
func (s *MemoryStorageBackend) Close() error {
	// No cleanup needed for memory storage
	return nil
}

// WriteMetrics writes performance metrics to storage
func (s *MemoryStorageBackend) WriteMetrics(ctx context.Context, metrics *PerformanceMetrics) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if metrics == nil {
		return fmt.Errorf("metrics cannot be nil")
	}

	// Append metrics to steward's history
	s.metrics[metrics.StewardID] = append(s.metrics[metrics.StewardID], metrics)

	return nil
}

// QueryMetrics retrieves metrics within a time range
func (s *MemoryStorageBackend) QueryMetrics(ctx context.Context, stewardID string, start, end time.Time) ([]*PerformanceMetrics, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	history, exists := s.metrics[stewardID]
	if !exists {
		return []*PerformanceMetrics{}, nil
	}

	// Filter by time range
	result := make([]*PerformanceMetrics, 0)
	for _, m := range history {
		if (m.Timestamp.After(start) || m.Timestamp.Equal(start)) &&
			(m.Timestamp.Before(end) || m.Timestamp.Equal(end)) {
			result = append(result, m)
		}
	}

	return result, nil
}

// DeleteOldMetrics removes metrics older than the retention period
func (s *MemoryStorageBackend) DeleteOldMetrics(ctx context.Context, retentionPeriod time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-retentionPeriod)

	// Clean up old metrics for all stewards
	for stewardID, history := range s.metrics {
		// Find first index to keep
		keepIndex := 0
		for i, m := range history {
			if m.Timestamp.After(cutoff) {
				keepIndex = i
				break
			}
		}

		// Remove old metrics
		if keepIndex > 0 {
			s.metrics[stewardID] = history[keepIndex:]
		}
	}

	return nil
}

// GetStorageType returns the storage type
func (s *MemoryStorageBackend) GetStorageType() string {
	return "memory"
}

// NoOpStorageBackend implements StorageBackend with no persistence
// Use this when storage is disabled in configuration
type NoOpStorageBackend struct{}

// NewNoOpStorageBackend creates a new no-op storage backend
func NewNoOpStorageBackend() StorageBackend {
	return &NoOpStorageBackend{}
}

// Connect establishes connection to the storage backend
func (s *NoOpStorageBackend) Connect(ctx context.Context) error {
	return nil
}

// Close closes the connection to the storage backend
func (s *NoOpStorageBackend) Close() error {
	return nil
}

// WriteMetrics writes performance metrics to storage (no-op)
func (s *NoOpStorageBackend) WriteMetrics(ctx context.Context, metrics *PerformanceMetrics) error {
	// No-op: metrics are discarded
	return nil
}

// QueryMetrics retrieves metrics within a time range (no-op)
func (s *NoOpStorageBackend) QueryMetrics(ctx context.Context, stewardID string, start, end time.Time) ([]*PerformanceMetrics, error) {
	// No-op: return empty result
	return []*PerformanceMetrics{}, nil
}

// DeleteOldMetrics removes metrics older than the retention period (no-op)
func (s *NoOpStorageBackend) DeleteOldMetrics(ctx context.Context, retentionPeriod time.Duration) error {
	// No-op: nothing to delete
	return nil
}

// GetStorageType returns the storage type
func (s *NoOpStorageBackend) GetStorageType() string {
	return "noop"
}
