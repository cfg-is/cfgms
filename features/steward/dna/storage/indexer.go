// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package storage implements indexing for DNA records to enable fast queries.

package storage

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// MemoryIndexer implements an in-memory indexer for DNA records
//
// This indexer maintains indices in memory for fast lookups and queries.
// It's suitable for development and smaller deployments.
type MemoryIndexer struct {
	logger logging.Logger
	config *Config

	// Device-based index: deviceID -> sorted list of record references
	deviceIndex map[string][]*RecordRef

	// Time-based index: time bucket -> list of record references
	timeIndex map[string][]*RecordRef

	// Attribute index: attribute key -> value -> list of record references
	attributeIndex map[string]map[string][]*RecordRef

	// Version tracking: deviceID -> current version
	versionIndex map[string]int64

	// Statistics
	stats *IndexStats

	// Synchronization
	mutex      sync.RWMutex
	statsMutex sync.RWMutex
}

// NewIndexer creates a new indexer based on the configuration
func NewIndexer(config *Config, logger logging.Logger) (Indexer, error) {
	// For now, only memory indexer is implemented
	return NewMemoryIndexer(config, logger)
}

// NewMemoryIndexer creates a new in-memory indexer
func NewMemoryIndexer(config *Config, logger logging.Logger) (*MemoryIndexer, error) {
	indexer := &MemoryIndexer{
		logger:         logger,
		config:         config,
		deviceIndex:    make(map[string][]*RecordRef),
		timeIndex:      make(map[string][]*RecordRef),
		attributeIndex: make(map[string]map[string][]*RecordRef),
		versionIndex:   make(map[string]int64),
		stats: &IndexStats{
			TotalEntries:     0,
			UniqueDevices:    0,
			IndexSize:        0,
			TotalQueries:     0,
			CacheHitRatio:    0.0,
			LastOptimization: time.Now(),
		},
	}

	logger.Info("Memory indexer initialized")
	return indexer, nil
}

// IndexRecord adds a DNA record to the index
func (i *MemoryIndexer) IndexRecord(ctx context.Context, record *DNARecord) error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// Create record reference
	ref := &RecordRef{
		DeviceID:    record.DeviceID,
		ContentHash: record.ContentHash,
		ShardID:     record.ShardID,
		Version:     record.Version,
		StoredAt:    record.StoredAt,
		Size:        record.CompressedSize,
	}

	// Update device index
	i.deviceIndex[record.DeviceID] = append(i.deviceIndex[record.DeviceID], ref)

	// Sort device records by version (newest first)
	sort.Slice(i.deviceIndex[record.DeviceID], func(a, b int) bool {
		return i.deviceIndex[record.DeviceID][a].Version > i.deviceIndex[record.DeviceID][b].Version
	})

	// Update time index (bucket by day)
	timeBucket := record.StoredAt.Format("2006-01-02")
	i.timeIndex[timeBucket] = append(i.timeIndex[timeBucket], ref)

	// Update attribute index (sample a few key attributes)
	if record.DNA != nil {
		i.indexSampleAttributes(ref, record.DNA.Attributes)
	}

	// Update version tracking
	i.versionIndex[record.DeviceID] = record.Version

	// Update statistics
	i.updateIndexStats()

	hashDisplay := record.ContentHash
	if len(hashDisplay) > 16 {
		hashDisplay = hashDisplay[:16]
	}

	i.logger.Debug("DNA record indexed",
		"device_id", record.DeviceID,
		"content_hash", hashDisplay,
		"version", record.Version,
		"time_bucket", timeBucket)

	return nil
}

// QueryRecords queries DNA records for a device with options
func (i *MemoryIndexer) QueryRecords(ctx context.Context, deviceID string, options *QueryOptions) ([]*RecordRef, int64, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	start := time.Now()
	defer func() {
		i.statsMutex.Lock()
		i.stats.TotalQueries++
		i.stats.AverageQueryTime = i.updateMovingAverage(i.stats.AverageQueryTime, time.Since(start), i.stats.TotalQueries)
		i.statsMutex.Unlock()
	}()

	// Get all records for device
	deviceRecords, exists := i.deviceIndex[deviceID]
	if !exists {
		return []*RecordRef{}, 0, nil
	}

	// Apply filters
	var filteredRecords []*RecordRef
	for _, ref := range deviceRecords {
		if i.matchesFilters(ref, options) {
			filteredRecords = append(filteredRecords, ref)
		}
	}

	totalCount := int64(len(filteredRecords))

	// Apply pagination
	start_idx := 0
	end_idx := len(filteredRecords)

	if options.Offset > 0 {
		start_idx = options.Offset
		if start_idx >= len(filteredRecords) {
			return []*RecordRef{}, totalCount, nil
		}
	}

	if options.Limit > 0 {
		end_idx = start_idx + options.Limit
		if end_idx > len(filteredRecords) {
			end_idx = len(filteredRecords)
		}
	}

	result := filteredRecords[start_idx:end_idx]

	i.logger.Debug("DNA records queried",
		"device_id", deviceID,
		"total_found", totalCount,
		"returned", len(result),
		"query_time", time.Since(start))

	return result, totalCount, nil
}

// GetNextVersion gets the next version number for a device
func (i *MemoryIndexer) GetNextVersion(ctx context.Context, deviceID string) (int64, error) {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	currentVersion := i.versionIndex[deviceID]
	nextVersion := currentVersion + 1
	i.versionIndex[deviceID] = nextVersion

	return nextVersion, nil
}

// GetDeviceStats returns statistics for a specific device
func (i *MemoryIndexer) GetDeviceStats(ctx context.Context, deviceID string) (*DeviceStats, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	records, exists := i.deviceIndex[deviceID]
	if !exists {
		return nil, fmt.Errorf("device not found: %s", deviceID)
	}

	if len(records) == 0 {
		return &DeviceStats{
			DeviceID:     deviceID,
			TotalRecords: 0,
		}, nil
	}

	// Calculate statistics
	totalSize := int64(0)
	var oldestTime, newestTime time.Time

	// Records are sorted by version (newest first)
	newestTime = records[0].StoredAt
	oldestTime = records[len(records)-1].StoredAt

	for _, ref := range records {
		totalSize += ref.Size
		if ref.StoredAt.Before(oldestTime) {
			oldestTime = ref.StoredAt
		}
		if ref.StoredAt.After(newestTime) {
			newestTime = ref.StoredAt
		}
	}

	averageSize := totalSize / int64(len(records))

	// Calculate update frequency
	var updateFrequency time.Duration
	if len(records) > 1 {
		timeDiff := newestTime.Sub(oldestTime)
		updateFrequency = timeDiff / time.Duration(len(records)-1)
	}

	stats := &DeviceStats{
		DeviceID:        deviceID,
		TotalRecords:    int64(len(records)),
		OldestRecord:    oldestTime,
		NewestRecord:    newestTime,
		TotalSize:       totalSize,
		AverageSize:     averageSize,
		UpdateFrequency: updateFrequency,
		LastChange:      newestTime,
	}

	return stats, nil
}

// GetGlobalStats returns global indexing statistics
func (i *MemoryIndexer) GetGlobalStats(ctx context.Context) (*IndexStats, error) {
	i.statsMutex.RLock()
	defer i.statsMutex.RUnlock()

	// Update current statistics
	i.calculateGlobalStats()

	// Return a copy
	statsCopy := *i.stats
	return &statsCopy, nil
}

// Close closes the indexer and releases resources
func (i *MemoryIndexer) Close() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	// Clear all indices
	i.deviceIndex = nil
	i.timeIndex = nil
	i.attributeIndex = nil
	i.versionIndex = nil

	i.logger.Info("Memory indexer closed")
	return nil
}

// Helper methods

func (i *MemoryIndexer) indexSampleAttributes(ref *RecordRef, attributes map[string]string) {
	// Index key attributes for fast lookup
	keyAttributes := []string{"os", "arch", "hostname", "cpu_model", "memory_total"}

	for _, key := range keyAttributes {
		if value, exists := attributes[key]; exists {
			if i.attributeIndex[key] == nil {
				i.attributeIndex[key] = make(map[string][]*RecordRef)
			}
			i.attributeIndex[key][value] = append(i.attributeIndex[key][value], ref)
		}
	}
}

func (i *MemoryIndexer) matchesFilters(ref *RecordRef, options *QueryOptions) bool {
	// Time range filter
	if options.TimeRange != nil {
		if ref.StoredAt.Before(options.TimeRange.Start) || ref.StoredAt.After(options.TimeRange.End) {
			return false
		}
	}

	// Additional filters can be added here
	return true
}

func (i *MemoryIndexer) updateIndexStats() {
	i.statsMutex.Lock()
	defer i.statsMutex.Unlock()

	// Count total entries across all indices
	totalEntries := int64(0)
	for _, refs := range i.deviceIndex {
		totalEntries += int64(len(refs))
	}

	i.stats.TotalEntries = totalEntries
	i.stats.UniqueDevices = int64(len(i.deviceIndex))

	// Estimate index size (rough calculation)
	i.stats.IndexSize = totalEntries * 100 // Approximate 100 bytes per entry
}

func (i *MemoryIndexer) calculateGlobalStats() {
	// This method updates real-time statistics
	// Called when getting global stats
}

func (i *MemoryIndexer) updateMovingAverage(current time.Duration, newValue time.Duration, count int64) time.Duration {
	// Simple exponential moving average
	if count == 1 {
		return newValue
	}

	alpha := 2.0 / (float64(count) + 1.0)
	if alpha > 0.1 {
		alpha = 0.1 // Cap the alpha to prevent too much volatility
	}

	return time.Duration(float64(current)*(1-alpha) + float64(newValue)*alpha)
}

// Advanced indexing features

// OptimizeIndex performs index optimization
func (i *MemoryIndexer) OptimizeIndex() error {
	i.mutex.Lock()
	defer i.mutex.Unlock()

	start := time.Now()

	// Clean up empty entries
	for deviceID, refs := range i.deviceIndex {
		if len(refs) == 0 {
			delete(i.deviceIndex, deviceID)
		}
	}

	for timeBucket, refs := range i.timeIndex {
		if len(refs) == 0 {
			delete(i.timeIndex, timeBucket)
		}
	}

	// Clean up attribute index
	for attr, valueMap := range i.attributeIndex {
		for value, refs := range valueMap {
			if len(refs) == 0 {
				delete(valueMap, value)
			}
		}
		if len(valueMap) == 0 {
			delete(i.attributeIndex, attr)
		}
	}

	// Update optimization timestamp
	i.statsMutex.Lock()
	i.stats.LastOptimization = time.Now()
	i.statsMutex.Unlock()

	optimizationTime := time.Since(start)
	i.logger.Info("Index optimization completed", "duration", optimizationTime)

	return nil
}

// GetAttributeValues returns all unique values for a specific attribute
func (i *MemoryIndexer) GetAttributeValues(ctx context.Context, attribute string) ([]string, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	valueMap, exists := i.attributeIndex[attribute]
	if !exists {
		return []string{}, nil
	}

	values := make([]string, 0, len(valueMap))
	for value := range valueMap {
		values = append(values, value)
	}

	sort.Strings(values)
	return values, nil
}

// QueryByAttribute queries records by attribute value
func (i *MemoryIndexer) QueryByAttribute(ctx context.Context, attribute, value string, options *QueryOptions) ([]*RecordRef, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	valueMap, exists := i.attributeIndex[attribute]
	if !exists {
		return []*RecordRef{}, nil
	}

	refs, exists := valueMap[value]
	if !exists {
		return []*RecordRef{}, nil
	}

	// Apply additional filters
	var filteredRefs []*RecordRef
	for _, ref := range refs {
		if i.matchesFilters(ref, options) {
			filteredRefs = append(filteredRefs, ref)
		}
	}

	// Apply pagination
	start_idx := 0
	end_idx := len(filteredRefs)

	if options.Offset > 0 {
		start_idx = options.Offset
		if start_idx >= len(filteredRefs) {
			return []*RecordRef{}, nil
		}
	}

	if options.Limit > 0 {
		end_idx = start_idx + options.Limit
		if end_idx > len(filteredRefs) {
			end_idx = len(filteredRefs)
		}
	}

	return filteredRefs[start_idx:end_idx], nil
}

// GetDeviceTimeline returns a timeline of changes for a device
func (i *MemoryIndexer) GetDeviceTimeline(ctx context.Context, deviceID string, options *QueryOptions) ([]*RecordRef, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	refs, exists := i.deviceIndex[deviceID]
	if !exists {
		return []*RecordRef{}, nil
	}

	// Records are already sorted by version (newest first)
	// Apply time range filter if specified
	var filteredRefs []*RecordRef
	for _, ref := range refs {
		if i.matchesFilters(ref, options) {
			filteredRefs = append(filteredRefs, ref)
		}
	}

	// For timeline, we might want to reverse the order (oldest first)
	// Reverse the slice
	for i := 0; i < len(filteredRefs)/2; i++ {
		j := len(filteredRefs) - 1 - i
		filteredRefs[i], filteredRefs[j] = filteredRefs[j], filteredRefs[i]
	}

	// Apply pagination
	start_idx := 0
	end_idx := len(filteredRefs)

	if options.Offset > 0 {
		start_idx = options.Offset
		if start_idx >= len(filteredRefs) {
			return []*RecordRef{}, nil
		}
	}

	if options.Limit > 0 {
		end_idx = start_idx + options.Limit
		if end_idx > len(filteredRefs) {
			end_idx = len(filteredRefs)
		}
	}

	return filteredRefs[start_idx:end_idx], nil
}

// GetTimeRangeStats returns statistics for a specific time range
func (i *MemoryIndexer) GetTimeRangeStats(ctx context.Context, timeRange *TimeRange) (*TimeRangeStats, error) {
	i.mutex.RLock()
	defer i.mutex.RUnlock()

	stats := &TimeRangeStats{
		TimeRange:     timeRange,
		TotalRecords:  0,
		UniqueDevices: make(map[string]bool),
		TotalSize:     0,
	}

	// Iterate through time buckets
	current := timeRange.Start
	for current.Before(timeRange.End) || current.Equal(timeRange.End) {
		bucket := current.Format("2006-01-02")
		if refs, exists := i.timeIndex[bucket]; exists {
			for _, ref := range refs {
				if ref.StoredAt.Before(timeRange.Start) || ref.StoredAt.After(timeRange.End) {
					continue
				}

				stats.TotalRecords++
				stats.UniqueDevices[ref.DeviceID] = true
				stats.TotalSize += ref.Size
			}
		}
		current = current.AddDate(0, 0, 1) // Next day
	}

	stats.DeviceCount = int64(len(stats.UniqueDevices))
	return stats, nil
}

// TimeRangeStats provides statistics for a specific time range
type TimeRangeStats struct {
	TimeRange     *TimeRange      `json:"time_range"`
	TotalRecords  int64           `json:"total_records"`
	DeviceCount   int64           `json:"device_count"`
	UniqueDevices map[string]bool `json:"-"` // Internal use only
	TotalSize     int64           `json:"total_size"`
	AverageSize   int64           `json:"average_size"`
}
