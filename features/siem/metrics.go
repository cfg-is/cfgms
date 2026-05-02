// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"sort"
	"sync"
	"time"
)

// LatencyTracker tracks processing latency with percentile calculations.
// The sample buffer is a fixed-size circular array: Record is O(1) per write.
type LatencyTracker struct {
	samples      [1000]float64
	mutex        sync.RWMutex
	head         int // next-write slot (never reset, wraps via modulo)
	count        int // valid slots filled so far, capped at 1000
	totalSamples int64
	totalLatency time.Duration
}

// ThroughputTracker tracks processing throughput over time windows
type ThroughputTracker struct {
	windows    []ThroughputWindow
	mutex      sync.RWMutex
	windowSize time.Duration
	maxWindows int
}

// ThroughputWindow represents a time window for throughput measurement
type ThroughputWindow struct {
	Start time.Time
	End   time.Time
	Count int64
}

// NewLatencyTracker creates a new latency tracker
func NewLatencyTracker() *LatencyTracker {
	return &LatencyTracker{}
}

// NewThroughputTracker creates a new throughput tracker
func NewThroughputTracker() *ThroughputTracker {
	return &ThroughputTracker{
		windows:    make([]ThroughputWindow, 0, 60),
		windowSize: 1 * time.Second,
		maxWindows: 60, // Keep 60 seconds of data
	}
}

// Record records a latency sample. O(1) — single indexed write, no copy/shift.
func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()

	latencyMs := float64(latency.Nanoseconds()) / 1e6
	lt.samples[lt.head%1000] = latencyMs
	lt.head++
	lt.count = min(lt.count+1, 1000)

	lt.totalSamples++
	lt.totalLatency += latency
}

// GetAverage returns the average latency in milliseconds
func (lt *LatencyTracker) GetAverage() float64 {
	lt.mutex.RLock()
	defer lt.mutex.RUnlock()

	if lt.totalSamples == 0 {
		return 0.0
	}

	return float64(lt.totalLatency.Nanoseconds()) / float64(lt.totalSamples) / 1e6
}

// percentileFromSorted returns the p-th percentile (0.0–1.0) from a pre-sorted
// slice using linear interpolation. Caller must sort before calling.
func percentileFromSorted(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0.0
	}
	index := p * float64(len(sorted)-1)
	lower := int(index)
	upper := lower + 1
	if upper >= len(sorted) {
		return sorted[len(sorted)-1]
	}
	weight := index - float64(lower)
	return sorted[lower] + weight*(sorted[upper]-sorted[lower])
}

// GetPercentile returns the specified percentile (0.0-1.0) in milliseconds.
// The lock is released before sorting so writes are not blocked by the sort.
func (lt *LatencyTracker) GetPercentile(percentile float64) float64 {
	if percentile < 0.0 || percentile > 1.0 {
		return 0.0
	}

	lt.mutex.RLock()
	count := lt.count
	temp := make([]float64, count)
	copy(temp, lt.samples[:count])
	lt.mutex.RUnlock()

	if count == 0 {
		return 0.0
	}

	sort.Float64s(temp)
	return percentileFromSorted(temp, percentile)
}

// GetStats returns comprehensive latency statistics.
// The buffer is copied once under a read lock; sorting and percentile math
// happen outside the lock so writes are not blocked.
func (lt *LatencyTracker) GetStats() map[string]interface{} {
	lt.mutex.RLock()
	count := lt.count
	totalSamples := lt.totalSamples
	totalLatency := lt.totalLatency
	temp := make([]float64, count)
	copy(temp, lt.samples[:count])
	lt.mutex.RUnlock()

	if count == 0 {
		return map[string]interface{}{
			"sample_count": 0,
			"average_ms":   0.0,
			"min_ms":       0.0,
			"max_ms":       0.0,
			"p50_ms":       0.0,
			"p95_ms":       0.0,
			"p99_ms":       0.0,
		}
	}

	minVal := temp[0]
	maxVal := temp[0]
	for _, s := range temp {
		if s < minVal {
			minVal = s
		}
		if s > maxVal {
			maxVal = s
		}
	}

	// Sort once; reuse for all three percentile calls.
	sort.Float64s(temp)

	var avgMs float64
	if totalSamples > 0 {
		avgMs = float64(totalLatency.Nanoseconds()) / float64(totalSamples) / 1e6
	}

	return map[string]interface{}{
		"sample_count":  count,
		"total_samples": totalSamples,
		"average_ms":    avgMs,
		"min_ms":        minVal,
		"max_ms":        maxVal,
		"p50_ms":        percentileFromSorted(temp, 0.50),
		"p95_ms":        percentileFromSorted(temp, 0.95),
		"p99_ms":        percentileFromSorted(temp, 0.99),
	}
}

// RecordCount records a count of processed items for throughput calculation
func (tt *ThroughputTracker) RecordCount(count int64) {
	tt.mutex.Lock()
	defer tt.mutex.Unlock()

	now := time.Now()

	// Find or create current window
	var currentWindow *ThroughputWindow
	if len(tt.windows) > 0 {
		lastWindow := &tt.windows[len(tt.windows)-1]
		if now.Sub(lastWindow.Start) < tt.windowSize {
			currentWindow = lastWindow
		}
	}

	if currentWindow == nil {
		// Create new window
		window := ThroughputWindow{
			Start: now.Truncate(tt.windowSize),
			End:   now.Truncate(tt.windowSize).Add(tt.windowSize),
			Count: 0,
		}
		tt.windows = append(tt.windows, window)
		currentWindow = &tt.windows[len(tt.windows)-1]

		// Remove old windows if we have too many
		if len(tt.windows) > tt.maxWindows {
			copy(tt.windows, tt.windows[1:])
			tt.windows = tt.windows[:len(tt.windows)-1]
			currentWindow = &tt.windows[len(tt.windows)-1]
		}
	}

	currentWindow.Count += count
}

// GetRate returns the current processing rate (items per second)
func (tt *ThroughputTracker) GetRate() float64 {
	tt.mutex.RLock()
	defer tt.mutex.RUnlock()

	if len(tt.windows) == 0 {
		return 0.0
	}

	// Calculate rate over last few windows
	windowsToConsider := 5
	if len(tt.windows) < windowsToConsider {
		windowsToConsider = len(tt.windows)
	}

	var totalCount int64
	var totalDuration time.Duration

	startIndex := len(tt.windows) - windowsToConsider
	for i := startIndex; i < len(tt.windows); i++ {
		window := tt.windows[i]
		totalCount += window.Count
		totalDuration += tt.windowSize
	}

	if totalDuration == 0 {
		return 0.0
	}

	return float64(totalCount) / totalDuration.Seconds()
}

// GetThroughputHistory returns throughput history
func (tt *ThroughputTracker) GetThroughputHistory() []ThroughputWindow {
	tt.mutex.RLock()
	defer tt.mutex.RUnlock()

	// Return a copy to prevent external modification
	history := make([]ThroughputWindow, len(tt.windows))
	copy(history, tt.windows)
	return history
}

// GetStats returns comprehensive throughput statistics
func (tt *ThroughputTracker) GetStats() map[string]interface{} {
	tt.mutex.RLock()
	defer tt.mutex.RUnlock()

	if len(tt.windows) == 0 {
		return map[string]interface{}{
			"current_rate": 0.0,
			"peak_rate":    0.0,
			"total_items":  0,
			"window_count": 0,
		}
	}

	var totalItems int64
	var peakRate float64
	currentRate := tt.GetRate()

	// Calculate statistics across all windows
	for _, window := range tt.windows {
		totalItems += window.Count
		windowRate := float64(window.Count) / tt.windowSize.Seconds()
		if windowRate > peakRate {
			peakRate = windowRate
		}
	}

	return map[string]interface{}{
		"current_rate":   currentRate,
		"peak_rate":      peakRate,
		"total_items":    totalItems,
		"window_count":   len(tt.windows),
		"window_size_ms": tt.windowSize.Milliseconds(),
	}
}
