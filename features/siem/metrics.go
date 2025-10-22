package siem

import (
	"sort"
	"sync"
	"time"
)

// LatencyTracker tracks processing latency with percentile calculations
type LatencyTracker struct {
	samples      []float64
	mutex        sync.RWMutex
	maxSamples   int
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
	return &LatencyTracker{
		samples:    make([]float64, 0, 1000),
		maxSamples: 1000, // Keep last 1000 samples for percentile calculation
	}
}

// NewThroughputTracker creates a new throughput tracker
func NewThroughputTracker() *ThroughputTracker {
	return &ThroughputTracker{
		windows:    make([]ThroughputWindow, 0, 60),
		windowSize: 1 * time.Second,
		maxWindows: 60, // Keep 60 seconds of data
	}
}

// Record records a latency sample
func (lt *LatencyTracker) Record(latency time.Duration) {
	lt.mutex.Lock()
	defer lt.mutex.Unlock()

	latencyMs := float64(latency.Nanoseconds()) / 1e6 // Convert to milliseconds

	// Add to samples
	if len(lt.samples) >= lt.maxSamples {
		// Remove oldest sample (shift left)
		copy(lt.samples, lt.samples[1:])
		lt.samples[len(lt.samples)-1] = latencyMs
	} else {
		lt.samples = append(lt.samples, latencyMs)
	}

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

// GetPercentile returns the specified percentile (0.0-1.0) in milliseconds
func (lt *LatencyTracker) GetPercentile(percentile float64) float64 {
	if percentile < 0.0 || percentile > 1.0 {
		return 0.0
	}

	lt.mutex.RLock()
	defer lt.mutex.RUnlock()

	if len(lt.samples) == 0 {
		return 0.0
	}

	// Create a copy and sort
	sortedSamples := make([]float64, len(lt.samples))
	copy(sortedSamples, lt.samples)
	sort.Float64s(sortedSamples)

	// Calculate percentile index
	index := percentile * float64(len(sortedSamples)-1)
	lowerIndex := int(index)
	upperIndex := lowerIndex + 1

	if upperIndex >= len(sortedSamples) {
		return sortedSamples[len(sortedSamples)-1]
	}

	// Linear interpolation between the two nearest values
	lowerValue := sortedSamples[lowerIndex]
	upperValue := sortedSamples[upperIndex]
	weight := index - float64(lowerIndex)

	return lowerValue + weight*(upperValue-lowerValue)
}

// GetStats returns comprehensive latency statistics
func (lt *LatencyTracker) GetStats() map[string]interface{} {
	lt.mutex.RLock()
	defer lt.mutex.RUnlock()

	if len(lt.samples) == 0 {
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

	// Calculate min and max
	min := lt.samples[0]
	max := lt.samples[0]
	for _, sample := range lt.samples {
		if sample < min {
			min = sample
		}
		if sample > max {
			max = sample
		}
	}

	return map[string]interface{}{
		"sample_count":  len(lt.samples),
		"total_samples": lt.totalSamples,
		"average_ms":    lt.GetAverage(),
		"min_ms":        min,
		"max_ms":        max,
		"p50_ms":        lt.GetPercentile(0.50),
		"p95_ms":        lt.GetPercentile(0.95),
		"p99_ms":        lt.GetPercentile(0.99),
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
