package workflow

import (
	"math"
	"runtime"
	"sync"
	"time"
)

// PerformanceCollector gathers system performance metrics during workflow execution
type PerformanceCollector struct {
	mutex        sync.RWMutex
	lastMemStats runtime.MemStats
	lastCPUTime  time.Time
	initialized  bool
}

// NewPerformanceCollector creates a new performance metrics collector
func NewPerformanceCollector() *PerformanceCollector {
	pc := &PerformanceCollector{
		lastCPUTime: time.Now(),
	}

	// Initialize baseline metrics
	pc.initializeBaseline()

	return pc
}

// initializeBaseline sets up initial metric baselines
func (pc *PerformanceCollector) initializeBaseline() {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	runtime.ReadMemStats(&pc.lastMemStats)
	pc.lastCPUTime = time.Now()
	pc.initialized = true
}

// CollectMetrics gathers current system performance metrics
func (pc *PerformanceCollector) CollectMetrics() *PerformanceMetrics {
	pc.mutex.Lock()
	defer pc.mutex.Unlock()

	if !pc.initialized {
		pc.initializeBaseline()
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Calculate GC pause time from debug.GCStats
	gcPauseTime := time.Duration(0)
	if memStats.NumGC > pc.lastMemStats.NumGC {
		// Use the most recent pause time from memstats with safe conversion
		pauseNs := memStats.PauseNs[(memStats.NumGC+255)%256]
		if pauseNs > math.MaxInt64 {
			gcPauseTime = time.Duration(math.MaxInt64)
		} else {
			gcPauseTime = time.Duration(pauseNs)
		}
	}

	metrics := &PerformanceMetrics{
		// CPU metrics (approximated via goroutine activity)
		CPUUsagePercent: pc.estimateCPUUsage(),
		GoRoutineCount:  runtime.NumGoroutine(),
		ThreadCount:     runtime.GOMAXPROCS(0),

		// Memory metrics
		MemoryUsageBytes:  memStats.Alloc,
		MemoryAllocBytes:  memStats.TotalAlloc,
		MemorySystemBytes: memStats.Sys,
		GCCount:           memStats.NumGC - pc.lastMemStats.NumGC,
		GCPauseTime:       gcPauseTime,

		// Workflow-specific metrics (to be set by caller)
		StepExecutionCount: 0, // Will be populated by caller
		ActiveStepCount:    0, // Will be populated by caller

		Timestamp: time.Now(),
	}

	// Update last readings
	pc.lastMemStats = memStats
	pc.lastCPUTime = time.Now()

	return metrics
}

// estimateCPUUsage provides a rough estimate of CPU usage based on goroutine count
// Note: This is a simple heuristic since Go doesn't provide direct CPU usage in stdlib
func (pc *PerformanceCollector) estimateCPUUsage() float64 {
	numGoroutines := runtime.NumGoroutine()
	maxProcs := runtime.GOMAXPROCS(0)

	// Simple heuristic: estimate based on goroutine density
	// This is not precise but gives a rough indication
	ratio := float64(numGoroutines) / float64(maxProcs)

	// Cap at 100% and apply scaling factor
	cpuEstimate := ratio * 25.0 // Scale factor for estimation
	if cpuEstimate > 100.0 {
		cpuEstimate = 100.0
	}

	return cpuEstimate
}

// GetMemoryUsage returns current memory usage statistics
func (pc *PerformanceCollector) GetMemoryUsage() (allocated, system uint64) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	return memStats.Alloc, memStats.Sys
}

// GetGCStats returns garbage collection statistics
func (pc *PerformanceCollector) GetGCStats() (count uint32, pauseTime time.Duration) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	pauseTime = time.Duration(0)
	if memStats.NumGC > 0 {
		// Safe conversion to prevent integer overflow
		pauseNs := memStats.PauseNs[(memStats.NumGC+255)%256]
		if pauseNs > math.MaxInt64 {
			pauseTime = time.Duration(math.MaxInt64)
		} else {
			pauseTime = time.Duration(pauseNs)
		}
	}

	return memStats.NumGC, pauseTime
}

// GetGoroutineCount returns the current number of goroutines
func (pc *PerformanceCollector) GetGoroutineCount() int {
	return runtime.NumGoroutine()
}

// Enhanced performance metrics with workflow context
type WorkflowPerformanceCollector struct {
	*PerformanceCollector
	activeSteps        map[string]time.Time
	stepExecutionCount int
	mutex              sync.RWMutex
}

// NewWorkflowPerformanceCollector creates a performance collector with workflow context
func NewWorkflowPerformanceCollector() *WorkflowPerformanceCollector {
	return &WorkflowPerformanceCollector{
		PerformanceCollector: NewPerformanceCollector(),
		activeSteps:          make(map[string]time.Time),
		stepExecutionCount:   0,
	}
}

// StartStep records the start of a workflow step
func (wpc *WorkflowPerformanceCollector) StartStep(stepName string) {
	wpc.mutex.Lock()
	defer wpc.mutex.Unlock()

	wpc.activeSteps[stepName] = time.Now()
	wpc.stepExecutionCount++
}

// EndStep records the completion of a workflow step
func (wpc *WorkflowPerformanceCollector) EndStep(stepName string) {
	wpc.mutex.Lock()
	defer wpc.mutex.Unlock()

	delete(wpc.activeSteps, stepName)
}

// CollectWorkflowMetrics gathers performance metrics with workflow context
func (wpc *WorkflowPerformanceCollector) CollectWorkflowMetrics() *PerformanceMetrics {
	metrics := wpc.CollectMetrics()

	wpc.mutex.RLock()
	metrics.StepExecutionCount = wpc.stepExecutionCount
	metrics.ActiveStepCount = len(wpc.activeSteps)
	wpc.mutex.RUnlock()

	return metrics
}

// Reset clears workflow-specific counters
func (wpc *WorkflowPerformanceCollector) Reset() {
	wpc.mutex.Lock()
	defer wpc.mutex.Unlock()

	wpc.activeSteps = make(map[string]time.Time)
	wpc.stepExecutionCount = 0
}

// GetActiveSteps returns currently active steps and their start times
func (wpc *WorkflowPerformanceCollector) GetActiveSteps() map[string]time.Time {
	wpc.mutex.RLock()
	defer wpc.mutex.RUnlock()

	result := make(map[string]time.Time)
	for name, startTime := range wpc.activeSteps {
		result[name] = startTime
	}

	return result
}

// GetStepExecutionCount returns the total number of steps executed
func (wpc *WorkflowPerformanceCollector) GetStepExecutionCount() int {
	wpc.mutex.RLock()
	defer wpc.mutex.RUnlock()

	return wpc.stepExecutionCount
}
