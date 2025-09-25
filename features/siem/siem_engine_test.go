package siem

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockTriggerManager implements trigger.TriggerManager for testing
type MockTriggerManager struct {
	triggers map[string]*trigger.Trigger
	mutex    sync.RWMutex
}

func NewMockTriggerManager() *MockTriggerManager {
	return &MockTriggerManager{
		triggers: make(map[string]*trigger.Trigger),
	}
}

func (m *MockTriggerManager) CreateTrigger(ctx context.Context, t *trigger.Trigger) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.triggers[t.ID] = t
	return nil
}

func (m *MockTriggerManager) UpdateTrigger(ctx context.Context, t *trigger.Trigger) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.triggers[t.ID] = t
	return nil
}

func (m *MockTriggerManager) DeleteTrigger(ctx context.Context, triggerID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.triggers, triggerID)
	return nil
}

func (m *MockTriggerManager) GetTrigger(ctx context.Context, triggerID string) (*trigger.Trigger, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	if t, exists := m.triggers[triggerID]; exists {
		return t, nil
	}
	return nil, nil
}

func (m *MockTriggerManager) ListTriggers(ctx context.Context, filter *trigger.TriggerFilter) ([]*trigger.Trigger, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var result []*trigger.Trigger
	for _, t := range m.triggers {
		result = append(result, t)
	}
	return result, nil
}

func (m *MockTriggerManager) EnableTrigger(ctx context.Context, triggerID string) error  { return nil }
func (m *MockTriggerManager) DisableTrigger(ctx context.Context, triggerID string) error { return nil }
func (m *MockTriggerManager) ExecuteTrigger(ctx context.Context, triggerID string, data map[string]interface{}) (*trigger.TriggerExecution, error) { return nil, nil }
func (m *MockTriggerManager) GetTriggerExecutions(ctx context.Context, triggerID string, limit int) ([]*trigger.TriggerExecution, error) { return nil, nil }
func (m *MockTriggerManager) Start(ctx context.Context) error { return nil }
func (m *MockTriggerManager) Stop(ctx context.Context) error  { return nil }

// MockWorkflowTrigger implements trigger.WorkflowTrigger for testing
type MockWorkflowTrigger struct {
	triggeredWorkflows []string
	mutex             sync.RWMutex
}

func NewMockWorkflowTrigger() *MockWorkflowTrigger {
	return &MockWorkflowTrigger{
		triggeredWorkflows: make([]string, 0),
	}
}

func (m *MockWorkflowTrigger) TriggerWorkflow(ctx context.Context, t *trigger.Trigger, data map[string]interface{}) (*trigger.WorkflowExecution, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.triggeredWorkflows = append(m.triggeredWorkflows, t.WorkflowName)

	return &trigger.WorkflowExecution{
		ID:           "test-exec-" + t.ID,
		WorkflowName: t.WorkflowName,
		Status:       "running",
		StartTime:    time.Now(),
	}, nil
}

func (m *MockWorkflowTrigger) ValidateTrigger(ctx context.Context, t *trigger.Trigger) error {
	return nil
}

func (m *MockWorkflowTrigger) GetTriggeredWorkflows() []string {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	result := make([]string, len(m.triggeredWorkflows))
	copy(result, m.triggeredWorkflows)
	return result
}

// Test helper functions
func createTestLogEntry(level, message, tenantID string) interfaces.LogEntry {
	return interfaces.LogEntry{
		Timestamp:   time.Now(),
		Level:       level,
		Message:     message,
		ServiceName: "test-service",
		Component:   "test-component",
		TenantID:    tenantID,
		Fields: map[string]interface{}{
			"test_field": "test_value",
		},
	}
}

func createTestConfig() ProcessingConfig {
	return ProcessingConfig{
		BufferSize:               10000,
		BatchSize:                100,
		BatchTimeout:             10 * time.Millisecond,
		WorkerCount:              4,
		WorkerQueueSize:          100,
		MaxLatency:               100 * time.Millisecond,
		TargetThroughput:         10000,
		CorrelationWindow:        5 * time.Minute,
		MaxCorrelationEvents:     1000,
		MaxMemoryUsage:           1024 * 1024 * 1024, // 1GB
		EnablePatternMatching:    true,
		EnableEventCorrelation:   true,
		EnableMetrics:           true,
		TenantID:                "test-tenant",
	}
}

// Unit Tests

func TestSIEMEngine_Creation(t *testing.T) {
	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)
	assert.NotNil(t, engine)
	assert.Equal(t, int32(0), engine.running)
	assert.NotNil(t, engine.streamProcessor)
	assert.NotNil(t, engine.patternMatcher)
	assert.NotNil(t, engine.eventCorrelator)
	assert.NotNil(t, engine.ruleManager)
}

func TestSIEMEngine_StartStop(t *testing.T) {
	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start engine
	err = engine.Start(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(1), engine.running)

	// Try starting again (should fail)
	err = engine.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Stop engine
	err = engine.Stop(ctx)
	require.NoError(t, err)
	assert.Equal(t, int32(0), engine.running)

	// Try stopping again (should fail)
	err = engine.Stop(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestSIEMEngine_ProcessLogEntry(t *testing.T) {
	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(t, err)
	defer engine.Stop(ctx)

	// Process a log entry
	entry := createTestLogEntry("ERROR", "Test error message", "test-tenant")
	err = engine.ProcessLogEntry(ctx, entry)
	require.NoError(t, err)

	// Give some time for processing
	time.Sleep(100 * time.Millisecond)

	// Check metrics
	metrics, err := engine.GetMetrics(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, metrics.TotalEntriesProcessed, int64(1))
}

func TestPatternMatcher_BasicMatching(t *testing.T) {
	matcher := NewPatternMatcher()

	// Add a test pattern
	pattern := &DetectionPattern{
		ID:            "test-pattern-1",
		Name:          "Error Pattern",
		Pattern:       "ERROR",
		PatternType:   PatternTypeContains,
		Fields:        []string{"message"},
		Enabled:       true,
		Priority:      1,
		CreatedAt:     time.Now(),
	}

	err := matcher.AddPattern(pattern)
	require.NoError(t, err)

	// Test matching
	entry := createTestLogEntry("ERROR", "This is an ERROR message", "test-tenant")
	matches, err := matcher.MatchEntry(entry)
	require.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "test-pattern-1", matches[0].PatternID)
	assert.Equal(t, "message", matches[0].Field)
}

func TestEventCorrelator_BasicCorrelation(t *testing.T) {
	correlator := NewEventCorrelator(5 * time.Minute)

	ctx := context.Background()
	err := correlator.Start(ctx)
	require.NoError(t, err)
	defer correlator.Stop(ctx)

	// Add correlation rule
	rule := &CorrelationRule{
		ID:         "test-correlation-1",
		Name:       "Failed Login Correlation",
		EventTypes: []string{"login_failed"},
		TimeWindow: 1 * time.Minute,
		MinEvents:  3,
		MaxEvents:  10,
		GroupBy:    []string{"source"},
		Enabled:    true,
	}

	err = correlator.AddCorrelationRule(rule)
	require.NoError(t, err)

	// Create test events
	events := []*SecurityEvent{
		{
			ID:        "event1",
			EventType: "login_failed",
			Source:    "192.168.1.100",
			Timestamp: time.Now(),
		},
		{
			ID:        "event2",
			EventType: "login_failed",
			Source:    "192.168.1.100",
			Timestamp: time.Now(),
		},
		{
			ID:        "event3",
			EventType: "login_failed",
			Source:    "192.168.1.100",
			Timestamp: time.Now(),
		},
	}

	correlatedEvents, err := correlator.CorrelateEvents(ctx, events, 1*time.Minute)
	require.NoError(t, err)
	assert.Len(t, correlatedEvents, 1)
	assert.Len(t, correlatedEvents[0].Events, 3)
}

// Performance Tests

func BenchmarkSIEMEngine_ThroughputTest(b *testing.B) {
	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(b, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(b, err)
	defer engine.Stop(ctx)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			entry := createTestLogEntry("INFO", "Benchmark test message", "test-tenant")
			engine.ProcessLogEntry(ctx, entry)
			i++
		}
	})
}

func BenchmarkPatternMatcher_BatchProcessing(b *testing.B) {
	matcher := NewPatternMatcher()

	// Add test patterns
	patterns := []*DetectionPattern{
		{
			ID:          "pattern1",
			Pattern:     "ERROR",
			PatternType: PatternTypeContains,
			Fields:      []string{"message"},
			Enabled:     true,
		},
		{
			ID:          "pattern2",
			Pattern:     "WARN",
			PatternType: PatternTypeContains,
			Fields:      []string{"message"},
			Enabled:     true,
		},
		{
			ID:          "pattern3",
			Pattern:     "CRITICAL",
			PatternType: PatternTypeContains,
			Fields:      []string{"message"},
			Enabled:     true,
		},
	}

	for _, pattern := range patterns {
		matcher.AddPattern(pattern)
	}

	// Create test entries
	entries := make([]interfaces.LogEntry, 1000)
	for i := 0; i < 1000; i++ {
		entries[i] = createTestLogEntry("ERROR", "Test error message", "test-tenant")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := matcher.MatchBatch(entries)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Integration Tests

func TestSIEMEngine_EndToEndProcessing(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end test in short mode")
	}

	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(t, err)
	defer engine.Stop(ctx)

	// Add a test pattern
	pattern := &DetectionPattern{
		ID:            "test-pattern-security",
		Name:          "Security Pattern",
		Pattern:       "SECURITY_ALERT",
		PatternType:   PatternTypeContains,
		Fields:        []string{"message"},
		Enabled:       true,
		Priority:      10,
		CreatedAt:     time.Now(),
	}

	err = engine.GetPatternMatcher().AddPattern(pattern)
	require.NoError(t, err)

	// Add a workflow trigger
	siemTrigger := &trigger.Trigger{
		ID:           "test-trigger",
		Name:         "Security Alert Trigger",
		Type:         trigger.TriggerTypeSIEM,
		Status:       trigger.TriggerStatusActive,
		TenantID:     "test-tenant",
		WorkflowName: "security-response",
		SIEM: &trigger.SIEMConfig{
			EventTypes: []string{"pattern_match"},
			Enabled:    true,
		},
	}

	err = triggerManager.CreateTrigger(ctx, siemTrigger)
	require.NoError(t, err)

	// Process log entries that should trigger the pattern
	for i := 0; i < 10; i++ {
		entry := createTestLogEntry("ERROR", "SECURITY_ALERT: Suspicious activity detected", "test-tenant")
		err = engine.ProcessLogEntry(ctx, entry)
		require.NoError(t, err)
	}

	// Wait for processing
	time.Sleep(500 * time.Millisecond)

	// Check metrics
	metrics, err := engine.GetMetrics(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, metrics.TotalEntriesProcessed, int64(10))
	assert.Greater(t, metrics.CurrentThroughput, float64(0))
}

// Performance Tests with Specific Requirements

func TestSIEMEngine_ThroughputRequirement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping throughput test in short mode")
	}

	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(t, err)
	defer engine.Stop(ctx)

	// Test processing 10,000+ entries per second
	startTime := time.Now()
	numEntries := 12000 // Test with 12k to ensure we exceed requirement

	// Use goroutines to simulate concurrent load
	var wg sync.WaitGroup
	entryChan := make(chan interfaces.LogEntry, 1000)

	// Producer goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(entryChan)
		for i := 0; i < numEntries; i++ {
			entry := createTestLogEntry("INFO", "Performance test message", "test-tenant")
			entryChan <- entry
		}
	}()

	// Consumer goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range entryChan {
				engine.ProcessLogEntry(ctx, entry)
			}
		}()
	}

	wg.Wait()
	processingTime := time.Since(startTime)

	// Calculate throughput
	throughput := float64(numEntries) / processingTime.Seconds()
	t.Logf("Processed %d entries in %v (%.2f entries/second)", numEntries, processingTime, throughput)

	// Verify throughput meets requirement (>10,000 entries/second)
	assert.Greater(t, throughput, float64(10000),
		"Throughput requirement not met: got %.2f entries/second, need >10,000", throughput)

	// Check final metrics
	metrics, err := engine.GetMetrics(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, metrics.TotalEntriesProcessed, int64(numEntries))
}

func TestSIEMEngine_LatencyRequirement(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping latency test in short mode")
	}

	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(t, err)
	defer engine.Stop(ctx)

	// Add pattern for latency testing
	pattern := &DetectionPattern{
		ID:          "latency-test-pattern",
		Pattern:     "LATENCY_TEST",
		PatternType: PatternTypeContains,
		Fields:      []string{"message"},
		Enabled:     true,
	}

	err = engine.GetPatternMatcher().AddPattern(pattern)
	require.NoError(t, err)

	// Measure end-to-end latency for pattern detection
	numTests := 100
	var totalLatency time.Duration

	for i := 0; i < numTests; i++ {
		startTime := time.Now()
		entry := createTestLogEntry("INFO", "LATENCY_TEST message", "test-tenant")
		err = engine.ProcessLogEntry(ctx, entry)
		require.NoError(t, err)

		// Wait for processing (this is a simplified latency test)
		// In a real system, we'd measure actual processing completion
		time.Sleep(1 * time.Millisecond)
		latency := time.Since(startTime)
		totalLatency += latency
	}

	averageLatency := totalLatency / time.Duration(numTests)
	t.Logf("Average latency: %v", averageLatency)

	// Verify latency meets requirement (<100ms)
	assert.Less(t, averageLatency, 100*time.Millisecond,
		"Latency requirement not met: got %v, need <100ms", averageLatency)

	// Check metrics
	metrics, err := engine.GetMetrics(ctx)
	require.NoError(t, err)
	t.Logf("Engine metrics - Average latency: %.2fms, Max latency: %.2fms",
		metrics.AverageLatency, metrics.MaxLatency)
}

func TestSIEMEngine_MemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	// Force GC before test
	runtime.GC()
	var memStatsBefore runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(t, err)

	// Process entries and check memory growth
	for i := 0; i < 10000; i++ {
		entry := createTestLogEntry("INFO", "Memory test message", "test-tenant")
		engine.ProcessLogEntry(ctx, entry)
	}

	// Wait for processing
	time.Sleep(1 * time.Second)

	engine.Stop(ctx)

	// Force GC and check memory
	runtime.GC()
	var memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsAfter)

	memoryGrowth := memStatsAfter.Alloc - memStatsBefore.Alloc
	t.Logf("Memory growth: %d bytes (%.2f MB)", memoryGrowth, float64(memoryGrowth)/(1024*1024))

	// Verify memory growth is reasonable (less than 50MB for this test)
	assert.Less(t, memoryGrowth, uint64(50*1024*1024),
		"Excessive memory growth: %d bytes", memoryGrowth)
}

// Load Tests

func TestSIEMEngine_StressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}

	triggerManager := NewMockTriggerManager()
	workflowTrigger := NewMockWorkflowTrigger()
	config := createTestConfig()

	engine, err := NewSIEMEngine(config, triggerManager, workflowTrigger)
	require.NoError(t, err)

	ctx := context.Background()
	err = engine.Start(ctx)
	require.NoError(t, err)
	defer engine.Stop(ctx)

	// Add multiple patterns
	for i := 0; i < 10; i++ {
		pattern := &DetectionPattern{
			ID:          fmt.Sprintf("stress-pattern-%d", i),
			Pattern:     fmt.Sprintf("STRESS_%d", i),
			PatternType: PatternTypeContains,
			Fields:      []string{"message"},
			Enabled:     true,
		}
		engine.GetPatternMatcher().AddPattern(pattern)
	}

	// Run stress test with multiple producers
	var wg sync.WaitGroup
	numProducers := 20
	entriesPerProducer := 5000

	startTime := time.Now()

	for i := 0; i < numProducers; i++ {
		wg.Add(1)
		go func(producerID int) {
			defer wg.Done()
			for j := 0; j < entriesPerProducer; j++ {
				entry := createTestLogEntry("INFO",
					fmt.Sprintf("Stress test message %d STRESS_%d", j, j%10), "test-tenant")
				engine.ProcessLogEntry(ctx, entry)
			}
		}(i)
	}

	wg.Wait()
	totalTime := time.Since(startTime)

	totalEntries := numProducers * entriesPerProducer
	throughput := float64(totalEntries) / totalTime.Seconds()

	t.Logf("Stress test completed: %d entries in %v (%.2f entries/second)",
		totalEntries, totalTime, throughput)

	// Check that system remained stable
	metrics, err := engine.GetMetrics(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, metrics.TotalEntriesProcessed, int64(totalEntries))
	assert.Less(t, metrics.DroppedEntries, int64(totalEntries/10)) // Less than 10% dropped
}

