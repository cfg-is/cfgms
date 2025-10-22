package workflow

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestFanOutStep(t *testing.T) {
	// Test fan-out that distributes work across multiple parallel workers
	workflow := Workflow{
		Name: "fanout-test",
		Variables: map[string]interface{}{
			"numbers": []interface{}{1, 2, 3, 4, 5},
		},
		Steps: []Step{
			{
				Name: "process-numbers",
				Type: StepTypeFanOut,
				FanOut: &FanOutConfig{
					DataSource:     "numbers",
					ResultVariable: "processed",
					MaxConcurrency: 2,
					Timeout:        5 * time.Second,
					WorkerTemplate: Step{
						Name: "multiply-by-two",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
							Message:  "Processing number",
						},
						Variables: map[string]interface{}{
							"processed": "{{item * 2}}", // Would need expression evaluation
						},
					},
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify fan-out results were stored
	processed, exists := execution.GetVariable("processed")
	assert.True(t, exists)
	assert.NotNil(t, processed)

	// Verify step results are available
	stepResults, exists := execution.GetVariable("process-numbers_results")
	assert.True(t, exists)
	assert.NotNil(t, stepResults)
}

func TestFanInStep(t *testing.T) {
	// Test fan-in that collects and combines results from multiple sources
	workflow := Workflow{
		Name: "fanin-test",
		Variables: map[string]interface{}{
			"source1": []interface{}{"a", "b", "c"},
			"source2": []interface{}{"d", "e", "f"},
			"source3": []interface{}{"g", "h", "i"},
		},
		Steps: []Step{
			{
				Name: "merge-sources",
				Type: StepTypeFanIn,
				FanIn: &FanInConfig{
					Sources:        []string{"source1", "source2", "source3"},
					Strategy:       FanInStrategyMerge,
					OutputVariable: "merged_result",
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify fan-in result
	merged, exists := execution.GetVariable("merged_result")
	assert.True(t, exists)
	assert.NotNil(t, merged)

	// Check that all items were merged
	if mergedSlice, ok := merged.([]interface{}); ok {
		assert.Equal(t, 9, len(mergedSlice)) // 3 sources × 3 items each
	}
}

func TestFanInStrategies(t *testing.T) {
	// Test different fan-in strategies
	testCases := []struct {
		name     string
		strategy FanInStrategy
		sources  map[string]interface{}
		expected interface{}
	}{
		{
			name:     "merge",
			strategy: FanInStrategyMerge,
			sources: map[string]interface{}{
				"list1": []interface{}{1, 2},
				"list2": []interface{}{3, 4},
			},
			expected: []interface{}{1, 2, 3, 4},
		},
		{
			name:     "concat",
			strategy: FanInStrategyConcat,
			sources: map[string]interface{}{
				"str1": "hello",
				"str2": "world",
			},
			expected: "helloworld",
		},
		{
			name:     "sum",
			strategy: FanInStrategySum,
			sources: map[string]interface{}{
				"num1": 10,
				"num2": 20,
				"num3": 30,
			},
			expected: float64(60),
		},
		{
			name:     "first",
			strategy: FanInStrategyFirst,
			sources: map[string]interface{}{
				"item1": "first",
				"item2": "second",
				"item3": "third",
			},
			expected: "first",
		},
		{
			name:     "last",
			strategy: FanInStrategyLast,
			sources: map[string]interface{}{
				"item1": "first",
				"item2": "second",
				"item3": "third",
			},
			expected: "third",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create workflow with fan-in step
			workflow := Workflow{
				Name:      "fanin-strategy-test",
				Variables: tc.sources,
				Steps: []Step{
					{
						Name: "combine-data",
						Type: StepTypeFanIn,
						FanIn: &FanInConfig{
							Sources:        getKeys(tc.sources),
							Strategy:       tc.strategy,
							OutputVariable: "result",
						},
					},
				},
			}

			// Create engine and execute workflow
			moduleFactory := createTestFactory()
			logger := pkgtesting.NewMockLogger(true)
			engine := NewEngine(moduleFactory, logger)
			ctx := context.Background()

			execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
			require.NoError(t, err)
			require.NotNil(t, execution)

			// Wait for completion
			time.Sleep(100 * time.Millisecond)

			// Verify execution completed successfully
			assert.Equal(t, StatusCompleted, execution.GetStatus())

			// Verify result matches expected
			result, exists := execution.GetVariable("result")
			assert.True(t, exists)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestFanOutEmptyData(t *testing.T) {
	// Test fan-out with empty data source
	workflow := Workflow{
		Name: "fanout-empty-test",
		Variables: map[string]interface{}{
			"empty_list": []interface{}{},
		},
		Steps: []Step{
			{
				Name: "process-empty",
				Type: StepTypeFanOut,
				FanOut: &FanOutConfig{
					DataSource: "empty_list",
					WorkerTemplate: Step{
						Name: "worker",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
						},
					},
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully (empty fan-out is valid)
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestFanInEmptyData(t *testing.T) {
	// Test fan-in with no data from sources
	workflow := Workflow{
		Name: "fanin-empty-test",
		Variables: map[string]interface{}{
			"empty1": nil,
			"empty2": nil,
		},
		Steps: []Step{
			{
				Name: "combine-empty",
				Type: StepTypeFanIn,
				FanIn: &FanInConfig{
					Sources:        []string{"empty1", "empty2", "nonexistent"},
					Strategy:       FanInStrategyMerge,
					OutputVariable: "result",
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify result is nil (no data to combine)
	result, exists := execution.GetVariable("result")
	assert.True(t, exists)
	assert.Nil(t, result)
}

func TestFanOutMissingConfiguration(t *testing.T) {
	// Test fan-out with missing configuration
	workflow := Workflow{
		Name: "fanout-missing-config",
		Steps: []Step{
			{
				Name: "invalid-fanout",
				Type: StepTypeFanOut,
				// No FanOut configuration
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution failed due to missing configuration
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestFanInMissingConfiguration(t *testing.T) {
	// Test fan-in with missing configuration
	workflow := Workflow{
		Name: "fanin-missing-config",
		Steps: []Step{
			{
				Name: "invalid-fanin",
				Type: StepTypeFanIn,
				// No FanIn configuration
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution failed due to missing configuration
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestFanOutFanInCombined(t *testing.T) {
	// Test combined fan-out then fan-in workflow
	workflow := Workflow{
		Name: "fanout-fanin-combined",
		Variables: map[string]interface{}{
			"input_data": []interface{}{"apple", "banana", "cherry"},
		},
		Steps: []Step{
			{
				Name: "process-items",
				Type: StepTypeFanOut,
				FanOut: &FanOutConfig{
					DataSource:     "input_data",
					ResultVariable: "processed_items",
					WorkerTemplate: Step{
						Name: "process-item",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 5 * time.Millisecond,
							Message:  "Processing item",
						},
					},
				},
			},
			{
				Name: "combine-results",
				Type: StepTypeFanIn,
				FanIn: &FanInConfig{
					Sources:        []string{"processed_items", "process-items_results"},
					Strategy:       FanInStrategyMerge,
					OutputVariable: "final_result",
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(200 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify final result exists
	finalResult, exists := execution.GetVariable("final_result")
	assert.True(t, exists)
	assert.NotNil(t, finalResult)
}

// Helper function to get keys from a map
func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Sort keys to ensure consistent order
	sort.Strings(keys)
	return keys
}
