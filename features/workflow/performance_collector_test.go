// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPerformanceCollector_CollectMetrics(t *testing.T) {
	collector := NewPerformanceCollector()

	metrics := collector.CollectMetrics()

	assert.NotNil(t, metrics)
	assert.GreaterOrEqual(t, metrics.CPUUsagePercent, 0.0)
	assert.LessOrEqual(t, metrics.CPUUsagePercent, 100.0)
	assert.Greater(t, metrics.GoRoutineCount, 0)
	assert.Greater(t, metrics.MemoryUsageBytes, uint64(0))
	assert.GreaterOrEqual(t, metrics.ThreadCount, 1)
	assert.NotZero(t, metrics.Timestamp)
}

func TestWorkflowPerformanceCollector_StepTracking(t *testing.T) {
	collector := NewWorkflowPerformanceCollector()

	collector.StartStep("step1")
	collector.StartStep("step2")

	activeSteps := collector.GetActiveSteps()
	assert.Len(t, activeSteps, 2)
	assert.Contains(t, activeSteps, "step1")
	assert.Contains(t, activeSteps, "step2")

	collector.EndStep("step1")

	activeSteps = collector.GetActiveSteps()
	assert.Len(t, activeSteps, 1)
	assert.Contains(t, activeSteps, "step2")
	assert.NotContains(t, activeSteps, "step1")

	assert.Equal(t, 2, collector.GetStepExecutionCount())

	metrics := collector.CollectWorkflowMetrics()
	assert.Equal(t, 2, metrics.StepExecutionCount)
	assert.Equal(t, 1, metrics.ActiveStepCount)
}

func TestWorkflowPerformanceCollector_Reset(t *testing.T) {
	collector := NewWorkflowPerformanceCollector()

	collector.StartStep("step1")
	collector.StartStep("step2")
	assert.Equal(t, 2, collector.GetStepExecutionCount())

	collector.Reset()

	assert.Equal(t, 0, collector.GetStepExecutionCount())
	assert.Empty(t, collector.GetActiveSteps())
}

func TestPerformanceCollector_GetMemoryUsage(t *testing.T) {
	collector := NewPerformanceCollector()

	allocated, system := collector.GetMemoryUsage()
	assert.Greater(t, allocated, uint64(0))
	assert.Greater(t, system, uint64(0))
}

func TestPerformanceCollector_GetGCStats(t *testing.T) {
	collector := NewPerformanceCollector()

	runtime.GC()

	count, pauseTime := collector.GetGCStats()
	assert.GreaterOrEqual(t, count, uint32(1))
	assert.GreaterOrEqual(t, pauseTime, time.Duration(0))
}

func TestPerformanceCollector_GetGoroutineCount(t *testing.T) {
	collector := NewPerformanceCollector()

	count := collector.GetGoroutineCount()
	assert.Greater(t, count, 0)
}
